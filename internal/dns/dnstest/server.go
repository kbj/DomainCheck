// Package dnstest provides scriptable in-process DNS servers for tests:
// plain UDP, DoT (DNS over TLS) and DoH (DNS over HTTPS). They speak just
// enough of the wire format for NS queries: single-question packets with
// either an answer section, NXDOMAIN or SERVFAIL responses.
package dnstest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Response is the scripted answer for one domain.
type Response struct {
	RCode   int      // 0 = NOERROR, 2 = SERVFAIL, 3 = NXDOMAIN
	NSNames []string // NS answer records; empty means no answers
}

// Server is a fake authoritative-ish DNS server on 127.0.0.1, available as
// plain UDP (Start), DoT (StartDoT) or DoH (StartDoH).
type Server struct {
	t           *testing.T
	conn        *net.UDPConn     // plain-UDP mode
	tlsListener net.Listener     // DoT mode
	httpSrv     *httptest.Server // DoH mode
	mu          sync.Mutex
	behavior    func(domain string) Response
	hits        map[string]int
	order       []string
	closed      bool
}

// debugDump enables hex logging of replies when tests need troubleshooting.
// DebugDump enables hex logging of replies when tests need troubleshooting.
var DebugDump = false

// Start launches the plain-UDP server goroutine and registers cleanup.
func Start(t *testing.T) *Server {
	t.Helper()
	addr := net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		t.Fatalf("dnstest: listen: %v", err)
	}
	s := &Server{t: t, conn: conn, hits: map[string]int{}}
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

// StartDoT launches a DoT server with a self-signed certificate and
// registers cleanup. Clients must skip verification (see dns.Options).
func StartDoT(t *testing.T) *Server {
	t.Helper()
	cert := selfSignedCert(t)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("dnstest: tls listen: %v", err)
	}
	s := &Server{t: t, tlsListener: l, hits: map[string]int{}}
	go s.serveTLS()
	t.Cleanup(s.Close)
	return s
}

// StartDoH launches an RFC 8484-style DoH server (plain HTTP via httptest)
// and registers cleanup.
func StartDoH(t *testing.T) *Server {
	t.Helper()
	s := &Server{t: t, hits: map[string]int{}}
	s.httpSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxQueryBytes))
		if err != nil || len(body) < 12 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reply := s.respond(body)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(reply)
	}))
	t.Cleanup(s.Close)
	return s
}

const maxQueryBytes = 1 << 16

// SetBehavior swaps the response script at any time.
func (s *Server) SetBehavior(fn func(domain string) Response) {
	s.mu.Lock()
	s.behavior = fn
	s.mu.Unlock()
}

// DefaultBehavior answers every name with one NS record "ns1.<domain>".
func DefaultBehavior(string) Response { return Response{} }

func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	switch {
	case s.conn != nil:
		s.conn.Close()
	case s.tlsListener != nil:
		s.tlsListener.Close()
	case s.httpSrv != nil:
		s.httpSrv.Close()
	}
}

// Addr returns "127.0.0.1:<port>" for resolver dial overrides.
func (s *Server) Addr() string { return s.conn.LocalAddr().String() }

// TLSAddr returns "127.0.0.1:<port>" for tls:// resolvers (DoT mode only).
func (s *Server) TLSAddr() string { return s.tlsListener.Addr().String() }

// URL returns the DoH endpoint URL (DoH mode only).
func (s *Server) URL() string { return s.httpSrv.URL }

func (s *Server) HitCount(domain string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[domain]
}

func (s *Server) serve() {
	buf := make([]byte, 1500)
	for {
		n, remote, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 12 {
			continue
		}
		// Copy: buf is reused by the next ReadFromUDP while handle runs.
		query := append([]byte(nil), buf[:n]...)
		if DebugDump {
			log.Printf("dnstest query from %s (%d bytes): % x", remote, len(query), query)
		}
		go s.handle(query, remote)
	}
}

func (s *Server) handle(query []byte, remote *net.UDPAddr) {
	out := s.respond(query)
	if DebugDump {
		s.t.Logf("dnstest reply to %s (%d bytes): % x", parseQName(query[12:]), len(out), out)
	}
	s.conn.WriteToUDP(out, remote)
}

// respond builds the scripted reply for one wire-format query.
func (s *Server) respond(query []byte) []byte {
	id := query[:2]
	// The client's packet may carry an EDNS0 OPT record after the question;
	// echo ONLY the actual question section in our reply.
	qnameLen := encodedNameLen(query[12:])
	question := query[12 : 12+qnameLen+4] // name + QTYPE + QCLASS
	domain := parseQName(query[12:])

	s.mu.Lock()
	s.hits[domain]++
	s.order = append(s.order, domain)
	fn := s.behavior
	s.mu.Unlock()

	resp := Response{}
	if fn != nil {
		resp = fn(domain)
	} else {
		resp = DefaultBehavior(domain)
	}
	rcode := resp.RCode
	var answers [][]byte
	for _, ns := range resp.NSNames {
		answers = append(answers, encodeNSAnswer(query, ns))
	}

	out := make([]byte, 0, 512)
	out = append(out, id...)
	flags := uint16(0x8000 | 0x0100 | 0x0080) // QR|RD|RA
	flags |= uint16(rcode & 0xF)
	out = append(out, byte(flags>>8), byte(flags))
	out = append(out, 0, 1)                                      // QDCOUNT
	out = append(out, byte(len(answers)>>8), byte(len(answers))) // ANCOUNT
	out = append(out, 0, 0, 0, 0)                                // NSCOUNT, ARCOUNT
	out = append(out, question...)                               // echo the question
	for _, a := range answers {
		out = append(out, a...)
	}
	return out
}

func (s *Server) serveTLS() {
	for {
		conn, err := s.tlsListener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			for { // one message per frame until the client hangs up
				query, err := readFramedMessage(c)
				if err != nil {
					return
				}
				if err := writeFramedMessage(c, s.respond(query)); err != nil {
					return
				}
			}
		}(conn)
	}
}

func readFramedMessage(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeFramedMessage(w io.Writer, msg []byte) error {
	if len(msg) > 0xFFFF {
		return fmt.Errorf("message too long for DNS framing: %d", len(msg))
	}
	frame := append(make([]byte, 2, 2+len(msg)), msg...)
	binary.BigEndian.PutUint16(frame, uint16(len(msg)))
	_, err := w.Write(frame)
	return err
}

// selfSignedCert mints a throwaway certificate valid for 127.0.0.1/localhost.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("dnstest: key gen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("dnstest: create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("dnstest: parse cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// encodedNameLen returns the wire length of a plain (uncompressed) name:
// one length byte plus content per label, plus the terminating zero byte.
func encodedNameLen(b []byte) int {
	i := 0
	for i < len(b) && b[i] != 0 {
		l := int(b[i])
		if i+1+l > len(b) {
			break
		}
		i += 1 + l
	}
	return i + 1 // zero terminator
}

// parseQName decodes a plain (uncompressed) QNAME into "example.com".
func parseQName(b []byte) string {
	var sb strings.Builder
	i := 0
	for i < len(b) && b[i] != 0 {
		l := int(b[i])
		if i+1+l > len(b) {
			break
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(b[i+1 : i+1+l])
		i += 1 + l
	}
	return strings.ToLower(sb.String())
}

// encodeNSAnswer builds one NS record pointing at nsName, with NAME as a
// compression pointer to the question name at offset 12.
func encodeNSAnswer(query []byte, nsName string) []byte {
	rd := encodeName(nsName)
	out := []byte{0xC0, 0x0C}        // pointer to QNAME
	out = append(out, 0, 2)          // TYPE=NS
	out = append(out, 0, 1)          // CLASS=IN
	out = append(out, 0, 0, 1, 0x2C) // TTL=300
	out = append(out, byte(len(rd)>>8), byte(len(rd)))
	return append(out, rd...)
}

func encodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || len(label) > 63 {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}
