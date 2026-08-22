// Package dnstest provides a scriptable in-process DNS server for tests.
// It speaks just enough of the wire format for net.Resolver NS queries:
// single-question packets with either an answer section, NXDOMAIN or
// SERVFAIL responses.
package dnstest

import (
	"log"
	"net"
	"strings"
	"sync"
	"testing"
)

// Response is the scripted answer for one domain.
type Response struct {
	RCode   int      // 0 = NOERROR, 2 = SERVFAIL, 3 = NXDOMAIN
	NSNames []string // NS answer records; empty means no answers
}

// Server is a fake authoritative-ish DNS server on 127.0.0.1.
type Server struct {
	t        *testing.T
	conn     *net.UDPConn
	mu       sync.Mutex
	behavior func(domain string) Response
	hits     map[string]int
	order    []string
	closed   bool
}

// debugDump enables hex logging of replies when tests need troubleshooting.
// DebugDump enables hex logging of replies when tests need troubleshooting.
var DebugDump = false

// Start launches the server goroutine and registers cleanup.
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
	s.conn.Close()
}

// Addr returns "127.0.0.1:<port>" for resolver dial overrides.
func (s *Server) Addr() string { return s.conn.LocalAddr().String() }

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
	id := query[:2]
	// The client's packet may carry an EDNS0 OPT record after the question;
	// echo ONLY the actual question section in our reply.
	qnameLen := encodedNameLen(query[12:])
	question := query[12 : 12+qnameLen+4] // name + QTYPE + QCLASS
	domain := parseQName(query[12:])
	rcode := 0
	var answers [][]byte

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
	rcode = resp.RCode
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
	if DebugDump {
		s.t.Logf("dnstest reply to %v (%d bytes): % x", domain, len(out), out)
	}
	s.conn.WriteToUDP(out, remote)
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
