// Minimal DNS wire-format helpers used by the hand-rolled DoT and DoH
// transports. Only what an NS lookup needs: build one query, parse one
// reply. Plain UDP/TCP keep using net.Resolver, which handles the full
// protocol (truncation retry, EDNS, ...) on its own.

package dns

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

const (
	typeNS  = 2
	classIN = 1
)

// newQueryID returns a random DNS message ID. The ID only guards against
// off-path spoofing; the transports verify it matches the query they sent.
func newQueryID() uint16 {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand never fails on modern platforms; fall back to a
		// constant rather than panicking in a scanner loop.
		return 0x434b // "CK"
	}
	return binary.BigEndian.Uint16(b[:])
}

// buildNSQuery encodes a single-question NS query for domain.
func buildNSQuery(id uint16, domain string) []byte {
	msg := make([]byte, 0, 12+1+len(domain)+4)
	msg = append(msg, byte(id>>8), byte(id))
	// Flags: RD=1 (recursion desired), everything else zero.
	msg = append(msg, 0x01, 0x00)
	msg = append(msg, 0, 1) // QDCOUNT=1
	msg = append(msg,
		0, 0, // ANCOUNT=0
		0, 0, // NSCOUNT=0
		0, 0) // ARCOUNT=0 (no EDNS needed for NS lookups)
	for _, label := range splitLabels(domain) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0) // root terminator
	msg = append(msg, 0, typeNS)
	msg = append(msg, 0, classIN)
	return msg
}

func splitLabels(domain string) []string {
	domain = trimDot(domain)
	if domain == "" {
		return nil
	}
	labels := make([]string, 0, 4)
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			if i > start {
				labels = append(labels, domain[start:i])
			}
			start = i + 1
		}
	}
	return labels
}

func trimDot(s string) string {
	for len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}

// parseReply validates a DNS reply and reports whether the answer section
// contains at least one NS record.
//
// Results mirror lookupOnce semantics:
//   - (true, true, nil)   : NS records present -> registered.
//   - (false, true, nil)  : NOERROR without NS answers, or NXDOMAIN ->
//     definitive "no NS".
//   - (false, false, err) : malformed reply or non-NXDOMAIN error RCODE;
//     transient, safe to retry.
func parseReply(queryID uint16, msg []byte) (hasNS bool, definitive bool, err error) {
	if len(msg) < 12 {
		return false, false, fmt.Errorf("reply shorter than DNS header (%d bytes)", len(msg))
	}
	if id := binary.BigEndian.Uint16(msg[0:2]); id != queryID {
		return false, false, fmt.Errorf("reply ID %d does not match query ID %d", id, queryID)
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 {
		return false, false, fmt.Errorf("message is not a response (QR=0)")
	}
	switch rcode := int(flags & 0xF); rcode {
	case 0: // NOERROR: presence of answers decides.
	case 3: // NXDOMAIN: name does not exist at all -> definitive.
		return false, true, nil
	default:
		return false, false, fmt.Errorf("rcode %d", rcode)
	}

	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	// Skip the question section to reach the answers. Replies from strict
	// servers echo exactly one question; tolerate none if QDCOUNT is odd.
	for i := 0; i < qd; i++ {
		var e error
		if off, e = skipName(msg, off); e != nil {
			return false, false, fmt.Errorf("malformed question section: %w", e)
		}
		off += 4 // QTYPE + QCLASS
		if off > len(msg) {
			return false, false, fmt.Errorf("question section overruns reply")
		}
	}
	for i := 0; i < an; i++ {
		var e error
		if off, e = skipName(msg, off); e != nil {
			return false, false, fmt.Errorf("malformed answer name: %w", e)
		}
		if off+10 > len(msg) {
			return false, false, fmt.Errorf("answer record truncated")
		}
		rtype := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10 + rdlen
		if off > len(msg) {
			return false, false, fmt.Errorf("rdata overruns reply")
		}
		if rtype == typeNS {
			hasNS = true
		}
	}
	return hasNS, true, nil
}

// skipName advances past a (possibly compressed) domain name and returns
// the offset just after it. Compression pointers are followed once — we
// only need the total consumed length, not the decoded name.
func skipName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, fmt.Errorf("name runs past end of message")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0: // pointer: two bytes total
			if off+2 > len(msg) {
				return 0, fmt.Errorf("truncated compression pointer")
			}
			return off + 2, nil
		case l&0xC0 != 0:
			return 0, fmt.Errorf("unsupported label type %#x", l&0xC0)
		default:
			off += 1 + l
		}
	}
}
