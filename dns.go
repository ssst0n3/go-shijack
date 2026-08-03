package gohijack

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/ssst0n3/awesome_libs/awesome_error"
	"net"
	"strings"
)

// BuildDNSResponse constructs a single-A-record DNS response for the given
// query: it reuses the query's transaction ID and question section, sets QR=1
// and appends one IN A answer with the supplied IP and a 600s TTL. The answer
// name is taken from the query's question so the question/answer names always
// agree (a resolver will drop a response whose answer name differs from the
// question it asked). The domain argument is only used by the caller to decide
// whether to answer at all; it is not stamped into the response.
func BuildDNSResponse(query *layers.DNS, domain string, ip net.IP) (response []byte, err error) {
	_ = domain
	answerName := []byte(domain)
	if len(query.Questions) > 0 {
		answerName = query.Questions[0].Name
	}
	dns := &layers.DNS{
		ID:           query.ID,
		QR:           true,
		OpCode:       query.OpCode,
		RD:           query.RD,
		RA:           true,
		ResponseCode: layers.DNSResponseCodeNoErr,
		Questions:    query.Questions,
		Answers: []layers.DNSResourceRecord{{
			Name:  answerName,
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			TTL:   600,
			IP:    ip.To4(),
		}},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = dns.SerializeTo(buf, opts)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	response = buf.Bytes()
	return
}

// RewriteTXID returns a copy of rawResponse with its DNS transaction ID (the
// first two bytes) overwritten by txid. Used in raw-response mode so a single
// pre-built answer file can be replayed against any query.
func RewriteTXID(rawResponse []byte, txid uint16) []byte {
	out := make([]byte, len(rawResponse))
	copy(out, rawResponse)
	binary.BigEndian.PutUint16(out[:2], txid)
	return out
}

// dnsNameEqual reports whether a wire-format name from a decoded DNS question
// matches the operator-supplied domain. Comparison is case-insensitive (DNS is
// case-insensitive per RFC 4343) and tolerant of a trailing dot on either side.
// gopacket decodes question names into dotted lowercase-free form, e.g.
// "example.com" or "EXAMPLE.COM" verbatim from the wire.
func dnsNameEqual(wireName []byte, domain string) bool {
	w := string(wireName)
	d := domain
	w = strings.TrimSuffix(w, ".")
	d = strings.TrimSuffix(d, ".")
	return strings.EqualFold(w, d)
}
