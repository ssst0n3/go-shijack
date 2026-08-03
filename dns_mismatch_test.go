package gohijack

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// TestBuildDNSResponseNameMismatch proves #5 is fixed: when the query asks for
// "google.com" but the operator passed --dns-domain example.com, the forged
// response now stamps the answer name from the query's question, so question
// and answer names always agree. (HijackDNS additionally skips queries whose
// name doesn't match --dns-domain — see TestDnsNameEqual.)
func TestBuildDNSResponseNameMismatch(t *testing.T) {
	query := &layers.DNS{
		ID: 0xdead, QR: false, OpCode: layers.DNSOpCodeQuery, RD: true, QDCount: 1,
		Questions: []layers.DNSQuestion{{
			Name:  []byte("google.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
	}
	resp, err := BuildDNSResponse(query, "example.com", net.ParseIP("1.2.3.4"))
	assert.NoError(t, err)

	var decoded layers.DNS
	err = decoded.DecodeFromBytes(resp, gopacket.NilDecodeFeedback)
	assert.NoError(t, err)

	qName := string(decoded.Questions[0].Name)
	aName := string(decoded.Answers[0].Name)
	assert.Equal(t, qName, aName, "answer name must match the question name actually asked")
}

func TestDnsNameEqual(t *testing.T) {
	cases := []struct {
		wire   string
		domain string
		want   bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "example.com.", true},
		{"example.com.", "example.com", true},
		{"example.com.", "example.com.", true},
		{"EXAMPLE.COM", "example.com", true},
		{"Example.Com", "example.com", true},
		{"google.com", "example.com", false},
		{"", "example.com", false},
		{"example.com", "", false},
		{"sub.example.com", "example.com", false},
	}
	for _, c := range cases {
		got := dnsNameEqual([]byte(c.wire), c.domain)
		assert.Equalf(t, c.want, got, "dnsNameEqual(%q,%q)", c.wire, c.domain)
	}
}
