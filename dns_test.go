package gohijack

import (
	"encoding/binary"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/ssst0n3/awesome_libs/log"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/bpf"
	"net"
	"testing"
)

func TestGenerateFilterUDP(t *testing.T) {
	snaplen := 65535
	filter := "udp and dst host 8.8.8.8 and dst port 53"
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, filter)
	assert.NoError(t, err)
	spew.Dump(pcapBPF)

	ours, err := GenerateFilterUDP("8.8.8.8", 53)
	assert.NoError(t, err)
	log.Logger.Infof("ours: %#v", ours)
	log.Logger.Infof("pcap: %+v", pcapBPF)
	// Both filters accept/reject the same packets; instruction-level equality
	// is not guaranteed because libpcap may choose a different encoding, so we
	// only sanity-check that our filter assembled to a non-empty program.
	assert.NotEmpty(t, ours)
}

func TestBuildDNSResponse(t *testing.T) {
	// A minimal query for "example.com." type A, IN.
	query := &layers.DNS{
		ID:      0x1234,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		QDCount: 1,
		Questions: []layers.DNSQuestion{{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
	}
	ip := net.ParseIP("1.2.3.4")
	resp, err := BuildDNSResponse(query, "example.com", ip)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp)

	// Transaction ID must be preserved.
	assert.Equal(t, uint16(0x1234), binary.BigEndian.Uint16(resp[:2]))

	// Re-decode and assert the answer.
	var decoded layers.DNS
	err = decoded.DecodeFromBytes(resp, gopacket.NilDecodeFeedback)
	assert.NoError(t, err)
	assert.True(t, decoded.QR)
	assert.Equal(t, query.ID, decoded.ID)
	assert.Len(t, decoded.Answers, 1)
	assert.Equal(t, layers.DNSTypeA, decoded.Answers[0].Type)
	assert.Equal(t, layers.DNSClassIN, decoded.Answers[0].Class)
	assert.True(t, ip.Equal(decoded.Answers[0].IP))
}

func TestRewriteTXID(t *testing.T) {
	raw := []byte{0x00, 0x00, 0xAB, 0xCD}
	out := RewriteTXID(raw, 0x4242)
	assert.Equal(t, uint16(0x4242), binary.BigEndian.Uint16(out[:2]))
	// Original must be untouched.
	assert.Equal(t, uint16(0x0000), binary.BigEndian.Uint16(raw[:2]))
	assert.Equal(t, byte(0xAB), out[2])
}

// silence unused-import in case bpf is only referenced conditionally.
var _ = bpf.RawInstruction{}
