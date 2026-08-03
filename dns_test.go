package gohijack

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

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

	// Section counts must be coherent.
	assert.Equal(t, uint16(1), decoded.QDCount, "one question should be echoed")
	assert.Equal(t, uint16(1), decoded.ANCount, "one answer should be present")
	assert.Equal(t, uint32(600), decoded.Answers[0].TTL)

	// The answer name must resolve to the queried domain. gopacket decodes the
	// wire-format name into a dotted string; this guards against the answer
	// being written as raw ASCII (bug #4).
	assert.Equal(t, "example.com", string(decoded.Answers[0].Name))
}

func TestRewriteTXID(t *testing.T) {
	raw := []byte{0x00, 0x00, 0xAB, 0xCD}
	out := RewriteTXID(raw, 0x4242)
	assert.Equal(t, uint16(0x4242), binary.BigEndian.Uint16(out[:2]))
	// Original must be untouched.
	assert.Equal(t, uint16(0x0000), binary.BigEndian.Uint16(raw[:2]))
	assert.Equal(t, byte(0xAB), out[2])
}
