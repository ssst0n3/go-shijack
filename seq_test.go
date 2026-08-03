package gohijack

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// buildTCPPacket builds an Ethernet/IPv4/TCP packet with the given flags and
// sequence numbers, then decodes it so NewConnectionFromPacket can be tested
// without a live capture. rawConn is nil — NewConnectionFromPacket only stores
// it, never uses it during construction.
func buildTCPPacket(t *testing.T, syn, ack bool, seq, ackNum uint32) gopacket.Packet {
	t.Helper()
	eth := &layers.Ethernet{SrcMAC: []byte{1, 2, 3, 4, 5, 6}, DstMAC: []byte{6, 5, 4, 3, 2, 1}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{SrcIP: []byte{169, 254, 169, 254}, DstIP: []byte{10, 0, 0, 2}, Version: 4, IHL: 5, Protocol: layers.IPProtocolTCP, TTL: 64}
	tcp := &layers.TCP{SrcPort: 80, DstPort: 12345, Seq: seq, Ack: ackNum, SYN: syn, ACK: ack}
	assert.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	assert.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp))
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

// TestSeqOffByOneSYNACK exposes the bug: on a SYN-ACK the server's Seq is its
// ISN, but SYN consumes one sequence number so the first data byte lives at
// ISN+1. Injecting at ISN makes the receiver trim the first payload byte
// (RFC 793 left-edge overlap), which corrupts the response. The leading-\n
// trick in the flag file is a workaround for this bug.
func TestSeqOffByOneSYNACK(t *testing.T) {
	pkt := buildTCPPacket(t, true, true, 1000, 2000)
	c, err := NewConnectionFromPacket(pkt, nil)
	assert.NoError(t, err)
	assert.Equal(t, uint32(1001), c.Seq, "SYN-ACK: must inject at ISN+1 (SYN consumes a sequence number)")
}

// TestSeqDataACKNoAdjust ensures we do NOT adjust on a pure data ACK: its Seq
// already points at the next data byte.
func TestSeqDataACKNoAdjust(t *testing.T) {
	pkt := buildTCPPacket(t, false, true, 1050, 2000)
	c, err := NewConnectionFromPacket(pkt, nil)
	assert.NoError(t, err)
	assert.Equal(t, uint32(1050), c.Seq, "data ACK: Seq is already correct, no adjustment")
}
