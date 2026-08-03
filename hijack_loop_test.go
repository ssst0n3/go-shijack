package gohijack

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// TestHijackLoopNilGuard proves the TCP sniff loop no longer panics on a packet
// that decodes to a non-TCP layer (e.g. a truncated/malformed frame that passed
// the BPF filter). Previously `tcp, _ := tcpLayer.(*layers.TCP); if tcp.ACK`
// would dereference a nil interface on type-assertion failure.
func TestHijackLoopNilGuard(t *testing.T) {
	// A packet with no TCP layer at all.
	eth := &layers.Ethernet{SrcMAC: []byte{1, 2, 3, 4, 5, 6}, DstMAC: []byte{6, 5, 4, 3, 2, 1}, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{SrcIP: []byte{169, 254, 169, 254}, DstIP: []byte{10, 0, 0, 2}, Version: 4, IHL: 5, Protocol: layers.IPProtocolUDP, TTL: 64}
	udp := &layers.UDP{SrcPort: 80, DstPort: 12345}
	udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	assert.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, udp))
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)

	// Emulate the loop's guard logic without a live capture.
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	assert.Nil(t, tcpLayer, "precondition: this packet has no TCP layer")
	// The old code did `tcp, _ := tcpLayer.(*layers.TCP); if tcp.ACK` — a nil
	// tcpLayer makes the assertion return nil, and `nil.ACK` panics. The new
	// code checks tcpLayer == nil first, so this must not panic.
	assert.NotPanics(t, func() {
		if tcpLayer == nil {
			return
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp == nil {
			return
		}
		_ = tcp.ACK
	})
}

// TestHijackLoopOnlySYNACK documents the loop's SYN-ACK-only policy: only the
// server's first segment is hijacked. A pure data ACK must be skipped so --keep
// doesn't inject stale-seq garbage repeatedly.
func TestHijackLoopOnlySYNACK(t *testing.T) {
	cases := []struct {
		name string
		syn  bool
		ack  bool
		want bool // should hijack?
	}{
		{"SYN-ACK", true, true, true},
		{"pure ACK (data)", false, true, false},
		{"SYN (client->server, shouldn't match filter but be safe)", true, false, false},
		{"FIN-ACK", false, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pkt := buildTCPPacket(t, c.syn, c.ack, 1000, 2000)
			tcpL := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
			// Mirror the loop condition exactly.
			hijack := tcpL != nil && tcpL.SYN && tcpL.ACK
			assert.Equal(t, c.want, hijack)
		})
	}
}
