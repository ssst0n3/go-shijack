package gohijack

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// serializeTCP builds a forged TCP segment the same way doHijack does, without
// touching a raw socket. It returns the decoded IP/TCP layers for assertion.
func serializeTCP(t *testing.T, payload []byte) (*layers.IPv4, *layers.TCP) {
	t.Helper()
	c := &Connection{
		SrcIP:   net.ParseIP("169.254.169.254"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: 80,
		DstPort: 12345,
		Seq:     1000,
		Ack:     2000,
	}
	tcpLayer, ipv4Layer, err := c.GenerateLayers(payload)
	assert.NoError(t, err)
	buf, err := c.Serialize(tcpLayer, ipv4Layer, payload)
	assert.NoError(t, err)

	pkt := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default)
	ipL := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcpL := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	return ipL, tcpL
}

// TestSerializeIPLength exposes #2: the IPv4 total length must equal
// 20 (IP) + 20 (TCP) + len(payload). Before the fix GenerateLayers computed
// Length as DataOffset+Window+5, which is wrong in units and value, and
// FixLengths was disabled in Serialize so the bogus value went on the wire.
func TestSerializeIPLength(t *testing.T) {
	payload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nflag{test}")
	ip, _ := serializeTCP(t, payload)
	want := uint16(20 + 20 + len(payload))
	assert.Equalf(t, want, ip.Length, "IPv4 total length: want %d (20+20+%d), got %d", want, len(payload), ip.Length)
}

// TestSerializeTCPDataOffset exposes the companion of #2: DataOffset must be 5
// (20 bytes / 4) for a header with no options, expressed in 32-bit words.
func TestSerializeTCPDataOffset(t *testing.T) {
	ip, tcp := serializeTCP(t, []byte("x"))
	_ = ip
	assert.Equal(t, uint8(5), tcp.DataOffset, "DataOffset must be 5 (20-byte header, no options)")
}

// TestSerializeTCPWindow exposes #3: Window was set to len(payload), which is
// the payload size, not a receive-window advertisement. A forged server reply
// with a tiny window makes the client throttle. Use a normal static window.
func TestSerializeTCPWindow(t *testing.T) {
	_, tcp := serializeTCP(t, []byte("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nflag{test}"))
	assert.Greater(t, tcp.Window, uint16(1024), "window should be a normal advertisement, not len(payload)")
	assert.Less(t, tcp.Window, uint16(65535), "window should fit in a normal range")
}

// TestSerializeChecksumsNonZero guards the ComputeChecksums path: a forged
// segment with a zero checksum would be dropped by the receiver.
func TestSerializeChecksumsNonZero(t *testing.T) {
	_, tcp := serializeTCP(t, []byte("flag{test}"))
	assert.NotZero(t, tcp.Checksum, "TCP checksum must be computed, not left zero")
}

// TestSerializeUDPFields checks the UDP path: length and checksum are computed
// by gopacket (FixLengths+ComputeChecksums both on) and IP length is correct.
func TestSerializeUDPFields(t *testing.T) {
	t.Helper()
	c := &UDPConnection{
		SrcIP:   net.ParseIP("8.8.8.8"),
		DstIP:   net.ParseIP("10.0.0.2"),
		SrcPort: 53,
		DstPort: 5353,
	}
	payload := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	udpLayer, ipv4Layer, err := c.GenerateLayersUDP(payload)
	assert.NoError(t, err)
	buf, err := c.SerializeUDP(udpLayer, ipv4Layer, payload)
	assert.NoError(t, err)

	pkt := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)

	wantIP := uint16(20 + 8 + len(payload))
	assert.Equal(t, wantIP, ip.Length, "UDP IPv4 total length")
	assert.Equal(t, uint16(8+len(payload)), udp.Length, "UDP length field")
	assert.NotZero(t, udp.Checksum, "UDP checksum must be computed")
}
