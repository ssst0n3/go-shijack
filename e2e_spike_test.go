//go:build integration

package gohijack

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv4"
)

// skipIfNoNetRaw skips when the process lacks CAP_NET_RAW (raw sockets and
// AF_PACKET capture both need it). We probe by trying to open the socket the
// tool itself uses.
func skipIfNoNetRaw(t *testing.T) {
	t.Helper()
	c, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		t.Skipf("requires CAP_NET_RAW: %v", err)
	}
	c.Close()
}

// TestSpikeLoopbackCapture verifies unknown #1: pcapgo.NewEthernetHandle("lo")
// can actually capture frames on Linux loopback. Linux lo presents a synthetic
// Ethernet header to AF_PACKET; if this didn't work the whole loopback e2e
// approach would be dead and we'd need netns+veth.
func TestSpikeLoopbackCapture(t *testing.T) {
	skipIfNoNetRaw(t)

	handle, err := pcapgo.NewEthernetHandle("lo")
	if err != nil {
		t.Fatalf("NewEthernetHandle(lo): %v", err)
	}
	defer handle.Close()

	// Generate traffic on lo: a listener that accepts and immediately closes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	_ = port

	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packets := src.Packets()

	// Dial in a goroutine; wait for a captured frame.
	go func() {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err == nil {
			c.Close()
		}
	}()

	select {
	case pkt := <-packets:
		// We captured *something* on lo. Confirm it decodes as IPv4.
		ipL := pkt.Layer(layers.LayerTypeIPv4)
		assert.NotNil(t, ipL, "captured frame should decode as IPv4")
		t.Logf("captured %d bytes on lo: %v", len(pkt.Data()), pkt.Data()[:min(64, len(pkt.Data()))])
	case <-time.After(3 * time.Second):
		t.Fatal("no packets captured on lo within 3s — NewEthernetHandle(lo) does not work")
	}
}

// TestSpikeLoopbackRawInject verifies unknown #2: a raw TCP segment injected
// via ipv4.RawConn to 127.0.0.1 is delivered to the CLIENT socket on lo. If
// the kernel rejects src==dst==127.0.0.1 raw injection, loopback e2e is dead.
func TestSpikeLoopbackRawInject(t *testing.T) {
	skipIfNoNetRaw(t)

	// Listener that accepts and holds the connection open without sending.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		time.Sleep(5 * time.Second) // hold open, never send
	}()

	// Sniff the handshake on lo to learn the server ISN.
	handle, err := pcapgo.NewEthernetHandle("lo")
	if err != nil {
		t.Fatalf("NewEthernetHandle(lo): %v", err)
	}
	defer handle.Close()
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packets := src.Packets()

	// Client connects.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Capture the SYN-ACK (server->client: SrcPort == port).
	var synack *layers.TCP
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case pkt := <-packets:
			tcpL := pkt.Layer(layers.LayerTypeTCP)
			if tcpL == nil {
				continue
			}
			tcp, _ := tcpL.(*layers.TCP)
			if tcp == nil {
				continue
			}
			if tcp.SYN && tcp.ACK && int(tcp.SrcPort) == port {
				synack = tcp
			}
		case <-time.After(50 * time.Millisecond):
		}
		if synack != nil {
			break
		}
	}
	if synack == nil {
		t.Fatal("did not capture SYN-ACK")
	}
	t.Logf("SYN-ACK: srcPort=%d dstPort=%d seq=%d ack=%d", synack.SrcPort, synack.DstPort, synack.Seq, synack.Ack)

	// Build a server->client data segment: seq = ISN+1 (SYN consumes one),
	// ack = the ack value from the SYN-ACK (client's ISN+1).
	marker := []byte("SPIKE-MARKER\n")
	ip4 := &layers.IPv4{
		Version: 4, IHL: 5,
		SrcIP:    net.ParseIP("127.0.0.1").To4(),
		DstIP:    net.ParseIP("127.0.0.1").To4(),
		Protocol: layers.IPProtocolTCP, TTL: 64,
		Flags: layers.IPv4DontFragment,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(port),
		DstPort: synack.DstPort,
		Seq:     synack.Seq + 1, // first data byte after SYN
		Ack:     synack.Ack,
		ACK:     true, PSH: true,
		Window: 64240,
	}
	assert.NoError(t, tcp.SetNetworkLayerForChecksum(ip4))
	buf := gopacket.NewSerializeBuffer()
	assert.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip4, tcp, gopacket.Payload(marker)))

	pc, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	rc, err := ipv4.NewRawConn(pc)
	if err != nil {
		t.Fatalf("NewRawConn: %v", err)
	}
	dst := &net.IPAddr{IP: net.ParseIP("127.0.0.1").To4()}
	n, err := rc.WriteToIP(buf.Bytes(), dst)
	assert.NoError(t, err)
	t.Logf("injected %d bytes", n)

	// The CLIENT (conn) should receive our marker — server->client data.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	rbuf := make([]byte, 256)
	nread, err := conn.Read(rbuf)
	t.Logf("client read %d bytes: %q (err=%v)", nread, rbuf[:nread], err)
	assert.Greater(t, nread, 0, "client must receive the injected segment")
	assert.Contains(t, string(rbuf[:nread]), "SPIKE-MARKER", "injected segment must reach the client")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
