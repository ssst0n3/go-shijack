package gohijack

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/ssst0n3/awesome_libs/awesome_error"
	"github.com/ssst0n3/awesome_libs/log"
	"golang.org/x/net/ipv4"
	"net"
)

type Connection struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort layers.TCPPort
	DstPort layers.TCPPort
	Seq     uint32
	Ack     uint32
	rawConn *ipv4.RawConn
}

// NewConnectionFromPacket builds a Connection that reuses the caller-supplied
// rawConn. The socket is created once per hijack session (see Hijack/HijackDNS)
// instead of per packet, so on-path injection stays fast and no file
// descriptors leak under --keep.
//
// Sequence-number fix: on a SYN-ACK the server's Seq is its ISN, but the SYN
// flag consumes one sequence number (RFC 793), so the first data byte lives at
// ISN+1. Injecting at ISN makes the receiver treat the first payload byte as a
// retransmission of the SYN and trim it, corrupting the response. We add 1
// when SYN is set so the injected segment's left edge is the first data byte.
func NewConnectionFromPacket(packet gopacket.Packet, rawConn *ipv4.RawConn) (*Connection, error) {
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	seq := tcp.Seq
	if tcp.SYN {
		seq++
	}
	return NewConnection(ip4.SrcIP, ip4.DstIP, tcp.SrcPort, tcp.DstPort, seq, tcp.Ack, rawConn)
}

func NewConnection(srcIp, dstIp net.IP, srcPort, dstPort layers.TCPPort, seq, ack uint32, rawConn *ipv4.RawConn) (connection *Connection, err error) {
	connection = &Connection{
		SrcIP:   srcIp,
		DstIP:   dstIp,
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		Ack:     ack,
		rawConn: rawConn,
	}
	return
}

func CreateSocket() (rawConn *ipv4.RawConn, err error) {
	// https://github.com/david415/HoneyBadger/blob/021246788e58cedf88dee75ac5dbf7ae60e12514/packetSendTest.go#L95
	var packetConn net.PacketConn
	packetConn, err = net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	rawConn, err = ipv4.NewRawConn(packetConn)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	return
}

func (c Connection) SendIP(buf []byte) (err error) {
	// DstIP is already a net.IP; avoid the stringify+parse round trip
	// (net.ResolveIPAddr) on every injected packet. Under --keep this runs
	// per SYN-ACK, so keeping it allocation-free matters.
	dstIP := &net.IPAddr{IP: c.DstIP.To4()}
	n, err := c.rawConn.WriteToIP(buf, dstIP)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	log.Logger.Infof("%d bytes sent", n)
	return
}

func (c Connection) GenerateLayers(payload []byte) (tcpLayer *layers.TCP, ipv4Layer *layers.IPv4, err error) {
	tcpLayer = &layers.TCP{
		DataOffset: 5,
		SrcPort:    c.SrcPort,
		DstPort:    c.DstPort,
		Seq:        c.Seq,
		Ack:        c.Ack,
		ACK:        true,
		PSH:        true,
		// Window is a receive-window advertisement, not the payload size.
		// Advertising len(payload) (often a few dozen bytes) makes the peer
		// throttle; use a normal static window instead.
		Window: 64240,
		// Checksum calculate during serializing when set opts.ComputeChecksums
	}
	ipv4Layer = &layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    c.SrcIP,
		DstIP:    c.DstIP,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Options:  nil,
		// Length is filled by SerializeLayers when FixLengths is set; leaving
		// it 0 here avoids the previous bogus manual computation.
	}
	err = tcpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		awesome_error.CheckErr(err)
	}
	return
}

func (c Connection) Serialize(tcpLayer *layers.TCP, ipv4Layer *layers.IPv4, payload []byte) (serialized []byte, err error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buf, opts,
		ipv4Layer,
		tcpLayer,
		gopacket.Payload(payload),
	)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	serialized = buf.Bytes()
	return
}

// UDPConnection represents a forged UDP packet path. SrcIP/SrcPort are the
// values that will appear on the wire as the source (i.e. the resolver being
// impersonated); DstIP/DstPort are the original client that issued the query.
type UDPConnection struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort layers.UDPPort
	DstPort layers.UDPPort
	rawConn *ipv4.RawConn
}

// NewUDPConnectionFromPacket builds a response path by swapping the source and
// destination of a captured UDP query: the resolver (original dst) becomes the
// source of the forged reply, the client (original src) becomes the destination.
// It reuses the caller-supplied rawConn (created once per hijack session).
func NewUDPConnectionFromPacket(packet gopacket.Packet, rawConn *ipv4.RawConn) (*UDPConnection, error) {
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	return NewUDPConnection(ip4.DstIP, ip4.SrcIP, udp.DstPort, udp.SrcPort, rawConn)
}

func NewUDPConnection(srcIp, dstIp net.IP, srcPort, dstPort layers.UDPPort, rawConn *ipv4.RawConn) (connection *UDPConnection, err error) {
	connection = &UDPConnection{
		SrcIP:   srcIp,
		DstIP:   dstIp,
		SrcPort: srcPort,
		DstPort: dstPort,
		rawConn: rawConn,
	}
	return
}

func CreateSocketUDP() (rawConn *ipv4.RawConn, err error) {
	var packetConn net.PacketConn
	packetConn, err = net.ListenPacket("ip4:udp", "0.0.0.0")
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	rawConn, err = ipv4.NewRawConn(packetConn)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	return
}

func (c UDPConnection) SendIP(buf []byte) (err error) {
	dstIP := &net.IPAddr{IP: c.DstIP.To4()}
	n, err := c.rawConn.WriteToIP(buf, dstIP)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	log.Logger.Infof("%d bytes sent", n)
	return
}

func (c UDPConnection) GenerateLayersUDP(payload []byte) (udpLayer *layers.UDP, ipv4Layer *layers.IPv4, err error) {
	udpLayer = &layers.UDP{
		SrcPort: c.SrcPort,
		DstPort: c.DstPort,
		// Length and Checksum calculated during serializing with FixLengths + ComputeChecksums
	}
	ipv4Layer = &layers.IPv4{
		Version:  4,
		IHL:      5,
		SrcIP:    c.SrcIP,
		DstIP:    c.DstIP,
		Protocol: layers.IPProtocolUDP,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Options:  nil,
	}
	err = udpLayer.SetNetworkLayerForChecksum(ipv4Layer)
	if err != nil {
		awesome_error.CheckErr(err)
	}
	return
}

func (c UDPConnection) SerializeUDP(udpLayer *layers.UDP, ipv4Layer *layers.IPv4, payload []byte) (serialized []byte, err error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buf, opts,
		ipv4Layer,
		udpLayer,
		gopacket.Payload(payload),
	)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	serialized = buf.Bytes()
	return
}
