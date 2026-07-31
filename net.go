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

func NewConnectionFromPacket(packet gopacket.Packet) (*Connection, error) {
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	return NewConnection(ip4.SrcIP, ip4.DstIP, tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack)
}

func NewConnection(srcIp, dstIp net.IP, srcPort, dstPort layers.TCPPort, seq, ack uint32) (connection *Connection, err error) {
	rawConn, err := CreateSocket()
	if err != nil {
		return
	}
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
	dstIP, err := net.ResolveIPAddr("ip4", c.DstIP.String())
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
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
		Window:     uint16(len(payload)),
		// Checksum calculate during serializing when set opts.ComputeChecksums
	}
	ipv4Layer = &layers.IPv4{
		Version:  4,
		IHL:      5,
		Length:   uint16(tcpLayer.DataOffset) + tcpLayer.Window + uint16(5),
		SrcIP:    c.SrcIP,
		DstIP:    c.DstIP,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Options:  nil,
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
		//FixLengths:       true,
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
func NewUDPConnectionFromPacket(packet gopacket.Packet) (*UDPConnection, error) {
	ip4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	return NewUDPConnection(ip4.DstIP, ip4.SrcIP, udp.DstPort, udp.SrcPort)
}

func NewUDPConnection(srcIp, dstIp net.IP, srcPort, dstPort layers.UDPPort) (connection *UDPConnection, err error) {
	rawConn, err := CreateSocketUDP()
	if err != nil {
		return
	}
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
	dstIP, err := net.ResolveIPAddr("ip4", c.DstIP.String())
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
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
