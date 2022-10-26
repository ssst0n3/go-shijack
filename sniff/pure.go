package sniff

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/ssst0n3/awesome_libs/awesome_error"
	"golang.org/x/net/bpf"
	"log"
)

type PureGo struct {
}

func (s PureGo) Sniff(device string, filter []bpf.RawInstruction) (packets chan gopacket.Packet, err error) {
	handle, err := pcapgo.NewEthernetHandle(device)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	err = handle.SetBPF(filter)
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	packets = packetSource.Packets()
	return
}
