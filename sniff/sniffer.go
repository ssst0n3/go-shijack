package sniff

import (
	"github.com/google/gopacket"
)

type Sniffer interface {
	Sniff(device string) (packets chan gopacket.Packet)
}
