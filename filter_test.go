package gohijack

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/ssst0n3/awesome_libs/log"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/bpf"
	"testing"
)

func TestCompileBPFFilter(t *testing.T) {
	snaplen := 65535
	filter := "tcp and host 169.254.169.254 and port 80"
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, filter)
	assert.NoError(t, err)
	spew.Dump(pcapBPF)
}

func TestDisassemble(t *testing.T) {
	snaplen := 65535
	//filter := "tcp and host 169.254.169.254 and port 80"
	//filter := "tcp and host 169.254.169.254 and port 80"
	//filter := "tcp and host 10.1.0.105 and port 80"
	//filter := "tcp and src host 10.1.0.105 and src port 80"
	filter := "tcp and src host 169.254.169.254 and src port 80"
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snaplen, filter)
	assert.NoError(t, err)
	var rawIns []bpf.RawInstruction
	for _, p := range pcapBPF {
		rawIns = append(rawIns, bpf.RawInstruction{
			Op: p.Code,
			Jt: p.Jt,
			Jf: p.Jf,
			K:  p.K,
		})
	}
	ins, allDecoded := bpf.Disassemble(rawIns)
	spew.Dump(ins)
	fmt.Printf("%#v\n", ins)
	log.Logger.Info(allDecoded)
}
