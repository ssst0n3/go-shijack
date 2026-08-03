package gohijack

import (
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/bpf"
)

// libpcapVM compiles a libpcap filter string into a classic-BPF VM so we can
// compare our hand-written filters against the reference implementation.
func libpcapVM(t *testing.T, filter string) *bpf.VM {
	t.Helper()
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, filter)
	assert.NoError(t, err)
	var rawIns []bpf.RawInstruction
	for _, p := range pcapBPF {
		rawIns = append(rawIns, bpf.RawInstruction{Op: p.Code, Jt: p.Jt, Jf: p.Jf, K: p.K})
	}
	ins, allDecoded := bpf.Disassemble(rawIns)
	assert.True(t, allDecoded, "libpcap filter should fully disassemble")
	vm, err := bpf.NewVM(ins)
	assert.NoError(t, err)
	return vm
}

// TestFilterEquivalentTCP asserts our GenerateFilter agrees with libpcap's
// "tcp and src host <ip> and src port <port>" over a packet corpus.
func TestFilterEquivalentTCP(t *testing.T) {
	const ip = "169.254.169.254"
	const port = uint32(80)

	ours := newVMFromFilter(t, mustFilter(t, ip, port))
	ref := libpcapVM(t, "tcp and src host "+ip+" and src port "+itoa(port))

	corpus := [][]byte{
		tcpFrame(net.ParseIP(ip), 80),
		tcpFrame(net.ParseIP(ip), 81),
		tcpFrame(net.ParseIP("10.0.0.1"), 80),
		udpFrame(net.ParseIP(ip), 80),
		buildEthernet(0x86dd, make([]byte, 40)),
	}
	for i, pkt := range corpus {
		got := vmAccept(t, ours, pkt)
		want := vmAccept(t, ref, pkt)
		assert.Equalf(t, want, got, "packet %d: ours=%v libpcap=%v", i, got, want)
	}
}

// TestFilterEquivalentUDP asserts our GenerateFilterUDP agrees with libpcap's
// "udp and dst host <ip> and dst port <port>" over a packet corpus.
func TestFilterEquivalentUDP(t *testing.T) {
	const ip = "8.8.8.8"
	const port = uint32(53)

	ours := newVMFromFilterUDP(t, ip, port)
	ref := libpcapVM(t, "udp and dst host "+ip+" and dst port "+itoa(port))

	corpus := [][]byte{
		udpFrame(net.ParseIP(ip), 53),
		udpFrame(net.ParseIP(ip), 54),
		udpFrame(net.ParseIP("1.1.1.1"), 53),
		buildEthernet(0x0800, buildIPv4(6, net.ParseIP("10.0.0.2"), net.ParseIP(ip), buildTCP(12345, 53))),
		buildEthernet(0x86dd, make([]byte, 40)),
	}
	for i, pkt := range corpus {
		got := vmAccept(t, ours, pkt)
		want := vmAccept(t, ref, pkt)
		assert.Equalf(t, want, got, "packet %d: ours=%v libpcap=%v", i, got, want)
	}
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
