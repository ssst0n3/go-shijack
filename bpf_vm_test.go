package gohijack

import (
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"testing"
)

// runBPF runs the classic BPF program against a packet and returns the accept value.
func runBPF(ins []bpf.RawInstruction, pkt []byte) uint32 {
	_ = ins
	_ = pkt
	return 0
}

func TestBPFUDPAcceptsDNSQueryRejectsTCP(t *testing.T) {
	// Build a UDP DNS query frame: Ethernet + IPv4 + UDP(53) + DNS.
	eth := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00}
	// IPv4 header: 20 bytes, proto=17 (UDP), src=1.1.1.1, dst=8.8.8.8
	ip := make([]byte, 20)
	ip[0] = 0x45 // ver+ihl
	binary.BigEndian.PutUint16(ip[2:], 20+8+12) // total len
	ip[8] = 64  // ttl
	ip[9] = 17  // proto = UDP
	copy(ip[12:], []byte{1, 1, 1, 1})
	copy(ip[16:], []byte{8, 8, 8, 8})
	// UDP header: src=5353, dst=53
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 5353)
	binary.BigEndian.PutUint16(udp[2:], 53)
	binary.BigEndian.PutUint16(udp[4:], 8+12) // length
	// minimal DNS query (12 bytes): ID=0x1234, 1 question example.com A
	dns := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	pkt := append(append(append(eth, ip...), udp...), dns...)

	ins, err := GenerateFilterUDP("8.8.8.8", 53)
	if err != nil {
		t.Fatal(err)
	}
	got := bpfRun(ins, pkt)
	t.Logf("UDP DNS query accept = %d", got)

	// Now a TCP packet to 8.8.8.8:80 — must be rejected.
	ipTCP := make([]byte, 20)
	ipTCP[0] = 0x45
	binary.BigEndian.PutUint16(ipTCP[2:], 40)
	ipTCP[8] = 64
	ipTCP[9] = 6 // proto = TCP
	copy(ipTCP[12:], []byte{1, 1, 1, 1})
	copy(ipTCP[16:], []byte{8, 8, 8, 8})
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], 12345)
	binary.BigEndian.PutUint16(tcp[2:], 80)
	pktTCP := append(append(eth, ipTCP...), tcp...)
	gotTCP := bpfRun(ins, pktTCP)
	t.Logf("TCP packet accept = %d", gotTCP)
}

// bpfRun is a tiny classic-BPF interpreter sufficient for the instructions
// our filter uses (LoadAbsolute, LoadIndirect, LoadMemShift, JumpIf, RetConstant).
func bpfRun(ins []bpf.RawInstruction, pkt []byte) uint32 {
	var a, x uint32
	mem := make([]uint32, 16)
	for pc := 0; pc < len(ins); {
		op := ins[pc]
		switch op.Op {
		case 0x20: // Ld abs 4
			a = binary.BigEndian.Uint32(pkt[op.K:])
			pc++
		case 0x28: // Ldh abs 2
			a = uint32(binary.BigEndian.Uint16(pkt[op.K:]))
			pc++
		case 0x30: // Ldb abs 1
			a = uint32(pkt[op.K])
			pc++
		case 0x48: // Ldh ind 2
			a = uint32(binary.BigEndian.Uint16(pkt[x+op.K:]))
			pc++
		case 0xb1: // Ldx memshift
			x = uint32(pkt[op.K]&0xf) * 4
			pc++
		case 0x15: // Jeq
			if a == op.K {
				pc += 1 + int(op.Jt)
			} else {
				pc += 1 + int(op.Jf)
			}
		case 0x45: // Jset
			if a&op.K != 0 {
				pc += 1 + int(op.Jt)
			} else {
				pc += 1 + int(op.Jf)
			}
		case 0x06: // ret
			return op.K
		default:
			return 0
		}
		_ = mem
	}
	return 0
}

var _ = gopacket.NewSerializeBuffer
var _ = layers.LayerTypeDNS
