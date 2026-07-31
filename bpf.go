package gohijack

import (
	"github.com/google/gopacket/layers"
	"github.com/ssst0n3/awesome_libs/awesome_error"
	"golang.org/x/net/bpf"
)

const (
	etherTypeIPv6 = 0x86dd
	etherTypeIP   = 0x800
)

func GenerateFilter(srcIp string, srcPort uint32) (ins []bpf.RawInstruction, err error) {
	srcIpAtoN := uint32(InetAtoN(srcIp))
	// https://gist.github.com/errzey/1111503/bbcda355e8ffbf5141dc10e0e551eb6edf666e36
	filter := []bpf.Instruction{
		// ldh [12]
		// Load "EtherType" field from the ethernet header.
		bpf.LoadAbsolute{Off: 0xc, Size: 2},
		// jeq #34525, 11
		// Skip over the next 0xf instruction if EtherType is IPv6
		// https://github.com/the-tcpdump-group/libpcap/blob/fbcc461fbc2bd3b98de401cc04e6a4a10614e99f/ethertype.h
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIPv6, SkipTrue: 0xb, SkipFalse: 0x0},
		// jneq #2048, 10
		// Skip over the next 0xe instruction if EtherType is not IP
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: etherTypeIP, SkipTrue: 0xa, SkipFalse: 0x0},
		// ldb [23],
		// Load the 1 byte value at packet offset 23 ( ip proto )
		bpf.LoadAbsolute{Off: 0x17, Size: 1},
		// jneq #6,8,
		// If the ip proto equals 6 (tcp) jump to 9, else jump to 15
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(layers.IPProtocolTCP), SkipTrue: 0x8, SkipFalse: 0x0},
		// ld [26],
		// Load offset 26 (IP Source-address)
		bpf.LoadAbsolute{Off: 0x1a, Size: 4},
		// jneq #2852039166,6,
		// Skip over the next 0x6 instruction if host is not 0xa9fea9fe(169.254.169.254)
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: srcIpAtoN, SkipTrue: 0x6, SkipFalse: 0x0},
		// ldh [20],
		// Load the half word value at packet offset 20 (flags + frag offset)
		bpf.LoadAbsolute{Off: 0x14, Size: 2},
		// jset #8191,4,
		//   Only look at the last 13 bits of the data
		//   0x1fff == 0001 1111 1111 1111 (fragment offset)
		//
		//  If any of the data in fragment offset is true, jump to 4
		//   Essentially, if this packet is a fragment, return true for packet match
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 0x4, SkipFalse: 0x0},
		// ldx 4*([14]&0xf),
		// x = ip header len * 4
		// In our case lets assume that we have a default size of 20 bytes.
		bpf.LoadMemShift{Off: 0xe},
		// ldh [x + 14],
		// Load the half word at packet offset x+14 (in our case offset 20)
		// 20 + 14 == 34
		bpf.LoadIndirect{Off: 0xe, Size: 2},
		// jneq #80,1,
		// If the value of packet offset 34 is 0x50 (tcp source port 80) jump to 1, else
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: srcPort, SkipTrue: 0x1, SkipFalse: 0x0},
		// ret #65535,
		bpf.RetConstant{Val: 0xffff},
		// ret #0
		bpf.RetConstant{Val: 0x0},
	}
	ins, err = bpf.Assemble(filter)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	return
}

// GenerateFilterUDP matches `udp and dst host <dstIp> and dst port <dstPort>`,
// i.e. DNS queries travelling client -> resolver. This mirrors GenerateFilter
// (which matches the TCP src direction) but checks IP proto 17 (UDP), the
// destination IP at offset 0x1e and the UDP destination port at [x+16].
func GenerateFilterUDP(dstIp string, dstPort uint32) (ins []bpf.RawInstruction, err error) {
	dstIpAtoN := uint32(InetAtoN(dstIp))
	filter := []bpf.Instruction{
		// ldh [12]
		// Load "EtherType" field from the ethernet header.
		bpf.LoadAbsolute{Off: 0xc, Size: 2},
		// jeq #34525, 11
		// Skip over the next 0xf instruction if EtherType is IPv6
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIPv6, SkipTrue: 0xb, SkipFalse: 0x0},
		// jneq #2048, 10
		// Skip over the next 0xe instruction if EtherType is not IP
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: etherTypeIP, SkipTrue: 0xa, SkipFalse: 0x0},
		// ldb [23],
		// Load the 1 byte value at packet offset 23 ( ip proto )
		bpf.LoadAbsolute{Off: 0x17, Size: 1},
		// jneq #17,8,
		// If the ip proto is not 17 (udp) jump to ret 0
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(layers.IPProtocolUDP), SkipTrue: 0x8, SkipFalse: 0x0},
		// ld [30],
		// Load offset 30 (IP Destination-address)
		bpf.LoadAbsolute{Off: 0x1e, Size: 4},
		// jneq #<dstIp>,6,
		// Skip over the next 0x6 instruction if destination is not dstIp
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: dstIpAtoN, SkipTrue: 0x6, SkipFalse: 0x0},
		// ldh [20],
		// Load the half word value at packet offset 20 (flags + frag offset)
		bpf.LoadAbsolute{Off: 0x14, Size: 2},
		// jset #8191,4,
		//   Only look at the last 13 bits of the data (fragment offset).
		//   If this packet is a fragment, jump to ret 0 (port unknowable).
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 0x4, SkipFalse: 0x0},
		// ldx 4*([14]&0xf),
		// x = ip header len * 4
		bpf.LoadMemShift{Off: 0xe},
		// ldh [x + 16],
		// Load the half word at packet offset x+16 (UDP destination port)
		bpf.LoadIndirect{Off: 0x10, Size: 2},
		// jneq #<dstPort>,1,
		// If the UDP destination port does not match, jump to ret 0
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: dstPort, SkipTrue: 0x1, SkipFalse: 0x0},
		// ret #65535,
		bpf.RetConstant{Val: 0xffff},
		// ret #0
		bpf.RetConstant{Val: 0x0},
	}
	ins, err = bpf.Assemble(filter)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	return
}
