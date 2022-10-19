package gohijack

import (
	"github.com/ssst0n3/awesome_libs/awesome_error"
	"golang.org/x/net/bpf"
)

const (
	etherTypeIPv6 = 0x86dd
	etherTypeIP   = 0x800
)

func GenerateFilter() (ins []bpf.RawInstruction, err error) {
	filter := []bpf.Instruction{
		// ldh [12]
		// Load "EtherType" field from the ethernet header.
		bpf.LoadAbsolute{Off: 0xc, Size: 2},
		// jeq #34525, 15
		// Skip over the next 0xf instruction if EtherType is IPv6
		// https://github.com/the-tcpdump-group/libpcap/blob/fbcc461fbc2bd3b98de401cc04e6a4a10614e99f/ethertype.h
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherTypeIPv6, SkipTrue: 0xf, SkipFalse: 0},
		// jneq #2048, 14
		// Skip over the next 0xe instruction if EtherType is not IP
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: etherTypeIP, SkipTrue: 0xe, SkipFalse: 0x0},
		// ldb [23],
		bpf.LoadAbsolute{Off: 0x17, Size: 1},
		// jneq #6,12
		// Skip over the next 0xc instruction if is
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x6, SkipTrue: 0xc, SkipFalse: 0x0},
		// ld [26]
		bpf.LoadAbsolute{Off: 0x1a, Size: 4},
		// jeq #2852039166,2
		// Skip over the next 0x2 instruction if host is 0xa9fea9fe(169.254.169.254)
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xa9fea9fe, SkipTrue: 0x2, SkipFalse: 0x0},

		bpf.LoadAbsolute{Off: 0x1e, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0xa9fea9fe, SkipTrue: 0x8, SkipFalse: 0x0},
		bpf.LoadAbsolute{Off: 0x14, Size: 2},
		// jset #8191,6
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 0x6, SkipFalse: 0x0},
		bpf.LoadMemShift{Off: 0xe},
		bpf.LoadIndirect{Off: 0xe, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x50, SkipTrue: 0x2, SkipFalse: 0x0},
		bpf.LoadIndirect{Off: 0x10, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x50, SkipTrue: 0x1, SkipFalse: 0x0},
		bpf.RetConstant{Val: 0xffff},
		bpf.RetConstant{Val: 0x0},
	}
	ins, err = bpf.Assemble(filter)
	if err != nil {
		awesome_error.CheckErr(err)
		return
	}
	return
}
