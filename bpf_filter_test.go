package gohijack

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/bpf"
)

// newVMFromFilter disassembles our raw BPF program and builds an in-process
// classic-BPF VM via golang.org/x/net/bpf. This lets us assert accept/reject
// semantics without libpcap, raw sockets, or privileges.
func newVMFromFilter(t *testing.T, raw []bpf.RawInstruction) *bpf.VM {
	t.Helper()
	ins, allDecoded := bpf.Disassemble(raw)
	assert.True(t, allDecoded, "filter should fully disassemble")
	vm, err := bpf.NewVM(ins)
	assert.NoError(t, err)
	return vm
}

func vmAccept(t *testing.T, vm *bpf.VM, pkt []byte) bool {
	t.Helper()
	n, err := vm.Run(pkt)
	assert.NoError(t, err)
	return n > 0
}

// --- frame builders ---

func buildEthernet(ethertype uint16, payload []byte) []byte {
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], ethertype)
	return append(eth, payload...)
}

func buildIPv4(proto byte, src, dst net.IP, payload []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45 // ver=4, ihl=5
	ip[9] = proto
	copy(ip[12:], src.To4())
	copy(ip[16:], dst.To4())
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(payload)))
	return append(ip, payload...)
}

// buildIPv4Fragment sets a non-zero fragment offset in the flags+frag field at
// offset 20 (0x14) so the BPF fragment check triggers.
func buildIPv4Fragment(proto byte, src, dst net.IP, payload []byte) []byte {
	pkt := buildIPv4(proto, src, dst, payload)
	binary.BigEndian.PutUint16(pkt[20:], 0x2000|0x0100) // MF=1, frag offset=256
	return pkt
}

func buildTCP(srcPort, dstPort uint16) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	tcp[12] = 0x50 // data offset 5
	return tcp
}

func buildUDP(srcPort, dstPort uint16, payload []byte) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	return append(udp, payload...)
}

func tcpFrame(srcIP net.IP, srcPort uint16) []byte {
	return buildEthernet(0x0800, buildIPv4(6, srcIP, net.ParseIP("10.0.0.2"), buildTCP(srcPort, 12345)))
}

func udpFrame(dstIP net.IP, dstPort uint16) []byte {
	return buildEthernet(0x0800, buildIPv4(17, net.ParseIP("10.0.0.2"), dstIP, buildUDP(5353, dstPort, []byte("query"))))
}

// --- GenerateFilter (TCP) matrix ---

func TestBPFTCP_AcceptsMatching(t *testing.T) {
	vm := newVMFromFilter(t, mustFilter(t, "169.254.169.254", 80))
	pkt := tcpFrame(net.ParseIP("169.254.169.254"), 80)
	assert.True(t, vmAccept(t, vm, pkt), "tcp src=169.254.169.254 srcport=80 must be accepted")
}

func TestBPFTCP_RejectsWrongPort(t *testing.T) {
	vm := newVMFromFilter(t, mustFilter(t, "169.254.169.254", 80))
	pkt := tcpFrame(net.ParseIP("169.254.169.254"), 81)
	assert.False(t, vmAccept(t, vm, pkt), "wrong src port must be rejected")
}

func TestBPFTCP_RejectsWrongIP(t *testing.T) {
	vm := newVMFromFilter(t, mustFilter(t, "169.254.169.254", 80))
	pkt := tcpFrame(net.ParseIP("10.0.0.1"), 80)
	assert.False(t, vmAccept(t, vm, pkt), "wrong src IP must be rejected")
}

func TestBPFTCP_RejectsUDP(t *testing.T) {
	vm := newVMFromFilter(t, mustFilter(t, "169.254.169.254", 80))
	pkt := udpFrame(net.ParseIP("169.254.169.254"), 80)
	assert.False(t, vmAccept(t, vm, pkt), "UDP must be rejected by TCP filter")
}

func TestBPFTCP_RejectsIPv6(t *testing.T) {
	vm := newVMFromFilter(t, mustFilter(t, "169.254.169.254", 80))
	pkt := buildEthernet(0x86dd, make([]byte, 40))
	assert.False(t, vmAccept(t, vm, pkt), "IPv6 must be rejected")
}

func TestBPFTCP_RejectsFragment(t *testing.T) {
	vm := newVMFromFilter(t, mustFilter(t, "169.254.169.254", 80))
	ip := buildIPv4Fragment(6, net.ParseIP("169.254.169.254"), net.ParseIP("10.0.0.2"), buildTCP(80, 12345))
	pkt := buildEthernet(0x0800, ip)
	assert.False(t, vmAccept(t, vm, pkt), "fragmented packet must be rejected (port unknowable)")
}

// --- GenerateFilterUDP (UDP) matrix ---

func TestBPFUDP_AcceptsMatching(t *testing.T) {
	vm := newVMFromFilterUDP(t, "8.8.8.8", 53)
	pkt := udpFrame(net.ParseIP("8.8.8.8"), 53)
	assert.True(t, vmAccept(t, vm, pkt), "udp dst=8.8.8.8 dstport=53 must be accepted")
}

func TestBPFUDP_RejectsWrongPort(t *testing.T) {
	vm := newVMFromFilterUDP(t, "8.8.8.8", 53)
	pkt := udpFrame(net.ParseIP("8.8.8.8"), 54)
	assert.False(t, vmAccept(t, vm, pkt), "wrong dst port must be rejected")
}

func TestBPFUDP_RejectsWrongIP(t *testing.T) {
	vm := newVMFromFilterUDP(t, "8.8.8.8", 53)
	pkt := udpFrame(net.ParseIP("1.1.1.1"), 53)
	assert.False(t, vmAccept(t, vm, pkt), "wrong dst IP must be rejected")
}

func TestBPFUDP_RejectsTCP(t *testing.T) {
	vm := newVMFromFilterUDP(t, "8.8.8.8", 53)
	pkt := buildEthernet(0x0800, buildIPv4(6, net.ParseIP("10.0.0.2"), net.ParseIP("8.8.8.8"), buildTCP(12345, 53)))
	assert.False(t, vmAccept(t, vm, pkt), "TCP must be rejected by UDP filter")
}

func TestBPFUDP_RejectsIPv6(t *testing.T) {
	vm := newVMFromFilterUDP(t, "8.8.8.8", 53)
	pkt := buildEthernet(0x86dd, make([]byte, 40))
	assert.False(t, vmAccept(t, vm, pkt), "IPv6 must be rejected")
}

// --- helpers ---

func mustFilter(t *testing.T, ip string, port uint32) []bpf.RawInstruction {
	t.Helper()
	ins, err := GenerateFilter(ip, port)
	assert.NoError(t, err)
	return ins
}

func newVMFromFilterUDP(t *testing.T, ip string, port uint32) *bpf.VM {
	t.Helper()
	ins, err := GenerateFilterUDP(ip, port)
	assert.NoError(t, err)
	return newVMFromFilter(t, ins)
}
