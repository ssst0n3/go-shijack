//go:build integration

package gohijack

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

// TestE2EHijackDNS proves the DNS hijack pipeline end-to-end: sniff → BPF →
// decode DNS query → BuildDNSResponse → SerializeUDP → raw inject delivers a
// forged A record that a real kernel UDP socket accepts.
//
// Topology (all in-process on loopback, needs CAP_NET_RAW):
//
//	FakeResolver (127.0.0.1:53) — never answers; the hijack races in
//	    │
//	    │ client sends DNS query for "hijack.test."
//	    ▼
//	HijackDNS(lo, 127.0.0.1, 53, "hijack.test.", 6.6.6.6, "", once=true)
//	    │
//	    ▼
//	Client reads → must get A=6.6.6.6, not the empty/no-answer from the resolver
//
// The resolver binds to 53 (not a random port) because gopacket's default
// decoder only surfaces a DNS layer for UDP port 53; on other ports the
// payload stays a generic Payload and HijackDNS skips it. Binding to 53 needs
// root, which is why `make e2e` runs inside an unshared user+net namespace.
func TestE2EHijackDNS(t *testing.T) {
	skipIfNoNetRaw(t)

	// 1. Fake resolver on port 53: bind UDP but never answer. Any response the
	//    client receives must therefore come from the hijack. Port 53 is required
	//    because gopacket's default decoder only presents a DNS layer for UDP
	//    port 53 — on other ports the payload stays a generic Payload and
	//    HijackDNS skips it. We run inside an unshared user+net namespace where
	//    we're uid 0, so binding to 53 is allowed.
	resolverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53})
	assert.NoError(t, err)
	defer resolverConn.Close()
	const port uint32 = 53

	// Drain the resolver so its buffer doesn't fill; just discard queries.
	go func() {
		buf := make([]byte, 1500)
		for {
			if _, _, err := resolverConn.ReadFrom(buf); err != nil {
				return
			}
		}
	}()

	// 2. Start the DNS hijacker on loopback, one-shot, auto mode.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hijackErr := make(chan error, 1)
	go func() {
		hijackErr <- HijackDNS(ctx, "lo", "127.0.0.1", port, "hijack.test.", net.ParseIP("6.6.6.6"), "", true)
	}()

	// Give the sniffer time to install its BPF filter before we query.
	time.Sleep(200 * time.Millisecond)

	// 3. Client sends a DNS A query for "hijack.test." to the fake resolver.
	query := &layers.DNS{
		ID:      0x4242,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		QDCount: 1,
		Questions: []layers.DNSQuestion{{
			Name:  []byte("hijack.test"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
	}
	qbuf := gopacket.NewSerializeBuffer()
	assert.NoError(t, query.SerializeTo(qbuf, gopacket.SerializeOptions{FixLengths: true}))

	clientConn, err := net.DialUDP("udp", nil, resolverConn.LocalAddr().(*net.UDPAddr))
	assert.NoError(t, err)
	defer clientConn.Close()
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	_, err = clientConn.Write(qbuf.Bytes())
	assert.NoError(t, err)

	// 4. Client reads the response — must be our forged A record.
	rbuf := make([]byte, 1500)
	n, err := clientConn.Read(rbuf)
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		select {
		case he := <-hijackErr:
			t.Fatalf("no response within 5s — hijack exited early: %v", he)
		default:
			t.Fatal("no response within 5s — forged DNS reply did not reach the client (hijack still running)")
		}
	}
	assert.NoError(t, err)
	t.Logf("client read %d bytes: % x", n, rbuf[:n])

	// 5. Decode and assert the forged answer.
	var resp layers.DNS
	assert.NoError(t, resp.DecodeFromBytes(rbuf[:n], gopacket.NilDecodeFeedback))
	assert.True(t, resp.QR, "response must have QR=1")
	assert.Equal(t, uint16(0x4242), resp.ID, "transaction ID must match the query")
	assert.Len(t, resp.Answers, 1, "exactly one answer")
	assert.Equal(t, layers.DNSTypeA, resp.Answers[0].Type)
	assert.True(t, net.ParseIP("6.6.6.6").Equal(resp.Answers[0].IP),
		"answer IP must be the poisoned 6.6.6.6, got %v", resp.Answers[0].IP)
}
