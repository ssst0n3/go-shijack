//go:build integration

package gohijack

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestE2EHijackTCP is the end-to-end test for the TCP hijack pipeline.
//
// It proves that the assembled tool — sniff → BPF → decode →
// NewConnectionFromPacket → GenerateLayers → Serialize → SendIP — produces a
// forged segment that a real kernel TCP stack accepts and delivers to the
// client. This guards every wire-level fix (#2 length, #3 window, #6 seq
// off-by-one, checksums) against silent regression: unit tests check each
// field in isolation, but only this test checks that the packet actually
// arrives.
//
// Topology (all in-process on loopback, needs CAP_NET_RAW):
//
//	SilentServer (127.0.0.1:port) — accepts, never sends data
//	    │
//	    │ SYN-ACK
//	    ▼
//	Hijack(lo, 127.0.0.1, port, payload, once=true) injects the forged reply
//	    │
//	    ▼
//	Client dials, reads → must get flag{test}, not HTTP/0.9, not empty
//
// The server intentionally never sends, so the only bytes the client can
// possibly read are the ones we injected. That makes the outcome deterministic.
func TestE2EHijackTCP(t *testing.T) {
	skipIfNoNetRaw(t)

	// 1. Payload file: a valid HTTP response whose body is flag{test}.
	body := "flag{test}\n"
	payload := "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
	payloadFile := filepath.Join(t.TempDir(), "flag")
	assert.NoError(t, os.WriteFile(payloadFile, []byte(payload), 0644))

	// 2. Silent server: accept and hold the connection open without writing.
	//    Any data the client receives must therefore come from the hijack.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer ln.Close()
	port := uint32(ln.Addr().(*net.TCPAddr).Port)

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold open; never send. Close on test end via ctx.
			go func(c net.Conn) {
				<-serverDone
				c.Close()
			}(c)
		}
	}()

	// 3. Start the hijacker on loopback, one-shot.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hijackErr := make(chan error, 1)
	go func() {
		hijackErr <- Hijack(ctx, "lo", "127.0.0.1", port, payloadFile, true)
	}()

	// Give the sniffer time to install its BPF filter before we connect.
	time.Sleep(200 * time.Millisecond)

	// 4. Client connects and reads the response.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 3*time.Second)
	assert.NoError(t, err)
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	resp, err := io.ReadAll(conn)
	t.Logf("client read %d bytes: %q (err=%v)", len(resp), resp, err)

	// 5. The client must have received our injected payload — specifically the
	//    flag body, not an HTTP/0.9 error, not an empty read, not a truncated
	//    response. This is the exact symptom the #6 seq off-by-one produced.
	assert.Contains(t, string(resp), "flag{test}",
		"client must receive the injected flag; HTTP/0.9 or empty means the forged segment was rejected")
}
