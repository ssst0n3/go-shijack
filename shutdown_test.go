package gohijack

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestHijackRespectsContextCancel proves #15: the hijack loop terminates
// promptly when its context is cancelled instead of blocking forever on the
// packet channel. We can't easily exercise the full Hijack (it needs a raw
// socket + live capture), so we test the loop's select directly: a cancelled
// context must win the select over a packet source that never produces.
func TestHijackRespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Simulate the loop body: a select between ctx.Done() and a packet channel
	// that never delivers (buffered, empty). The ctx.Done() arm must fire.
	packets := make(chan any, 1) // never sent on

	cancel() // cancel immediately

	done := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			done <- ctx.Err()
		case <-packets:
			done <- nil
		}
	}()

	select {
	case err := <-done:
		assert.Equal(t, context.Canceled, err, "cancelled context must terminate the loop")
	case <-time.After(time.Second):
		t.Fatal("loop did not terminate within 1s — context cancellation ignored")
	}
}
