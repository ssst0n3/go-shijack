package gohijack

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestClassifyAck is a table-driven test for the three ackResult categories.
// The injected segment occupies [injectedSeq, injectedSeq+len(payload)); the
// victim's ACK value is what its stack sends as the next expected byte.
func TestClassifyAck(t *testing.T) {
	const injectedSeq = uint32(1000)
	const payloadLen = uint32(86)
	const expectedAck = injectedSeq + payloadLen // 1086

	cases := []struct {
		name string
		ack  uint32
		want ackResult
	}{
		// WIN: victim acked exactly one-past our injected bytes.
		{"win exact expected", expectedAck, ackWin},

		// LOSS: victim acked past our injection point but to a different
		// boundary — it consumed the real server's segment of a different
		// length. Both a shorter and a longer real response count as LOSS.
		{"loss past injected shorter real", injectedSeq + 10, ackLoss},
		{"loss past injected longer real", injectedSeq + 200, ackLoss},

		// PENDING: ACK at or before the injection point — the bare ACK
		// acknowledging the SYN-ACK (ack == injectedSeq, since SYN consumes
		// one and our Seq is ISN+1), or a retransmit/dup ACK. Not decisive.
		{"pending bare syn-ack ack", injectedSeq, ackPending},
		{"pending before injected", injectedSeq - 1, ackPending},
		{"pending zero", 0, ackPending},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyAck(c.ack, expectedAck, injectedSeq)
			assert.Equalf(t, c.want, got, "ack=%d expectedAck=%d injectedSeq=%d", c.ack, expectedAck, injectedSeq)
		})
	}
}

// TestClassifyAckFalseWinLimitation documents the known false-WIN case: when
// the real server's first response is exactly len(payload) bytes, the victim's
// ACK collides with expectedAck and classifyAck returns ackWin even though the
// real server may have won. This is an inherent wire ambiguity in the
// first-response race model — the test pins the current (best-effort) behavior
// so a future change to the classifier is a conscious decision, not an accident.
func TestClassifyAckFalseWinLimitation(t *testing.T) {
	const injectedSeq = uint32(1000)
	const payloadLen = uint32(86)
	const expectedAck = injectedSeq + payloadLen

	// Real server also sent 86 bytes -> victim acks 1086 either way.
	got := classifyAck(expectedAck, expectedAck, injectedSeq)
	assert.Equal(t, ackWin, got,
		"known limitation: equal-length real response is indistinguishable from a win on the wire")
}
