package gohijack

// ackResult is the outcome of comparing a victim's ACK against the injected
// segment's sequence space. It is the on-path operator's only feedback channel
// — the victim runs curl on a different machine, so the result must be inferred
// from the wire rather than read from the victim's stdout.
type ackResult int

const (
	ackPending ackResult = iota // not enough information yet; keep waiting
	ackWin                      // victim acked exactly the injected segment -> race won
	ackLoss                     // victim acked past the injected segment via the real server's data -> race lost
)

// classifyAck decides whether a victim's ACK confirms the injected segment.
//
// injectedSeq is the left edge of the bytes we injected (connection.Seq, already
// ISN+1-adjusted for SYN-ACK). expectedAck is injectedSeq + len(payload): the
// ack value the victim's stack will send once it has consumed our segment. ack
// is the Ack field from a victim->server TCP segment we sniffed.
//
// Classification:
//
//   - ack == expectedAck -> ackWin. The victim's left edge advanced to exactly
//     one-past our injected bytes, which is the signature of having accepted
//     our segment.
//   - ack > injectedSeq && ack != expectedAck -> ackLoss. The victim advanced
//     its left edge beyond our injection point but to a different boundary,
//     meaning it consumed the real server's segment (different length) and ours
//     was either dropped or is now stale/overlapping.
//   - otherwise -> ackPending. The ACK is at or before our injection point
//     (e.g. the bare ACK acknowledging the SYN-ACK, or a retransmit). Wait for
//     a more decisive ACK.
//
// Known limitation: if the real server's first response happens to be exactly
// len(payload) bytes, the victim's ACK value collides with expectedAck and we
// report a false WIN. In the first-response race model this ambiguity is
// inherent on the wire — the ACK alone cannot distinguish two segments of
// equal length. This is an honest best-effort, not a guarantee.
func classifyAck(ack, expectedAck, injectedSeq uint32) ackResult {
	if ack == expectedAck {
		return ackWin
	}
	if ack > injectedSeq {
		return ackLoss
	}
	return ackPending
}
