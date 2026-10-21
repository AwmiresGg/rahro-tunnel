// Package obfs provides traffic-shaping obfuscation for the Rahro tunnel:
// frame length padding (now) and, together with the uTLS transport option,
// browser-fingerprint mimicry. The goal is to make the encrypted length and
// timing patterns of the tunnel resemble ordinary HTTPS rather than a
// recognizable proxy protocol.
package obfs

import (
	"math/rand/v2"

	"github.com/awmiresgg/rahro/core/proto"
)

// RandomPadder pads frames to blur their on-wire length:
//   - small control frames (SYN/FIN/RST/WND_UPDATE/PING) are padded up to a
//     random size in [CtrlMin, CtrlMax], hiding their otherwise tell-tale tiny,
//     fixed sizes;
//   - DATA frames get a small random amount of padding (0..DataMax) so stream
//     boundaries and record sizes are less regular.
//
// Padding content is irrelevant (it rides inside TLS); only the resulting
// length matters, so this is cheap. Safe for concurrent use (math/rand/v2 top-
// level functions are goroutine-safe).
type RandomPadder struct {
	CtrlMin int
	CtrlMax int
	DataMax int
}

// NewRandomPadder returns a padder with sensible defaults.
func NewRandomPadder() *RandomPadder {
	return &RandomPadder{CtrlMin: 96, CtrlMax: 256, DataMax: 256}
}

// PadLen implements proto.Padder.
func (p *RandomPadder) PadLen(t proto.FrameType, payloadLen int) uint16 {
	switch t {
	case proto.FrameData:
		if p.DataMax <= 0 {
			return 0
		}
		return uint16(rand.IntN(p.DataMax + 1))
	default:
		// Control frame: pad the total frame body up to a random target size.
		if p.CtrlMax <= p.CtrlMin {
			return 0
		}
		target := p.CtrlMin + rand.IntN(p.CtrlMax-p.CtrlMin+1)
		if pad := target - payloadLen; pad > 0 {
			if pad > int(^uint16(0)) {
				pad = int(^uint16(0))
			}
			return uint16(pad)
		}
		return 0
	}
}

// compile-time check that RandomPadder satisfies proto.Padder.
var _ proto.Padder = (*RandomPadder)(nil)
