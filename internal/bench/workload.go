package bench

import (
	"math/rand"
	"time"
)

type OpType int

const (
	OpRead OpType = iota
	OpTransfer
)

type Op struct {
	Type   OpType
	From   string
	To     string
	Amount int32
}

type Workload struct {
	nAccounts  int
	writeRatio float64
	rng        *rand.Rand
	zipf       *rand.Zipf
}

// NewWorkload creates a SmallBank-like skewed workload over 'accounts' (A..J).
// writeRatio in [0,1]. Zipf parameters s (>1) and v (>1).
func NewWorkload(nAccounts int, writeRatio float64, seed int64, s, v float64) *Workload {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	src := rand.NewSource(seed)
	r := rand.New(src)
	zipf := rand.NewZipf(r, s, v, uint64(nAccounts-1))
	return &Workload{nAccounts: nAccounts, writeRatio: writeRatio, rng: r, zipf: zipf}
}

func (w *Workload) pickAccount() int { return int(w.zipf.Uint64()) }

func (w *Workload) NextOp() Op {
	if w.rng.Float64() < w.writeRatio {
		from := w.pickAccount()
		to := w.pickAccount()
		if to == from {
			to = (to + 1) % w.nAccounts
		}
		amt := int32(w.rng.Intn(5) + 1)
		return Op{Type: OpTransfer, From: idxToID(from), To: idxToID(to), Amount: amt}
	}
	id := idxToID(w.pickAccount())
	return Op{Type: OpRead, From: id, To: id}
}

func idxToID(i int) string { return string('A' + rune(i%26)) }
