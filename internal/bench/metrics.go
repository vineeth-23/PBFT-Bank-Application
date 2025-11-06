package bench

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type Metrics struct {
	mu            sync.Mutex
	writeLat      []time.Duration
	readLat       []time.Duration
	writesOK      int64
	readsOK       int64
	writesFail    int64
	readsFail     int64
	start, finish time.Time
}

func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) Start() { m.start = time.Now() }
func (m *Metrics) Stop()  { m.finish = time.Now() }

func (m *Metrics) AddWrite(ok bool, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok {
		m.writesOK++
		m.writeLat = append(m.writeLat, d)
	} else {
		m.writesFail++
	}
}

func (m *Metrics) AddRead(ok bool, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ok {
		m.readsOK++
		m.readLat = append(m.readLat, d)
	} else {
		m.readsFail++
	}
}

func percentile(durs []time.Duration, p float64) time.Duration {
	if len(durs) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), durs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := int(float64(len(s)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func (m *Metrics) Summary() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	dur := m.finish.Sub(m.start)
	ops := float64(m.writesOK+m.readsOK) / dur.Seconds()
	// fail=%d
	return fmt.Sprintf(
		"Duration: %v\nThroughput: %.2f ops/s\nWrites: ok=%d p50=%v p95=%v p99=%v\nReads : ok=%d p50=%v p95=%v p99=%v\n",
		dur,
		ops,
		m.writesOK, percentile(m.writeLat, 0.50), percentile(m.writeLat, 0.95), percentile(m.writeLat, 0.99),
		m.readsOK, percentile(m.readLat, 0.50), percentile(m.readLat, 0.95), percentile(m.readLat, 0.99),
	)
}
