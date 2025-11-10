package client

import (
	"crypto/ed25519"
	"sync"
	"time"

	pb "pbft-bank-application/pbft-bank-application/proto"
)

const (
	F = 2
	N = 3*F + 1 // 7
)

const quorum = 2*F + 1

const clientTimeout = 20000 * time.Millisecond

type ReplyKey = int32 // tx.Time

type bucket struct {
	replies  map[int32]*pb.ReplyToClientRequest
	tally    map[bool]int
	accepted *pb.ReplyToClientRequest
	waitCh   chan struct{}
}

type Hub struct {
	ReplicaAddrs map[int32]string
	ReplicaPubs  map[int32]ed25519.PublicKey

	ClientPriv map[string]ed25519.PrivateKey
	ClientPub  map[string]ed25519.PublicKey

	Mu         sync.Mutex
	buckets    map[ReplyKey]*bucket
	LatestView int32

	AliveNodes     []int32
	ByzantineNodes []int32

	Attacks []*Attack
}

func NewHub() *Hub {
	return &Hub{
		ReplicaAddrs: map[int32]string{},
		ReplicaPubs:  map[int32]ed25519.PublicKey{},
		ClientPriv:   map[string]ed25519.PrivateKey{},
		ClientPub:    map[string]ed25519.PublicKey{},
		buckets:      map[ReplyKey]*bucket{},
	}
}

func (h *Hub) ResetForNewSet() {
	h.Mu.Lock()
	defer h.Mu.Unlock()

	h.buckets = make(map[ReplyKey]*bucket)
	h.AliveNodes = nil
	h.ByzantineNodes = nil
	h.LatestView = 0
	h.Attacks = nil
}
