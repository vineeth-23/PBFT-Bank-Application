package client

import (
	"crypto/ed25519"
	"sync"
	"time"

	pb "pbft-bank-application/pbft-bank-application/proto"
)

// PBFT params
const (
	F = 2
	N = 3*F + 1 // 7
)

// quorum needed at client (matching replies with same time & result)
const quorum = F + 1

// fixed per-request wait before broadcasting to all replicas
const clientTimeout = 1500 * time.Millisecond

// We key replies by global transaction time (unique across CSV)
type ReplyKey = int32 // tx.Time

type bucket struct {
	replies  map[int32]*pb.ReplyToClientRequest // replica_id -> reply (dedupe)
	tally    map[bool]int                       // result -> count
	accepted *pb.ReplyToClientRequest
	waitCh   chan struct{}
}

type Hub struct {
	// cluster
	ReplicaAddrs map[int32]string            // id -> addr
	ReplicaPubs  map[int32]ed25519.PublicKey // id -> pub ed25519

	// clients (A..J)
	ClientPriv map[string]ed25519.PrivateKey // "A".."J" -> priv
	ClientPub  map[string]ed25519.PublicKey  // "A".."J" -> pub

	// aggregation / view tracking
	Mu         sync.Mutex
	buckets    map[ReplyKey]*bucket
	LatestView int32

	AliveNodes     []int32
	ByzantineNodes []int32
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
}
