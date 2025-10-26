package client

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"pbft-bank-application/internal/crypto"
	"sync"
	"time"

	pb "pbft-bank-application/pbft-bank-application/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	maxRetryCount = 3                      // total retry rounds after the first attempt
	retryBackoff  = 500 * time.Millisecond // sleep between rounds; tune as needed
)

func (h *Hub) verifyReplySig(r *pb.ReplyToClientRequest) bool {
	pub, ok := h.ReplicaPubs[r.ReplicaId]
	if !ok {
		return false
	}
	return ed25519.Verify(pub, crypto.GenerateBytesForReplySigning(r), r.Signature)
}

// ===== aggregation =====

func (h *Hub) ProcessNodeReply(r *pb.ReplyToClientRequest) {
	log.Printf("[Hub] Processing reply from replica=%d | view=%d | time=%d | result=%t",
		r.ReplicaId, r.View, r.Time, r.Result)

	if r.GetView() > h.LatestView {
		log.Printf("[Hub] 🔄 Updating latest view: old=%d → new=%d", h.LatestView, r.GetView())
		h.LatestView = r.GetView()
	}

	// Verify signature before accepting
	if !h.verifyReplySig(r) {
		log.Printf("[Hub] ❌ Dropped invalid signature from replica=%d | time=%d | view=%d",
			r.ReplicaId, r.Time, r.View)
		return
	}

	key := ReplyKey(r.Time)
	h.Mu.Lock()
	defer h.Mu.Unlock()

	b := h.buckets[key]
	if b == nil {
		b = &bucket{
			replies: make(map[int32]*pb.ReplyToClientRequest),
			tally:   make(map[bool]int),
			waitCh:  make(chan struct{}),
		}
		h.buckets[key] = b
		log.Printf("[Hub] 🆕 Created new bucket for time=%d", r.Time)
	}

	if _, seen := b.replies[r.ReplicaId]; seen {
		log.Printf("[Hub] ⚠️ Duplicate reply ignored from replica=%d | time=%d", r.ReplicaId, r.Time)
		return
	}

	// Record and tally this reply
	b.replies[r.ReplicaId] = r
	b.tally[r.Result]++
	log.Printf("[Hub] 🧮 Tally update: result=%t → count=%d (replica=%d, time=%d)",
		r.Result, b.tally[r.Result], r.ReplicaId, r.Time)

	// Check if quorum reached
	if b.accepted == nil && b.tally[r.Result] >= quorum {
		b.accepted = r
		close(b.waitCh)
		log.Printf("[Hub] ✅ Quorum reached for time=%d | result=%t | view=%d | decided by replica=%d",
			r.Time, r.Result, r.View, r.ReplicaId)
	}
}

func (h *Hub) waitQuorumOrTimeout(key ReplyKey, d time.Duration) (*pb.ReplyToClientRequest, bool) {
	h.Mu.Lock()
	b := h.buckets[key]
	if b == nil {
		b = &bucket{
			replies: make(map[int32]*pb.ReplyToClientRequest),
			tally:   make(map[bool]int),
			waitCh:  make(chan struct{}),
		}
		h.buckets[key] = b
	}
	if b.accepted != nil {
		r := b.accepted
		h.Mu.Unlock()
		return r, true
	}
	ch := b.waitCh
	h.Mu.Unlock()

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ch:
		h.Mu.Lock()
		r := h.buckets[key].accepted
		h.Mu.Unlock()
		return r, true
	case <-timer.C:
		return nil, false
	}
}

func (h *Hub) signTx(clientID string, tx *pb.Transaction) ([]byte, bool) {
	priv, ok := h.ClientPriv[clientID]
	if !ok {
		return nil, false
	}
	return ed25519.Sign(priv, crypto.TxSigningBytes(tx)), true
}

func leaderForView(view int32) int32 { return (view % N) + 1 }

func (h *Hub) ExecuteReadTransaction(ctx context.Context, clientID string) (int32, bool) {
	sig, ok := crypto.SignReadRequestByClient(clientID, h.ClientPriv)
	if !ok {
		log.Printf("[READ][%s] no client key — abort", clientID)
		return 0, false
	}
	req := &pb.ReadClientBalanceRequest{ClientId: clientID, Signature: sig}

	all := h.dialAll()
	if len(all) == 0 {
		log.Printf("[READ][%s] no alive replicas to contact", clientID)
		return 0, false
	}
	log.Printf("[READ][%s] broadcasting to %d replicas", clientID, len(all))

	type item struct {
		bal int32
		rid int32
		sig []byte
	}
	respCh := make(chan item, len(all))

	var wg sync.WaitGroup
	for rid, cli := range all {
		wg.Add(1)
		go func(rid int32, c pb.PBFTReplicaClient) {
			defer wg.Done()
			rpcCtx, cancel := context.WithTimeout(ctx, clientTimeout)
			defer cancel()
			resp, err := c.ReadClientBalance(rpcCtx, req)
			if err != nil {
				return
			}
			respCh <- item{bal: resp.GetBalance(), rid: rid, sig: resp.GetSignature()}
		}(rid, cli)
	}
	wg.Wait()

	// tally balances: balance -> set(replicaIDs)
	tally := make(map[int32]map[int32]bool)
	timeout := time.NewTimer(clientTimeout)
	defer timeout.Stop()

	remaining := len(all)
	for remaining > 0 {
		select {
		case it := <-respCh:
			remaining--
			if !crypto.VerifyReadRespSigByClient(it.rid, it.sig, h.ReplicaPubs) {
				log.Printf("[READ][%s] drop invalid sig from r=%d", clientID, it.rid)
				continue
			}
			if _, ok := tally[it.bal]; !ok {
				tally[it.bal] = map[int32]bool{}
			}
			tally[it.bal][it.rid] = true
			count := len(tally[it.bal])
			log.Printf("[READ][%s] tally balance=%d -> %d/%d", clientID, it.bal, count, quorum)
			if count >= quorum {
				log.Printf("[READ][%s] ✅ quorum reached: balance=%d", clientID, it.bal)
				return it.bal, true
			}
		case <-timeout.C:
			log.Printf("[READ][%s] ⏱️ timeout waiting for quorum", clientID)
			return 0, false
		}
	}

	log.Printf("[READ][%s] finished without quorum", clientID)
	return 0, false
}

func (h *Hub) ExecuteTransaction(ctx context.Context, clientID string, tx *pb.Transaction, live, byz []string) (*pb.ReplyToClientRequest, bool) {
	sig, ok := h.signTx(clientID, tx)
	if !ok {
		log.Printf("no key for client %s", clientID)
		return nil, false
	}
	req := &pb.ClientRequestMessage{
		ClientId:       clientID,
		Transaction:    tx,
		ClientSig:      sig,
		LiveNodes:      live,
		ByzantineNodes: byz,
	}
	key := ReplyKey(tx.Time)

	if r, ok := h.waitQuorumOrTimeout(key, 1*time.Millisecond); ok {
		return r, true
	}

	round := 0
	for {
		h.Mu.Lock()
		leader := leaderForView(h.LatestView)
		h.Mu.Unlock()

		if cli, conn, err := h.dialReplica(leader); err == nil {
			rpcCtx, cancel := context.WithTimeout(ctx, clientTimeout)
			_, _ = cli.SendRequestToLeader(rpcCtx, req)
			cancel()
			conn.Close()
		}

		if r, ok := h.waitQuorumOrTimeout(key, retryBackoff); ok {
			return r, true
		}

		all := h.dialAll()
		var wg sync.WaitGroup
		for _, cli := range all {
			wg.Add(1)
			go func(c pb.PBFTReplicaClient) {
				defer wg.Done()
				rpcCtx, cancel := context.WithTimeout(ctx, clientTimeout)
				_, _ = c.SendRequestToLeader(rpcCtx, req)
				cancel()
			}(cli)
		}
		wg.Wait()

		if r, ok := h.waitQuorumOrTimeout(key, clientTimeout); ok {
			return r, true
		}

		if round >= maxRetryCount {
			return nil, false
		}
		round++
		time.Sleep(retryBackoff)
	}
}

// ===== dialing =====

func (h *Hub) dialReplica(id int32) (pb.PBFTReplicaClient, *grpc.ClientConn, error) {
	addr, ok := h.ReplicaAddrs[id]
	if !ok {
		return nil, nil, fmt.Errorf("unknown replica %d", id)
	}
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return pb.NewPBFTReplicaClient(conn), conn, nil
}

func (h *Hub) dialAll() map[int32]pb.PBFTReplicaClient {
	out := map[int32]pb.PBFTReplicaClient{}
	aliveSet := make(map[int32]struct{}, len(h.AliveNodes))
	for _, id := range h.AliveNodes {
		aliveSet[id] = struct{}{}
	}
	for id, addr := range h.ReplicaAddrs {
		if _, ok := aliveSet[id]; !ok {
			continue
		}
		conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			continue
		}
		out[id] = pb.NewPBFTReplicaClient(conn)
	}
	return out
}
