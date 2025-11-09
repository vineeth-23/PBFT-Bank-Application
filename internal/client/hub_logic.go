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
	maxRetryCount = 5
	retryBackoff  = 6000 * time.Millisecond
)

func (h *Hub) verifyReplySig(r *pb.ReplyToClientRequest) bool {
	pub, ok := h.ReplicaPubs[r.ReplicaId]
	if !ok {
		return false
	}
	return ed25519.Verify(pub, crypto.GenerateBytesForReplySigning(r), r.Signature)
}

func (h *Hub) ProcessNodeReply(r *pb.ReplyToClientRequest) {
	//log.Printf("[Hub] Processing reply from replica=%d | view=%d | time=%d | result=%t",
	//	r.ReplicaId, r.View, r.Time, r.Result)

	if r.GetView() > h.LatestView {
		//log.Printf("[Hub] Updating latest view: old=%d → new=%d", h.LatestView, r.GetView())
		h.LatestView = r.GetView()
	}

	if !h.verifyReplySig(r) {
		//log.Printf("[Hub] Dropped invalid signature from replica=%d | time=%d | view=%d",
		//	r.ReplicaId, r.Time, r.View)
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
		//log.Printf("[Hub] Created new bucket for time=%d", r.Time)
	}

	if _, seen := b.replies[r.ReplicaId]; seen {
		//log.Printf("[Hub]  Duplicate reply ignored from replica=%d | time=%d", r.ReplicaId, r.Time)
		return
	}

	b.replies[r.ReplicaId] = r
	b.tally[r.Result]++
	//log.Printf("[Hub] Tally update: result=%t → count=%d (replica=%d, time=%d)",
	//	r.Result, b.tally[r.Result], r.ReplicaId, r.Time)

	if b.accepted == nil && b.tally[r.Result] >= quorum {
		b.accepted = r
		select {
		case <-b.waitCh:
			log.Printf("It is in b.waitCh")
		default:
			close(b.waitCh)
			//log.Printf("[Hub] Quorum reached for time=%d | result=%t | view=%d | decided by replica=%d",
			//	r.Time, r.Result, r.View, r.ReplicaId)
		}
	}
}

func (h *Hub) waitQuorumOrTimeout(key ReplyKey) (*pb.ReplyToClientRequest, bool) {
	d := 500 * time.Millisecond
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
	if h.buckets[key] != nil {
		repliesReceived := h.buckets[key].replies
		if len(repliesReceived) > 0 {
			for _, reply := range repliesReceived {
				h.Mu.Unlock()
				return reply, true
			}
		}
	}
	ch := b.waitCh
	h.Mu.Unlock()

	timer := time.NewTimer(d)
	defer timer.Stop()

	for {
		select {
		case <-ch:
			h.Mu.Lock()
			r := h.buckets[key].accepted
			h.Mu.Unlock()
			return r, true
		case <-time.After(400 * time.Millisecond):
			h.Mu.Lock()
			if h.buckets[key] != nil {
				repliesReceived := h.buckets[key].replies
				if len(repliesReceived) > 0 {
					for _, reply := range repliesReceived {
						//log.Printf("Recievied reply for trnscn time: %d and closing", reply.Time)
						h.Mu.Unlock()
						return reply, true
					}
				}
			}
			h.Mu.Unlock()
		case <-timer.C:
			return nil, false
		}
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
		return 0, false
	}
	req := &pb.ReadClientBalanceRequest{ClientId: clientID, Signature: sig}

	all := h.dialAll()
	if len(all) == 0 {
		return 0, false
	}
	//log.Printf("[READ][%s] broadcasting to %d replicas", clientID, len(all))

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

	tally := make(map[int32]map[int32]bool)
	timeout := time.NewTimer(clientTimeout)
	defer timeout.Stop()

	remaining := len(all)
	for remaining > 0 {
		select {
		case it := <-respCh:
			remaining--
			if !crypto.VerifyReadRespSigByClient(it.rid, it.sig, h.ReplicaPubs) {
				//log.Printf("[READ][%s] drop invalid sig from r=%d", clientID, it.rid)
				continue
			}
			if _, ok := tally[it.bal]; !ok {
				tally[it.bal] = map[int32]bool{}
			}
			tally[it.bal][it.rid] = true
			count := len(tally[it.bal])
			//log.Printf("[READ][%s] tally balance=%d -> %d/%d", clientID, it.bal, count, quorum)
			if count >= quorum {
				log.Printf("[READ][%s] Recievied same response from %d nodes => quorum reached: balance=%d", clientID, count, it.bal)
				return it.bal, true
			}
		case <-timeout.C:
			log.Printf("[READ][%s]  timeout waiting for quorum", clientID)
			return 0, false
		}
	}

	//log.Printf("[READ][%s] finished without quorum", clientID)
	return 0, false
}

func (h *Hub) ExecuteTransaction(ctx context.Context, clientID string, tx *pb.Transaction, live, byz []string) (*pb.ReplyToClientRequest, bool) {
	sig, ok := h.signTx(clientID, tx)
	if !ok {
		//log.Printf("no key for client %s", clientID)
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

	if r, ok := h.waitQuorumOrTimeout(key); ok {
		//log.Printf(" Transaction %d quorum satisfied before sending request", tx.Time)
		return r, true
	}

	round := 0
	for {
		if h.buckets[key] != nil {
			repliesRecievied := h.buckets[key].replies
			if len(repliesRecievied) > 0 {
				//log.Printf("Transaction %d already has cached reply — returning cached response", tx.Time)
				return repliesRecievied[0], true
			}
		}

		h.Mu.Lock()
		leader := leaderForView(h.LatestView)
		h.Mu.Unlock()

		//log.Printf("[Round %d] Sending transaction %d to leader node %d", round, tx.Time, leader)
		if node, conn, err := h.dialReplica(leader); err == nil {
			rpcCtx, cancel := context.WithTimeout(ctx, clientTimeout)
			_, _ = node.SendRequestToLeader(rpcCtx, req)
			cancel()
			conn.Close()
			//if err != nil {
			//	log.Printf(" Failed to send transaction %d to leader node %d: %v", tx.Time, leader, err)
			//} else {
			//	log.Printf(" Successfully sent transaction %d to leader node %d", tx.Time, leader)
			//}
		}

		if r, ok := h.waitQuorumOrTimeout(key); ok {
			//log.Printf(" Transaction %d quorum reached after sending to leader", tx.Time)
			return r, true
		}

		time.Sleep(3 * time.Second)

		all := h.dialAll()
		var wg sync.WaitGroup
		//log.Printf(" [Round %d] Broadcasting transaction %d to all replicas (%d total)", round, tx.Time, len(all))
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

		if r, ok := h.waitQuorumOrTimeout(key); ok {
			return r, true
		}

		if round >= maxRetryCount {
			log.Printf(" Transaction %d failed after %d retries — giving up", tx.Time, round)
			return nil, false
		}
		round++
		time.Sleep(retryBackoff)
	}
}

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
