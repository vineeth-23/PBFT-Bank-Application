package gRPC

import (
	"context"
	"fmt"
	"log"
	"net"
	"pbft-bank-application/internal/crypto"
	"pbft-bank-application/internal/node"
	pb "pbft-bank-application/pbft-bank-application/proto"
	"sort"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// NodeServer wraps a *node.Node and implements pb.PBFTReplicaServer
type NodeServer struct {
	pb.UnimplementedPBFTReplicaServer
	Node *node.Node
}

func NewNodeServer(node *node.Node) *NodeServer {
	return &NodeServer{Node: node}
}
func (s *NodeServer) StartServer() {
	addr := s.Node.Address
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Node %s failed to listen on %s: %v", s.Node.ID, addr, err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterPBFTReplicaServer(grpcServer, s)

	log.Printf("Node %d running gRPC server at %s", s.Node.ID, addr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Node %s failed to serve: %v", s.Node.ID, err)
	}
}

func (s *NodeServer) SendRequestToLeader(ctx context.Context, req *pb.ClientRequestMessage) (*pb.ReplyToClientRequest, error) {
	n := s.Node

	if !n.IsAlive {
		return nil, status.Error(codes.Aborted, "Node is not alive")
	}

	n.Lock()

	tx := req.GetTransaction()
	digest := s.TxDigest(tx)

	// 1) Fast path: already executed
	if cached, ok := n.AlreadyExecutedTransactions[digest]; ok && cached != nil {
		n.Unlock()
		log.Printf("[Node %d] 🔁 Cache hit for t=%d (digest=%s) → returning cached reply",
			n.ID, tx.GetTime(), digest[:8])
		return cached, nil
	}

	if !n.VerifyClientSignatureBasedOnTransaction(req.GetClientId(), tx, req.GetClientSig()) {
		n.Unlock()
		log.Printf("[Node %d] ❌ Invalid client signature for client_id=%s tx=(%s→%s a=%d t=%d)",
			n.ID, req.GetClientId(), tx.GetFromClientId(), tx.GetToClientId(), tx.GetAmount(), tx.GetTime())
		return nil, status.Errorf(codes.PermissionDenied, "invalid client signature for client_id=%s", req.GetClientId())
	}

	currentLeaderID := GetLeaderBasedOnViewNumber(n.ViewNumber)
	if n.ID != currentLeaderID {
		leaderAddr, ok := s.Node.Peers[currentLeaderID]
		if !ok {
			n.Unlock()
			log.Printf("[Node %d] ⚠️ Leader for view=%d is n%d but address unknown",
				s.Node.ID, n.ViewNumber, currentLeaderID)
			return nil, status.Error(codes.FailedPrecondition, "leader unknown")
		}
		n.Unlock()

		log.Printf("[Node %d] ↪️ Forwarding t=%d (digest=%s) to leader n%d @ %s",
			s.Node.ID, tx.GetTime(), digest[:8], currentLeaderID, leaderAddr)

		conn, err := grpc.Dial(leaderAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Printf("[Node %d] ❌ dial leader n%d failed: %v", s.Node.ID, currentLeaderID, err)
			return nil, status.Error(codes.Unavailable, "leader unreachable")
		}
		defer conn.Close()

		leader := pb.NewPBFTReplicaClient(conn)
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		respFromLeader, err2 := leader.SendRequestToLeader(cctx, req)
		if err2 != nil {
			log.Printf("[Node %d] ❌ forward to leader n%d failed: %v", s.Node.ID, currentLeaderID, err2)
			return nil, err2
		}
		return respFromLeader, nil
	}

	var seq, view int32
	{
		var maxi int32
		for sseq := range n.LogEntries {
			if sseq > maxi {
				maxi = sseq
			}
		}
		seq = maxi + 1
		view = n.ViewNumber

		if _, exists := n.LogEntries[seq]; !exists {
			intTx := &node.Transaction{
				FromClientID: tx.FromClientId,
				ToClientID:   tx.ToClientId,
				Amount:       tx.Amount,
				Time:         tx.Time,
			}
			n.LogEntries[seq] = &node.LogEntry{
				Digest:         digest,
				ViewNumber:     view,
				SequenceNumber: seq,
				Status:         node.StatusPrePrepared,
				Transaction:    intTx,
				PreparedProof:  make(map[int32][]*node.StatusProof),
				CommittedProof: make(map[int32][]*node.StatusProof),
			}
		}
	}
	log.Printf("[Leader %d] 📌 Assigned (v=%d, n=%d) for t=%d digest=%s",
		n.ID, view, seq, tx.GetTime(), digest[:8])

	ppReq := &pb.PrePrepareMessageRequest{
		ViewNumber:     view,
		SequenceNumber: seq,
		Digest:         digest,
		ReplicaId:      n.ID,
		Transaction:    tx,
		Signature:      n.Sign(GenerateBytesForSign(seq, digest)),
	}

	targetPeers := make(map[int32]string, len(n.Peers))
	for pid, addr := range n.Peers {
		if pid == n.ID {
			continue
		}
		targetPeers[pid] = addr
	}

	ppResponses := make([]*pb.PrePrepareMessageResponse, 0, len(targetPeers)+1)

	n.Unlock()

	if resp, _ := s.SendPrePrepare(context.Background(), ppReq); resp != nil {
		ppResponses = append(ppResponses, resp)
	}
	{
		var wg sync.WaitGroup
		responses := make(chan *pb.PrePrepareMessageResponse, len(targetPeers))
		for pid, addr := range targetPeers {
			wg.Add(1)
			go func(peerID int32, peerAddr string) {
				defer wg.Done()
				conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					log.Printf("[Leader %d] ❌ SendPrePrepare dial %s failed: %v", s.Node.ID, peerAddr, err)
					return
				}
				defer conn.Close()

				follower := pb.NewPBFTReplicaClient(conn)
				cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				resp, err := follower.SendPrePrepare(cctx, ppReq)
				if err != nil {
					log.Printf("[Leader %d] ❌ SendPrePrepare->n%d error: %v", s.Node.ID, peerID, err)
					return
				}
				responses <- resp
			}(pid, addr)
		}
		wg.Wait()
		close(responses)
		for r := range responses {
			ppResponses = append(ppResponses, r)
		}
	}
	log.Printf("[Leader %d] 📤 PRE-PREPARE collected %d/%d follower acks (plus local)",
		s.Node.ID, len(ppResponses)-1, len(targetPeers))

	n.Lock()
	prepReq := &pb.PrepareMessageRequest{
		PrePreparedMessageResponse: ppResponses,
		ReplicaId:                  s.Node.ID,
		Signature:                  s.Node.Sign(GenerateBytesForSign(seq, digest)),
		SequenceNumber:             seq,
	}
	n.Unlock()

	prepResponses := make([]*pb.PrepareMessageResponse, 0, len(targetPeers)+1)

	if resp, _ := s.SendPrepare(context.Background(), prepReq); resp != nil {
		prepResponses = append(prepResponses, resp)
	}
	{
		var wg sync.WaitGroup
		responses := make(chan *pb.PrepareMessageResponse, len(targetPeers))
		for pid, addr := range targetPeers {
			wg.Add(1)
			go func(peerID int32, peerAddr string) {
				defer wg.Done()
				conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					log.Printf("[Leader %d] ❌ SendPrepare dial %s failed: %v", s.Node.ID, peerAddr, err)
					return
				}
				defer conn.Close()

				cli := pb.NewPBFTReplicaClient(conn)
				cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				resp, err := cli.SendPrepare(cctx, prepReq)
				if err != nil {
					log.Printf("[Leader %d] ❌ SendPrepare->n%d error: %v", s.Node.ID, peerID, err)
					return
				}
				responses <- resp
			}(pid, addr)
		}
		wg.Wait()
		close(responses)
		for r := range responses {
			prepResponses = append(prepResponses, r)
		}
	}
	log.Printf("[Leader %d] 📤 PREPARE collected %d/%d follower acks (plus local)",
		s.Node.ID, len(prepResponses)-1, len(targetPeers))

	n.Lock()
	commitReq := &pb.CommitMessageRequest{
		PreparedMessageResponse: prepResponses,
		ReplicaId:               s.Node.ID,
		SequenceNumber:          seq,
		Signature:               s.Node.Sign(GenerateBytesForSign(seq, digest)),
	}
	n.Unlock()

	if _, err := s.SendCommit(context.Background(), commitReq); err != nil {
		log.Printf("[Leader %d] ❌ local SendCommit error: %v", s.Node.ID, err)
	}

	{
		var wg sync.WaitGroup
		for pid, addr := range targetPeers {
			wg.Add(1)
			go func(peerID int32, peerAddr string) {
				defer wg.Done()
				conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					log.Printf("[Leader %d] ❌ SendCommit dial %s failed: %v", s.Node.ID, peerAddr, err)
					return
				}
				defer conn.Close()

				cli := pb.NewPBFTReplicaClient(conn)
				cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				if _, err := cli.SendCommit(cctx, commitReq); err != nil {
					log.Printf("[Leader %d] ❌ SendCommit->n%d error: %v", s.Node.ID, peerID, err)
					return
				}
			}(pid, addr)
		}
		wg.Wait()
	}
	log.Printf("[Leader %d] ✅ Commit phase dispatched for t=%d (v=%d, n=%d, digest=%s). Execution will be reported via client callback.",
		s.Node.ID, tx.GetTime(), view, seq, digest[:8])

	return nil, nil
}

//func (s *NodeServer) SendRequestToLeader(ctx context.Context, req *pb.ClientRequestMessage) (*pb.ReplyToClientRequest, error) {
//	n := s.Node
//
//	n.Lock()
//
//	tx := req.GetTransaction()
//	digest := s.TxDigest(tx)
//
//	if cached, ok := n.AlreadyExecutedTransactions[digest]; ok && cached != nil {
//		n.Unlock()
//		return cached, nil
//	}
//
//	if !n.VerifyClientSignatureBasedOnTransaction(req.GetClientId(), tx, req.GetClientSig()) {
//		n.Unlock()
//		log.Printf("[Node %d] ❌ Invalid client signature for client_id=%s, transaction=(%s → %s, amount=%d, time=%d)",
//			n.ID,
//			req.GetClientId(),
//			tx.GetFromClientId(),
//			tx.GetToClientId(),
//			tx.GetAmount(),
//			tx.GetTime(),
//		)
//		return nil, status.Errorf(codes.PermissionDenied,
//			"invalid client signature for client_id=%s", req.GetClientId())
//	}
//
//	currentLeaderID := GetLeaderBasedOnViewNumber(n.ViewNumber)
//	if n.ID != currentLeaderID {
//		leaderAddr, ok := s.Node.Peers[currentLeaderID]
//		if !ok {
//			n.Unlock()
//			log.Printf("[Node %d] No valid leader address", s.Node.ID)
//			return nil, status.Error(codes.FailedPrecondition, "leader unknown")
//		}
//
//		n.Unlock()
//
//		conn, err := grpc.NewClient(
//			leaderAddr,
//			grpc.WithTransportCredentials(insecure.NewCredentials()),
//		)
//		if err != nil {
//			//log.Printf("[Node %d] Could not forward to leader %d: %v", s.node.ID, s.node.CurrentLeaderID, err)
//			return nil, status.Error(codes.Unavailable, "leader unreachable")
//		}
//		defer conn.Close()
//
//		leader := pb.NewPBFTReplicaClient(conn)
//		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
//		defer cancel()
//		respFromLeader, err2 := leader.SendRequestToLeader(cctx, req)
//		if err2 != nil {
//			return nil, err2
//		}
//		return respFromLeader, nil
//	}
//
//	var seq, view int32
//	{
//		var maxi int32
//		for sseq := range n.LogEntries {
//			if sseq > maxi {
//				maxi = sseq
//			}
//		}
//		seq = maxi + 1
//		view = n.ViewNumber
//
//		if _, exists := n.LogEntries[seq]; !exists {
//			intTx := &node.Transaction{
//				FromClientID: tx.FromClientId,
//				ToClientID:   tx.ToClientId,
//				Amount:       tx.Amount,
//				Time:         tx.Time,
//			}
//			n.LogEntries[seq] = &node.LogEntry{
//				Digest:         digest,
//				ViewNumber:     view,
//				SequenceNumber: seq,
//				Status:         node.StatusPrePrepared,
//				Transaction:    intTx,
//				PreparedProof:  make(map[int32][]*node.StatusProof),
//				CommittedProof: make(map[int32][]*node.StatusProof),
//			}
//		}
//	}
//
//	ppReq := &pb.PrePrepareMessageRequest{
//		ViewNumber:     view,
//		SequenceNumber: seq,
//		Digest:         digest,
//		ReplicaId:      n.ID,
//		Transaction:    tx,
//		Signature:      n.Sign(GenerateBytesForSign(seq, digest)),
//	}
//
//	targetPeers := make(map[int32]string, len(n.Peers))
//	for pid, addr := range n.Peers {
//		if pid == n.ID {
//			continue
//		}
//		targetPeers[pid] = addr
//	}
//
//	ppResponses := make([]*pb.PrePrepareMessageResponse, 0, len(targetPeers)+1)
//
//	n.Unlock()
//
//	if resp, _ := s.SendPrePrepare(context.Background(), ppReq); resp != nil {
//		ppResponses = append(ppResponses, resp)
//	}
//
//	{
//		var wg sync.WaitGroup
//		responses := make(chan *pb.PrePrepareMessageResponse, len(targetPeers))
//		for pid, addr := range targetPeers {
//			wg.Add(1)
//			go func(peerID int32, peerAddr string) {
//				defer wg.Done()
//				conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
//				if err != nil {
//					log.Printf("[Leader %d] dial %s failed: %v", s.Node.ID, peerAddr, err)
//					return
//				}
//				defer conn.Close()
//
//				follower := pb.NewPBFTReplicaClient(conn)
//				cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
//				defer cancel()
//				resp, err := follower.SendPrePrepare(cctx, ppReq)
//				if err != nil {
//					log.Printf("[Leader %d] SendPrePrepare->%d error: %v", s.Node.ID, peerID, err)
//					return
//				}
//				responses <- resp
//			}(pid, addr)
//		}
//		wg.Wait()
//		close(responses)
//		for r := range responses {
//			ppResponses = append(ppResponses, r)
//		}
//	}
//
//	n.Lock()
//	prepReq := &pb.PrepareMessageRequest{
//		PrePreparedMessageResponse: ppResponses,
//		ReplicaId:                  s.Node.ID,
//		Signature:                  s.Node.Sign(GenerateBytesForSign(seq, digest)),
//		SequenceNumber:             seq,
//	}
//
//	prepResponses := make([]*pb.PrepareMessageResponse, 0, len(targetPeers)+1)
//	n.Unlock()
//
//	if resp, _ := s.SendPrepare(context.Background(), prepReq); resp != nil {
//		prepResponses = append(prepResponses, resp)
//	}
//
//	{
//		var wg sync.WaitGroup
//		responses := make(chan *pb.PrepareMessageResponse, len(targetPeers))
//		for pid, addr := range targetPeers {
//			wg.Add(1)
//			go func(peerID int32, peerAddr string) {
//				defer wg.Done()
//				conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
//				if err != nil {
//					log.Printf("[Leader %d] dial %s failed: %v", s.Node.ID, peerAddr, err)
//					return
//				}
//				defer conn.Close()
//
//				cli := pb.NewPBFTReplicaClient(conn)
//				cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
//				defer cancel()
//				resp, err := cli.SendPrepare(cctx, prepReq)
//				if err != nil {
//					log.Printf("[Leader %d] SendPrepare->%d error: %v", s.Node.ID, peerID, err)
//					return
//				}
//				responses <- resp
//			}(pid, addr)
//		}
//		wg.Wait()
//		close(responses)
//		for r := range responses {
//			prepResponses = append(prepResponses, r)
//		}
//	}
//
//	n.Lock()
//	commitReq := &pb.CommitMessageRequest{
//		PreparedMessageResponse: prepResponses,
//		ReplicaId:               s.Node.ID,
//		SequenceNumber:          seq,
//		Signature:               s.Node.Sign(GenerateBytesForSign(seq, digest)),
//	}
//	n.Unlock()
//
//	if _, err := s.SendCommit(context.Background(), commitReq); err != nil {
//		log.Printf("[Leader %d] local SendCommit error: %v", s.Node.ID, err)
//	}
//
//	{
//		var wg sync.WaitGroup
//		for pid, addr := range targetPeers {
//			wg.Add(1)
//			go func(peerID int32, peerAddr string) {
//				defer wg.Done()
//				conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
//				if err != nil {
//					log.Printf("[Leader %d] dial %s failed: %v", s.Node.ID, peerAddr, err)
//					return
//				}
//				defer conn.Close()
//
//				cli := pb.NewPBFTReplicaClient(conn)
//				cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
//				defer cancel()
//				if _, err := cli.SendCommit(cctx, commitReq); err != nil {
//					log.Printf("[Leader %d] SendCommit->%d error: %v", s.Node.ID, peerID, err)
//					return
//				}
//			}(pid, addr)
//		}
//		wg.Wait()
//	}
//	return nil, nil
//	//deadline := time.Now().Add(2 * time.Second)
//	//for {
//	//	n.Lock()
//	//	reply, ok := n.AlreadyExecutedTransactions[digest]
//	//	n.Unlock()
//	//	if ok && reply != nil {
//	//		return reply, nil
//	//	}
//	//	if time.Now().After(deadline) {
//	//		// Not executed yet; return a non-final acknowledgement (client may retry/poll)
//	//		return &pb.ReplyToClientRequest{
//	//			View:      view,
//	//			Time:      tx.Time,
//	//			Result:    false,
//	//			ReplicaId: s.Node.ID,
//	//			Signature: s.Node.Sign(GenerateBytesForSign(seq, digest)),
//	//		}, nil
//	//	}
//	//	time.Sleep(25 * time.Millisecond)
//	//}
//}

func (s *NodeServer) SendPrePrepare(ctx context.Context, req *pb.PrePrepareMessageRequest) (*pb.PrePrepareMessageResponse, error) {
	n := s.Node

	if !n.IsAlive {
		log.Printf("Node is not alive")
		return nil, status.Error(codes.Aborted, "Node is not alive")
	}

	n.Lock()
	defer n.Unlock()

	// 1) View check: must be in the same view
	if req.ViewNumber != n.ViewNumber {
		log.Printf("[Node %d] Reject PrePrepare: wrong view (got=%d, cur=%d)",
			n.ID, req.ViewNumber, n.ViewNumber)
		return &pb.PrePrepareMessageResponse{
			ViewNumber:     req.ViewNumber,
			SequenceNumber: req.SequenceNumber,
			Digest:         req.Digest,
			ReplicaId:      n.ID,
			Signature:      nil,
			Status:         string(node.StatusWrongView),
		}, nil
	}

	// 2) No conflicting pre-prepare for same (view, seq) with different digest
	if existing, ok := n.LogEntries[req.SequenceNumber]; ok {
		if existing.ViewNumber == req.ViewNumber && existing.Digest != req.Digest {
			log.Printf("[Node %d] Reject PrePrepare: conflicting digest for (v=%d, n=%d) (have=%s, got=%s)",
				n.ID, req.ViewNumber, req.SequenceNumber, existing.Digest, req.Digest)
			return &pb.PrePrepareMessageResponse{
				ViewNumber:     req.ViewNumber,
				SequenceNumber: req.SequenceNumber,
				Digest:         req.Digest,
				ReplicaId:      n.ID,
				Status:         string(node.StatusConflictingDigest),
			}, nil
		}

		// idempotent accept: if already PREPREPARED, just acknowledge again
		if existing.Status == node.StatusPrePrepared || existing.Status == node.StatusPrepared ||
			existing.Status == node.StatusCommitted || existing.Status == node.StatusExecuted {
			resp := &pb.PrePrepareMessageResponse{
				ViewNumber:     existing.ViewNumber,
				SequenceNumber: existing.SequenceNumber,
				Digest:         existing.Digest,
				ReplicaId:      n.ID,
				Status:         string(existing.Status),
			}
			//resp.Signature = n.Sign([]byte(fmt.Sprintf("%d:%d:%s:%s",
			//	resp.ViewNumber, resp.SequenceNumber, resp.Digest, resp.Status)))
			return resp, nil
		}
	}

	// 3) Verify leader's signature over (sequence_number, digest)
	prepBytes := GenerateBytesForSign(req.SequenceNumber, req.Digest)
	if ok := n.VerifyReplicaSig(req.ReplicaId, prepBytes, req.Signature); !ok {
		log.Printf("[Node %d] Reject PrePrepare: invalid leader signature from %d", n.ID, req.ReplicaId)
		return &pb.PrePrepareMessageResponse{
			ViewNumber:     req.ViewNumber,
			SequenceNumber: req.SequenceNumber,
			Digest:         req.Digest,
			ReplicaId:      n.ID,
			Status:         string(node.StatusInvalidLeaderSignature),
		}, nil
	}

	if req.Transaction == nil {
		log.Printf("[Node %d] Reject PrePrepare: nil transaction", n.ID)
		return &pb.PrePrepareMessageResponse{
			ViewNumber:     req.ViewNumber,
			SequenceNumber: req.SequenceNumber,
			Digest:         req.Digest,
			ReplicaId:      n.ID,
			Status:         string(node.StatusNilTransaction),
		}, nil
	}

	// 4) Verify digest(m) == d
	expectedDigest := s.TxDigest(req.Transaction)
	if expectedDigest != req.Digest {
		log.Printf("[Node %d] Reject PrePrepare: digest mismatch (expected=%s, got=%s)",
			n.ID, expectedDigest, req.Digest)
		return &pb.PrePrepareMessageResponse{
			ViewNumber:     req.ViewNumber,
			SequenceNumber: req.SequenceNumber,
			Digest:         req.Digest,
			ReplicaId:      n.ID,
			Status:         string(node.StatusBadDigest),
		}, nil
	}

	// 5) Accept: append to log and mark PREPREPARED
	entry := &node.LogEntry{
		Digest:         req.Digest,
		ViewNumber:     req.ViewNumber,
		SequenceNumber: req.SequenceNumber,
		Status:         node.StatusPrePrepared,
		Transaction: &node.Transaction{
			FromClientID: req.Transaction.GetFromClientId(),
			ToClientID:   req.Transaction.GetToClientId(),
			Amount:       req.Transaction.GetAmount(),
			Time:         req.Transaction.GetTime(),
		},
		PreparedProof:  make(map[int32][]*node.StatusProof),
		CommittedProof: make(map[int32][]*node.StatusProof),
	}
	n.LogEntries[req.SequenceNumber] = entry

	log.Printf("[Node %d] Accepted PrePrepare (v=%d, n=%d, d=%s) from leader %d -> PRE-PREPARED",
		n.ID, req.ViewNumber, req.SequenceNumber, req.Digest, req.ReplicaId)

	// Build response signed by this replica (so the leader can collect it if needed)
	resp := &pb.PrePrepareMessageResponse{
		ViewNumber:     req.ViewNumber,
		SequenceNumber: req.SequenceNumber,
		Digest:         req.Digest,
		ReplicaId:      n.ID,
		Status:         string(node.StatusPrePrepared),
	}
	resp.Signature = n.Sign(GenerateBytesForSign(resp.SequenceNumber, resp.Digest))

	return resp, nil
}

func (s *NodeServer) SendPrepare(ctx context.Context, req *pb.PrepareMessageRequest) (*pb.PrepareMessageResponse, error) {
	n := s.Node

	if !n.IsAlive {
		return nil, status.Error(codes.Aborted, "Node is not alive")
	}

	n.Lock()
	defer n.Unlock()

	if len(req.PrePreparedMessageResponse) == 0 {
		return &pb.PrepareMessageResponse{
			Status: "REJECTED_EMPTY_PROOFS",
		}, nil
	}

	// Must already have accepted the PrePrepare for (v, n, d)
	entry, ok := n.LogEntries[req.GetSequenceNumber()]
	if !ok {
		return &pb.PrepareMessageResponse{
			ViewNumber:     0,
			SequenceNumber: req.SequenceNumber,
			Digest:         "",
			ReplicaId:      n.ID,
			Status:         "REJECTED_NO_ENTRY",
		}, nil
	}

	currentViewNumber := entry.ViewNumber
	currentDigest := entry.Digest
	currentSequenceNumber := entry.SequenceNumber

	if entry.Status != node.StatusPrePrepared {
		return &pb.PrepareMessageResponse{
			ViewNumber:     currentViewNumber,
			SequenceNumber: currentSequenceNumber,
			Digest:         currentDigest,
			ReplicaId:      n.ID,
			Status:         "REJECTED_NO_PREPREPARE",
		}, nil
	}

	seen := map[int32]bool{}
	validBackupCount := 0
	proofs := make(map[int32]*node.StatusProof)

	for _, pp := range req.PrePreparedMessageResponse {
		if !s.Node.VerifyNodeSignatureBasedOnSequenceNumberAndDigest(pp.ReplicaId, pp.GetSequenceNumber(), pp.GetDigest(), pp.GetSignature()) {
			continue
		}

		if pp.ViewNumber != currentViewNumber || pp.SequenceNumber != currentSequenceNumber || pp.Digest != currentDigest || pp.Status != string(node.StatusPrePrepared) {
			continue
		}

		// Count only distinct backups (not the primary)
		if !seen[pp.ReplicaId] {
			seen[pp.ReplicaId] = true
			validBackupCount++
			proofs[pp.ReplicaId] = &node.StatusProof{
				NodeID:         pp.ReplicaId,
				Digest:         pp.GetDigest(),
				View:           pp.GetViewNumber(),
				SequenceNumber: pp.GetSequenceNumber(),
				Status:         node.Status(pp.GetStatus()),
				Signature:      append([]byte(nil), pp.GetSignature()...),
			}
		}
	}

	// Need at least 2f proofs from different backups
	if validBackupCount < 2*F {
		return &pb.PrepareMessageResponse{
			ViewNumber:     currentViewNumber,
			SequenceNumber: currentSequenceNumber,
			Digest:         currentDigest,
			ReplicaId:      n.ID,
			Status:         string(node.StatusNotEnoughPrePrepared),
		}, nil
	}

	// Mark PREPARED and optionally retain proofs
	entry.Status = node.StatusPrepared
	if entry.PreparedProof == nil {
		entry.PreparedProof = make(map[int32][]*node.StatusProof)
	}
	for _, sp := range proofs {
		entry.PreparedProof[currentSequenceNumber] = append(entry.PreparedProof[currentSequenceNumber], sp)
	}

	resp := &pb.PrepareMessageResponse{
		ViewNumber:     currentViewNumber,
		SequenceNumber: currentSequenceNumber,
		Digest:         currentDigest,
		ReplicaId:      n.ID,
		Status:         string(node.StatusPrepared),
	}
	resp.Signature = n.Sign(GenerateBytesForSign(resp.SequenceNumber, resp.Digest))

	log.Printf("[Node %d] Updated to PREPARED (sequence_no=%d) -> PREPARED",
		n.ID, req.GetSequenceNumber())

	return resp, nil
}

func (s *NodeServer) SendCommit(ctx context.Context, req *pb.CommitMessageRequest) (*pb.CommitMessageResponse, error) {
	n := s.Node

	if !n.IsAlive {
		log.Printf("Node is not alive")
		return nil, status.Error(codes.Aborted, "Node is not alive")
	}

	n.Lock()
	defer n.Unlock()

	if len(req.PreparedMessageResponse) == 0 {
		return &pb.CommitMessageResponse{
			Status: "REJECTED_EMPTY_PROOFS",
		}, nil
	}

	seq := req.GetSequenceNumber()
	entry, ok := n.LogEntries[seq]
	if !ok {
		return &pb.CommitMessageResponse{
			ViewNumber:     0,
			SequenceNumber: seq,
			Digest:         "",
			ReplicaId:      n.ID,
			Status:         "REJECTED_NO_ENTRY",
		}, nil
	}

	currentViewNumber := entry.ViewNumber
	currentDigest := entry.Digest
	currentSequenceNumber := entry.SequenceNumber

	if entry.Status != node.StatusPrepared {
		return &pb.CommitMessageResponse{
			ViewNumber:     currentViewNumber,
			SequenceNumber: currentSequenceNumber,
			Digest:         currentDigest,
			ReplicaId:      n.ID,
			Status:         "REJECTED_NOT_PREPARED",
		}, nil
	}

	// Collect and verify PREPARED proofs from distinct replicas
	seen := map[int32]bool{}
	validPreparedCount := 0
	proofs := make(map[int32]*node.StatusProof)

	for _, pmr := range req.PreparedMessageResponse {
		if !n.VerifyNodeSignatureBasedOnSequenceNumberAndDigest(
			pmr.ReplicaId,
			pmr.GetSequenceNumber(),
			pmr.GetDigest(),
			pmr.GetSignature(),
		) {
			continue
		}

		if pmr.ViewNumber != currentViewNumber ||
			pmr.SequenceNumber != currentSequenceNumber ||
			pmr.Digest != currentDigest ||
			pmr.Status != string(node.StatusPrepared) {
			continue
		}

		if !seen[pmr.ReplicaId] {
			seen[pmr.ReplicaId] = true
			validPreparedCount++

			proofs[pmr.ReplicaId] = &node.StatusProof{
				NodeID:         pmr.ReplicaId,
				Digest:         pmr.GetDigest(),
				View:           pmr.GetViewNumber(),
				SequenceNumber: pmr.GetSequenceNumber(),
				Status:         node.Status(pmr.GetStatus()),
				Signature:      append([]byte(nil), pmr.GetSignature()...),
			}
		}
	}

	// Need at least 2f+1 PREPARED proofs to COMMIT
	if validPreparedCount < (2*F + 1) {
		return &pb.CommitMessageResponse{
			ViewNumber:     currentViewNumber,
			SequenceNumber: currentSequenceNumber,
			Digest:         currentDigest,
			ReplicaId:      n.ID,
			Status:         string(node.StatusNotEnoughPrepared),
		}, nil
	}

	entry.Status = node.StatusCommitted
	if entry.CommittedProof == nil {
		entry.CommittedProof = make(map[int32][]*node.StatusProof)
	}

	for _, sp := range proofs {
		entry.CommittedProof[currentSequenceNumber] = append(entry.CommittedProof[currentSequenceNumber], sp)
	}

	resp := &pb.CommitMessageResponse{
		ViewNumber:     currentViewNumber,
		SequenceNumber: currentSequenceNumber,
		Digest:         currentDigest,
		ReplicaId:      n.ID,
		Status:         string(node.StatusCommitted),
	}

	resp.Signature = n.Sign(GenerateBytesForSign(resp.SequenceNumber, resp.Digest))
	log.Printf("[Node %d] Updated to COMMITTED (sequence_no=%d)",
		n.ID, req.GetSequenceNumber())

	// Execute in order right before returning (as you requested)
	s.executeInOrder()

	return resp, nil
}

func (s *NodeServer) ReadClientBalance(ctx context.Context, req *pb.ReadClientBalanceRequest) (*pb.ReadClientBalanceResponse, error) {
	if !s.Node.IsAlive {
		return nil, status.Error(codes.Aborted, "Node is not alive")
	}

	clientID := req.GetClientId()

	if !crypto.VerifyClientSignatureForReadRequest(clientID, req.GetSignature(), s.Node.PubKeysOfClients) {
		return nil, status.Errorf(codes.PermissionDenied, "invalid read signature for client %s", clientID)
	}

	s.Node.Lock()
	bal := s.Node.Balances[clientID]
	s.Node.Unlock()

	resp := &pb.ReadClientBalanceResponse{
		Balance: bal,
	}
	resp.Signature = s.Node.Sign(crypto.GenerateBytesForSigningReadResponse(s.Node.ID))
	return resp, nil
}

func (s *NodeServer) FlushPreviousDataAndUpdatePeersStatus(ctx context.Context, req *pb.FlushAndUpdateStatusRequest) (*emptypb.Empty, error) {
	s.Node.ResetForNewSetAndUpdateNodeStatus(req)
	log.Printf("[Node %d] Flushed state for new set. updated live nodes: %v", s.Node.ID, req.GetLiveNodes())
	return &emptypb.Empty{}, nil
}

//--------------------CLIENT FUNCNS-----------------------------

func (s *NodeServer) PrintDB(ctx context.Context, _ *emptypb.Empty) (*pb.PrintDBResponse, error) {
	n := s.Node
	n.Lock()
	defer n.Unlock()

	if s.Node.LogEntries != nil {

	}
	out := make(map[string]int32, len(n.Balances))
	for k, v := range n.Balances {
		out[k] = v
	}

	entriesMap := s.Node.LogEntries
	entries := make([]*node.LogEntry, 0, len(entriesMap))
	for _, v := range entriesMap {
		entries = append(entries, v)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SequenceNumber < entries[j].SequenceNumber
	})

	fmt.Println("Log:")
	if len(entries) == 0 {
		fmt.Println("  (empty)")
	} else {
		for _, le := range entries {
			if le.Transaction != nil {
				fmt.Printf("  n=%d v=%d status=%s  tx=(%s→%s a=%d t=%d)\n",
					le.SequenceNumber,
					le.ViewNumber,
					le.Status,
					le.Transaction.FromClientID,
					le.Transaction.ToClientID,
					le.Transaction.Amount,
					le.Transaction.Time,
				)
			} else {
				fmt.Printf("  n=%d v=%d status=%s tx=(nil)\n",
					le.SequenceNumber,
					le.ViewNumber,
					le.Status,
				)
			}
		}
	}

	return &pb.PrintDBResponse{
		ReplicaId:       n.ID,
		Balances:        out,
		ViewNumber:      n.ViewNumber,
		LastExecutedSeq: n.LastExecutedSequenceNumber,
	}, nil
}
