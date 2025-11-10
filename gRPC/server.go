package gRPC

import (
	"context"
	"fmt"
	"log"
	"net"
	"pbft-bank-application/common"
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
	"google.golang.org/protobuf/types/known/timestamppb"
)

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

	//log.Printf("Node %d running gRPC server at %s", s.Node.ID, addr)
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
	//log.Printf(
	//	"[Node %d] Received ClientRequestttt → client_id=%s, tx=(%s→%s, amount=%d, time=%d)",
	//	n.ID,
	//	req.GetClientId(),
	//	tx.GetFromClientId(),
	//	tx.GetToClientId(),
	//	tx.GetAmount(),
	//	tx.GetTime(),
	//)
	digest := s.TxDigest(tx)

	for _, entry := range n.LogEntries {
		if entry.Digest == digest &&
			(entry.Status == node.StatusPrePrepared || entry.Status == node.StatusPrepared || entry.Status == node.StatusCommitted || entry.Status == node.StatusExecuted) {
			n.Unlock()
			//log.Printf("[Node %d] Transaction digest=%s already in log with status=%v → ignoring",
			//	n.ID, digest[:8], entry.Status)
			return nil, nil
		}
	}

	if cached, ok := n.AlreadyExecutedTransactions[digest]; ok && cached != nil {
		n.Unlock()
		//log.Printf("[Node %d] Cache hit for t=%d (digest=%s) → returning cached reply",
		//	n.ID, tx.GetTime(), digest[:8])
		return cached, nil
	}

	if !n.VerifyClientSignatureBasedOnTransaction(req.GetClientId(), tx, req.GetClientSig()) {
		n.Unlock()
		//log.Printf("[Node %d] Invalid client signature for client_id=%s tx=(%s→%s a=%d t=%d)",
		//	n.ID, req.GetClientId(), tx.GetFromClientId(), tx.GetToClientId(), tx.GetAmount(), tx.GetTime())
		return nil, status.Errorf(codes.PermissionDenied, "invalid client signature for client_id=%s", req.GetClientId())
	}

	isCrashAttack, _ := s.HasAttack(string(common.CrashAttack))
	if isCrashAttack {
		n.Unlock()
		return nil, status.Error(codes.Unavailable, "Node is simulating a crash attack and is temporarily unavailable")
	}

	n.Unlock()
	//log.Printf("Calling ResetNodeTimer from SendReqToLeader func")
	n.ResetNodeTimer()
	n.Lock()

	currentLeaderID := GetLeaderBasedOnViewNumber(n.ViewNumber)
	if n.ID != currentLeaderID {
		leaderAddr, ok := s.Node.Peers[currentLeaderID]
		if !ok {
			n.Unlock()
			//log.Printf("[Node %d] Leader for view=%d is n%d but address unknown",
			//	s.Node.ID, n.ViewNumber, currentLeaderID)
			return nil, status.Error(codes.FailedPrecondition, "leader unknown")
		}
		n.Unlock()

		//log.Printf("[Node %d] Forwarding t=%d (digest=%s) to leader n%d @ %s",
		//	s.Node.ID, tx.GetTime(), digest[:8], currentLeaderID, leaderAddr)

		conn, err := grpc.Dial(leaderAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Printf("[Node %d] dial leader n%d failed: %v", s.Node.ID, currentLeaderID, err)
			return nil, status.Error(codes.Unavailable, "leader unreachable")
		}
		defer conn.Close()

		leader := pb.NewPBFTReplicaClient(conn)
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		respFromLeader, err2 := leader.SendRequestToLeader(cctx, req)
		if err2 != nil {
			log.Printf("[Node %d] forward to leader n%d failed: %v", s.Node.ID, currentLeaderID, err2)
			return nil, err2
		}
		return respFromLeader, nil
	}

	for _, entry := range n.LogEntries {
		if entry.Digest == digest &&
			(entry.Status == node.StatusPrePrepared || entry.Status == node.StatusPrepared || entry.Status == node.StatusCommitted || entry.Status == node.StatusExecuted) {
			n.Unlock()
			//log.Printf("[Node %d] Transaction digest=%s already in log with status=%v → ignoring",
			//	n.ID, digest[:8], entry.Status)
			return nil, nil
		}
	}

	var majSeq, view int32
	var maxi int32
	for _, entry := range n.LogEntries {
		if n.ViewNumber == entry.ViewNumber && entry.SequenceNumber > maxi {
			maxi = entry.SequenceNumber
		}
		//if n.ViewNumber == entry.ViewNumber {
		//	log.Printf("Already existing transaction in the same view:%d, sequence_num:%d with digest:%s", entry.ViewNumber, entry.SequenceNumber, digest[:8])
		//	if entry.Transaction != nil {
		//		log.Printf("Transaction is: (%s->%s (%d): amnt:%d", entry.Transaction.FromClientID, entry.Transaction.ToClientID, entry.Transaction.Time, entry.Transaction.Amount)
		//	}
		//}
	}
	majSeq = maxi + 1
	view = n.ViewNumber
	//log.Printf("Assigining majSeq=%d in view=%d for trasaction: (%s->%s (%d) amt:%d)", majSeq, view, req.Transaction.FromClientId, req.Transaction.ToClientId, req.Transaction.Time, req.Transaction.Amount)

	isEquiv, eqTargets := s.HasAttack(string(common.EquivocationAttack))
	baseSeq := majSeq
	if isEquiv {
		baseSeq = majSeq + 1
	}

	intTx := &node.Transaction{
		FromClientID: tx.FromClientId,
		ToClientID:   tx.ToClientId,
		Amount:       tx.Amount,
		Time:         tx.Time,
	}
	n.LogEntries[majSeq] = &node.LogEntry{
		Digest:         digest,
		ViewNumber:     view,
		SequenceNumber: majSeq,
		Status:         node.StatusPrePrepared,
		Transaction:    intTx,
		PreparedProof:  make(map[int32][]*node.StatusProof),
		CommittedProof: make(map[int32][]*node.StatusProof),
	}

	if _, exists := n.LogEntries[baseSeq]; !exists {
		intTx := &node.Transaction{
			FromClientID: tx.FromClientId,
			ToClientID:   tx.ToClientId,
			Amount:       tx.Amount,
			Time:         tx.Time,
		}
		n.LogEntries[baseSeq] = &node.LogEntry{
			Digest:         digest,
			ViewNumber:     view,
			SequenceNumber: baseSeq,
			Status:         node.StatusPrePrepared,
			Transaction:    intTx,
			PreparedProof:  make(map[int32][]*node.StatusProof),
			CommittedProof: make(map[int32][]*node.StatusProof),
		}
	}

	ppVictim := &pb.PrePrepareMessageRequest{
		ViewNumber:     view,
		SequenceNumber: baseSeq,
		Digest:         digest,
		ReplicaId:      n.ID,
		Transaction:    tx,
	}
	bytes := GenerateBytesForSign(baseSeq, digest)

	if isSignAttack, _ := s.HasAttack(string(common.SignAttack)); isSignAttack {
		//log.Printf("node %d: Signing invalid sign for sending Pre-PrePare message", s.Node.ID)
		ppVictim.Signature = crypto.SignInvalidTamper(n.PrivKey, bytes)
	} else {
		ppVictim.Signature = n.Sign(bytes)
	}

	ppMajor := &pb.PrePrepareMessageRequest{
		ViewNumber:     view,
		SequenceNumber: majSeq,
		Digest:         digest,
		ReplicaId:      n.ID,
		Transaction:    tx,
	}

	bytes = GenerateBytesForSign(majSeq, digest)

	if isSignAttack, _ := s.HasAttack(string(common.SignAttack)); isSignAttack {
		//log.Printf("node %d: Signing invalid sign for sending Pre-PrePare message", s.Node.ID)
		ppMajor.Signature = crypto.SignInvalidTamper(n.PrivKey, bytes)
	} else {
		ppMajor.Signature = n.Sign(bytes)
	}

	targetPeers := make(map[int32]string, len(n.Peers))
	for pid, addr := range n.Peers {
		if pid == n.ID {
			continue
		}
		targetPeers[pid] = addr
	}

	isVictim := func(id int32) bool {
		if !isEquiv || len(eqTargets) == 0 {
			return false
		}
		for _, t := range eqTargets {
			if t == id {
				return true
			}
		}
		return false
	}

	n.Unlock()

	ppResponses := make([]*pb.PrePrepareMessageResponse, 0, len(targetPeers)+1)
	n.AddMessageLog("PREPREPARE", "sent", ppMajor.SequenceNumber, n.ID, n.ID, ppMajor.ViewNumber)
	if resp, _ := s.SendPrePrepare(context.Background(), ppMajor); resp != nil {
		if resp.Status == string(node.StatusPrePrepared) {
			ppResponses = append(ppResponses, resp)
		}
	}

	isTimeAttack, _ := s.HasAttack(string(common.TimeAttack))
	if isTimeAttack {
		time.Sleep(1 * time.Millisecond)
	}

	{
		var wg sync.WaitGroup
		responses := make(chan *pb.PrePrepareMessageResponse, len(targetPeers))
		for pid, addr := range targetPeers {
			if isDarkAttack, darkAttackNodes := s.HasAttack(string(common.DarkAttack)); isDarkAttack &&
				IsNodePresentInAttackNodes(darkAttackNodes, pid) {
				//log.Printf("[Node %d] in-dark: Not sending pre-prepare to n%d",
				//	s.Node.ID, pid)
				continue
			}

			prePrepareRequest := ppMajor
			if isVictim(pid) {
				//log.Printf("Equivocation attack:: Sending wrong preprepare request to node %d", pid)
				prePrepareRequest = ppVictim
			}

			wg.Add(1)
			go func(peerID int32, peerAddr string, m *pb.PrePrepareMessageRequest) {
				defer wg.Done()
				conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					//log.Printf("[Leader %d] SendPrePrepare dial %s failed: %v", s.Node.ID, peerAddr, err)
					return
				}
				defer conn.Close()

				follower := pb.NewPBFTReplicaClient(conn)
				cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				n.AddMessageLog("PREPREPARE", "sent", m.SequenceNumber, n.ID, peerID, m.ViewNumber)
				resp, err := follower.SendPrePrepare(cctx, m)
				if resp.GetStatus() == string(node.StatusPrePrepared) {
					n.AddMessageLog("PREPREPARED", "received", m.GetSequenceNumber(), peerID, n.ID, m.ViewNumber)
				}
				if err != nil {
					//log.Printf("[Leader %d] SendPrePrepare->n%d error: %v", s.Node.ID, peerID, err)
					return
				}
				responses <- resp
			}(pid, addr, prePrepareRequest)
		}
		wg.Wait()
		close(responses)
		for r := range responses {
			ppResponses = append(ppResponses, r)
		}
	}
	//log.Printf("[Leader %d] PRE-PREPARE collected %d/%d follower acks (plus local)",
	//	s.Node.ID, len(ppResponses)-1, len(targetPeers))

	n.Lock()
	prepReq := &pb.PrepareMessageRequest{
		PrePreparedMessageResponse: ppResponses,
		ReplicaId:                  s.Node.ID,
		SequenceNumber:             majSeq,
	}
	bytes = GenerateBytesForSign(majSeq, digest)

	if isSignAttack, _ := s.HasAttack(string(common.SignAttack)); isSignAttack {
		//log.Printf("node %d: Signing invalid sign for sending Pre-PrePare message", s.Node.ID)
		prepReq.Signature = crypto.SignInvalidTamper(n.PrivKey, bytes)
	} else {
		prepReq.Signature = s.Node.Sign(bytes)
	}
	n.Unlock()

	prepResponses := make([]*pb.PrepareMessageResponse, 0, len(targetPeers)+1)

	if isTimeAttack {
		time.Sleep(1 * time.Millisecond)
	}

	n.AddMessageLog("PREPARE", "sent", prepReq.GetSequenceNumber(), n.ID, n.ID, s.Node.ViewNumber)
	if resp, _ := s.SendPrepare(context.Background(), prepReq); resp != nil {
		if resp.Status == string(node.StatusPrepared) {
			prepResponses = append(prepResponses, resp)
		}
	}
	{
		var wg sync.WaitGroup
		responses := make(chan *pb.PrepareMessageResponse, len(targetPeers))
		for pid, addr := range targetPeers {
			if isDarkAttack, darkAttackNodes := s.HasAttack(string(common.DarkAttack)); isDarkAttack &&
				IsNodePresentInAttackNodes(darkAttackNodes, pid) {
				//log.Printf("[Node %d] in-dark: Not sending prepare to n%d",
				//	s.Node.ID, pid)
				continue
			}
			wg.Add(1)
			go func(peerID int32, peerAddr string) {
				defer wg.Done()
				conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					//log.Printf("[Leader %d] SendPrepare dial %s failed: %v", s.Node.ID, peerAddr, err)
					return
				}
				defer conn.Close()

				replica := pb.NewPBFTReplicaClient(conn)
				cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				n.AddMessageLog("PREPARE", "sent", prepReq.GetSequenceNumber(), n.ID, peerID, s.Node.ViewNumber)
				resp, err := replica.SendPrepare(cctx, prepReq)
				if err != nil {
					//log.Printf("[Leader %d] SendPrepare->n%d error: %v", s.Node.ID, peerID, err)
					return
				}
				if resp.GetStatus() == string(node.StatusPrepared) {
					n.AddMessageLog("PREPARED", "received", prepReq.GetSequenceNumber(), peerID, n.ID, resp.GetViewNumber())
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
	//log.Printf("[Leader %d] PREPARE collected %d/%d follower acks (plus local)",
	//	s.Node.ID, len(prepResponses), len(targetPeers))

	if len(prepResponses) <= 2*F {
		//log.Printf("Not enough Prepared found to go to commit")
		return nil, nil
	}
	n.Lock()
	commitReq := &pb.CommitMessageRequest{
		PreparedMessageResponse: prepResponses,
		ReplicaId:               s.Node.ID,
		SequenceNumber:          majSeq,
	}
	bytes = GenerateBytesForSign(majSeq, digest)

	if isSignAttack, _ := s.HasAttack(string(common.SignAttack)); isSignAttack {
		//log.Printf("node %d: Signing invalid sign for sending Pre-PrePare message", s.Node.ID)
		commitReq.Signature = crypto.SignInvalidTamper(n.PrivKey, bytes)
	} else {
		commitReq.Signature = s.Node.Sign(bytes)
	}

	n.Unlock()

	if isTimeAttack {
		time.Sleep(1 * time.Millisecond)
	}

	//if _, err := s.SendCommit(context.Background(), commitReq); err != nil {
	//	log.Printf("[Leader %d] local SendCommit error: %v", s.Node.ID, err)
	//}

	s.SendCommit(context.Background(), commitReq)

	{
		var wg sync.WaitGroup
		for pid, addr := range targetPeers {
			if isDarkAttack, darkAttackNodes := s.HasAttack(string(common.DarkAttack)); isDarkAttack &&
				IsNodePresentInAttackNodes(darkAttackNodes, pid) {
				//log.Printf("[Node %d] in-dark: Not sending commit to n%d",
				//	s.Node.ID, pid)
				continue
			}

			wg.Add(1)
			go func(peerID int32, peerAddr string) {
				defer wg.Done()
				conn, err := grpc.Dial(peerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					//log.Printf("[Leader %d] SendCommit dial %s failed: %v", s.Node.ID, peerAddr, err)
					return
				}
				defer conn.Close()

				replica := pb.NewPBFTReplicaClient(conn)
				cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				n.AddMessageLog("COMMIT", "send", commitReq.GetSequenceNumber(), n.ID, peerID, n.ViewNumber)
				if _, err := replica.SendCommit(cctx, commitReq); err != nil {
					//log.Printf("[Leader %d] SendCommit->n%d error: %v", s.Node.ID, peerID, err)
					return
				}
			}(pid, addr)
		}
		wg.Wait()
	}
	//log.Printf("[Leader %d] ✅ Commit phase dispatched for t=%d (v=%d, n=%d, digest=%s). Execution will be reported via client callback.",
	//	s.Node.ID, tx.GetTime(), view, majSeq, digest[:8])

	return nil, nil
}

func (s *NodeServer) SendPrePrepare(ctx context.Context, req *pb.PrePrepareMessageRequest) (*pb.PrePrepareMessageResponse, error) {
	n := s.Node

	if !n.IsAlive {
		//log.Printf("Node is not alive")
		return nil, status.Error(codes.Aborted, "Node is not alive")
	}

	isCrashAttack, _ := s.HasAttack(string(common.CrashAttack))
	if isCrashAttack {
		//log.Printf("[Node %d] Simulating crash attack — No response sent for SendPrePrepare", s.Node.ID)
		return nil, fmt.Errorf("node %d is simulating a crash attack and cannot respond to SendPrePrepare request", s.Node.ID)
	}

	//log.Printf("Calling ResetNodeTimer from sendPrePrepare func")
	n.ResetNodeTimer()

	n.Lock()

	n.AddMessageLog("PREPREPARE", "received", req.SequenceNumber, req.ReplicaId, n.ID, req.ViewNumber)

	if req.ViewNumber != n.ViewNumber {
		//log.Printf("[Node %d] Reject PrePrepare: wrong view (got=%d, cur=%d)", n.ID, req.ViewNumber, n.ViewNumber)
		n.Unlock()
		return &pb.PrePrepareMessageResponse{
			ViewNumber:     req.ViewNumber,
			SequenceNumber: req.SequenceNumber,
			Digest:         req.Digest,
			ReplicaId:      n.ID,
			Signature:      nil,
			Status:         string(node.StatusWrongView),
		}, nil
	}

	if existing, ok := n.LogEntries[req.SequenceNumber]; ok {
		if existing.ViewNumber == req.ViewNumber && existing.Digest != req.Digest {
			//log.Printf("[Node %d] Reject PrePrepare: conflicting digest for (v=%d, n=%d) (have=%s, got=%s)",
			//	n.ID, req.ViewNumber, req.SequenceNumber, existing.Digest, req.Digest)
			n.Unlock()
			return &pb.PrePrepareMessageResponse{
				ViewNumber:     req.ViewNumber,
				SequenceNumber: req.SequenceNumber,
				Digest:         req.Digest,
				ReplicaId:      n.ID,
				Status:         string(node.StatusConflictingDigest),
			}, nil
		}
	}

	prepBytes := GenerateBytesForSign(req.SequenceNumber, req.Digest)
	if ok := n.VerifyReplicaSig(req.ReplicaId, prepBytes, req.Signature); !ok {
		//log.Printf("[Node %d] Reject PrePrepare: invalid leader signature from %d", n.ID, req.ReplicaId)
		n.Unlock()
		return &pb.PrePrepareMessageResponse{
			ViewNumber:     req.ViewNumber,
			SequenceNumber: req.SequenceNumber,
			Digest:         req.Digest,
			ReplicaId:      n.ID,
			Status:         string(node.StatusInvalidLeaderSignature),
		}, nil
	}

	if req.Transaction == nil {
		//log.Printf("[Node %d] Reject PrePrepare: nil transaction", n.ID)
		n.Unlock()
		return &pb.PrePrepareMessageResponse{
			ViewNumber:     req.ViewNumber,
			SequenceNumber: req.SequenceNumber,
			Digest:         req.Digest,
			ReplicaId:      n.ID,
			Status:         string(node.StatusNilTransaction),
		}, nil
	}

	expectedDigest := s.TxDigest(req.Transaction)
	if expectedDigest != req.Digest {
		//log.Printf("[Node %d] Reject PrePrepare: digest mismatch (expected=%s, got=%s)",
		//	n.ID, expectedDigest, req.Digest)
		n.Unlock()
		return &pb.PrePrepareMessageResponse{
			ViewNumber:     req.ViewNumber,
			SequenceNumber: req.SequenceNumber,
			Digest:         req.Digest,
			ReplicaId:      n.ID,
			Status:         string(node.StatusBadDigest),
		}, nil
	}

	n.LogEntries[req.SequenceNumber] = &node.LogEntry{
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
	n.Unlock()

	//log.Printf("[Node %d] Accepted PrePrepare (v=%d, n=%d, d=%s) from leader %d -> PRE-PREPARED",
	//	n.ID, req.ViewNumber, req.SequenceNumber, req.Digest, req.ReplicaId)

	resp := &pb.PrePrepareMessageResponse{
		ViewNumber:     req.ViewNumber,
		SequenceNumber: req.SequenceNumber,
		Digest:         req.Digest,
		ReplicaId:      n.ID,
		Status:         string(node.StatusPrePrepared),
	}
	bytes := GenerateBytesForSign(resp.SequenceNumber, resp.Digest)

	if isSignAttack, _ := s.HasAttack(string(common.SignAttack)); isSignAttack {
		//log.Printf("Signing invalid sign for node %d in SendPrePrepare", s.Node.ID)
		resp.Signature = crypto.SignInvalidTamper(n.PrivKey, bytes)
	} else {
		resp.Signature = n.Sign(bytes)
	}

	if isDarkAttack, darkAttackNodes := s.HasAttack(string(common.DarkAttack)); isDarkAttack &&
		IsNodePresentInAttackNodes(darkAttackNodes, req.ReplicaId) {
		//log.Printf("[Node %d] in-dark: dropping PrePrepare reply to n%d (v=%d,n=%d,d=%s)",
		//	s.Node.ID, req.ReplicaId, resp.ViewNumber, resp.SequenceNumber, resp.Digest[:8])
		return nil, status.Error(codes.Unavailable, "in-dark: simulated drop")
	}

	n.AddMessageLog("PREPREPARED", "sent", resp.SequenceNumber, n.ID, req.ReplicaId, resp.ViewNumber)

	return resp, nil
}

func (s *NodeServer) SendPrepare(ctx context.Context, req *pb.PrepareMessageRequest) (*pb.PrepareMessageResponse, error) {
	n := s.Node

	if !n.IsAlive {
		return nil, status.Error(codes.Aborted, "Node is not alive")
	}

	isCrashAttack, _ := s.HasAttack(string(common.CrashAttack))
	if isCrashAttack {
		//log.Printf("[Node %d] Simulating crash attack — No response sent for SendPrepare", s.Node.ID)
		return nil, fmt.Errorf("node %d is simulating a crash attack and cannot respond to SendPrepare request", s.Node.ID)
	}

	//log.Printf("Calling ResetNodeTimer from SendPrepare func")
	//n.ResetNodeTimer()

	n.Lock()

	if len(req.PrePreparedMessageResponse) == 0 {
		n.Unlock()
		return &pb.PrepareMessageResponse{
			Status: "REJECTED_EMPTY_PROOFS",
		}, nil
	}

	entry, ok := n.LogEntries[req.GetSequenceNumber()]
	if !ok {
		n.Unlock()
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
	n.AddMessageLog("PREPARE", "received", req.GetSequenceNumber(), req.ReplicaId, n.ID, currentViewNumber)

	if entry.Status != node.StatusPrePrepared {
		n.Unlock()
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
		if !crypto.VerifyNodeSignatureBasedOnSequenceNumberAndDigest(
			pp.ReplicaId, pp.GetSequenceNumber(), pp.GetDigest(), pp.GetSignature(), s.Node.PubKeysOfNodes) {
			//log.Printf("Invalid signature in SendPrepare found for node-%d", pp.ReplicaId)
			continue
		}

		if pp.ViewNumber != currentViewNumber || pp.SequenceNumber != currentSequenceNumber ||
			pp.Digest != currentDigest || pp.Status != string(node.StatusPrePrepared) {
			continue
		}

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

	//log.Printf("validBackupCount: %d for sequence number: %d", validBackupCount, req.GetSequenceNumber())
	if validBackupCount < 2*F+1 {
		n.Unlock()
		//log.Printf("No quorum reached for PREPARED (i.e., no atleast 4 pre-prepared acks) for sequence_num=%d", currentSequenceNumber)
		return &pb.PrepareMessageResponse{
			ViewNumber:     currentViewNumber,
			SequenceNumber: currentSequenceNumber,
			Digest:         currentDigest,
			ReplicaId:      n.ID,
			Status:         string(node.StatusNotEnoughPrePrepared),
		}, nil
	}

	//for _, logEntry := range s.Node.LogEntries {
	//	log.Printf("Seq_No: %d,  Status: %s, View_no: %d", logEntry.SequenceNumber, logEntry.Status, logEntry.ViewNumber)
	//}
	for _, logEntry := range s.Node.LogEntries {
		existingDigest := logEntry.Digest
		if existingDigest == currentDigest && isValidStatus(logEntry.Status) {
			n.Unlock()
			//log.Printf("Already message is prepared: Duplicacy found")
			return nil, nil
		}
	}

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

	n.Unlock()

	bytes := GenerateBytesForSign(resp.SequenceNumber, resp.Digest)
	isSignAttack, _ := s.HasAttack(string(common.SignAttack))
	if isSignAttack {
		//log.Printf("Signing invalid sign for node %d in SendPrepare", s.Node.ID)
		resp.Signature = crypto.SignInvalidTamper(n.PrivKey, bytes)
	} else {
		resp.Signature = n.Sign(bytes)
	}

	isDarkAttack, darkAttackNodes := s.HasAttack(string(common.DarkAttack))
	if isDarkAttack && IsNodePresentInAttackNodes(darkAttackNodes, req.ReplicaId) {
		//log.Printf("[Node %d] in-dark: dropping Prepare reply to n%d (v=%d,n=%d,d=%s)",
		//	s.Node.ID, req.ReplicaId, resp.ViewNumber, resp.SequenceNumber, resp.Digest[:8])
		return nil, status.Error(codes.Unavailable, "in-dark: simulated drop")
	}

	//log.Printf("[Node %d] Updated to PREPARED (sequence_no=%d) -> PREPARED", n.ID, req.GetSequenceNumber())

	n.AddMessageLog("PREPARED", "sent", resp.SequenceNumber, n.ID, req.ReplicaId, resp.ViewNumber)

	return resp, nil
}

func (s *NodeServer) SendCommit(ctx context.Context, req *pb.CommitMessageRequest) (*pb.CommitMessageResponse, error) {
	n := s.Node

	if !n.IsAlive {
		//log.Printf("Node is not alive")
		return nil, status.Error(codes.Aborted, "Node is not alive")
	}

	isCrashAttack, _ := s.HasAttack(string(common.CrashAttack))
	if isCrashAttack {
		//log.Printf("[Node %d]  Simulating crash attack — No response sent for SendCommit", s.Node.ID)
		return nil, fmt.Errorf("node %d is simulating a crash attack and cannot respond to SendCommit request", s.Node.ID)
	}

	//log.Printf("Calling ResetNodeTimer from SendCommit func")
	//n.ResetNodeTimer()

	n.Lock()

	if len(req.PreparedMessageResponse) == 0 {
		n.Unlock()
		return &pb.CommitMessageResponse{
			Status: "REJECTED_EMPTY_PROOFS",
		}, nil
	}

	for _, logEntry := range s.Node.LogEntries {
		if logEntry.SequenceNumber == req.SequenceNumber {
			continue
		}
		existingDigest := logEntry.Digest
		currentLogEntry := s.Node.LogEntries[req.SequenceNumber]
		if currentLogEntry == nil {
			continue
		}
		currentDigest := currentLogEntry.Digest

		if existingDigest == currentDigest && isValidStatusForCommitted(logEntry.Status) {
			n.Unlock()
			//log.Printf("Already message is in valid state so no committing again: Duplicacy found")
			return nil, nil
		}
	}

	entry, ok := n.LogEntries[req.GetSequenceNumber()]
	seq := req.GetSequenceNumber()
	if !ok {
		n.Unlock()
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
	n.AddMessageLog("COMMIT", "received", req.GetSequenceNumber(), req.ReplicaId, n.ID, currentViewNumber)

	if entry.Status != node.StatusPrepared {
		n.Unlock()
		return &pb.CommitMessageResponse{
			ViewNumber:     currentViewNumber,
			SequenceNumber: currentSequenceNumber,
			Digest:         currentDigest,
			ReplicaId:      n.ID,
			Status:         "REJECTED_NOT_PREPARED",
		}, nil
	}

	seen := map[int32]bool{}
	validPreparedCount := 0
	proofs := make(map[int32]*node.StatusProof)

	for _, pmr := range req.PreparedMessageResponse {
		if !crypto.VerifyNodeSignatureBasedOnSequenceNumberAndDigest(
			pmr.GetReplicaId(),
			pmr.GetSequenceNumber(),
			pmr.GetDigest(),
			pmr.GetSignature(),
			s.Node.PubKeysOfNodes,
		) {
			//log.Printf("Invalid signature in SendCommit found for node-%d", pmr.ReplicaId)
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

	//log.Printf("ValidPreparedCount: %d for sequence number: %d", validPreparedCount, req.GetSequenceNumber())
	if validPreparedCount < (2*F + 1) {
		n.Unlock()
		//log.Printf("No quorum reached for COMMIT (i.e., no atleast 5 prepared acks) for viewnumber=%d", currentViewNumber)
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

	bytes := GenerateBytesForSign(resp.SequenceNumber, resp.Digest)
	isSignAttack, _ := s.HasAttack(string(common.SignAttack))
	if isSignAttack {
		//log.Printf("Signing invalid sign for node %d in SendPrePrepare", s.Node.ID)
		resp.Signature = crypto.SignInvalidTamper(n.PrivKey, bytes)
	} else {
		resp.Signature = n.Sign(bytes)
	}
	//log.Printf("[Node %d] Updated to COMMITTED (sequence_no=%d)",
	//	n.ID, req.GetSequenceNumber())

	n.AddMessageLog("COMMITTED", "sent", resp.SequenceNumber, n.ID, req.ReplicaId, resp.ViewNumber)

	n.Unlock()
	s.executeInOrder()

	isDarkAttack, darkAttackNodes := s.HasAttack(string(common.DarkAttack))
	if isDarkAttack && IsNodePresentInAttackNodes(darkAttackNodes, req.ReplicaId) {
		//log.Printf("[Node %d] in-dark: dropping Commit reply to n%d (v=%d,n=%d,d=%s)",
		//	s.Node.ID, req.ReplicaId, resp.ViewNumber, resp.SequenceNumber, resp.Digest[:8])
		return nil, status.Error(codes.Unavailable, "in-dark: simulated drop")
	}

	return resp, nil
}

func (s *NodeServer) ReadClientBalance(ctx context.Context, req *pb.ReadClientBalanceRequest) (*pb.ReadClientBalanceResponse, error) {
	if !s.Node.IsAlive {
		return nil, status.Error(codes.Aborted, "Node is not alive")
	}

	isCrashAttack, _ := s.HasAttack(string(common.CrashAttack))
	if isCrashAttack {
		//log.Printf("[Node %d]  Simulating crash attack — No response sent for ReadClientBalance", s.Node.ID)
		return nil, fmt.Errorf("node %d is simulating a crash attack and cannot respond to ReadClientBalance request", s.Node.ID)
	}

	clientID := req.GetClientId()

	if !crypto.VerifyClientSignatureForReadRequest(clientID, req.GetSignature(), s.Node.PubKeysOfClients) {
		return nil, status.Errorf(codes.PermissionDenied, "invalid read signature for client %s", clientID)
	}

	s.Node.Lock()
	bal := s.Node.Balances[clientID]
	s.Node.AddMessageLog("READ", "received", -1, s.Node.ID, -1, -1)
	s.Node.Unlock()

	resp := &pb.ReadClientBalanceResponse{
		Balance: bal,
	}

	bytes := crypto.GenerateBytesForSigningReadResponse(s.Node.ID)
	isSignAttack, _ := s.HasAttack(string(common.SignAttack))
	if isSignAttack {
		resp.Signature = crypto.SignInvalidTamper(s.Node.PrivKey, bytes)
	} else {
		resp.Signature = s.Node.Sign(bytes)
	}

	s.Node.AddMessageLog("READ", "sent", -1, s.Node.ID, -1, s.Node.ViewNumber)

	return resp, nil
}

func (s *NodeServer) FlushPreviousDataAndUpdatePeersStatus(ctx context.Context, req *pb.FlushAndUpdateStatusRequest) (*emptypb.Empty, error) {
	s.Node.ResetForNewSetAndUpdateNodeStatus(req)
	//log.Printf("[Node %d] Flushed state for new set. updated live nodes: %v", s.Node.ID, req.GetLiveNodes())
	return &emptypb.Empty{}, nil
}

//--------------------------- VIEW CHANGE / NEW VIEW -------------------------

func (s *NodeServer) SendViewChange(ctx context.Context, msg *pb.ViewChangeMessage) (*emptypb.Empty, error) {
	n := s.Node

	if !n.IsAlive {
		//log.Printf("[Node %d] Ignoring view-change from n%d: not alive", n.ID, msg.NodeId)
		return nil, status.Error(codes.Aborted, "Node is not alive")
	}

	isCrashAttack, _ := s.HasAttack(string(common.CrashAttack))
	if isCrashAttack {
		//log.Printf("[Node %d] Simulating crash attack — No response sent for SendViewChange", s.Node.ID)
		return nil, fmt.Errorf("node %d is simulating a crash attack and cannot respond to SendViewChange request", s.Node.ID)
	}

	if msg.NewViewNumber <= n.ViewNumber {
		//log.Printf("[Node %d] Ignoring outdated view-change from n%d (new_view=%d, current=%d)",
		//	n.ID, msg.NodeId, msg.NewViewNumber, n.ViewNumber)
		return nil, nil
	}

	if !n.VerifyReplicaSig(msg.NodeId, crypto.GenerateBytesForViewChangeMessage(msg.NodeId), msg.Signature) {
		//log.Printf("[Node %d] Invalid signature on view-change from n%d", n.ID, msg.NodeId)
		return &emptypb.Empty{}, nil
	}

	n.Lock()
	n.AddMessageLog("VIEW-CHANGE", "received", -1, msg.NodeId, n.ID, msg.NewViewNumber)
	//log.Printf("SendViewChange: Recievied %d prepared messages from node-%d", len(msg.GetPreparedProofSet()), n.ID)
	if _, ok := n.ViewChangeMessages[msg.NewViewNumber]; !ok {
		n.ViewChangeMessages[msg.NewViewNumber] = []*pb.ViewChangeMessage{}
	}

	alreadyExists := false
	for _, existing := range n.ViewChangeMessages[msg.NewViewNumber] {
		if existing.NodeId == msg.NodeId {
			alreadyExists = true
			break
		}
	}
	if !alreadyExists {
		n.ViewChangeMessages[msg.NewViewNumber] = append(n.ViewChangeMessages[msg.NewViewNumber], msg)
		//log.Printf("[Node %d] Received VIEW-CHANGE for view=%d from n%d number_of_view_change_msgs_recievied = (%d)",
		//	n.ID, msg.NewViewNumber, msg.NodeId, len(n.ViewChangeMessages[msg.NewViewNumber]))
	}

	msgs := n.ViewChangeMessages[msg.NewViewNumber]
	quorumSizeForTriggeringNewViewMsg := quorumSizeForTriggeringNewViewMessage()
	isNodeLeaderForNewView := isLeaderForNewView(n.ID, msg.NewViewNumber, int32(len(n.Peers)))
	n.Unlock()

	if len(msgs) >= quorumSizeForTriggeringNewViewMsg && isNodeLeaderForNewView {
		//log.Printf("[Node %d] Quorum (2f+1=%d) view-change messages for v=%d reached and I am new primary → initiating NEW-VIEW",
		//	n.ID, len(msgs), msg.NewViewNumber)
		err := n.InitiateNewView(ctx, msg.NewViewNumber, msgs)
		if err != nil {
			return nil, err
		}
		return &emptypb.Empty{}, nil
	}

	n.Lock()
	quorumSizeForTriggeringViewChange := quorumSizeForTriggeringViewChangeMessage()
	if len(n.ViewChangeMessages[msg.NewViewNumber]) >= quorumSizeForTriggeringViewChange {
		if !n.TriggeredViewChange[msg.NewViewNumber] {
			//log.Printf("[Node %d] Quorum for view-change v=%d reached (%d msgs) → initiating own view-change",
			//	n.ID, msg.NewViewNumber, len(n.ViewChangeMessages[msg.NewViewNumber]))
			n.TriggeredViewChange[msg.NewViewNumber] = true
			n.Unlock()
			go n.InitiateViewChange()
			return &emptypb.Empty{}, nil
		}
	}
	n.Unlock()

	return &emptypb.Empty{}, nil
}

func (s *NodeServer) SendNewView(ctx context.Context, msg *pb.NewViewMessage) (*emptypb.Empty, error) {
	n := s.Node

	//log.Printf("Recievied New View Message from NodeID: %d with new_view_number: %d", msg.GetSourceId(), msg.GetNewViewNumber())
	if !n.IsAlive {
		//log.Printf("[Node %d] Ignoring NEW-VIEW from n%d: not alive", n.ID, msg.SourceId)
		return nil, status.Error(codes.Aborted, "Node is not alive")
	}

	isCrashAttack, _ := s.HasAttack(string(common.CrashAttack))
	if isCrashAttack {
		//log.Printf("[Node %d] Simulating crash attack — No response sent for SendNewView", s.Node.ID)
		return nil, fmt.Errorf("node %d is simulating a crash attack and cannot respond to SendNewView request", s.Node.ID)
	}

	n.AddMessageLog("NEW-VIEW", "received", -1, msg.GetSourceId(), s.Node.ID, msg.GetNewViewNumber())

	if !n.VerifyReplicaSig(msg.SourceId, crypto.GenerateBytesOnlyForNodeID(msg.SourceId), msg.Signature) {
		//log.Printf("[Node %d] Invalid signature on NEW-VIEW from n%d", n.ID, msg.SourceId)
		return &emptypb.Empty{}, nil
	}

	if msg.NewViewNumber <= n.ViewNumber {
		//log.Printf("[Node %d]  Ignoring NEW-VIEW with view=%d <= current=%d", n.ID, msg.NewViewNumber, n.ViewNumber)
		return &emptypb.Empty{}, nil
	}

	s.performActionsAfterNewViewIsRecievied(msg.NewViewNumber)
	//log.Printf("[Node %d] Accepted NEW-VIEW v=%d from n%d", n.ID, msg.NewViewNumber, msg.SourceId)

	n.Lock()
	n.AllNewViewMessagesForPrinting[msg.GetNewViewNumber()] = msg
	n.Unlock()

	constructedOSet := s.Node.ConstructOSet(msg.NewViewNumber, msg.ViewChanges)
	oSetFromLeader := msg.GetPrePrepares()
	verifyOSetFromLeader(constructedOSet, oSetFromLeader)

	if len(msg.PrePrepares) == 0 {
		for _, entry := range s.Node.LogEntries {
			entry.Digest = node.NullDigest
		}
	} else {
		for _, pre := range msg.PrePrepares {
			n.Lock()
			digest := pre.Digest
			seq := pre.SequenceNumber
			view := msg.NewViewNumber
			transaction := pre.GetTransaction()

			s.addToLogRecordsForSendNewView(seq, msg, view)

			if existing, ok := n.LogEntries[pre.SequenceNumber]; ok && existing != nil {
				if existing.Status == node.StatusExecuted {
					if !(s.Node.Cp && existing.SequenceNumber > s.Node.LastCheckpointedSequenceNumber) {
						existing.ViewNumber = view
					}
					n.Unlock()
					continue
				}
			}

			entry := &node.LogEntry{
				Digest:         digest,
				SequenceNumber: seq,
				ViewNumber:     view,
				Status:         node.StatusCommitted,
				PreparedProof:  make(map[int32][]*node.StatusProof),
				CommittedProof: make(map[int32][]*node.StatusProof),
			}
			if transaction != nil {
				entry.Transaction = &node.Transaction{
					FromClientID: transaction.FromClientId,
					ToClientID:   transaction.ToClientId,
					Amount:       transaction.Amount,
					Time:         transaction.Time,
				}
			}
			n.LogEntries[seq] = entry
			n.Unlock()
		}
	}

	s.executeInOrder()

	return &emptypb.Empty{}, nil
}

// -----------------------BONUS----------------------------------------

func (s *NodeServer) SendCheckPointMessage(ctx context.Context, req *pb.CheckpointMessageRequest) (*pb.CheckpointMessageResponse, error) {
	n := s.Node

	if !n.VerifyReplicaSig(req.GetReplicaId(), crypto.GenerateBytesOnlyForNodeID(req.GetReplicaId()), req.Signature) {
		//log.Printf("[Node %d] Invalid signature on Node from n%d", n.ID, req.GetReplicaId())
		return nil, nil
	}

	n.Lock()
	defer n.Unlock()

	n.AddMessageLog("CHECKPOINT", "received", req.GetSequenceNumber(), req.GetReplicaId(), n.ID, n.ViewNumber)

	seq := req.GetSequenceNumber()

	if seq <= n.LastCheckpointedSequenceNumber {
		//log.Printf("[Node %d] Checkpoint for seq=%d already completed", n.ID, seq)
		return &pb.CheckpointMessageResponse{}, nil
	}

	if n.CheckpointProofs[seq] == nil {
		n.CheckpointProofs[seq] = []*pb.CheckpointMessageRequest{}
	}

	for _, proof := range n.CheckpointProofs[seq] {
		if proof.ReplicaId == req.ReplicaId {
			return nil, nil
		}
	}

	n.CheckpointProofs[seq] = append(n.CheckpointProofs[seq], req)
	//log.Printf("[Node %d] Received checkpoint from n%d for seq=%d (%d total)",
	//	n.ID, req.ReplicaId, seq, len(n.CheckpointProofs[seq]))

	digestCounts := make(map[string]int)
	for _, proof := range n.CheckpointProofs[seq] {
		digestCounts[proof.Digest]++
	}

	for _, count := range digestCounts {
		if count >= 2*F+1 {
			n.LastCheckpointedSequenceNumber = seq
			n.AddMessageLog("CHECKPOINTED_SEQ_NO", "updated", req.GetSequenceNumber(), n.ID, n.ID, n.ViewNumber)
			//log.Printf("[Node %d] CHECKPOINT COMPLETE for seq=%d with digest=%s", n.ID, seq, d)
			break
		}
	}

	return &pb.CheckpointMessageResponse{}, nil
}

//--------------------CLIENT FUNCNS-----------------------------

func (s *NodeServer) PrintDB(ctx context.Context, _ *emptypb.Empty) (*pb.PrintDBResponse, error) {
	n := s.Node
	n.Lock()
	defer n.Unlock()

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

	fmt.Println("===========================================")
	fmt.Printf("Node %d State:\n", n.ID)
	fmt.Printf("  Current ViewNumber       : %d\n", n.ViewNumber)
	fmt.Printf("  LastExecutedSequenceNumber: %d\n", n.LastExecutedSequenceNumber)
	fmt.Println("===========================================")

	fmt.Println("Log:")
	if len(entries) == 0 {
		fmt.Println("  (empty)")
	} else {
		for _, le := range entries {
			if le.Transaction != nil {
				fmt.Printf("  n=%d v=%d status=%s  tx=(%s→%s a=%d t=%d) \n",
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

func (s *NodeServer) PrintStatus(ctx context.Context, req *pb.PrintStatusRequest) (*pb.PrintStatusResponse, error) {
	n := s.Node
	n.Lock()
	defer n.Unlock()

	seq := req.GetSequenceNumber()
	entry, ok := n.LogEntries[seq]

	if !ok || entry == nil {
		return &pb.PrintStatusResponse{
			NodeId:         n.ID,
			SequenceNumber: seq,
			Status:         "X",
			Transaction:    nil,
		}, nil
	}

	statusMap := map[node.Status]string{
		node.StatusPrePrepared: "PP",
		node.StatusPrepared:    "P",
		node.StatusCommitted:   "C",
		node.StatusExecuted:    "E",
	}

	shortStatus, ok := statusMap[entry.Status]
	if !ok {
		shortStatus = "X"
	}

	resp := &pb.PrintStatusResponse{
		NodeId:         n.ID,
		SequenceNumber: entry.SequenceNumber,
		Status:         shortStatus,
	}

	if entry.Transaction != nil {
		resp.Transaction = &pb.Transaction{
			FromClientId: entry.Transaction.FromClientID,
			ToClientId:   entry.Transaction.ToClientID,
			Amount:       entry.Transaction.Amount,
			Time:         entry.Transaction.Time,
		}
	}

	return resp, nil
}

func (s *NodeServer) PrintView(ctx context.Context, req *pb.PrintViewRequest) (*pb.PrintViewResponse, error) {
	n := s.Node
	n.Lock()
	defer n.Unlock()

	resp := &pb.PrintViewResponse{
		NewViewNumberToNewViewMessageMap: make(map[int32]*pb.NewViewMessage),
	}

	for newViewNumber, newViewMsg := range n.AllNewViewMessagesForPrinting {
		if newViewMsg == nil {
			continue
		}
		resp.NewViewNumberToNewViewMessageMap[newViewNumber] = newViewMsg
	}

	return resp, nil
}

func (s *NodeServer) PrintLog(ctx context.Context, req *pb.PrintLogRequest) (*pb.PrintLogResponse, error) {
	n := s.Node

	n.Lock()
	defer n.Unlock()

	if len(n.AllMessagesForPrintingLog) == 0 {
		//log.Printf("[Node %d] No message logs available to print", n.ID)
		return &pb.PrintLogResponse{
			PrintLogEntries: []*pb.PrintLogEntry{},
		}, nil
	}
	sort.Slice(n.AllMessagesForPrintingLog, func(i, j int) bool {
		return n.AllMessagesForPrintingLog[i].Timestamp.Before(n.AllMessagesForPrintingLog[j].Timestamp)
	})

	printEntries := make([]*pb.PrintLogEntry, 0, len(n.AllMessagesForPrintingLog))

	for _, logEntry := range n.AllMessagesForPrintingLog {
		printEntries = append(printEntries, &pb.PrintLogEntry{
			MessageType: logEntry.MessageType,
			SequenceNum: logEntry.SequenceNum,
			FromNodeId:  logEntry.FromNodeID,
			ToNodeId:    logEntry.ToNodeID,
			Direction:   logEntry.Direction,
			ViewNumber:  logEntry.ViewNumber,
			Timestamp:   timestamppb.New(logEntry.Timestamp),
		})
	}

	return &pb.PrintLogResponse{
		PrintLogEntries: printEntries,
	}, nil
}

func (s *NodeServer) PrintLogEntries(ctx context.Context, req *pb.PrintLogRequest) (*pb.PrintLogEntriesResponse, error) {
	n := s.Node

	n.Lock()
	defer n.Unlock()

	resp := &pb.PrintLogEntriesResponse{
		LogEntries: make([]*pb.LogEntryMessage, 0),
	}

	for _, entry := range n.LogEntries {
		protoEntry := &pb.LogEntryMessage{
			Digest:         entry.Digest,
			SequenceNumber: entry.SequenceNumber,
			ViewNumber:     entry.ViewNumber,
			Status:         string(entry.Status),
		}

		if entry.Transaction != nil {
			protoEntry.Transaction = &pb.Transaction{
				FromClientId: entry.Transaction.FromClientID,
				ToClientId:   entry.Transaction.ToClientID,
				Amount:       entry.Transaction.Amount,
				Time:         entry.Transaction.Time,
			}
		}

		protoEntry.PreparedProof = make(map[int32]*pb.StatusProofList)
		for replicaID, proofs := range entry.PreparedProof {
			list := &pb.StatusProofList{}
			for _, proof := range proofs {
				list.Proofs = append(list.Proofs, &pb.StatusProof{
					Digest:         proof.Digest,
					Signature:      proof.Signature,
					NodeId:         proof.NodeID,
					View:           proof.View,
					SequenceNumber: proof.SequenceNumber,
					Status:         string(proof.Status),
				})
			}
			protoEntry.PreparedProof[replicaID] = list
		}

		protoEntry.CommittedProof = make(map[int32]*pb.StatusProofList)
		for replicaID, proofs := range entry.CommittedProof {
			list := &pb.StatusProofList{}
			for _, proof := range proofs {
				list.Proofs = append(list.Proofs, &pb.StatusProof{
					Digest:         proof.Digest,
					Signature:      proof.Signature,
					NodeId:         proof.NodeID,
					View:           proof.View,
					SequenceNumber: proof.SequenceNumber,
					Status:         string(proof.Status),
				})
			}
			protoEntry.CommittedProof[replicaID] = list
		}
		resp.LogEntries = append(resp.LogEntries, protoEntry)
	}
	resp.CheckPointMessageProofs = toProtoCheckpointProofs(n.CheckpointProofs)
	resp.LastCheckpointedSequenceNumber = n.LastCheckpointedSequenceNumber

	return resp, nil
}
