package node

import (
	"context"
	"fmt"
	"log"
	"pbft-bank-application/common"

	"pbft-bank-application/internal/crypto"
	pb "pbft-bank-application/pbft-bank-application/proto"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	NullDigest = "NULL"
)

func (s *Node) ResetNodeTimer() {
	log.Printf("ResetNodeTimer started at %v", time.Now())
	s.Lock()
	if s.electionTimer != nil {
		s.electionTimer.Stop()
		s.electionTimer = nil
	}
	s.Unlock()

	// +rand.Intn(600)
	timeout := 4000 * time.Millisecond

	s.electionTimer = time.AfterFunc(timeout, func() {
		newViewNumber := s.getNextValidNewViewNumber()
		if s.TriggeredViewChange[newViewNumber] {
			return
		}
		s.TriggeredViewChange[newViewNumber] = true
		s.InitiateViewChange()
	})
}

func (s *Node) InitiateViewChange() {
	s.Lock()

	newViewNumber := s.getNextValidNewViewNumber()
	s.TriggeredViewChange[newViewNumber] = true
	log.Printf("[Node %d] Timer expired → Initiating VIEW CHANGE to view %d", s.ID, newViewNumber)

	var pm []*pb.PreparedProofSet
	log.Printf("InitiateViewChange: Number of entries in logEntries I have is: %d", len(s.LogEntries))
	for seq, le := range s.LogEntries {
		if isValidStateToIncludeInViewChange(le.Status) {
			prepProofs := []*pb.StatusProof{}
			for _, p := range le.PreparedProof[seq] {
				prepProofs = append(prepProofs, &pb.StatusProof{
					NodeId:         p.NodeID,
					Digest:         p.Digest,
					View:           p.View,
					SequenceNumber: p.SequenceNumber,
					Status:         string(p.Status),
					Signature:      p.Signature,
				})
			}
			pmReq := &pb.PreparedProofSet{
				SequenceNumber: seq,
				Digest:         le.Digest,
				ViewNumber:     le.ViewNumber,
				Proofs:         prepProofs,
				Status:         string(le.Status),
			}
			if le.Transaction != nil {
				pmReq.Transaction = &pb.Transaction{
					FromClientId: le.Transaction.FromClientID,
					ToClientId:   le.Transaction.ToClientID,
					Amount:       le.Transaction.Amount,
					Time:         le.Transaction.Time,
				}
				log.Printf("My valid log is: Transaction: (%s->%s (%d) Amnt: %d) SeqNo: %d - Status: %s", le.Transaction.FromClientID, le.Transaction.ToClientID, le.Transaction.Time, le.Transaction.Amount, le.SequenceNumber, le.Status)
			}
			pm = append(pm, pmReq)
		}
	}

	log.Printf("InitiateViewChange: Number of valid logEntries I have is: %d", len(pm))

	vcm := &pb.ViewChangeMessage{
		NewViewNumber:    newViewNumber,
		NodeId:           s.ID,
		PreparedProofSet: pm,
	}

	bytes := crypto.GenerateBytesForViewChangeMessage(s.ID)
	isSignAttack, _ := s.HasAttack(string(common.SignAttack))
	if isSignAttack {
		log.Printf("Signing invalid sign for node %d in InitiateViewChange", s.ID)
		vcm.Signature = crypto.SignInvalidTamper(s.PrivKey, bytes)
	} else {
		vcm.Signature = s.Sign(bytes)
	}

	s.Unlock()

	for peerID, addr := range s.Peers {
		isDarkAttack, darkAttackNodes := s.HasAttack(string(common.DarkAttack))
		if isDarkAttack && common.IsNodePresentInAttackNodes(darkAttackNodes, peerID) {
			log.Printf("[Node %d] 🕳️ in-dark: view change rpc is not sent to n%d ",
				s.ID, peerID)
			continue
		}

		go func(pid int32, paddr string) {
			conn, err := grpc.Dial(paddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				log.Printf("[Node %d] ⚠️ Failed to dial node n%d for view change: %v", s.ID, pid, err)
				return
			}
			defer conn.Close()
			node := pb.NewPBFTReplicaClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_, err = node.SendViewChange(ctx, vcm)
			if err != nil {
				log.Printf("[Node %d] ❌ SendViewChange to n%d failed: %v", s.ID, pid, err)
			}
		}(peerID, addr)
	}
}

func (s *Node) InitiateNewView(newView int32, viewChangeMessages []*pb.ViewChangeMessage) error {
	if newView < s.ViewNumber {
		log.Printf("[Node %d] Ignoring NEW-VIEW for outdated view=%d (current=%d)", s.ID, newView, s.ViewNumber)
		return nil
	}

	isCrashAttack, _ := s.HasAttack(string(common.CrashAttack))
	if isCrashAttack {
		log.Printf("[Node %d] Simulating crash attack — ignoring NEW-VIEW for view=%d", s.ID, newView)
		return fmt.Errorf("node %d is simulating a crash attack and cannot initiate new view", s.ID)
	}

	s.Lock()
	log.Printf("[Node %d] 🆕 Initiating NEW-VIEW v=%d with %d view-change messages", s.ID, newView, len(viewChangeMessages))

	oSet := make([]*pb.PrePrepareMessageRequest, 0)
	maxSeq := int32(0)

	for _, msg := range viewChangeMessages {
		log.Printf("Recievied %d messages from Node-%d for intiating new view", len(msg.GetPreparedProofSet()), msg.NodeId)
		for _, pset := range msg.PreparedProofSet {
			if pset.SequenceNumber > maxSeq {
				maxSeq = pset.SequenceNumber
			}
		}
	}

	log.Printf("IntiateNewView: Max sequence number: %d", maxSeq)

	for seq := int32(1); seq <= maxSeq; seq++ {
		var selectedPset *pb.PreparedProofSet
		var highestView int32 = -1

		for _, msg := range viewChangeMessages {
			for _, pset := range msg.PreparedProofSet {
				if pset.SequenceNumber == seq && pset.ViewNumber > highestView {
					highestView = pset.ViewNumber
					selectedPset = pset
				}
			}
		}

		var digest string
		if selectedPset != nil {
			digest = selectedPset.Digest
		} else {
			digest = NullDigest
		}

		oSet = append(oSet, &pb.PrePrepareMessageRequest{
			ViewNumber:     newView,
			SequenceNumber: seq,
			Digest:         digest,
			ReplicaId:      s.ID,
			Transaction:    selectedPset.GetTransaction(),
			Signature:      s.Sign(crypto.GenerateBytesOnlyForNodeID(s.ID)),
		})
	}

	s.ViewNumber = newView
	log.Printf("[Node %d] ✅ Entered new view v=%d with max sequence=%d", s.ID, s.ViewNumber, maxSeq)

	newViewMsg := &pb.NewViewMessage{
		NewViewNumber: newView,
		SourceId:      s.ID,
		PrePrepares:   oSet,
		ViewChanges:   viewChangeMessages,
	}

	bytes := crypto.GenerateBytesOnlyForNodeID(s.ID)
	isSignAttack, _ := s.HasAttack(string(common.SignAttack))
	if isSignAttack {
		log.Printf("Signing invalid sign for node %d in InitiateViewChange", s.ID)
		newViewMsg.Signature = crypto.SignInvalidTamper(s.PrivKey, bytes)
	} else {
		newViewMsg.Signature = s.Sign(bytes)
	}

	s.Unlock()
	for pid, addr := range s.Peers {
		isDarkAttack, darkAttackNodes := s.HasAttack(string(common.DarkAttack))
		if isDarkAttack && common.IsNodePresentInAttackNodes(darkAttackNodes, pid) {
			log.Printf("[Node %d] 🕳️ in-dark: view change rpc is not sent to n%d ",
				s.ID, pid)
			continue
		}
		go func(id int32, addr string) {
			conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				log.Printf("[Node %d] ❌ Failed to dial peer n%d: %v", s.ID, id, err)
				return
			}
			defer conn.Close()

			node := pb.NewPBFTReplicaClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			s.AddMessageLog("NEW-VIEW", "sent", -1, s.ID, id, newViewMsg.NewViewNumber)
			_, err = node.SendNewView(ctx, newViewMsg)
			if err != nil {
				log.Printf("[Node %d] ❌ SendNewView to n%d failed: %v", s.ID, id, err)
			}
		}(pid, addr)
	}
	return nil
}

func (s *Node) getNextValidNewViewNumber() int32 {
	nextView := s.ViewNumber

	for {
		nextView++
		nextLeader := ((nextView - 1) % int32(len(s.Peers))) + 1
		isNextLeaderHavingCrashAttack, _ := HasAttack(nextLeader, common.CrashAttack, s.MaliciousPeers, s.Attacks)
		isNextLeaderPresentInAlivePeers := checkIfNodeIsPresentInGivenPeers(s.AlivePeers, nextLeader)
		if isNextLeaderPresentInAlivePeers && !isNextLeaderHavingCrashAttack {
			log.Printf("Current view number is %d and next valid view number for me is: %d", s.ViewNumber, nextView)
			return nextView
		}
	}
}

func checkIfNodeIsPresentInGivenPeers(slice []*int32, value int32) bool {
	for _, v := range slice {
		if *v == value {
			return true
		}
	}
	return false
}

func HasAttack(nodeID int32, name common.Attack, maliciousPeers []*int32, attacks []*Attack) (bool, []int32) {
	isNodeMalicious := checkIfNodeIsPresentInGivenPeers(maliciousPeers, nodeID)
	if !isNodeMalicious {
		return false, nil
	}
	if len(attacks) == 0 {
		return false, nil
	}
	for _, a := range attacks {
		if a != nil && a.Name == string(name) {
			return true, a.Nodes
		}
	}
	return false, nil
}
