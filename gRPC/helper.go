package gRPC

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"pbft-bank-application/database"
	"pbft-bank-application/internal/crypto"
	"pbft-bank-application/internal/node"
	pb "pbft-bank-application/pbft-bank-application/proto"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	F                      = 2
	clientCallbackAddr     = "localhost:7000"
	checkPointingInterval  = 100
	isCheckPointingEnabled = false
)

func generateBytesForDigest(tx *pb.Transaction) []byte {
	if tx == nil {
		return nil
	}
	return []byte(fmt.Sprintf("%s|%s|%d|%d",
		strings.TrimSpace(tx.FromClientId),
		strings.TrimSpace(tx.ToClientId),
		tx.Amount,
		tx.Time,
	))
}

func (s *NodeServer) TxDigest(tx *pb.Transaction) string {
	return s.Node.DigestBytes(generateBytesForDigest(tx))
}

func GenerateBytesForSign(sequenceNumber int32, digest string) []byte {
	return []byte(fmt.Sprintf("%d:%s", sequenceNumber, digest))
}

func GetLeaderBasedOnViewNumber(viewNumber int32) int32 {
	return ((viewNumber - 1) % 7) + 1
}

func (s *NodeServer) executeInOrder() {
	n := s.Node

	for {
		n.Lock()
		nextSeq := n.LastExecutedSequenceNumber + 1
		entry, ok := n.LogEntries[nextSeq]

		if !ok || entry == nil {
			n.Unlock()
			return
		}

		if entry.Status != node.StatusCommitted {
			n.Unlock()
			return
		}

		if ok && entry != nil && entry.Digest == node.NullDigest {
			//log.Printf("executeInOrder: sequence number is %d and updated to executed", nextSeq)
			entry.ViewNumber = s.Node.ViewNumber
			entry.Status = node.StatusExecuted
			n.LastExecutedSequenceNumber = nextSeq
			n.Unlock()
			s.UpdateNodeTimer()
			if n.LastExecutedSequenceNumber > 0 && n.LastExecutedSequenceNumber%checkPointingInterval == 0 {
				start := n.LastExecutedSequenceNumber - 99
				digest := s.ComputeCheckpointDigest(start, n.LastExecutedSequenceNumber)
				go s.sendCheckpointMessage(n.LastExecutedSequenceNumber, digest)
			}
			continue
		}

		if entry.Transaction == nil {
			n.Unlock()
			return
		}

		clientID := entry.Transaction.FromClientID
		if cached, exists := n.AlreadyExecutedTransactions[entry.Digest]; exists && cached != nil {
			if entry.Digest == node.NullDigest {
				entry.Status = node.StatusExecuted
			}
			n.LastExecutedSequenceNumber = nextSeq
			n.Unlock()
			s.UpdateNodeTimer()
			if err := s.sendReplyToClient(clientID, cached); err != nil {
				log.Printf("[Node %d] send cached reply to client %s failed: %v", s.Node.ID, clientID, err)
			}
			if n.LastExecutedSequenceNumber > 0 && n.LastExecutedSequenceNumber%checkPointingInterval == 0 {
				start := n.LastExecutedSequenceNumber - 99
				digest := s.ComputeCheckpointDigest(start, n.LastExecutedSequenceNumber)
				go s.sendCheckpointMessage(n.LastExecutedSequenceNumber, digest)
			}
			continue
		}

		tx := &pb.Transaction{
			FromClientId: entry.Transaction.FromClientID,
			ToClientId:   entry.Transaction.ToClientID,
			Amount:       entry.Transaction.Amount,
			Time:         entry.Transaction.Time,
		}
		expectedDigest := s.TxDigest(tx)

		if entry.Digest != expectedDigest {
			n.Unlock()
			log.Printf("!!!This should not happen!!! :: expected digest: %s, received: %s", expectedDigest, entry.Digest)
			return
		}

		if cached, exists := n.AlreadyExecutedTransactions[entry.Digest]; exists && cached != nil {
			n.LastExecutedSequenceNumber = nextSeq
			n.Unlock()
			s.UpdateNodeTimer()
			if err := s.sendReplyToClient(clientID, cached); err != nil {
				log.Printf("[Node %d] send cached reply to client %s failed: %v", s.Node.ID, clientID, err)
			}
			continue
		}

		from := entry.Transaction.FromClientID
		to := entry.Transaction.ToClientID
		amt := entry.Transaction.Amount

		var result bool
		if n.Balances[from] >= amt {
			n.Balances[from] -= amt
			n.Balances[to] += amt
			result = true
			_ = database.UpdateClientBalance(s.Node.ID, from, n.Balances[from])
			_ = database.UpdateClientBalance(s.Node.ID, to, n.Balances[to])
		} else {
			result = false
		}

		entry.Status = node.StatusExecuted
		n.LastExecutedSequenceNumber = nextSeq

		reply := &pb.ReplyToClientRequest{
			View:      entry.ViewNumber,
			Time:      entry.Transaction.Time,
			Result:    result,
			ReplicaId: s.Node.ID,
		}

		bytes := crypto.GenerateBytesForReplySigning(reply)
		reply.Signature = n.Sign(bytes)

		n.AlreadyExecutedTransactions[entry.Digest] = reply
		//log.Printf("Updated the executedTransaction for transaction: %v, digest is: %s", entry.Transaction, entry.Digest)
		n.Unlock()

		//log.Printf("[Node %d] ✅ EXECUTED t=%d: %s → %s (amt=%d) result=%t",
		//	n.ID, tx.Time, tx.FromClientId, tx.ToClientId, tx.Amount, result)
		s.UpdateNodeTimer()

		n.AddMessageLog("EXECUTED", "sent", entry.SequenceNumber, n.ID, n.ID, n.ViewNumber)

		if err := s.sendReplyToClient(clientID, reply); err != nil {
			log.Printf("[Node %d] send reply to client %s failed: %v", s.Node.ID, clientID, err)
		}
		if n.LastExecutedSequenceNumber > 0 && n.LastExecutedSequenceNumber%checkPointingInterval == 0 {
			start := n.LastExecutedSequenceNumber - 99
			digest := s.ComputeCheckpointDigest(start, n.LastExecutedSequenceNumber)
			go s.sendCheckpointMessage(n.LastExecutedSequenceNumber, digest)
		}
	}
}

func (s *NodeServer) UpdateNodeTimer() {
	s.Node.Lock()
	isTransactionProcessing := false
	for _, entry := range s.Node.LogEntries {
		if entry == nil || entry.Digest == node.NullDigest {
			continue
		}
		_, ok := s.Node.AlreadyExecutedTransactions[entry.Digest]
		if entry.Status != node.StatusExecuted && !ok {
			//if entry.Transaction != nil {
			//	log.Printf("UpdateNodeTimer: Transaction is: %v; Digest is: %s", entry.Transaction, entry.Digest)
			//} else {
			//	log.Printf("UpdateNodeTimer: Transaction is: nil and marking isTransactionProcessing")
			//}
			isTransactionProcessing = true
			break
		}
	}
	if !isTransactionProcessing {
		//log.Printf("Stop node timer in view-%d as all transactions are executed", s.Node.ViewNumber)
		s.Node.Unlock()
		s.Node.StopNodeTimer()
	} else {
		//log.Printf("Resetting node timer in UpdateNodeTimer")
		s.Node.Unlock()
		s.Node.ResetNodeTimer()
	}
}

func (s *NodeServer) sendReplyToClient(clientID string, r *pb.ReplyToClientRequest) error {
	addr := clientCallbackAddr

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("[Node %d] dial client(%s @ %s) failed: %w", s.Node.ID, clientID, addr, err)
	}
	defer conn.Close()

	cli := pb.NewClientCallbackClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := cli.ReplyToClientFromNode(ctx, r); err != nil {
		return fmt.Errorf("[Node %d] ReplyToClientFromNode -> %s failed: %w", s.Node.ID, addr, err)
	}
	s.Node.AddMessageLog("REPLY", "sent", -1, s.Node.ID, -1, r.GetView())
	return nil
}

func (s *NodeServer) HasAttack(name string) (bool, []int32) {
	if !s.Node.IsMalicious {
		return false, nil
	}
	if len(s.Node.Attacks) == 0 {
		return false, nil
	}
	for _, a := range s.Node.Attacks {
		if a != nil && a.Name == name {
			return true, a.Nodes
		}
	}
	return false, nil
}

func IsNodePresentInAttackNodes(attackNodes []int32, nodeID int32) bool {
	for _, t := range attackNodes {
		if t == nodeID {
			return true
		}
	}
	return false
}

func quorumSizeForTriggeringViewChangeMessage() int {
	return 3 // F+1
}

func isLeaderForNewView(nodeID int32, newView int32, totalPeers int32) bool {
	if nodeID == ((newView-1)%totalPeers)+1 {
		return true
	}
	return false
}

func (s *NodeServer) performActionsAfterNewViewIsRecievied(newViewNumber int32) {
	s.Node.Lock()
	s.Node.ViewNumber = newViewNumber
	//s.Node.ViewChangeOngoing = false
	s.Node.Unlock()
}

func isValidStatus(status node.Status) bool {
	if status == node.StatusPrepared || status == node.StatusCommitted || status == node.StatusExecuted {
		return true
	}
	return false
}

func isValidStatusForCommitted(status node.Status) bool {
	if status == node.StatusExecuted {
		return true
	}
	return false
}

func (s *NodeServer) ComputeCheckpointDigest(start, end int32) string {
	n := s.Node
	digests := make([]string, 0, end-start+1)

	for i := start; i <= end; i++ {
		entry, ok := n.LogEntries[i]
		if !ok || entry == nil || entry.Digest == "" {
			continue
		}
		digests = append(digests, entry.Digest)
	}

	combined := strings.Join(digests, "|")
	hash := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(hash[:])
}

func (s *NodeServer) sendCheckpointMessage(seq int32, digest string) {
	n := s.Node
	msg := &pb.CheckpointMessageRequest{
		SequenceNumber: seq,
		Digest:         digest,
		ReplicaId:      n.ID,
	}
	bytes := crypto.GenerateBytesOnlyForNodeID(n.ID)
	msg.Signature = s.Node.Sign(bytes)

	for peerID, addr := range n.Peers {
		go func(pid int32, addr string) {
			conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				log.Printf("[Node %d]  Failed to dial peer n%d: %v", n.ID, pid, err)
				return
			}
			defer conn.Close()

			node := pb.NewPBFTReplicaClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			n.AddMessageLog("CHECKPOINT", "sent", msg.GetSequenceNumber(), n.ID, pid, n.ViewNumber)
			_, err = node.SendCheckPointMessage(ctx, msg)
			if err != nil {
				log.Printf("[Node %d]  SendCheckpointMessage to n%d failed: %v", n.ID, pid, err)
			}
		}(peerID, addr)
	}
}

func toProtoCheckpointProofs(src map[int32][]*pb.CheckpointMessageRequest) map[int32]*pb.CheckPointMessageProof {
	dst := make(map[int32]*pb.CheckPointMessageProof)
	for view, reqList := range src {
		dst[view] = &pb.CheckPointMessageProof{
			CheckpointMessageRequests: reqList,
		}
	}
	return dst
}

func (s *NodeServer) addToLogRecordsForSendNewView(seq int32, msg *pb.NewViewMessage, view int32) {
	n := s.Node
	n.AddMessageLog("PREPREPARE", "received", seq, msg.SourceId, s.Node.ID, view)
	n.AddMessageLog("PREPREPARED", "sent", seq, s.Node.ID, msg.SourceId, view)
	n.AddMessageLog("PREPARE", "received", seq, msg.SourceId, s.Node.ID, view)
	n.AddMessageLog("PREPARED", "sent", seq, s.Node.ID, msg.SourceId, view)
	n.AddMessageLog("COMMIT", "received", seq, msg.SourceId, s.Node.ID, view)
	n.AddMessageLog("COMMITTED", "sent", seq, s.Node.ID, msg.SourceId, view)
}
