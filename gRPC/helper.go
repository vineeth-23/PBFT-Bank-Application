package gRPC

import (
	"context"
	"fmt"
	"log"
	"pbft-bank-application/internal/crypto"
	"pbft-bank-application/internal/node"
	pb "pbft-bank-application/pbft-bank-application/proto"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	F                  = 2
	clientCallbackAddr = "localhost:7000"
)

// txSigningBytes returns the canonical bytes the client is assumed to have signed.
// Adjust to your actual Transaction fields as needed.
func generateBytesForDigest(tx *pb.Transaction) []byte {
	// Example canonicalization (do NOT include the client's signature field)
	// Order and separators must be identical on client and server sides.
	if tx == nil {
		return nil
	}
	// Deterministic canonical order: from, to, amount, time
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
	return (viewNumber % 7) + 1
}

func (s *NodeServer) executeInOrder() {
	n := s.Node

	for {
		nextSeq := n.LastExecutedSequenceNumber + 1
		entry, ok := n.LogEntries[nextSeq]
		if !ok || entry == nil || entry.Transaction == nil || entry.Status != node.StatusCommitted {
			return
		}

		expectedDigest := s.TxDigest(&pb.Transaction{
			FromClientId: entry.Transaction.FromClientID,
			ToClientId:   entry.Transaction.ToClientID,
			Amount:       entry.Transaction.Amount,
			Time:         entry.Transaction.Time,
		})
		if entry.Digest != expectedDigest {
			log.Printf("!!!This should not happen!!! :: expected digest: %s, received: %s", expectedDigest, entry.Digest)
			return
		}

		clientID := entry.Transaction.FromClientID
		if cached, exists := n.AlreadyExecutedTransactions[entry.Digest]; exists && cached != nil {
			if err := s.sendReplyToClient(clientID, cached); err != nil {
				log.Printf("[Node %d] send cached reply to client %s failed: %v", s.Node.ID, clientID, err)
			}
			n.LastExecutedSequenceNumber = nextSeq
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
		reply.Signature = n.Sign(crypto.GenerateBytesForReplySigning(reply))
		log.Printf("[Node %d] Updated to EXECUTED for transaction: (%s -> %s; amount: %d; time: %d)",
			n.ID, entry.Transaction.FromClientID, entry.Transaction.ToClientID, entry.Transaction.Amount, entry.Transaction.Time)
		n.AlreadyExecutedTransactions[entry.Digest] = reply
		if err := s.sendReplyToClient(clientID, reply); err != nil {
			log.Printf("[Node %d] send reply to client %s failed: %v", s.Node.ID, clientID, err)
		}
	}
}

// sendReplyToClient dials the client's callback server and pushes the reply.
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
	return nil
}
