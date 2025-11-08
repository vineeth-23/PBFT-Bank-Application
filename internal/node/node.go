package node

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"pbft-bank-application/database"
	"strings"
	"sync"
	"time"

	pb "pbft-bank-application/pbft-bank-application/proto"

	mycrypto "pbft-bank-application/internal/crypto"

	"crypto/ed25519"
)

const (
	F = 2
	N = 3*F + 1
)

type Status string

const (
	StatusPrePrepared            Status = "PREPREPARED"
	StatusPrepared               Status = "PREPARED"
	StatusCommitted              Status = "COMMITTED"
	StatusExecuted               Status = "EXECUTED"
	StatusWrongView              Status = "WRONG_VIEW" // when the node's view number is not equal to req view number
	StatusConflictingDigest      Status = "CONFLICTING_DIGEST"
	StatusInvalidLeaderSignature Status = "INVALID_LEADER_SIGNATURE"
	StatusNilTransaction         Status = "NIL_TRANSACTION"
	StatusBadDigest              Status = "BAD_DIGEST"
	StatusNotEnoughPrePrepared   Status = "NOT_ENOUGH_PREPREPARED"
	StatusNotEnoughPrepared      Status = "NOT_ENOUGH_PREPARED"
)

// ReplicaEntryForKeys and Manifest are used for getting generated public and private keys for each node
type ReplicaEntryForKeys struct {
	ID     int32  `json:"id"`
	Addr   string `json:"addr"`
	PubKey string `json:"pubkey_hex"` // hex-encoded ed25519 pub key
}

type ClientEntryForKeys struct {
	Name   string `json:"name"`
	PubKey string `json:"pubkey_hex"`
}
type ManifestForKeys struct {
	Replicas []ReplicaEntryForKeys `json:"replicas"`
	Clients  []ClientEntryForKeys  `json:"clients"`
}

type StatusProof struct {
	NodeID         int32
	Digest         string
	View           int32
	SequenceNumber int32
	Status         Status
	Signature      []byte
}

type Transaction struct {
	FromClientID string
	ToClientID   string
	Amount       int32
	Time         int32
}

type LogEntry struct {
	Digest         string
	ViewNumber     int32
	SequenceNumber int32
	Status         Status
	Transaction    *Transaction

	PreparedProof  map[int32][]*StatusProof
	CommittedProof map[int32][]*StatusProof
}

type Attack struct {
	Name  string
	Nodes []int32
}

type MessageLogEntry struct {
	MessageType string
	SequenceNum int32
	FromNodeID  int32
	ToNodeID    int32
	Direction   string
	ViewNumber  int32
}

type LogKey struct {
	SeqNumber  int32
	ViewNumber int32
}

// Node holds replica state. It will be wrapped by the gRPC server type.
type Node struct {
	ID             int32
	Address        string
	ViewNumber     int32
	SequenceNumber int32

	// crypto
	PrivKey          ed25519.PrivateKey
	PubKey           ed25519.PublicKey
	PubKeysOfNodes   map[int32]ed25519.PublicKey
	PubKeysOfClients map[string]ed25519.PublicKey

	// network
	Peers          map[int32]string // nodeID -> address (all known peers)
	AlivePeers     []*int32
	MaliciousPeers []*int32

	// protocol state
	LogEntries map[int32]*LogEntry
	Balances   map[string]int32

	AlreadyExecutedTransactions map[string]*pb.ReplyToClientRequest
	LastExecutedSequenceNumber  int32

	IsAlive     bool
	IsMalicious bool

	Attacks []*Attack

	electionTimer       *time.Timer
	ViewChangeMessages  map[int32][]*pb.ViewChangeMessage
	TriggeredViewChange map[int32]bool

	AllNewViewMessagesForPrinting map[int32]*pb.NewViewMessage
	AllMessagesForPrintingLog     []*MessageLogEntry

	LastCheckpointedSequenceNumber int32
	CheckpointProofs               map[int32][]*pb.CheckpointMessageRequest

	mu sync.Mutex
}

func NewNode(id int32, address string, peers map[int32]string) *Node {
	pub, priv, err := mycrypto.GenerateEd25519()
	if err != nil {
		panic(err)
	}
	n := &Node{
		ID:                             id,
		Address:                        address,
		ViewNumber:                     1,
		SequenceNumber:                 0,
		PrivKey:                        priv,
		PubKey:                         pub,
		PubKeysOfNodes:                 make(map[int32]ed25519.PublicKey),
		LogEntries:                     make(map[int32]*LogEntry),
		Balances:                       make(map[string]int32),
		AlreadyExecutedTransactions:    make(map[string]*pb.ReplyToClientRequest),
		TriggeredViewChange:            make(map[int32]bool),
		AllNewViewMessagesForPrinting:  make(map[int32]*pb.NewViewMessage),
		AllMessagesForPrintingLog:      make([]*MessageLogEntry, 0),
		LastExecutedSequenceNumber:     0,
		IsMalicious:                    false,
		LastCheckpointedSequenceNumber: 0,
		CheckpointProofs:               make(map[int32][]*pb.CheckpointMessageRequest),
	}
	n.Peers = peers

	for r := 'A'; r <= 'J'; r++ {
		n.Balances[string(r)] = 10
	}

	for r := 'A'; r <= 'J'; r++ {
		clientID := string(r)
		err := database.UpdateClientBalance(id, clientID, 10)
		if err != nil {
			log.Printf("[Node %d] Failed to initialize Redis balance for client=%s: %v", id, clientID, err)
		}
	}

	return n
}

func (s *Node) ResetForNewSetAndUpdateNodeStatus(req *pb.FlushAndUpdateStatusRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LogEntries = make(map[int32]*LogEntry)
	s.AlreadyExecutedTransactions = make(map[string]*pb.ReplyToClientRequest)
	s.LastExecutedSequenceNumber = 0
	s.SequenceNumber = 0
	s.ViewNumber = 1
	s.IsAlive = false
	s.IsMalicious = false
	s.Attacks = nil
	s.ViewChangeMessages = make(map[int32][]*pb.ViewChangeMessage)
	s.AllNewViewMessagesForPrinting = make(map[int32]*pb.NewViewMessage)
	s.AllMessagesForPrintingLog = make([]*MessageLogEntry, 0)
	s.TriggeredViewChange = make(map[int32]bool)
	s.LastCheckpointedSequenceNumber = 0
	s.CheckpointProofs = make(map[int32][]*pb.CheckpointMessageRequest)

	if s.electionTimer != nil {
		s.electionTimer.Stop()
	}
	s.electionTimer = nil

	s.AlivePeers = make([]*int32, len(req.GetLiveNodes()))
	for i, v := range req.LiveNodes {
		val := v
		if val == s.ID {
			s.IsAlive = true
		}
		s.AlivePeers[i] = &val
	}

	s.MaliciousPeers = make([]*int32, len(req.GetByzantineNodes()))
	for i, v := range req.GetByzantineNodes() {
		val := v
		if val == s.ID {
			s.IsMalicious = true
		}
		s.MaliciousPeers[i] = &val
	}

	s.Balances = make(map[string]int32)
	for r := 'A'; r <= 'J'; r++ {
		s.Balances[string(r)] = 10
	}

	for nodeID := int32(1); nodeID <= 5; nodeID++ {
		for r := 'A'; r <= 'J'; r++ {
			clientID := string(r)
			err := database.UpdateClientBalance(nodeID, clientID, 10)
			if err != nil {
				log.Printf("[Node %d] ⚠️ Failed to reset Redis balance for node=%d client=%s: %v",
					s.ID, nodeID, clientID, err)
			}
		}
	}

	s.Attacks = convertAttacksFromProto(req.Attacks)
}

func (n *Node) AddMessageLog(messageType string, direction string, seqNum, fromID, toID, viewNum int32) {
	entry := &MessageLogEntry{
		MessageType: messageType,
		SequenceNum: seqNum,
		FromNodeID:  fromID,
		ToNodeID:    toID,
		Direction:   direction,
		ViewNumber:  viewNum,
	}
	n.AllMessagesForPrintingLog = append(n.AllMessagesForPrintingLog, entry)
}

// Load the node's private key (hex-encoded 64-byte ed25519)
func (s *Node) LoadPrivateKey(privHexPath string) error {
	b, err := os.ReadFile(privHexPath)
	if err != nil {
		return err
	}
	raw, err := hex.DecodeString(string(b))
	if err != nil {
		return fmt.Errorf("bad priv hex: %w", err)
	}
	if l := len(raw); l != ed25519.PrivateKeySize {
		return fmt.Errorf("unexpected priv size %d", l)
	}
	s.PrivKey = ed25519.PrivateKey(raw)
	s.PubKey = s.PrivKey.Public().(ed25519.PublicKey)

	fmt.Printf("[Node %d] Loaded PrivateKey (len=%d): %s\n", s.ID, len(s.PrivKey), hex.EncodeToString(s.PrivKey))
	fmt.Printf("[Node %d] Loaded PublicKey  (len=%d): %s\n", s.ID, len(s.PubKey), hex.EncodeToString(s.PubKey))
	return nil
}

// Load manifest with replica public keys (and addresses). Returns the address book.
func (s *Node) LoadManifest(path string) (map[int32]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m ManifestForKeys
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	addrs := map[int32]string{}
	for _, r := range m.Replicas {
		pubBytes, err := hex.DecodeString(r.PubKey)
		if err != nil {
			return nil, fmt.Errorf("bad pub hex for id %d: %w", r.ID, err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("bad pub len for id %d", r.ID)
		}
		s.PubKeysOfNodes[r.ID] = ed25519.PublicKey(pubBytes)
		addrs[r.ID] = r.Addr
	}

	for _, c := range m.Clients {
		pubBytes, err := hex.DecodeString(c.PubKey)
		if err != nil {
			return nil, fmt.Errorf("bad pub hex for id %d: %w", c.Name, err)
		}
		if len(pubBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("bad pub len for id %d", c.Name)
		}
		if s.PubKeysOfClients == nil {
			s.PubKeysOfClients = make(map[string]ed25519.PublicKey)
		}
		s.PubKeysOfClients[c.Name] = ed25519.PublicKey(pubBytes)
	}

	return addrs, nil
}

func (s *Node) DigestBytes(data []byte) string { return mycrypto.DigestBytes(data) }
func (s *Node) Sign(data []byte) []byte {
	return mycrypto.Sign(s.PrivKey, data)
}

func (s *Node) VerifyReplicaSig(id int32, data, sig []byte) bool {
	pub, ok := s.PubKeysOfNodes[id]
	if !ok {
		return false
	}
	return mycrypto.Verify(pub, data, sig)
}

func (s *Node) VerifyNodeSignatureBasedOnSequenceNumberAndDigest(ID int32, sequenceNumber int32, digest string, signature []byte) bool {
	prepBytes := []byte(fmt.Sprintf("%d:%s", sequenceNumber, digest))
	if ok := s.VerifyReplicaSig(ID, prepBytes, signature); !ok {
		return false
	}
	return true
}

func (s *Node) VerifyClientSignatureBasedOnTransaction(clientID string, tx *pb.Transaction, signature []byte) bool {
	if tx == nil {
		return false
	}
	pub, ok := s.PubKeysOfClients[clientID]
	if !ok {
		return false
	}

	msg := []byte(fmt.Sprintf("%s|%s|%d|%d",
		strings.TrimSpace(tx.FromClientId),
		strings.TrimSpace(tx.ToClientId),
		tx.Amount,
		tx.Time,
	))

	return mycrypto.Verify(pub, msg, signature)
}

func (s *Node) Lock()   { s.mu.Lock() }
func (s *Node) Unlock() { s.mu.Unlock() }
