package node

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

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

	mu sync.Mutex
}

func NewNode(id int32, address string, peers map[int32]string) *Node {
	pub, priv, err := mycrypto.GenerateEd25519()
	if err != nil {
		panic(err)
	}
	n := &Node{
		ID:                          id,
		Address:                     address,
		ViewNumber:                  0,
		SequenceNumber:              0,
		PrivKey:                     priv,
		PubKey:                      pub,
		PubKeysOfNodes:              make(map[int32]ed25519.PublicKey),
		LogEntries:                  make(map[int32]*LogEntry),
		Balances:                    make(map[string]int32),
		AlreadyExecutedTransactions: make(map[string]*pb.ReplyToClientRequest),
		LastExecutedSequenceNumber:  0,
		IsMalicious:                 false,
	}
	n.Peers = peers

	for r := 'A'; r <= 'J'; r++ {
		n.Balances[string(r)] = 10
	}

	return n
}

func (n *Node) ResetForNewSetAndUpdateNodeStatus(req *pb.FlushAndUpdateStatusRequest) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.LogEntries = make(map[int32]*LogEntry)
	n.AlreadyExecutedTransactions = make(map[string]*pb.ReplyToClientRequest)
	n.LastExecutedSequenceNumber = 0
	n.SequenceNumber = 0
	n.ViewNumber = 0
	n.IsAlive = false
	n.IsMalicious = false

	n.AlivePeers = make([]*int32, len(req.GetLiveNodes()))
	for i, v := range req.LiveNodes {
		val := v
		if val == n.ID {
			n.IsAlive = true
		}
		n.AlivePeers[i] = &val
	}

	n.MaliciousPeers = make([]*int32, len(req.GetByzantineNodes()))
	for i, v := range req.GetByzantineNodes() {
		val := v
		if val == n.ID {
			n.IsMalicious = true
		}
		n.MaliciousPeers[i] = &val
	}

	n.Balances = make(map[string]int32)
	for r := 'A'; r <= 'J'; r++ {
		n.Balances[string(r)] = 10
	}

}

// Load the node's private key (hex-encoded 64-byte ed25519)
func (n *Node) LoadPrivateKey(privHexPath string) error {
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
	n.PrivKey = ed25519.PrivateKey(raw)
	n.PubKey = n.PrivKey.Public().(ed25519.PublicKey)

	fmt.Printf("[Node %d] Loaded PrivateKey (len=%d): %s\n", n.ID, len(n.PrivKey), hex.EncodeToString(n.PrivKey))
	fmt.Printf("[Node %d] Loaded PublicKey  (len=%d): %s\n", n.ID, len(n.PubKey), hex.EncodeToString(n.PubKey))
	return nil
}

// Load manifest with replica public keys (and addresses). Returns the address book.
func (n *Node) LoadManifest(path string) (map[int32]string, error) {
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
		n.PubKeysOfNodes[r.ID] = ed25519.PublicKey(pubBytes)
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
		if n.PubKeysOfClients == nil {
			n.PubKeysOfClients = make(map[string]ed25519.PublicKey)
		}
		n.PubKeysOfClients[c.Name] = ed25519.PublicKey(pubBytes)
	}

	return addrs, nil
}

func (n *Node) DigestBytes(data []byte) string { return mycrypto.DigestBytes(data) }
func (n *Node) Sign(data []byte) []byte        { return mycrypto.Sign(n.PrivKey, data) }
func (n *Node) VerifyReplicaSig(id int32, data, sig []byte) bool {
	pub, ok := n.PubKeysOfNodes[id]
	if !ok {
		return false
	}
	return mycrypto.Verify(pub, data, sig)
}

func (n *Node) VerifyNodeSignatureBasedOnSequenceNumberAndDigest(ID int32, sequenceNumber int32, digest string, signature []byte) bool {
	prepBytes := []byte(fmt.Sprintf("%d:%s", sequenceNumber, digest))
	if ok := n.VerifyReplicaSig(ID, prepBytes, signature); !ok {
		return false
	}
	return true
}

func (n *Node) VerifyClientSignatureBasedOnTransaction(clientID string, tx *pb.Transaction, signature []byte) bool {
	if tx == nil {
		return false
	}
	pub, ok := n.PubKeysOfClients[clientID]
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

func (n *Node) Lock()   { n.mu.Lock() }
func (n *Node) Unlock() { n.mu.Unlock() }
