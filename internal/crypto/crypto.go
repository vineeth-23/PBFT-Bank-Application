package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	pb "pbft-bank-application/pbft-bank-application/proto"
	"strings"
)

func GenerateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func DigestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func Sign(priv ed25519.PrivateKey, data []byte) []byte {
	return ed25519.Sign(priv, data)
}

func Verify(pub ed25519.PublicKey, data []byte, sig []byte) bool {
	return ed25519.Verify(pub, data, sig)
}

func TxSigningBytes(tx *pb.Transaction) []byte {
	return []byte(fmt.Sprintf("%s|%s|%d|%d",
		strings.TrimSpace(tx.FromClientId),
		strings.TrimSpace(tx.ToClientId),
		tx.Amount,
		tx.Time,
	))
}

func GenerateBytesForReplySigning(r *pb.ReplyToClientRequest) []byte {
	return []byte(fmt.Sprintf("%d|%d|%t|%d", r.View, r.Time, r.Result, r.ReplicaId))
}

func generateSignedBytesForReadRequest(clientID string) []byte {
	return []byte("READ|" + clientID)
}

func GenerateBytesForSigningReadResponse(replicaID int32) []byte {
	return []byte(fmt.Sprintf("READ-RESP|r%d", replicaID))
}

func GenerateBytesForViewChangeMessage(replicaID int32) []byte {
	return []byte(fmt.Sprintf("VC|%d", replicaID))
}

func GenerateBytesOnlyForNodeID(replicaID int32) []byte {
	return []byte(fmt.Sprintf("NID|%d", replicaID))
}

func VerifyClientSignatureForReadRequest(clientID string, sig []byte, PubKeysOfClients map[string]ed25519.PublicKey) bool {
	pub, ok := PubKeysOfClients[clientID]
	if !ok {
		return false
	}
	return ed25519.Verify(pub, generateSignedBytesForReadRequest(clientID), sig)
}

func SignReadRequestByClient(clientID string, ClientPriv map[string]ed25519.PrivateKey) ([]byte, bool) {
	priv, ok := ClientPriv[clientID]
	if !ok {
		return nil, false
	}
	return ed25519.Sign(priv, generateSignedBytesForReadRequest(clientID)), true
}

func VerifyReadRespSigByClient(replicaID int32, sig []byte, replicaPubs map[int32]ed25519.PublicKey) bool {
	pub, ok := replicaPubs[replicaID]
	if !ok {
		return false
	}
	return ed25519.Verify(pub, GenerateBytesForSigningReadResponse(replicaID), sig)
}

func SignInvalidTamper(priv ed25519.PrivateKey, data []byte) []byte {
	sig := ed25519.Sign(priv, data)
	out := append([]byte(nil), sig...)

	if len(out) >= 3 {
		out[0] ^= 0xA5
		out[2] ^= 0x5A
	} else if len(out) > 0 {
		out[0] ^= 0xFF
	}
	return out
}

func VerifyNodeSignatureBasedOnSequenceNumberAndDigest(ID int32, sequenceNumber int32, digest string, signature []byte, PubKeysOfNodes map[int32]ed25519.PublicKey) bool {
	prepBytes := []byte(fmt.Sprintf("%d:%s", sequenceNumber, digest))
	if ok := VerifyReplicaSig(ID, prepBytes, signature, PubKeysOfNodes); !ok {
		return false
	}
	return true
}

func VerifyReplicaSig(id int32, data, sig []byte, PubKeysOfNodes map[int32]ed25519.PublicKey) bool {
	pub, ok := PubKeysOfNodes[id]
	if !ok {
		return false
	}
	return Verify(pub, data, sig)
}
