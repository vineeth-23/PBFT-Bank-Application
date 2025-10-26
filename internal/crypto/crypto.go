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
