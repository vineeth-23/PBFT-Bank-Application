package bench

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Manifest struct {
	Replicas []struct {
		ID     int32  `json:"id"`
		Addr   string `json:"addr"`
		PubKey string `json:"pubkey_hex"`
	} `json:"replicas"`
}

func LoadManifest(path string) (map[int32]string, map[int32]ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, nil, err
	}
	addrs := map[int32]string{}
	pubs := map[int32]ed25519.PublicKey{}
	for _, r := range m.Replicas {
		addrs[r.ID] = r.Addr
		raw, err := hex.DecodeString(strings.TrimSpace(r.PubKey))
		if err != nil {
			return nil, nil, fmt.Errorf("bad replica pub hex (id=%d): %w", r.ID, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("replica pub wrong size (id=%d): %d", r.ID, len(raw))
		}
		pubs[r.ID] = ed25519.PublicKey(raw)
	}
	return addrs, pubs, nil
}

func LoadClientKeys(keysDir string) (map[string]ed25519.PrivateKey, map[string]ed25519.PublicKey, error) {
	privs := map[string]ed25519.PrivateKey{}
	pubs := map[string]ed25519.PublicKey{}
	for r := 'A'; r <= 'J'; r++ {
		name := string(r)
		path := filepath.Join(keysDir, fmt.Sprintf("client%s.priv", name))
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return nil, nil, fmt.Errorf("bad client priv hex (%s): %w", name, err)
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("client priv wrong size (%s): %d", name, len(raw))
		}
		priv := ed25519.PrivateKey(raw)
		privs[name] = priv
		pubs[name] = priv.Public().(ed25519.PublicKey)
	}
	return privs, pubs, nil
}
