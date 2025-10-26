package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type ReplicaEntry struct {
	ID     int32  `json:"id"`
	Addr   string `json:"addr"`
	PubKey string `json:"pubkey_hex"`
}

type ClientEntry struct {
	Name   string `json:"name"`
	PubKey string `json:"pubkey_hex"`
}

type Manifest struct {
	Replicas []ReplicaEntry `json:"replicas"`
	Clients  []ClientEntry  `json:"clients"`
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func writeHex(path string, data []byte, perm os.FileMode) {
	must(os.WriteFile(path, []byte(hex.EncodeToString(data)), perm))
}

func main() {
	const (
		NReplicas = 7
		basePort  = 50050
	)
	must(os.MkdirAll("keys", 0o755))
	must(os.MkdirAll("cluster", 0o755))

	manifest := Manifest{
		Replicas: make([]ReplicaEntry, 0, NReplicas),
		Clients:  make([]ClientEntry, 0, 10),
	}

	for i := 1; i <= NReplicas; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		must(err)

		writeHex(filepath.Join("keys", fmt.Sprintf("node%d.priv", i)), priv, 0o600)
		writeHex(filepath.Join("keys", fmt.Sprintf("node%d.pub", i)), pub, 0o644)

		manifest.Replicas = append(manifest.Replicas, ReplicaEntry{
			ID:     int32(i),
			Addr:   fmt.Sprintf("localhost:%d", basePort+i),
			PubKey: hex.EncodeToString(pub),
		})
	}

	for c := 'A'; c <= 'J'; c++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		must(err)

		name := string(c)

		writeHex(filepath.Join("keys", fmt.Sprintf("client%s.priv", name)), priv, 0o600)
		writeHex(filepath.Join("keys", fmt.Sprintf("client%s.pub", name)), pub, 0o644)

		manifest.Clients = append(manifest.Clients, ClientEntry{
			Name:   name,
			PubKey: hex.EncodeToString(pub),
		})
	}

	b, err := json.MarshalIndent(manifest, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join("cluster", "manifest.json"), b, 0o644))

	log.Println("Wrote keys/ for replicas & clients, and cluster/manifest.json")
}
