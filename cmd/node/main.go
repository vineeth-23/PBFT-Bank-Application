package main

import (
	"flag"
	"fmt"
	"log"
	"path/filepath"

	gRPC1 "pbft-bank-application/gRPC"
	"pbft-bank-application/internal/node"
)

func main() {
	id := flag.Int("id", 1, "node ID (1–7)")
	priv := flag.String("priv", "", "path to node's private key (e.g., keys/node1.priv)")
	manifest := flag.String("manifest", "cluster/manifest.json", "path to cluster manifest")
	flag.Parse()

	if *priv == "" {
		*priv = filepath.Join("keys", fmt.Sprintf("node%d.priv", *id))
	}

	if *manifest == "" {
		*manifest = filepath.Join("cluster", "manifest.json")
	}

	n := node.NewNode(int32(*id), "", map[int32]string{})

	addrs, err := n.LoadManifest(*manifest)
	if err != nil {
		log.Fatalf("LoadManifest failed: %v", err)
	}

	addr, ok := addrs[int32(*id)]
	if !ok {
		log.Fatalf("Node %d not found in manifest", *id)
	}
	n.Address = addr
	n.Peers = addrs

	fmt.Println("Loading key file:", *priv)
	if err := n.LoadPrivateKey(*priv); err != nil {
		log.Fatalf("LoadPrivateKey(%s) failed: %v", *priv, err)
	}

	srv := gRPC1.NewNodeServer(n)
	srv.StartServer()
}
