package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	pb "pbft-bank-application/pbft-bank-application/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"
)

type replicaEntry struct {
	ID     int32  `json:"id"`
	Addr   string `json:"addr"`
	PubKey string `json:"pubkey_hex"`
}
type manifest struct {
	Replicas []replicaEntry `json:"replicas"`
}

const manifestPath = "cluster/manifest.json"

func loadManifest(path string) (map[int32]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	addrs := make(map[int32]string, len(m.Replicas))
	for _, r := range m.Replicas {
		// (optional) sanity check pubkey is hex
		if _, err := hex.DecodeString(strings.TrimSpace(r.PubKey)); err != nil {
			// ignore pubkey decode errors for ops tool; address is what we need
		}
		addrs[r.ID] = r.Addr
	}
	return addrs, nil
}

func dialReplica(addr string) (pb.PBFTReplicaClient, *grpc.ClientConn, error) {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	return pb.NewPBFTReplicaClient(conn), conn, nil
}

func printOne(addr string, id int32) {
	node, conn, err := dialReplica(addr)
	if err != nil {
		log.Printf("[n%d] dial %s failed: %v", id, addr, err)
		return
	}
	defer conn.Close()

	ctx, cancel := timeoutCtx(2 * time.Second)
	defer cancel()
	resp, err := node.PrintDB(ctx, &emptypb.Empty{})
	if err != nil {
		log.Printf("[n%d] PrintDB error: %v", id, err)
		return
	}

	fmt.Printf("\n=== Node n%d @ %s ===\n", id, addr)
	fmt.Printf("View=%d  LastExecutedSeq=%d\n", resp.GetViewNumber(), resp.GetLastExecutedSeq())

	ids := make([]string, 0, len(resp.Balances))
	for k := range resp.Balances {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	for _, cid := range ids {
		fmt.Printf("  %s : %d\n", cid, resp.Balances[cid])
	}
}

func timeoutCtx(d time.Duration) (ctx context.Context, cancel context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func main() {
	mode := flag.String("mode", "db", "mode to run (db)")
	node := flag.Int("node", 0, "node id to query; 0 = all")
	flag.Parse()

	if *mode != "db" {
		log.Fatalf("unsupported mode: %s", *mode)
	}

	addrs, err := loadManifest(manifestPath)
	if err != nil {
		log.Fatalf("manifest: %v", err)
	}

	if *node == 0 {
		// all
		ids := make([]int32, 0, len(addrs))
		for id := range addrs {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			printOne(addrs[id], id)
		}
	} else {
		// specific
		id := int32(*node)
		addr, ok := addrs[id]
		if !ok {
			log.Fatalf("node %d not found in manifest", id)
		}
		printOne(addr, id)
	}
}
