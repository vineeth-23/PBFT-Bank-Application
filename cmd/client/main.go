package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	cl "pbft-bank-application/internal/client"
	pb "pbft-bank-application/pbft-bank-application/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	manifestPath = "cluster/manifest.json"
	csvPath      = `C:\Users\skotha\Downloads\Project-2-Testcases.csv`
	callbackAddr = "localhost:7000"
)

func main() {
	ctx := context.Background()

	sets, err := cl.ParseCSVStrict(csvPath)
	if err != nil {
		log.Fatalf("parse CSV: %v", err)
	}
	log.Printf("Loaded %d sets.", len(sets))

	h := cl.NewHub()
	if err := loadManifestIntoHub(h, manifestPath); err != nil {
		log.Fatalf("manifest: %v", err)
	}
	if err := loadAllClientKeysIntoHub(h); err != nil {
		log.Fatalf("client keys: %v", err)
	}

	go func() {
		if err := cl.NewCallbackServer(h).Start(callbackAddr); err != nil {
			log.Fatalf("callback server: %v", err)
		}
	}()
	log.Printf("Client callback server listening at %s", callbackAddr)

	reader := bufio.NewReader(os.Stdin)

	fmt.Printf("Ready to run %d set(s). Press ENTER to start Set 1...", len(sets))
	_, _ = reader.ReadString('\n')

	for si, s := range sets {
		log.Printf("========== SET %d ==========", s.Number)

		if len(s.Attacks) > 0 {
			for _, a := range s.Attacks {
				if len(a.Nodes) > 0 {
					log.Printf("  Attack: %s | Nodes: %v", a.Name, a.Nodes)
				} else {
					log.Printf("  Attack: %s | Nodes: (none)", a.Name)
				}
			}
		}

		h.ResetForNewSet()

		h.AliveNodes = s.Live
		fmt.Println("Alive nodes:", h.AliveNodes)

		h.ByzantineNodes = s.Byz

		h.Attacks = s.Attacks

		flushAllReplicasAndUpdateNodeStatus(ctx, h)

		liveAddrs := NodeIdsToAddrs(s.Live, h)
		byzAddrs := NodeIdsToAddrs(s.Byz, h)

		runClientTxsSequentially(ctx, h, s.Txs, liveAddrs, byzAddrs)

		if si < len(sets)-1 {
			fmt.Print("Press ENTER to run the next set...")
			_, _ = reader.ReadString('\n')
		}
	}

	log.Println("All sets completed.")

	fmt.Print("All done. Press ENTER to stop the client...")
	_, _ = reader.ReadString('\n')
}

// Run all transactions of a set with per-client sequentiality:
// - Different clients run in parallel
// - For the same client, txs run strictly one after another (by Time).
func runClientTxsSequentially(
	ctx context.Context,
	h *cl.Hub,
	txs []*pb.Transaction,
	liveAddrs, byzAddrs []string,
) {
	byClient := make(map[string][]*pb.Transaction)
	for _, tx := range txs {
		cid := tx.FromClientId
		byClient[cid] = append(byClient[cid], tx)
	}

	for cid := range byClient {
		list := byClient[cid]
		sort.Slice(list, func(i, j int) bool { return list[i].Time < list[j].Time })
	}

	var wg sync.WaitGroup
	for cid, list := range byClient {
		cid := cid
		list := list
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, tx := range list {
				if tx.Amount == -1 && tx.FromClientId == tx.ToClientId {
					bal, ok := h.ExecuteReadTransaction(ctx, tx.FromClientId)
					if !ok {
						log.Printf("[READ][%s] no quorum", cid)
						continue
					}
					log.Printf("[READ][%s] balance=%d", cid, bal)
					continue
				}

				reply, ok := h.ExecuteTransaction(ctx, cid, tx, liveAddrs, byzAddrs)
				if !ok || reply == nil {
					log.Printf("[t=%d][%s] no quorum (timeout)", tx.Time, cid)
					continue
				}

				if reply.View > hLatestView(h) {
					hSetLatestView(h, reply.View)
				}
				log.Printf("[t=%d][%s] ACCEPTED result=%t view=%d by r=%d",
					tx.Time, cid, reply.Result, reply.View, reply.ReplicaId)
			}
		}()
	}
	wg.Wait()
}

// ===== helpers (unchanged) =====

func loadManifestIntoHub(h *cl.Hub, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var obj struct {
		Replicas []struct {
			ID     int32  `json:"id"`
			Addr   string `json:"addr"`
			PubKey string `json:"pubkey_hex"`
		} `json:"replicas"`
	}
	if err := json.Unmarshal(b, &obj); err != nil {
		return err
	}
	for _, r := range obj.Replicas {
		h.ReplicaAddrs[r.ID] = r.Addr
		raw, err := hex.DecodeString(strings.TrimSpace(r.PubKey))
		if err != nil {
			return fmt.Errorf("bad replica pub hex (id=%d): %w", r.ID, err)
		}
		if len(raw) != ed25519.PrivateKeySize && len(raw) != ed25519.PublicKeySize {
			// being lenient; main check was already done in your node code
		}
		h.ReplicaPubs[r.ID] = ed25519.PublicKey(raw)
	}
	return nil
}

func loadAllClientKeysIntoHub(h *cl.Hub) error {
	for r := 'A'; r <= 'J'; r++ {
		name := string(r)
		path := filepath.Join("keys", fmt.Sprintf("client%s.priv", name))
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			return fmt.Errorf("bad client priv hex (%s): %w", name, err)
		}
		if len(raw) != ed25519.PrivateKeySize {
			return fmt.Errorf("client priv wrong size (%s): %d", name, len(raw))
		}
		priv := ed25519.PrivateKey(raw)
		h.ClientPriv[name] = priv
		h.ClientPub[name] = priv.Public().(ed25519.PublicKey)
	}
	return nil
}

func NodeIdsToAddrs(nodeIds []int32, h *cl.Hub) []string {
	if len(nodeIds) == 0 {
		return nil
	}
	var out []string
	for _, id := range nodeIds {
		addr := h.ReplicaAddrs[id]
		if addr != "" {
			out = append(out, addr)
		}
	}
	return out
}

func flushAllReplicasAndUpdateNodeStatus(ctx context.Context, h *cl.Hub) {
	var wg sync.WaitGroup
	for id, addr := range h.ReplicaAddrs {
		wg.Add(1)
		go func(rid int32, a string) {
			defer wg.Done()
			conn, err := grpc.Dial(a, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				return
			}
			defer conn.Close()
			cli := pb.NewPBFTReplicaClient(conn)
			req := &pb.FlushAndUpdateStatusRequest{
				LiveNodes:      h.AliveNodes,
				ByzantineNodes: h.ByzantineNodes,
				Attacks:        convertAttacksToProto(h.Attacks),
			}
			_, _ = cli.FlushPreviousDataAndUpdatePeersStatus(ctx, req)
		}(id, addr)
	}
	wg.Wait()
}

// small helpers to read/set latest view with lock
func hLatestView(h *cl.Hub) int32 {
	h.Mu.Lock()
	defer h.Mu.Unlock()
	return h.LatestView
}
func hSetLatestView(h *cl.Hub, v int32) {
	h.Mu.Lock()
	h.LatestView = v
	h.Mu.Unlock()
}

func convertAttacksToProto(attacks []*cl.Attack) []*pb.Attack {
	if len(attacks) == 0 {
		return nil
	}
	out := make([]*pb.Attack, 0, len(attacks))
	for _, a := range attacks {
		out = append(out, &pb.Attack{
			Name:  a.Name,
			Nodes: a.Nodes,
		})
	}
	return out
}
