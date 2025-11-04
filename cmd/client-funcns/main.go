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

func timeoutCtx(d time.Duration) (ctx context.Context, cancel context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

func printDB(addr string, id int32) {
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

func printStatus(addr string, id int32, seq int32) {
	node, conn, err := dialReplica(addr)
	if err != nil {
		log.Printf("[n%d] dial %s failed: %v", id, addr, err)
		return
	}
	defer conn.Close()

	ctx, cancel := timeoutCtx(2 * time.Second)
	defer cancel()
	resp, err := node.PrintStatus(ctx, &pb.PrintStatusRequest{SequenceNumber: seq})
	if err != nil {
		log.Printf("[n%d] PrintStatus error: %v", id, err)
		return
	}

	fmt.Printf("Node %d (seq=%d): Status=%s", resp.NodeId, seq, resp.Status)
	if resp.Transaction != nil && resp.Transaction.FromClientId != "" {
		fmt.Printf(" | Txn=(%s->%s (%d), Amount=%d)\n",
			resp.Transaction.FromClientId,
			resp.Transaction.ToClientId,
			resp.Transaction.Time,
			resp.Transaction.Amount)
	} else {
		fmt.Println()
	}
}

func printView(addr string, id int32) {
	node, conn, err := dialReplica(addr)
	if err != nil {
		log.Printf("[n%d] dial %s failed: %v", id, addr, err)
		return
	}
	defer conn.Close()

	ctx, cancel := timeoutCtx(3 * time.Second)
	defer cancel()

	resp, err := node.PrintView(ctx, &pb.PrintViewRequest{})
	if err != nil {
		log.Printf("[n%d] PrintView error: %v", id, err)
		return
	}

	fmt.Printf("\n=================== Node n%d @ %s ===================\n", id, addr)
	if len(resp.NewViewNumberToNewViewMessageMap) == 0 {
		fmt.Println("No NewViewMessages recorded.")
		return
	}

	viewNumbers := make([]int32, 0, len(resp.NewViewNumberToNewViewMessageMap))
	for v := range resp.NewViewNumberToNewViewMessageMap {
		viewNumbers = append(viewNumbers, v)
	}
	sort.Slice(viewNumbers, func(i, j int) bool { return viewNumbers[i] < viewNumbers[j] })

	for _, view := range viewNumbers {
		msg := resp.NewViewNumberToNewViewMessageMap[view]
		fmt.Printf("\n🔹 NewViewMessage(view=%d)\n", msg.NewViewNumber)
		//fmt.Printf("   ├── Signature: %x\n", msg.Signature)
		fmt.Printf("   ├── #PrePrepares: %d\n", len(msg.PrePrepares))
		fmt.Printf("   ├── #ViewChanges: %d\n", len(msg.ViewChanges))

		if len(msg.PrePrepares) > 0 {
			fmt.Println("   ├── PrePrepareMessages:")
			for _, p := range msg.PrePrepares {
				fmt.Printf("   │   ↪ Seq=%d, View=%d, Transaction=(%s->%s (%d) Amnt: %d), Digest=%s\n",
					p.SequenceNumber, p.ViewNumber, p.GetTransaction().GetFromClientId(), p.GetTransaction().ToClientId, p.GetTransaction().GetTime(), p.GetTransaction().GetAmount(), p.Digest)
			}
		}
		if len(msg.ViewChanges) > 0 {
			fmt.Println("   ├── ViewChangeMessages:")
			for _, v := range msg.ViewChanges {
				fmt.Printf("   │   ↪ FromNode=%d, NewView=%d, PreparedProofSets=%d\n",
					v.NodeId, v.NewViewNumber, len(v.PreparedProofSet))
			}
		}
	}
	fmt.Println("====================================================")
}

func printLog(addr string, id int32) {
	node, conn, err := dialReplica(addr)
	if err != nil {
		log.Printf("[n%d] dial %s failed: %v", id, addr, err)
		return
	}
	defer conn.Close()

	ctx, cancel := timeoutCtx(3 * time.Second)
	defer cancel()

	resp, err := node.PrintLog(ctx, &pb.PrintLogRequest{NodeId: id})
	if err != nil {
		log.Printf("[n%d] PrintLog error: %v", id, err)
		return
	}

	fmt.Printf("\n===================  Message Log — Node n%d @ %s ===================\n", id, addr)

	if len(resp.PrintLogEntries) == 0 {
		fmt.Println("No message logs recorded.")
		fmt.Println("=====================================================================")
		return
	}

	sort.Slice(resp.PrintLogEntries, func(i, j int) bool {
		if resp.PrintLogEntries[i].SequenceNum == resp.PrintLogEntries[j].SequenceNum {
			return resp.PrintLogEntries[i].ViewNumber < resp.PrintLogEntries[j].ViewNumber
		}
		return resp.PrintLogEntries[i].SequenceNum < resp.PrintLogEntries[j].SequenceNum
	})

	for _, entry := range resp.PrintLogEntries {
		if entry.SequenceNum == -1 && entry.ViewNumber == -1 &&
			entry.FromNodeId == -1 && entry.ToNodeId == -1 {
			continue
		}

		fmt.Printf("Type: %-12s", entry.MessageType)

		if entry.Direction != "" {
			fmt.Printf(" | Dir: %-8s", entry.Direction)
		}
		if entry.SequenceNum != -1 {
			fmt.Printf(" | Seq: %-3d", entry.SequenceNum)
		}
		if entry.ViewNumber != -1 {
			fmt.Printf(" | View: %-3d", entry.ViewNumber)
		}
		if entry.FromNodeId != -1 {
			fmt.Printf(" | From: n%-2d", entry.FromNodeId)
		}
		if entry.ToNodeId != -1 {
			fmt.Printf(" | To: n%-2d", entry.ToNodeId)
		}
		fmt.Println()
	}
	fmt.Println("=====================================================================")
}

func main() {
	mode := flag.String("mode", "db", "mode to run (db | status | view)")
	node := flag.Int("node", 0, "node id to query; 0 = all")
	seq := flag.Int("seq", 0, "sequence number for status mode")
	flag.Parse()

	addrs, err := loadManifest(manifestPath)
	if err != nil {
		log.Fatalf("manifest: %v", err)
	}

	switch *mode {
	case "db":
		if *node == 0 {
			ids := make([]int32, 0, len(addrs))
			for id := range addrs {
				ids = append(ids, id)
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			for _, id := range ids {
				printDB(addrs[id], id)
			}
		} else {
			id := int32(*node)
			addr, ok := addrs[id]
			if !ok {
				log.Fatalf("node %d not found in manifest", id)
			}
			printDB(addr, id)
		}

	case "status":
		if *seq == 0 {
			log.Fatalf("--seq must be provided for mode=status")
		}
		if *node == 0 {
			ids := make([]int32, 0, len(addrs))
			for id := range addrs {
				ids = append(ids, id)
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			for _, id := range ids {
				printStatus(addrs[id], id, int32(*seq))
			}
		} else {
			id := int32(*node)
			addr, ok := addrs[id]
			if !ok {
				log.Fatalf("node %d not found in manifest", id)
			}
			printStatus(addr, id, int32(*seq))
		}

	case "view":
		if *node == 0 {
			ids := make([]int32, 0, len(addrs))
			for id := range addrs {
				ids = append(ids, id)
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			for _, id := range ids {
				printView(addrs[id], id)
			}
		} else {
			id := int32(*node)
			addr, ok := addrs[id]
			if !ok {
				log.Fatalf("node %d not found in manifest", id)
			}
			printView(addr, id)
		}
	case "log":
		if *node == 0 {
			ids := make([]int32, 0, len(addrs))
			for id := range addrs {
				ids = append(ids, id)
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			for _, id := range ids {
				printLog(addrs[id], id)
			}
		} else {
			id := int32(*node)
			addr, ok := addrs[id]
			if !ok {
				log.Fatalf("node %d not found in manifest", id)
			}
			printLog(addr, id)
		}
	default:
		log.Fatalf("unsupported mode: %s", *mode)
	}
}
