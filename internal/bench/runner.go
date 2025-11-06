package bench

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	cl "pbft-bank-application/internal/client"
	pb "pbft-bank-application/pbft-bank-application/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Config struct {
	ManifestPath string
	KeysDir      string
	CallbackAddr string
	Duration     time.Duration

	// The maximum number of operations you run at the same time in a batch.
	Concurrency int
	// A way to cap how many operations you start per second
	// Rate = 200 (ops/sec) → period = 5ms.
	//  A cap on how many operations you start per second (pace of launches), irrespective of how many are currently in-flight
	Rate       float64
	WriteRatio float64
	ZipfS      float64
	ZipfV      float64
	LeaderID   int32
	FlushFirst bool
}

type Runner struct {
	cfg     Config
	addrs   map[int32]string
	clients map[int32]pb.PBFTReplicaClient
	hub     *cl.Hub
	cb      *cl.CallbackServer
	met     *Metrics

	work *Workload

	seq int32
}

func NewRunner(cfg Config) *Runner { return &Runner{cfg: cfg, met: NewMetrics()} }

func (r *Runner) init(ctx context.Context) error {
	addrs, pubs, err := LoadManifest(r.cfg.ManifestPath)
	if err != nil {
		return err
	}
	r.addrs = addrs

	priv, pub, err := LoadClientKeys(r.cfg.KeysDir)
	if err != nil {
		return err
	}

	// Initialize Hub and callback server from existing client package
	r.hub = cl.NewHub()
	r.hub.ReplicaAddrs = addrs
	r.hub.ReplicaPubs = pubs
	r.hub.ClientPriv = priv
	r.hub.ClientPub = pub
	r.hub.AliveNodes = make([]int32, 0, len(addrs))
	for id := range addrs {
		r.hub.AliveNodes = append(r.hub.AliveNodes, id)
	}

	r.cb = cl.NewCallbackServer(r.hub)
	go func() { _ = r.cb.Start(r.cfg.CallbackAddr) }()
	time.Sleep(200 * time.Millisecond)

	r.clients = make(map[int32]pb.PBFTReplicaClient)
	for id, addr := range r.addrs {
		conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return fmt.Errorf("dial %s: %w", addr, err)
		}
		r.clients[id] = pb.NewPBFTReplicaClient(conn)
	}

	if r.cfg.FlushFirst {
		if err := r.flushAll(ctx); err != nil {
			return err
		}
	}

	// value of seed is 0 for realistic non-deterministic runs, non-zero fixed for reproducible tests
	seed := time.Now().UnixNano()
	//seed = 40
	r.work = NewWorkload(10, r.cfg.WriteRatio, seed, r.cfg.ZipfS, r.cfg.ZipfV)
	return nil
}

func (r *Runner) flushAll(ctx context.Context) error {
	var wg sync.WaitGroup
	alive := make([]int32, 0, len(r.addrs))
	for id := range r.addrs {
		alive = append(alive, id)
	}
	for id, cli := range r.clients {
		wg.Add(1)
		go func(id int32, c pb.PBFTReplicaClient) {
			defer wg.Done()
			ctx2, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			req := &pb.FlushAndUpdateStatusRequest{LiveNodes: alive, ByzantineNodes: nil, Attacks: nil}
			_, _ = c.FlushPreviousDataAndUpdatePeersStatus(ctx2, req)
			log.Printf("[bench] flushed n%d", id)
		}(id, cli)
	}
	wg.Wait()
	return nil
}

func (r *Runner) Run(ctx context.Context) error {
	if err := r.init(ctx); err != nil {
		return err
	}
	log.Printf("[bench] starting: dur=%v, conc=%d, rate=%.1f, writeRatio=%.2f", r.cfg.Duration, r.cfg.Concurrency, r.cfg.Rate, r.cfg.WriteRatio)
	r.met.Start()

	var wg sync.WaitGroup
	stop := time.After(r.cfg.Duration)
	var tick <-chan time.Time
	if r.cfg.Rate > 0 {
		period := time.Duration(float64(time.Second) / r.cfg.Rate)
		t := time.NewTicker(period)
		defer t.Stop()
		tick = t.C
	}

	launch := func() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op := r.work.NextOp()
			start := time.Now()
			var ok bool
			if op.Type == OpTransfer {
				ok = r.doWrite(ctx, op)
				r.met.AddWrite(ok, time.Since(start))
			} else {
				_, ok = r.doRead(ctx, op.From)
				r.met.AddRead(ok, time.Since(start))
			}
		}()
	}

	inflight := 0
	for {
		select {
		case <-stop:
			wg.Wait()
			r.met.Stop()
			fmt.Print(r.met.Summary())
			return nil
		default:
			if tick == nil {
				for inflight < r.cfg.Concurrency {
					launch()
					inflight++
				}
				wg.Wait()
				inflight = 0
			} else {
				select {
				case <-tick:
					launch()
				case <-stop:
					wg.Wait()
					r.met.Stop()
					fmt.Print(r.met.Summary())
					return nil
				}
			}
		}
	}
}

func (r *Runner) nextTime() int32 { return atomic.AddInt32(&r.seq, 1) }

func (r *Runner) doWrite(ctx context.Context, op Op) bool {
	leader := r.cfg.LeaderID
	if leader == 0 {
		leader = 1
	}

	tx := &pb.Transaction{FromClientId: op.From, ToClientId: op.To, Amount: op.Amount, Time: r.nextTime()}
	if _, ok := r.hub.ExecuteTransaction(ctx, op.From, tx, nil, nil); ok {
		return true
	}
	return false
}

func (r *Runner) doRead(ctx context.Context, clientID string) (int32, bool) {
	return r.hub.ExecuteReadTransaction(ctx, clientID)
}
