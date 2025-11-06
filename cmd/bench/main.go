package main

import (
	"context"
	"flag"
	"log"
	"time"

	"pbft-bank-application/internal/bench"
)

func main() {
	benchmark := flag.Bool("benchmark", false, "run SmallBank-style benchmark")
	manifest := flag.String("manifest", "cluster/manifest.json", "path to manifest.json")
	keys := flag.String("keys", "keys", "directory containing client private keys")
	callback := flag.String("callback", "localhost:7000", "client callback listen addr")
	dur := flag.Duration("duration", 30*time.Second, "benchmark duration")
	conc := flag.Int("concurrency", 1, "number of concurrent workers")
	rate := flag.Float64("rate", 0, "target ops/sec (0 = unlimited)")
	writeRatio := flag.Float64("write_ratio", 0.3, "fraction of transfers vs reads (0..1)")
	zipfS := flag.Float64("zipf_s", 1.0000001, "zipf skew parameter (0 = uniform)")
	zipfV := flag.Float64("zipf_v", 1.0, "zipf v parameter (>1)")
	leader := flag.Int("leader", 1, "initial leader node id")
	flush := flag.Bool("flush", true, "flush replicas before running benchmark")

	flag.Parse()

	if !*benchmark {
		log.Printf("Benchmark flag is false. Nothing to do. Run with -benchmark=true to start benchmark.")
		return
	}

	cfg := bench.Config{
		ManifestPath: *manifest,
		KeysDir:      *keys,
		CallbackAddr: *callback,
		Duration:     *dur,
		Concurrency:  *conc,
		Rate:         *rate,
		WriteRatio:   *writeRatio,
		ZipfS:        *zipfS,
		ZipfV:        *zipfV,
		LeaderID:     int32(*leader),
		FlushFirst:   *flush,
	}

	ctx := context.Background()
	r := bench.NewRunner(cfg)
	if err := r.Run(ctx); err != nil {
		log.Fatalf("benchmark failed: %v", err)
	}
}
