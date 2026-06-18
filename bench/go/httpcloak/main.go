// httpcloak (sardanioss) benchmark harness. Implements the shared bench/HARNESS.md
// contract. Supports H1/H2/H3. Trusts the origin CA via SSL_CERT_FILE (Go x509);
// if that proves insufficient the orchestrator can fall back, but we avoid
// skip-verify for fair handshake cost. Closed-loop, --concurrency goroutines.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sardanioss/httpcloak/client"
)

func pctl(sorted []float64, p float64) float64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	rank := int(p/100.0*float64(n) + 0.999999)
	if rank < 1 {
		rank = 1
	}
	if rank > n {
		rank = n
	}
	return sorted[rank-1]
}

func normProto(p string) string {
	switch p {
	case "h3", "HTTP/3":
		return "h3"
	case "h2", "HTTP/2.0", "HTTP/2":
		return "h2"
	case "h1", "http/1.1", "HTTP/1.1", "HTTP/1.0":
		return "h1"
	default:
		return p
	}
}

func main() {
	url := flag.String("url", "", "")
	proto := flag.String("protocol", "h2", "h1|h2|h3")
	mode := flag.String("mode", "keepalive", "cold|keepalive")
	requests := flag.Int("requests", 1000, "")
	concurrency := flag.Int("concurrency", 1, "")
	warmup := flag.Int("warmup", 200, "")
	singleThread := flag.Int("single-thread", 1, "")
	maxConns := flag.Int("max-conns", -1, "")
	ca := flag.String("ca", "", "")
	out := flag.String("out", "", "")
	flag.Parse()
	_ = maxConns

	if *ca != "" {
		os.Setenv("SSL_CERT_FILE", *ca)
	}
	if *singleThread != 0 {
		runtime.GOMAXPROCS(1)
	}

	emit := func(obj map[string]interface{}) {
		b, _ := json.MarshalIndent(obj, "", "  ")
		if *out != "" {
			os.WriteFile(*out, append(b, '\n'), 0644)
		} else {
			fmt.Println(string(b))
		}
	}

	opts := []client.Option{client.WithTimeout(30 * time.Second)}
	switch *proto {
	case "h1":
		opts = append(opts, client.WithForceHTTP1())
	case "h3":
		opts = append(opts, client.WithForceHTTP3())
	default:
		opts = append(opts, client.WithForceHTTP2())
	}
	cold := *mode == "cold"
	if cold {
		opts = append(opts, client.WithDisableKeepAlives())
	}
	c := client.NewClient("chrome-143", opts...)
	defer c.Close()

	ctx := context.Background()
	var statusOnce sync.Once
	var gotStatus int
	var gotProto string
	var errSample atomic.Value
	errSample.Store("")

	doOne := func() (float64, bool, int64) {
		t0 := time.Now()
		resp, e := c.Get(ctx, *url, nil)
		if e != nil {
			errSample.Store(e.Error())
			return 0, false, 0
		}
		body, _ := resp.Bytes()
		resp.Close()
		ms := float64(time.Since(t0).Nanoseconds()) / 1e6
		statusOnce.Do(func() { gotStatus = resp.StatusCode; gotProto = resp.Protocol })
		return ms, true, int64(len(body))
	}

	runPhase := func(total int, measuring bool) ([]float64, int64, int64, float64) {
		var remaining int64 = int64(total)
		var bytes, errors int64
		var mu sync.Mutex
		all := make([]float64, 0, total)
		var wg sync.WaitGroup
		t0 := time.Now()
		for w := 0; w < *concurrency; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				local := make([]float64, 0, total / *concurrency+1)
				for atomic.AddInt64(&remaining, -1) >= 0 {
					ms, ok, nb := doOne()
					if ok {
						if measuring {
							local = append(local, ms)
							atomic.AddInt64(&bytes, nb)
						}
					} else {
						atomic.AddInt64(&errors, 1)
					}
				}
				mu.Lock()
				all = append(all, local...)
				mu.Unlock()
			}()
		}
		wg.Wait()
		return all, bytes, errors, time.Since(t0).Seconds()
	}

	if *warmup > 0 {
		runPhase(*warmup, false)
	}
	runtime.GC()
	runtime.GC()
	var ru0, ru1 syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru0)
	samples, bytes, errors, wall := runPhase(*requests, true)
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru1)

	sort.Float64s(samples)
	measured := len(samples)
	rps := 0.0
	if wall > 0 {
		rps = float64(measured) / wall
	}
	tv := func(a, b syscall.Timeval) float64 {
		return float64(a.Sec-b.Sec)*1000.0 + float64(a.Usec-b.Usec)/1000.0
	}
	// Connections are not directly observable through httpcloak's transport, so
	// report by construction: keepalive reuses one conn (0 new during measure),
	// cold opens one per request.
	var conns int64
	if cold {
		conns = int64(measured)
	}
	emit(map[string]interface{}{
		"client": "httpcloak", "client_version": "sardanioss/httpcloak@v1.6.7",
		"protocol_requested": *proto, "protocol_negotiated": normProto(gotProto),
		"mode": *mode, "concurrency": *concurrency, "single_thread": *singleThread,
		"requests": measured, "warmup": *warmup, "throughput_rps": rps,
		"latency_ms": map[string]float64{
			"p50": pctl(samples, 50), "p90": pctl(samples, 90),
			"p99": pctl(samples, 99), "p999": pctl(samples, 99.9),
			"max": pctl(samples, 100),
		},
		"handshake_ms":        map[string]float64{"p50": 0},
		"connections_created": conns,
		"pool_reuses":         int64(measured) - conns,
		"bytes_received":      bytes,
		"status":              gotStatus,
		"errors":              errors,
		"error_sample":        errSample.Load().(string),
		"peak_rss_kb":         ru1.Maxrss,
		"cpu_user_ms":         tv(ru1.Utime, ru0.Utime),
		"cpu_sys_ms":          tv(ru1.Stime, ru0.Stime),
		"wall_ms":             wall * 1000.0,
		"alloc":               map[string]uint64{"arenas_created": 0, "bytes_reserved": 0},
	})
	if measured == 0 {
		os.Exit(1)
	}
}
