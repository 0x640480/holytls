// tls-client (bogdanfinn) benchmark harness. Implements the shared bench/HARNESS.md
// contract: same CLI + JSON as the other clients. H1/H2 only — H3 exits with an
// honest error (tls-client has no QUIC). Trusts the origin CA via SSL_CERT_FILE
// (no skip-verify, so handshake cost is comparable). Closed-loop: --concurrency
// worker goroutines pull from a shared count.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	http "github.com/bogdanfinn/fhttp"
	"github.com/bogdanfinn/fhttp/httptrace"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
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
	switch {
	case p == "HTTP/2.0" || p == "HTTP/2":
		return "h2"
	case p == "HTTP/1.1" || p == "HTTP/1.0":
		return "h1"
	default:
		return p
	}
}

type result struct {
	samples []float64
	bytes   int64
	errors  int64
}

func main() {
	url := flag.String("url", "", "target URL")
	proto := flag.String("protocol", "h2", "h1|h2|h3")
	mode := flag.String("mode", "keepalive", "cold|keepalive")
	requests := flag.Int("requests", 1000, "")
	concurrency := flag.Int("concurrency", 1, "")
	warmup := flag.Int("warmup", 200, "")
	singleThread := flag.Int("single-thread", 1, "")
	maxConns := flag.Int("max-conns", -1, "")
	ca := flag.String("ca", "", "PEM CA to trust")
	out := flag.String("out", "", "output file (default stdout)")
	flag.Parse()
	_ = maxConns

	if *ca != "" {
		os.Setenv("SSL_CERT_FILE", *ca) // Go x509 honors this for the system pool
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

	if *proto == "h3" {
		emit(map[string]interface{}{
			"client": "tls-client", "client_version": tlsClientVersion(),
			"protocol_requested": "h3", "protocol_negotiated": "", "mode": *mode,
			"concurrency": *concurrency, "single_thread": *singleThread,
			"requests": 0, "warmup": *warmup, "throughput_rps": 0.0,
			"latency_ms":  map[string]float64{"p50": 0, "p90": 0, "p99": 0, "p999": 0, "max": 0},
			"handshake_ms": map[string]float64{"p50": 0},
			"connections_created": 0, "pool_reuses": 0, "bytes_received": 0, "status": 0,
			"errors": *requests, "error_sample": "tls-client does not support HTTP/3",
			"peak_rss_kb": 0, "cpu_user_ms": 0.0, "cpu_sys_ms": 0.0, "wall_ms": 0.0,
			"alloc": map[string]uint64{"arenas_created": 0, "bytes_reserved": 0},
		})
		os.Exit(3)
	}

	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(30),
		tls_client.WithClientProfile(profiles.Chrome_133),
		tls_client.WithNotFollowRedirects(),
	}
	if *proto == "h1" {
		opts = append(opts, tls_client.WithForceHttp1())
	}
	if *mode == "cold" {
		opts = append(opts, tls_client.WithTransportOptions(&tls_client.TransportOptions{DisableKeepAlives: true}))
	}
	client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls-client: new client:", err)
		os.Exit(2)
	}

	var conns int64
	trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		if !i.Reused {
			atomic.AddInt64(&conns, 1)
		}
	}}

	var statusOnce sync.Once
	var gotStatus int
	var gotProto string
	var errSample atomic.Value
	errSample.Store("")

	doOne := func() (float64, bool, int64) {
		req, e := http.NewRequest(http.MethodGet, *url, nil)
		if e != nil {
			errSample.Store(e.Error())
			return 0, false, 0
		}
		req = req.WithContext(httptrace.WithClientTrace(context.Background(), trace))
		t0 := time.Now()
		resp, e := client.Do(req)
		if e != nil {
			errSample.Store(e.Error())
			return 0, false, 0
		}
		nb, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		ms := float64(time.Since(t0).Nanoseconds()) / 1e6
		if *mode == "cold" {
			client.CloseIdleConnections() // force a fresh handshake next request
		}
		statusOnce.Do(func() { gotStatus = resp.StatusCode; gotProto = resp.Proto })
		return ms, true, nb
	}

	runPhase := func(total int, measuring bool) (result, float64) {
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
		return result{all, bytes, errors}, time.Since(t0).Seconds()
	}

	if *warmup > 0 {
		runPhase(*warmup, false)
	}
	atomic.StoreInt64(&conns, 0) // count only NEW connections during the measured phase
	runtime.GC()
	runtime.GC()
	var ru0, ru1 syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru0)
	res, wall := runPhase(*requests, true)
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru1)

	sort.Float64s(res.samples)
	measured := len(res.samples)
	rps := 0.0
	if wall > 0 {
		rps = float64(measured) / wall
	}
	tv := func(a, b syscall.Timeval) float64 {
		return float64(a.Sec-b.Sec)*1000.0 + float64(a.Usec-b.Usec)/1000.0
	}
	emit(map[string]interface{}{
		"client": "tls-client", "client_version": tlsClientVersion(),
		"protocol_requested": *proto, "protocol_negotiated": normProto(gotProto),
		"mode": *mode, "concurrency": *concurrency, "single_thread": *singleThread,
		"requests": measured, "warmup": *warmup, "throughput_rps": rps,
		"latency_ms": map[string]float64{
			"p50": pctl(res.samples, 50), "p90": pctl(res.samples, 90),
			"p99": pctl(res.samples, 99), "p999": pctl(res.samples, 99.9),
			"max": pctl(res.samples, 100),
		},
		"handshake_ms":        map[string]float64{"p50": 0}, // not isolated for tls-client
		"connections_created": conns,
		"pool_reuses":         int64(measured) - conns,
		"bytes_received":      res.bytes,
		"status":              gotStatus,
		"errors":              res.errors,
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

func tlsClientVersion() string { return "bogdanfinn/tls-client" }
