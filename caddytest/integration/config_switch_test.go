package integration

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// This file verifies online configuration switching through the admin API's
// POST /load endpoint: a running site must move to a new configuration
// without disturbing requests that are already in flight, and a rejected
// configuration must leave the previous one serving untouched.
//
// Two configurations, A and B, share one listen address but answer /version
// with a different status, header and body. Config A's /hold route proxies
// to a test-controlled upstream that emits an A-marked prefix and then blocks
// until the test releases it by closing a control connection to the upstream.
// That gives the test a deterministic "request in flight across the switch"
// window: the prefix proves the response started on A, the switch is
// committed while the response is held, and the released response must then
// complete entirely with A's status, headers and body - never truncated,
// never duplicated, never mixed with B.
//
// The same matrix runs over plaintext HTTP/1.1 (JSON configs) and over
// HTTP/2 on an HTTPS listener configured with a Caddyfile using
// `tls internal`; the protocol must not change the switch boundary, the
// rollback on failure, or the in-flight response semantics.

const (
	// switchAdminAddr keeps the admin endpoint stable across every config
	// loaded by these tests so the test never loses contact with the server
	switchAdminAddr = "localhost:2999"

	// holdPrefix is flushed by the held upstream before it blocks;
	// holdSuffix is written only after the test releases the hold
	holdPrefix = "A-prefix;"
	holdSuffix = "A-suffix;"

	// holdStatus is the distinctive status the held upstream responds with
	holdStatus = 209
)

// holdUpstream is a local HTTP server whose single endpoint writes an
// A-marked prefix, flushes, and then blocks until the test releases the
// response by closing a control connection to the upstream's gate listener.
// Each release closes the currently pending hold exactly once, and the hit
// counter lets the test prove a request reached the upstream exactly once.
type holdUpstream struct {
	addr     string
	gateAddr string

	mu      sync.Mutex
	hits    int
	pending chan struct{} // closed to release the currently held request
}

func newHoldUpstream(t *testing.T) *holdUpstream {
	t.Helper()

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for hold upstream: %v", err)
	}
	gateLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		httpLn.Close()
		t.Fatalf("listen for hold gate: %v", err)
	}

	u := &holdUpstream{
		addr:     toHostPort(httpLn.Addr()),
		gateAddr: toHostPort(gateLn.Addr()),
	}

	srv := &http.Server{Handler: http.HandlerFunc(u.serveHold)}
	go func() { _ = srv.Serve(httpLn) }()

	// the gate listener accepts control connections from the test; when the
	// test closes its connection the read side sees EOF and the currently
	// held response is released
	go func() {
		for {
			conn, err := gateLn.Accept()
			if err != nil {
				return
			}
			go func() {
				_, _ = io.Copy(io.Discard, conn)
				conn.Close()
				u.release()
			}()
		}
	}()

	t.Cleanup(func() {
		srv.Close()
		gateLn.Close()
	})
	return u
}

// toHostPort normalizes a listener address to 127.0.0.1:port form so it can
// be embedded in a caddy config or dialed directly.
func toHostPort(addr net.Addr) string {
	_, port, _ := net.SplitHostPort(addr.String())
	return net.JoinHostPort("127.0.0.1", port)
}

func (u *holdUpstream) serveHold(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.hits++
	if u.pending == nil {
		u.pending = make(chan struct{})
	}
	release := u.pending
	u.mu.Unlock()

	w.Header().Set("X-Upstream-Mark", "A")
	w.WriteHeader(holdStatus)
	_, _ = io.WriteString(w, holdPrefix)
	w.(http.Flusher).Flush()

	select {
	case <-release:
	case <-r.Context().Done():
		// the downstream request went away while held; nothing to complete
		return
	}
	_, _ = io.WriteString(w, holdSuffix)
}

// release unblocks the currently held request, if any.
func (u *holdUpstream) release() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.pending != nil {
		close(u.pending)
		u.pending = nil
	}
}

func (u *holdUpstream) hitCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits
}

// holdSession is one in-flight /hold request plus the control connection
// that releases it.
type holdSession struct {
	resp *http.Response
	gate net.Conn
}

// startHold issues a /hold request and blocks until the A-marked prefix has
// arrived, proving the response is in flight on the config that was active
// when the request started. The returned session must be completed with
// releaseAndAssertComplete.
func startHold(t *testing.T, client *http.Client, u *holdUpstream, baseURL string, wantProto int) *holdSession {
	t.Helper()

	gate, err := net.DialTimeout("tcp", u.gateAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dialing hold gate: %v", err)
	}

	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := client.Get(baseURL + "/hold")
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	var resp *http.Response
	select {
	case resp = <-respCh:
	case err := <-errCh:
		gate.Close()
		t.Fatalf("GET /hold: %v", err)
	case <-time.After(10 * time.Second):
		gate.Close()
		t.Fatal("GET /hold: timed out waiting for response headers")
	}

	if resp.StatusCode != holdStatus {
		t.Fatalf("held response status: got %d, want %d", resp.StatusCode, holdStatus)
	}
	if mark := resp.Header.Get("X-Upstream-Mark"); mark != "A" {
		t.Fatalf("held response X-Upstream-Mark: got %q, want A", mark)
	}
	if resp.ProtoMajor != wantProto {
		t.Fatalf("held response protocol: got HTTP/%d, want HTTP/%d", resp.ProtoMajor, wantProto)
	}

	// the A-marked prefix must arrive while the upstream is still holding
	// the rest of the response back
	prefix := make([]byte, len(holdPrefix))
	if _, err := io.ReadFull(resp.Body, prefix); err != nil {
		gate.Close()
		t.Fatalf("reading held prefix: %v", err)
	}
	if string(prefix) != holdPrefix {
		t.Fatalf("held prefix: got %q, want %q", prefix, holdPrefix)
	}

	return &holdSession{resp: resp, gate: gate}
}

// releaseAndAssertComplete releases the held upstream by closing the control
// connection, then requires the in-flight response to finish cleanly with
// exactly the A-marked prefix and suffix - no truncation, no duplication, no
// content from any other config.
func (s *holdSession) releaseAndAssertComplete(t *testing.T) {
	t.Helper()

	// release the held response by closing the control connection to the
	// upstream
	if err := s.gate.Close(); err != nil {
		t.Fatalf("closing hold gate: %v", err)
	}

	rest, err := io.ReadAll(s.resp.Body)
	s.resp.Body.Close()
	if err != nil {
		t.Fatalf("held response did not complete cleanly after release: %v", err)
	}
	if got := holdPrefix + string(rest); got != holdPrefix+holdSuffix {
		t.Fatalf("held response body: got %q, want exactly %q", got, holdPrefix+holdSuffix)
	}
}

// versionResponse identifies one config's /version answer.
type versionResponse struct {
	status int
	mark   string
}

func (v versionResponse) body() string { return "config-" + v.mark }

// assertVersion requires a single /version response to match the expected
// config exactly: status, marker header and body.
func assertVersion(t *testing.T, client *http.Client, baseURL string, want versionResponse, wantProto int) {
	t.Helper()

	resp, err := client.Get(baseURL + "/version")
	if err != nil {
		t.Fatalf("GET /version: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading /version body: %v", err)
	}

	if resp.ProtoMajor != wantProto {
		t.Errorf("/version protocol: got HTTP/%d, want HTTP/%d", resp.ProtoMajor, wantProto)
	}
	if resp.StatusCode != want.status {
		t.Errorf("/version status: got %d, want %d", resp.StatusCode, want.status)
	}
	if mark := resp.Header.Get("X-Config-Version"); mark != want.mark {
		t.Errorf("/version X-Config-Version: got %q, want %q", mark, want.mark)
	}
	if string(body) != want.body() {
		t.Errorf("/version body: got %q, want %q", body, want.body())
	}
}

// waitForVersion polls /version on fresh connections until the expected
// config answers, allowing the old server's listener handoff to settle; it
// fails if the new config does not take over promptly.
func waitForVersion(t *testing.T, v switchVariant, want versionResponse) {
	t.Helper()

	client := newSwitchProbeClient(v.h2)
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := client.Get(v.baseURL + "/version")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			mark := resp.Header.Get("X-Config-Version")
			resp.Body.Close()
			if resp.StatusCode == want.status && mark == want.mark && string(body) == want.body() {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("config %s did not take over /version within 5s", want.mark)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// probeResult collects anomalies seen by a prober hammering /version across
// a config switch.
type probeResult struct {
	mu        sync.Mutex
	requests  int
	retried   int
	anomalies []string
}

func (p *probeResult) record(format string, args ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.anomalies = append(p.anomalies, fmt.Sprintf(format, args...))
}

func (p *probeResult) assertClean(t *testing.T, maxRetried int) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.requests == 0 {
		t.Error("prober issued no requests during the config load")
	}
	if p.retried > maxRetried {
		t.Errorf("prober had to retry %d requests, want at most %d", p.retried, maxRetried)
	}
	for _, a := range p.anomalies {
		t.Errorf("probe anomaly: %s", a)
	}
}

// probeDuringLoad hammers /version on fresh connections until stop is
// closed. Every response received must be a complete, consistent answer from
// one of the allowed configs - never a mix of one config's status with
// another's header or body. A transport error must be immediately retryable
// onto a consistent response; anything worse is an anomaly. This is what
// catches a transient no-config state or two instances answering at once.
func probeDuringLoad(v switchVariant, allowed []versionResponse, stop <-chan struct{}, p *probeResult, wg *sync.WaitGroup) {
	defer wg.Done()

	client := newSwitchProbeClient(v.h2)
	for {
		select {
		case <-stop:
			return
		default:
		}

		resp, err := client.Get(v.baseURL + "/version")
		if err != nil {
			// during a successful switch the old server's accept loop can
			// claim a connection in the handoff instant and have it closed
			// by the stdlib shutdown path before it is served; an immediate
			// retry must then land on a consistent config. Anything else is
			// an anomaly.
			p.mu.Lock()
			p.retried++
			p.mu.Unlock()
			resp, err = client.Get(v.baseURL + "/version")
			if err != nil {
				p.record("transport error during load: %v", err)
				continue
			}
		}
		body, err := io.ReadAll(resp.Body)
		mark := resp.Header.Get("X-Config-Version")
		status := resp.StatusCode
		resp.Body.Close()

		p.mu.Lock()
		p.requests++
		p.mu.Unlock()

		if err != nil {
			p.record("body read error during load: %v", err)
			continue
		}
		consistent := false
		for _, a := range allowed {
			if status == a.status && mark == a.mark && string(body) == a.body() {
				consistent = true
				break
			}
		}
		if !consistent {
			p.record("inconsistent response during load: status=%d mark=%q body=%q", status, mark, body)
		}
	}
}

// switchVariant describes one protocol leg of the switch matrix.
type switchVariant struct {
	name       string
	configType string // "json" or "caddyfile"
	baseURL    string
	listenAddr string // listen address used by the invalid config
	h2         bool
	wantProto  int
	config     func(mark string, status int, upstreamAddr string) string
}

func switchVariants() []switchVariant {
	return []switchVariant{
		{
			name:       "HTTP/1.1 plaintext JSON",
			configType: "json",
			baseURL:    "http://127.0.0.1:9088",
			listenAddr: "127.0.0.1:9088",
			h2:         false,
			wantProto:  1,
			config: func(mark string, status int, upstreamAddr string) string {
				return jsonSwitchConfig("127.0.0.1:9088", mark, status, upstreamAddr)
			},
		},
		{
			name:       "HTTP/2 over TLS Caddyfile",
			configType: "caddyfile",
			baseURL:    "https://localhost:9451",
			listenAddr: "127.0.0.1:9451",
			h2:         true,
			wantProto:  2,
			config: func(mark string, status int, upstreamAddr string) string {
				return caddyfileSwitchConfig("https://localhost:9451", mark, status, upstreamAddr)
			},
		},
	}
}

// jsonSwitchConfig is a complete JSON config for configs A and B: one server
// on the shared listen address answering /version with the given mark and
// proxying /hold to the test's upstream.
func jsonSwitchConfig(listenAddr, mark string, status int, upstreamAddr string) string {
	return fmt.Sprintf(`{
		"admin": {"listen": "%s"},
		"apps": {
			"http": {
				"servers": {
					"switch": {
						"listen": ["%s"],
						"routes": [
							{
								"match": [{"path": ["/version"]}],
								"handle": [{
									"handler": "static_response",
									"status_code": %d,
									"headers": {"X-Config-Version": ["%s"]},
									"body": "config-%s"
								}]
							},
							{
								"match": [{"path": ["/hold"]}],
								"handle": [{
									"handler": "reverse_proxy",
									"upstreams": [{"dial": "%s"}]
								}]
							}
						]
					}
				}
			}
		}
	}`, switchAdminAddr, listenAddr, status, mark, mark, upstreamAddr)
}

// caddyfileSwitchConfig is the Caddyfile equivalent for the HTTPS leg, using
// `tls internal` for the localhost site.
func caddyfileSwitchConfig(siteAddr, mark string, status int, upstreamAddr string) string {
	return fmt.Sprintf(`
	{
		skip_install_trust
		admin %s
	}
	%s {
		tls internal
		handle /version {
			header X-Config-Version %s
			respond "config-%s" %d
		}
		handle /hold {
			reverse_proxy %s
		}
	}
	`, switchAdminAddr, siteAddr, mark, mark, status, upstreamAddr)
}

// invalidSwitchConfig is a complete but unloadable JSON config: two HTTP
// servers claim the same listen address, which must be rejected while the
// running config keeps serving.
func invalidSwitchConfig(listenAddr string) string {
	return fmt.Sprintf(`{
		"admin": {"listen": "%s"},
		"apps": {
			"http": {
				"servers": {
					"first": {
						"listen": ["%s"],
						"routes": [{"handle": [{"handler": "static_response", "body": "one"}]}]
					},
					"second": {
						"listen": ["%s"],
						"routes": [{"handle": [{"handler": "static_response", "body": "two"}]}]
					}
				}
			}
		}
	}`, switchAdminAddr, listenAddr, listenAddr)
}

// postLoad submits a full config to the admin API's /load endpoint and
// returns the HTTP status and response body.
func postLoad(t *testing.T, rawConfig, configType string) (int, string) {
	t.Helper()

	contentType := "application/json"
	if configType != "json" {
		contentType = "text/" + configType
	}

	req, err := http.NewRequest(http.MethodPost, "http://"+switchAdminAddr+"/load", strings.NewReader(rawConfig))
	if err != nil {
		t.Fatalf("building /load request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req) //nolint:gosec // admin endpoint is hard-coded to localhost
	if err != nil {
		t.Fatalf("POST /load: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading /load response: %v", err)
	}
	return resp.StatusCode, string(body)
}

// mustLoad submits a config that must be accepted.
func mustLoad(t *testing.T, rawConfig, configType string) {
	t.Helper()
	if code, body := postLoad(t, rawConfig, configType); code != http.StatusOK {
		t.Fatalf("POST /load: got status %d, want 200; body: %s", code, body)
	}
}

// newSwitchClient builds a client for the held request and one-shot checks.
func newSwitchClient(h2 bool) *http.Client {
	tr := &http.Transport{
		DialContext:        (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		DisableCompression: true,
	}
	if h2 {
		tr.ForceAttemptHTTP2 = true
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only client
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// newSwitchProbeClient builds a client that never reuses connections, so
// every request is accepted fresh by whichever config currently owns the
// listener.
func newSwitchProbeClient(h2 bool) *http.Client {
	tr := &http.Transport{
		DialContext:        (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		DisableCompression: true,
		DisableKeepAlives:  true,
	}
	if h2 {
		tr.ForceAttemptHTTP2 = true
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only client
	}
	return &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

// TestConfigSwitchPreservesInFlightResponse runs the full switch matrix:
// a successful A->B switch with a request in flight, a rejected config that
// must roll back while B keeps serving, and a second successful switch back
// to A - proving the rounds stay isolated from each other.
func TestConfigSwitchPreservesInFlightResponse(t *testing.T) {
	for _, v := range switchVariants() {
		t.Run(v.name, func(t *testing.T) {
			upstream := newHoldUpstream(t)
			cfgA := v.config("A", 201, upstream.addr)
			cfgB := v.config("B", 202, upstream.addr)
			badCfg := invalidSwitchConfig(v.listenAddr)

			tester := caddytest.NewTester(t)
			tester.InitServer(cfgA, v.configType)

			client := newSwitchClient(v.h2)
			assertVersion(t, client, v.baseURL, versionResponse{status: 201, mark: "A"}, v.wantProto)

			// --- successful switch A->B with a request in flight ---
			baseHits := upstream.hitCount()
			hold := startHold(t, client, upstream, v.baseURL, v.wantProto)

			// while the switch commits, every /version response must be a
			// complete A or B answer; the address must never go dark
			stop := make(chan struct{})
			probes := &probeResult{}
			var wg sync.WaitGroup
			wg.Add(1)
			go probeDuringLoad(v, []versionResponse{{status: 201, mark: "A"}, {status: 202, mark: "B"}}, stop, probes, &wg)

			mustLoad(t, cfgB, v.configType)

			close(stop)
			wg.Wait()
			// a handful of retried connections is tolerable in the handoff
			// instant; every response itself must have been consistent
			probes.assertClean(t, 5)

			// after the commit, new requests on fresh connections are only
			// ever answered by B: exactly one instance owns the address
			waitForVersion(t, v, versionResponse{status: 202, mark: "B"})
			for i := 0; i < 3; i++ {
				assertVersion(t, newSwitchProbeClient(v.h2), v.baseURL, versionResponse{status: 202, mark: "B"}, v.wantProto)
			}

			// release the upstream; the in-flight request must complete
			// entirely with A's status, headers and body
			hold.releaseAndAssertComplete(t)
			if got := upstream.hitCount() - baseHits; got != 1 {
				t.Errorf("upstream hits during A->B switch: got %d new, want 1", got)
			}

			// --- failed switch: an invalid config is rejected and B keeps
			// serving, including the request already in flight on B ---
			baseHits = upstream.hitCount()
			holdOnB := startHold(t, client, upstream, v.baseURL, v.wantProto)

			stopB := make(chan struct{})
			probesB := &probeResult{}
			wg.Add(1)
			go probeDuringLoad(v, []versionResponse{{status: 202, mark: "B"}}, stopB, probesB, &wg)

			code, body := postLoad(t, badCfg, "json")

			close(stopB)
			wg.Wait()

			if code == http.StatusOK {
				t.Fatalf("invalid config with a repeated listener address was accepted")
			}
			if !strings.Contains(body, "listener address repeated") {
				t.Errorf("load error does not report the repeated listener address: %q", body)
			}
			probesB.assertClean(t, 0)

			// B is still the only config serving; the in-flight request on B
			// completes untouched by the rollback
			assertVersion(t, newSwitchProbeClient(v.h2), v.baseURL, versionResponse{status: 202, mark: "B"}, v.wantProto)
			holdOnB.releaseAndAssertComplete(t)
			assertVersion(t, newSwitchProbeClient(v.h2), v.baseURL, versionResponse{status: 202, mark: "B"}, v.wantProto)
			if got := upstream.hitCount() - baseHits; got != 1 {
				t.Errorf("upstream hits during rejected load: got %d new, want 1", got)
			}

			// --- second successful switch B->A: success, failure, success
			// rounds must not leak requests, responses or errors into each
			// other ---
			baseHits = upstream.hitCount()
			holdOnB2 := startHold(t, client, upstream, v.baseURL, v.wantProto)

			mustLoad(t, cfgA, v.configType)

			waitForVersion(t, v, versionResponse{status: 201, mark: "A"})
			assertVersion(t, newSwitchProbeClient(v.h2), v.baseURL, versionResponse{status: 201, mark: "A"}, v.wantProto)

			holdOnB2.releaseAndAssertComplete(t)
			if got := upstream.hitCount() - baseHits; got != 1 {
				t.Errorf("upstream hits during B->A switch: got %d new, want 1", got)
			}
			assertVersion(t, newSwitchProbeClient(v.h2), v.baseURL, versionResponse{status: 201, mark: "A"}, v.wantProto)
		})
	}
}

// TestConfigSwitchOrderingRegression pins down the ordering between commit
// completion, request release and rollback: a hold released before the new
// config is even submitted must complete on the config that started it, the
// subsequent commit must still take effect, and a rollback after everything
// has settled must leave the running config untouched. The rounds repeat so
// the ordering guarantees are exercised regressively, not just once.
func TestConfigSwitchOrderingRegression(t *testing.T) {
	for _, v := range switchVariants() {
		t.Run(v.name, func(t *testing.T) {
			for i := 1; i <= 3; i++ {
				t.Run(fmt.Sprintf("iteration-%d", i), func(t *testing.T) {
					upstream := newHoldUpstream(t)
					cfgA := v.config("A", 201, upstream.addr)
					cfgB := v.config("B", 202, upstream.addr)

					tester := caddytest.NewTester(t)
					tester.InitServer(cfgA, v.configType)

					client := newSwitchClient(v.h2)

					// release before commit: the hold completes entirely on A
					// before B is ever submitted
					baseHits := upstream.hitCount()
					hold := startHold(t, client, upstream, v.baseURL, v.wantProto)
					hold.releaseAndAssertComplete(t)
					if got := upstream.hitCount() - baseHits; got != 1 {
						t.Errorf("upstream hits before commit: got %d new, want 1", got)
					}
					assertVersion(t, newSwitchProbeClient(v.h2), v.baseURL, versionResponse{status: 201, mark: "A"}, v.wantProto)

					// the commit after the release still switches cleanly
					mustLoad(t, cfgB, v.configType)
					waitForVersion(t, v, versionResponse{status: 202, mark: "B"})
					assertVersion(t, newSwitchProbeClient(v.h2), v.baseURL, versionResponse{status: 202, mark: "B"}, v.wantProto)

					// rollback after everything settled: the invalid config is
					// rejected and B keeps serving without a blip
					code, body := postLoad(t, invalidSwitchConfig(v.listenAddr), "json")
					if code == http.StatusOK {
						t.Fatalf("invalid config with a repeated listener address was accepted")
					}
					if !strings.Contains(body, "listener address repeated") {
						t.Errorf("load error does not report the repeated listener address: %q", body)
					}
					assertVersion(t, newSwitchProbeClient(v.h2), v.baseURL, versionResponse{status: 202, mark: "B"}, v.wantProto)
				})
			}
		})
	}
}
