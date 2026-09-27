package integration

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file verifies online configuration switches through the admin API
// (POST /load) against a real `caddy` subprocess:
//
//   - a successful load starts serving the new configuration as soon as the
//     admin response reports success, while requests that were already in
//     flight keep being served by the configuration that accepted them;
//   - a configuration that fails to parse/provision/start is rejected and the
//     previously running configuration keeps serving without any gap in which
//     the listen address is unconfigured;
//   - success, failure and success again stay isolated: each round's requests
//     and responses match exactly the configuration of that round.
//
// The matrix runs twice: on a plaintext HTTP/1.1 listener (native JSON
// submitted to /load) and on an HTTPS listener configured with the Caddyfile
// `tls internal` (Caddyfile submitted to /load, negotiated over HTTP/2). The
// protocol must not change any switch boundary, rollback or in-flight
// semantics.

const (
	// holdPrefix/holdSuffix are the two halves of the response body that the
	// test upstream sends for /hold. The prefix is flushed before the config
	// switch; the suffix is only flushed when the test releases the upstream
	// connection, so the client can prove the in-flight response is neither
	// spliced with the new configuration, truncated nor duplicated.
	holdPrefix = "A-inflight-prefix----"
	holdSuffix = "A-inflight-suffix----"

	versionABody = "variant-a-payload"
	versionBBody = "variant-b-payload"
)

// reloadHoldUpstream is a test-process HTTP/1.1 upstream that /hold is proxied
// to. For each /hold request it writes the A status line, an A marker header
// and the A body prefix, then parks the (hijacked) connection until the test
// releases it, at which point it writes the suffix and the terminating chunk
// and closes the connection.
type reloadHoldUpstream struct {
	ln          net.Listener
	mu          sync.Mutex
	held        []net.Conn
	variantHits map[string]int
}

func newReloadHoldUpstream(t *testing.T) *reloadHoldUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for hold upstream: %v", err)
	}
	u := &reloadHoldUpstream{
		ln:          ln,
		variantHits: make(map[string]int),
	}
	srv := &http.Server{Handler: http.HandlerFunc(u.handle)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return u
}

func (u *reloadHoldUpstream) addr() string { return u.ln.Addr().String() }

func (u *reloadHoldUpstream) variantHit(variant string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.variantHits[variant]
}

// releaseAll finalizes every held response with the A suffix and then closes
// its connection. It is the only way a held response may complete.
func (u *reloadHoldUpstream) releaseAll() {
	u.mu.Lock()
	conns := u.held
	u.held = nil
	u.mu.Unlock()
	for _, conn := range conns {
		fmt.Fprintf(conn, "%x\r\n%s\r\n", len(holdSuffix), holdSuffix)
		_, _ = io.WriteString(conn, "0\r\n\r\n")
		_ = conn.Close()
	}
}

func (u *reloadHoldUpstream) handle(w http.ResponseWriter, r *http.Request) {
	variant := r.Header.Get("X-Variant")
	u.mu.Lock()
	u.variantHits[variant]++
	u.mu.Unlock()

	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		panic(err)
	}
	_, _ = io.WriteString(rw,
		"HTTP/1.1 200 OK\r\n"+
			"X-Hold-Marker: hold-A\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n")
	fmt.Fprintf(rw, "%x\r\n%s\r\n", len(holdPrefix), holdPrefix)
	_ = rw.Flush()

	u.mu.Lock()
	u.held = append(u.held, conn)
	u.mu.Unlock()

	// park the handler until Caddy (or releaseAll) closes the connection;
	// after a Hijack the stdlib server no longer touches this connection
	_, _ = io.Copy(io.Discard, rw)
}

// inflightHold is one /hold request running in its own goroutine while the
// test drives configuration switches on other connections.
type inflightHold struct {
	prefixReady chan struct{}
	done        chan struct{}

	resp      *http.Response
	prefix    []byte
	prefixErr error
	rest      []byte
	restErr   error
}

func startInflightHold(t *testing.T, client *http.Client, baseURL string) *inflightHold {
	t.Helper()
	h := &inflightHold{
		prefixReady: make(chan struct{}),
		done:        make(chan struct{}),
	}
	go func() {
		defer close(h.done)
		resp, err := client.Get(baseURL + "/hold")
		if err != nil {
			h.prefixErr = err
			close(h.prefixReady)
			return
		}
		h.resp = resp
		h.prefix = make([]byte, len(holdPrefix))
		_, h.prefixErr = io.ReadFull(resp.Body, h.prefix)
		close(h.prefixReady)
		if h.prefixErr != nil {
			return
		}
		h.rest, h.restErr = io.ReadAll(resp.Body)
	}()
	return h
}

// waitPrefix waits until the A status line, marker header and prefix body have
// arrived; the configuration switch must only be started after this.
func (h *inflightHold) waitPrefix(t *testing.T) {
	t.Helper()
	select {
	case <-h.prefixReady:
	case <-time.After(30 * time.Second):
		t.Fatal("held request never produced its A prefix")
	}
	if h.prefixErr != nil {
		t.Fatalf("reading held prefix: %v", h.prefixErr)
	}
	if string(h.prefix) != holdPrefix {
		t.Fatalf("held prefix: got %q, want %q", h.prefix, holdPrefix)
	}
	if h.resp.StatusCode != http.StatusOK {
		t.Fatalf("held status: got %d, want 200", h.resp.StatusCode)
	}
	if got := h.resp.Header.Get("X-Hold-Marker"); got != "hold-A" {
		t.Fatalf("held marker: got %q, want hold-A", got)
	}
}

// assertStillOpen proves the in-flight response has not picked up any further
// data (in particular no B content) and has not ended while another
// configuration is active.
func (h *inflightHold) assertStillOpen(t *testing.T, phase string) {
	t.Helper()
	select {
	case <-h.done:
		t.Fatalf("held request completed during %s before the upstream was released", phase)
	case <-time.After(500 * time.Millisecond):
	}
}

// waitAndAssertComplete waits for the held response to end (after the upstream
// release) and asserts it is exactly the A response in full: A status and
// marker already asserted at prefix time, plus a clean read of exactly the A
// suffix, with no B payload spliced in, no truncation and no duplicated
// prefix.
func (h *inflightHold) waitAndAssertComplete(t *testing.T, wantProto int) {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		t.Fatal("held request never completed after the upstream was released")
	}
	if h.restErr != nil {
		t.Fatalf("reading held response to completion: %v", h.restErr)
	}
	if string(h.rest) != holdSuffix {
		t.Errorf("held suffix: got %q, want %q", h.rest, holdSuffix)
	}
	full := string(append(append([]byte{}, h.prefix...), h.rest...))
	if want := holdPrefix + holdSuffix; full != want {
		t.Errorf("held full body: got %q, want %q", full, want)
	}
	if bytes.Count([]byte(full), []byte(holdPrefix)) != 1 {
		t.Errorf("held prefix was delivered more than once: %q", full)
	}
	if strings.Contains(full, versionBBody) {
		t.Errorf("held response was spliced with B content: %q", full)
	}
	if h.resp.ProtoMajor != wantProto {
		t.Errorf("held response protocol: got HTTP/%d, want HTTP/%d", h.resp.ProtoMajor, wantProto)
	}
}

// versionResult is the exact /version answer a configuration gave one client.
type versionResult struct {
	status  int
	variant string
	body    string
	proto   int
}

// versionExpectation is the exact /version answer one configuration must give.
type versionExpectation struct {
	status  int
	variant string
	body    string
}

var (
	versionA = versionExpectation{status: http.StatusCreated, variant: "A", body: versionABody}
	versionB = versionExpectation{status: http.StatusAccepted, variant: "B", body: versionBBody}
)

func fetchVersion(t *testing.T, client *http.Client, baseURL string) versionResult {
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
	return versionResult{
		status:  resp.StatusCode,
		variant: resp.Header.Get("X-Variant"),
		body:    string(body),
		proto:   resp.ProtoMajor,
	}
}

func (v versionResult) assertMatches(t *testing.T, want versionExpectation, wantProto int, where string) {
	t.Helper()
	if v.status != want.status {
		t.Errorf("%s: /version status: got %d, want %d", where, v.status, want.status)
	}
	if v.variant != want.variant {
		t.Errorf("%s: /version X-Variant: got %q, want %q", where, v.variant, want.variant)
	}
	if v.body != want.body {
		t.Errorf("%s: /version body: got %q, want %q", where, v.body, want.body)
	}
	if v.proto != wantProto {
		t.Errorf("%s: /version protocol: got HTTP/%d, want HTTP/%d", where, v.proto, wantProto)
	}
}

// assertOnlyVariant issues /version over both the shared keep-alive client and
// brand-new connections, so an old listener still accepting new connections
// after a switch (which would answer the previous variant) cannot hide, and
// neither can a brief window in which the address answers nothing.
func assertOnlyVariant(t *testing.T, baseURL string, h2 bool, wantProto int, want versionExpectation, where string) {
	t.Helper()
	shared := newFailoverClient(h2)
	for i := 0; i < 16; i++ {
		client := shared
		if i%2 == 0 {
			client = newFailoverClient(h2) // force a brand-new connection
		}
		got := fetchVersion(t, client, baseURL)
		got.assertMatches(t, want, wantProto, fmt.Sprintf("%s request %d", where, i))
	}
}

// switchProbe continuously issues /version requests on its own keep-alive
// connections while a configuration switch is in flight. Every answer must be
// a well-formed A or B answer (which side of the switch boundary a request
// lands on is unspecified); a connection error, a missing listener or any
// third answer shape would mean the address was briefly unconfigured.
type switchProbe struct {
	done           chan struct{}
	wg             sync.WaitGroup
	mu             sync.Mutex
	errs           []string
	odd            []string
	aCount, bCount int
}

func startSwitchProbe(t *testing.T, baseURL string, h2 bool) *switchProbe {
	t.Helper()
	p := &switchProbe{done: make(chan struct{})}
	wantProto := 1
	if h2 {
		wantProto = 2
	}
	for w := 0; w < 4; w++ {
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			// one client per worker: connections are reused, so probing never
			// exhausts the ephemeral port range
			client := newFailoverClient(h2)
			for {
				select {
				case <-p.done:
					return
				default:
				}
				resp, err := client.Get(baseURL + "/version")
				if err != nil {
					p.mu.Lock()
					p.errs = append(p.errs, err.Error())
					p.mu.Unlock()
					continue
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				got := versionResult{
					status:  resp.StatusCode,
					variant: resp.Header.Get("X-Variant"),
					body:    string(body),
					proto:   resp.ProtoMajor,
				}
				p.mu.Lock()
				switch {
				case got.status == versionA.status && got.variant == "A" && got.body == versionABody && got.proto == wantProto:
					p.aCount++
				case got.status == versionB.status && got.variant == "B" && got.body == versionBBody && got.proto == wantProto:
					p.bCount++
				default:
					p.odd = append(p.odd, fmt.Sprintf("%d %q %q HTTP/%d", got.status, got.variant, got.body, got.proto))
				}
				p.mu.Unlock()
			}
		}()
	}
	return p
}

func (p *switchProbe) stop() { close(p.done); p.wg.Wait() }

// assertCleanAcrossSwitch checks that probing saw neither errors nor malformed
// answers, and that it observed both sides of the boundary (A before the switch
// completed, B afterwards).
func (p *switchProbe) assertCleanAcrossSwitch(t *testing.T, where string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.errs {
		t.Errorf("%s: request failed while the switch was in flight: %s", where, e)
	}
	for _, o := range p.odd {
		t.Errorf("%s: neither A nor B answer while the switch was in flight: %s", where, o)
	}
	if p.aCount == 0 {
		t.Errorf("%s: probe never observed an A answer before the switch completed", where)
	}
	if p.bCount == 0 {
		t.Errorf("%s: probe never observed a B answer after the switch completed", where)
	}
}

// postLoad submits a complete configuration to POST /load.
func postLoad(t *testing.T, adminURL, contentType string, body io.Reader) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(adminURL+"/load", contentType, body)
	if err != nil {
		t.Fatalf("POST /load: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(respBody)
}

// assertLoadSucceeds submits a configuration and requires the admin API to
// accept it. By the time the 200 is returned the new configuration must be the
// one answering new requests.
func assertLoadSucceeds(t *testing.T, adminURL, contentType, body, label string) {
	t.Helper()
	status, respBody := postLoad(t, adminURL, contentType, strings.NewReader(body))
	if status != http.StatusOK {
		t.Fatalf("%s: POST /load status: got %d, want 200; body: %s", label, status, respBody)
	}
	if respBody != "" {
		t.Errorf("%s: POST /load body: got %q, want empty", label, respBody)
	}
}

// assertLoadRejected submits an invalid configuration and requires it to be
// refused with the duplicate-listener validation error; nothing about the
// running configuration may change.
func assertLoadRejected(t *testing.T, adminURL, badBody, label string) {
	t.Helper()
	status, respBody := postLoad(t, adminURL, "application/json", strings.NewReader(badBody))
	if status != http.StatusBadRequest {
		t.Fatalf("%s: POST /load status: got %d, want 400; body: %s", label, status, respBody)
	}
	if !strings.Contains(respBody, "listener address repeated") {
		t.Fatalf("%s: POST /load error: got %q, want it to mention a repeated listener address", label, respBody)
	}
}

// startReloadCaddy launches `caddy run` with the given initial configuration
// and waits until /version answers wantReadyStatus, proving the instance owns
// the listen address.
func startReloadCaddy(t *testing.T, bin, cfgPath, adapter, runDir, adminURL, baseURL string, h2 bool, wantReadyStatus int) *caddyInstance {
	t.Helper()

	logFile, err := os.Create(filepath.Join(runDir, "caddy.log"))
	if err != nil {
		t.Fatalf("creating log file: %v", err)
	}
	args := []string{"run", "--config", cfgPath}
	if adapter != "" {
		args = append(args, "--adapter", adapter)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// isolate every on-disk artifact (autosave, internal CA, locks) from the
	// developer machine and from other test runs
	cmd.Env = isolatedCaddyEnv(runDir, "state")
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("starting caddy: %v", err)
	}

	inst := &caddyInstance{
		cmd:      cmd,
		logPath:  logFile.Name(),
		waitDone: make(chan error, 1),
		adminURL: adminURL,
	}
	go func() { inst.waitDone <- cmd.Wait(); logFile.Close() }()

	client := newFailoverClient(h2)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-inst.waitDone:
			t.Fatalf("caddy exited before becoming ready: %v\n%s", err, inst.tailLog())
		default:
		}
		resp, err := client.Get(baseURL + "/version")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == wantReadyStatus {
				return inst
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("caddy did not become ready within 60s\n%s", inst.tailLog())
	return nil
}

// config builders for the plaintext HTTP/1.1 matrix (native JSON over /load).

func reloadJSONA(adminAddr, siteAddr, upstreamAddr string) string {
	return fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {
		"http": {
			"grace_period": "60s",
			"servers": {
				"srv0": {
					"listen": [%q],
					"routes": [
						{
							"match": [{"path": ["/version"]}],
							"handle": [{
								"handler": "static_response",
								"status_code": 201,
								"headers": {"X-Variant": ["A"]},
								"body": %q
							}]
						},
						{
							"match": [{"path": ["/hold"]}],
							"handle": [{
								"handler": "reverse_proxy",
								"headers": {"request": {"set": {"X-Variant": ["A"]}}},
								"upstreams": [{"dial": %q}]
							}]
						}
					]
				}
			}
		}
	}
}`, adminAddr, siteAddr, versionABody, upstreamAddr)
}

func reloadJSONB(adminAddr, siteAddr string) string {
	return fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {
		"http": {
			"grace_period": "60s",
			"servers": {
				"srv0": {
					"listen": [%q],
					"routes": [
						{
							"match": [{"path": ["/version"]}],
							"handle": [{
								"handler": "static_response",
								"status_code": 202,
								"headers": {"X-Variant": ["B"]},
								"body": %q
							}]
						}
					]
				}
			}
		}
	}
}`, adminAddr, siteAddr, versionBBody)
}

// reloadJSONBad is deliberately invalid: two HTTP servers declare the same
// listen address, which Validate() must reject before anything starts.
func reloadJSONBad(adminAddr, siteAddr string) string {
	return fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {
		"http": {
			"grace_period": "60s",
			"servers": {
				"one": {"listen": [%q], "routes": []},
				"two": {"listen": [%q], "routes": []}
			}
		}
	}
}`, adminAddr, siteAddr, siteAddr)
}

// config builders for the HTTPS HTTP/2 matrix (Caddyfile with `tls internal`
// submitted to /load).

func reloadCaddyfileA(adminAddr, siteAddr, upstreamAddr string) string {
	return fmt.Sprintf(`{
	skip_install_trust
	admin %s
	grace_period 60s
}
%s {
	tls internal
	handle /version {
		header X-Variant A
		respond %q 201
	}
	handle /hold {
		reverse_proxy %s {
			header_up X-Variant A
		}
	}
}
`, adminAddr, siteAddr, versionABody, upstreamAddr)
}

func reloadCaddyfileB(adminAddr, siteAddr string) string {
	return fmt.Sprintf(`{
	skip_install_trust
	admin %s
	grace_period 60s
}
%s {
	tls internal
	handle /version {
		header X-Variant B
		respond %q 202
	}
}
`, adminAddr, siteAddr, versionBBody)
}

// reloadCase parameterizes one protocol matrix.
type reloadCase struct {
	name        string
	h2          bool
	wantProto   int
	siteAddr    string
	adminAddr   string
	contentType string // Content-Type used when submitting A and B to /load
}

// TestConfigReloadInFlightIsolation drives the complete online-switch matrix
// on a real caddy binary for a plaintext HTTP/1.1 listener and an HTTPS
// HTTP/2 listener:
//
//  1. A is started and serves A on /version.
//  2. a /hold request is opened; once its A prefix has arrived, B is loaded;
//  3. from the moment /load answers 200, only B answers new /version requests
//     while the held A response stays exactly where it was; concurrent probes
//     during the commit prove the address is continuously available;
//  4. releasing the upstream completes the held response as exactly A;
//  5. an invalid duplicate-listener config is rejected and B keeps serving;
//  6. A loads again and a second /hold is opened, interleaving the three
//     events: a rolled-back failure (A keeps serving, hold unchanged), then a
//     successful commit while the same hold is open (B serves new requests,
//     address continuously available), and only then is the request released
//     to finish as exactly A;
//  7. one more successful load closes the success/failure/success sequence.
func TestConfigReloadInFlightIsolation(t *testing.T) {
	bin := buildCaddyBinary(t)

	for _, tc := range []reloadCase{
		{
			name:        "HTTP/1.1 plaintext",
			h2:          false,
			wantProto:   1,
			siteAddr:    "127.0.0.1:9088",
			adminAddr:   "127.0.0.1:2992",
			contentType: "application/json",
		},
		{
			name:        "HTTP/2 over TLS internal",
			h2:          true,
			wantProto:   2,
			siteAddr:    "localhost:9451",
			adminAddr:   "127.0.0.1:2991",
			contentType: "text/caddyfile",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runReloadMatrix(t, bin, tc)
		})
	}
}

func runReloadMatrix(t *testing.T, bin string, tc reloadCase) {
	upstream := newReloadHoldUpstream(t)

	adminURL := "http://" + tc.adminAddr
	scheme := "http"
	if tc.h2 {
		scheme = "https"
	}
	baseURL := scheme + "://" + tc.siteAddr

	var cfgA, cfgB, initialCfg, initialName, adapter string
	if tc.h2 {
		initialName = "initial.Caddyfile"
		adapter = "caddyfile"
		cfgA = reloadCaddyfileA(tc.adminAddr, tc.siteAddr, upstream.addr())
		cfgB = reloadCaddyfileB(tc.adminAddr, tc.siteAddr)
	} else {
		initialName = "initial.json"
		cfgA = reloadJSONA(tc.adminAddr, tc.siteAddr, upstream.addr())
		cfgB = reloadJSONB(tc.adminAddr, tc.siteAddr)
	}
	initialCfg = cfgA
	cfgBad := reloadJSONBad(tc.adminAddr, tc.siteAddr)

	runDir := t.TempDir()
	cfgPath := filepath.Join(runDir, initialName)
	if err := os.WriteFile(cfgPath, []byte(initialCfg), 0o600); err != nil {
		t.Fatalf("writing initial config: %v", err)
	}

	inst := startReloadCaddy(t, bin, cfgPath, adapter, runDir, adminURL, baseURL, tc.h2, versionA.status)
	t.Cleanup(func() { inst.stopCaddy(t) })

	// the held stream must outlive ordinary request deadlines, the rest of
	// the matrix uses the standard bounded client
	holdClient := newFailoverClient(tc.h2)
	holdClient.Timeout = 0
	client := newFailoverClient(tc.h2)

	// 1. A is the running configuration.
	fetchVersion(t, client, baseURL).assertMatches(t, versionA, tc.wantProto, "initial A")

	// 2. open /hold and wait for the A prefix before switching anything.
	held := startInflightHold(t, holdClient, baseURL)
	held.waitPrefix(t)
	if got := upstream.variantHit("A"); got != 1 {
		t.Fatalf("upstream X-Variant=A hits: got %d, want 1", got)
	}
	if got := upstream.variantHit("B"); got != 0 {
		t.Fatalf("upstream unexpectedly received X-Variant=B %d times", got)
	}

	// everything immediately before the switch is still A
	fetchVersion(t, client, baseURL).assertMatches(t, versionA, tc.wantProto, "pre-switch")

	// 3. load B while the address is being hammered; once this returns, new
	// requests only ever see B and the address never stopped answering.
	probe := startSwitchProbe(t, baseURL, tc.h2)
	// let the probe demonstrably observe A before submitting B
	time.Sleep(100 * time.Millisecond)
	assertLoadSucceeds(t, adminURL, tc.contentType, cfgB, "load B")
	// the successful response already marks the boundary; let probes observe
	// the B side as well before stopping them
	time.Sleep(100 * time.Millisecond)
	probe.stop()
	probe.assertCleanAcrossSwitch(t, "load B")
	assertOnlyVariant(t, baseURL, tc.h2, tc.wantProto, versionB, "after B load")

	// the held response must still be exactly the open A response: no
	// completion and no extra (B) bytes while B serves new requests
	held.assertStillOpen(t, "B active")

	// 4. releasing the upstream finalizes the old response as exactly A.
	upstream.releaseAll()
	held.waitAndAssertComplete(t, tc.wantProto)
	if got := upstream.variantHit("A"); got != 1 {
		t.Errorf("upstream X-Variant=A hits after release: got %d, want still 1", got)
	}

	// 5. a rejected load must not change anything: B keeps serving.
	assertLoadRejected(t, adminURL, cfgBad, "bad config while B active")
	assertOnlyVariant(t, baseURL, tc.h2, tc.wantProto, versionB, "after rejected load on B")

	// 6. A loads successfully again; then a second /hold request is opened and
	// kept open while the other two events interleave around it: first a
	// rejected (rolled back) load, then a successful commit. This fixes the
	// ordering of commit completion, rollback and request release.
	assertLoadSucceeds(t, adminURL, tc.contentType, cfgA, "reload A")
	assertOnlyVariant(t, baseURL, tc.h2, tc.wantProto, versionA, "after A reload")

	held2 := startInflightHold(t, holdClient, baseURL)
	held2.waitPrefix(t)
	if got := upstream.variantHit("A"); got != 2 {
		t.Fatalf("upstream X-Variant=A hits after second hold: got %d, want 2", got)
	}

	// 6b. rollback while the request is held: rejected, A keeps serving, and
	// the held response neither completes nor changes.
	assertLoadRejected(t, adminURL, cfgBad, "bad config while A active")
	assertOnlyVariant(t, baseURL, tc.h2, tc.wantProto, versionA, "after rejected load on A")
	held2.assertStillOpen(t, "rollback while held")

	// 6c. successful commit while the very same request is held: from the
	// successful response onwards only B answers new requests, and the address
	// is continuously available across the boundary.
	probe2 := startSwitchProbe(t, baseURL, tc.h2)
	time.Sleep(100 * time.Millisecond)
	assertLoadSucceeds(t, adminURL, tc.contentType, cfgB, "reload B while held")
	time.Sleep(100 * time.Millisecond)
	probe2.stop()
	probe2.assertCleanAcrossSwitch(t, "reload B while held")
	assertOnlyVariant(t, baseURL, tc.h2, tc.wantProto, versionB, "after commit while held")
	held2.assertStillOpen(t, "successful commit while held")

	// 6d. only now is the request released; it was accepted by A, survived
	// both a rolled-back failure and a successful commit, and must finish as
	// exactly A with no B content, truncation or duplication.
	upstream.releaseAll()
	held2.waitAndAssertComplete(t, tc.wantProto)
	if got := upstream.variantHit("A"); got != 2 {
		t.Errorf("upstream X-Variant=A hits after second release: got %d, want still 2", got)
	}

	// 7. one last successful load (A again) completes the
	// success/failure/success/failure/success chain; every round must stay
	// isolated from the others.
	assertLoadSucceeds(t, adminURL, tc.contentType, cfgA, "final reload A")
	assertOnlyVariant(t, baseURL, tc.h2, tc.wantProto, versionA, "after final A load")
}
