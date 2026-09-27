package integration

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// This file exercises failover isolation across *process* boundaries: the
// proxy is a real, separately built `caddy` binary that is started, queried,
// cleanly stopped and restarted on the very same listen addresses. The
// in-process matrix in reverseproxy_failover_test.go proves request-to-request
// isolation inside one running server; these tests prove that stopping a
// process and starting a new one on the same ports leaves no retry budget,
// deadline, request body, response header or half-alive instance behind.

var (
	caddyBinOnce sync.Once
	caddyBinPath string
	caddyBinErr  error
)

// buildCaddyBinary builds the caddy binary from this repository once and
// returns its path. The integration package runs with the repository as its
// working directory's grandparent ("<repo>/caddytest/integration").
func buildCaddyBinary(t *testing.T) string {
	t.Helper()
	caddyBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "caddy-failover-e2e-*")
		if err != nil {
			caddyBinErr = err
			return
		}
		// The binary lives in the OS temporary directory and is reaped by the
		// OS; it is intentionally not removed via the first caller's
		// t.Cleanup, because later tests in the same binary reuse it.
		bin := filepath.Join(dir, "caddy")
		// -C makes the build independent of the caller's working directory.
		cmd := exec.Command("go", "-C", repoRoot(), "build", "-o", bin, "./cmd/caddy")
		if out, err := cmd.CombinedOutput(); err != nil {
			caddyBinErr = fmt.Errorf("building caddy binary: %v\n%s", err, out)
			return
		}
		caddyBinPath = bin
	})
	if caddyBinErr != nil {
		if runtime.GOOS == "windows" || runtime.GOOS == "js" || runtime.GOOS == "plan9" {
			t.Skipf("cross-process failover test is unix-only: %v", caddyBinErr)
		}
		t.Fatalf("%v", caddyBinErr)
	}
	return caddyBinPath
}

func repoRoot() string {
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

// caddyProc is one running caddy child process running a Caddyfile on disk.
type caddyProc struct {
	t          *testing.T
	cmd        *exec.Cmd
	logs       bytes.Buffer
	configPath string
	httpURL    string
	httpsURL   string
	httpAddr   string
}

// failoverCaddyfile renders a Caddyfile with two fixed-order upstreams. When
// retries is true the catch-all route has a one-retry budget, a whole-attempt
// time limit and a transport-error retry matcher - and deliberately declares
// NO request/response buffering directive. When retries is false no retry
// budget is configured at all, so failover must be impossible.
func failoverCaddyfile(httpPort, httpsPort int, firstAddr, backupAddr string, retries bool) string {
	var block string
	if retries {
		block = fmt.Sprintf(`
		reverse_proxy %s %s {
			lb_policy first
			lb_retries 1
			lb_try_duration 1s
			lb_try_interval 25ms
			lb_retry_match {
				expression `+"`{rp.is_transport_error} == true`"+`
			}
		}
		`, firstAddr, backupAddr)
	} else {
		block = fmt.Sprintf(`
		reverse_proxy %s %s {
			lb_policy first
		}
		`, firstAddr, backupAddr)
	}
	return fmt.Sprintf(`
	{
		skip_install_trust
		auto_https disable_redirects
		admin off
		grace_period 1ns
	}
	http://127.0.0.1:%d {
%s
	}
	https://localhost:%d {
		tls internal
%s
	}
	`, httpPort, block, httpsPort, block)
}

// startCaddy writes cfg to dir, launches a fresh caddy process with it, and
// waits until the new instance actually serves on its HTTP listener. Every
// instance is pointed at isolated config/data directories so disk state from
// a previous run can never masquerade as in-memory isolation.
func startCaddy(t *testing.T, bin, dir string, cfg string, httpPort, httpsPort int) *caddyProc {
	t.Helper()
	configPath := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write Caddyfile: %v", err)
	}

	p := &caddyProc{
		t:          t,
		configPath: configPath,
		httpAddr:   fmt.Sprintf("127.0.0.1:%d", httpPort),
		httpURL:    fmt.Sprintf("http://127.0.0.1:%d", httpPort),
		httpsURL:   fmt.Sprintf("https://localhost:%d", httpsPort),
	}
	p.cmd = exec.Command(bin, "run", "--config", configPath, "--adapter", "caddyfile")
	p.cmd.Stdout = &p.logs
	p.cmd.Stderr = &p.logs
	p.cmd.Env = append(os.Environ(),
		"XDG_CONFIG_HOME="+filepath.Join(dir, "config"),
		"XDG_DATA_HOME="+filepath.Join(dir, "data"),
	)
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start caddy: %v\n%s", err, p.logs.String())
	}
	t.Cleanup(func() {
		if p.cmd.ProcessState == nil {
			_ = p.kill()
		}
	})

	ready := false
	deadline := time.Now().Add(30 * time.Second)
	httpClient := &http.Client{Timeout: 2 * time.Second}
	tlsClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test-only readiness probe
		},
	}
	for time.Now().Before(deadline) {
		if p.cmd.ProcessState != nil {
			p.dumpLogsAndKill()
			p.t.Fatalf("caddy exited during startup with code %d before becoming ready",
				p.cmd.ProcessState.ExitCode())
		}
		// ready only once BOTH listeners serve: the HTTP site and the TLS
		// site (whose localhost certificate must actually be provisioned,
		// otherwise an early HTTPS handshake gets a tls internal_error)
		httpOK, tlsOK := false, false
		if resp, err := httpClient.Get(p.httpURL + "/ok"); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			httpOK = resp.StatusCode == http.StatusOK
		}
		if resp, err := tlsClient.Get(p.httpsURL + "/ok"); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			tlsOK = resp.StatusCode == http.StatusOK
		}
		if httpOK && tlsOK {
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		p.dumpLogsAndKill()
		t.Fatalf("caddy on %s never became ready", p.httpAddr)
	}
	return p
}

func (p *caddyProc) dumpLogsAndKill() {
	_ = p.kill()
	p.t.Logf("caddy logs:\n%s", p.logs.String())
}

// stop cleanly stops the instance with SIGTERM, waits for it to be fully
// reaped with a successful exit code, and verifies the listen address has
// been released (it can be bound again). Once this returns there is no
// half-alive instance and no previous process can still answer requests.
func (p *caddyProc) stop() {
	p.t.Helper()
	if p.cmd.ProcessState != nil {
		return
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		p.t.Fatalf("signal caddy: %v\n%s", err, p.logs.String())
	}
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			p.t.Fatalf("caddy did not shut down cleanly: %v\n%s", err, p.logs.String())
		}
	case <-time.After(20 * time.Second):
		p.dumpLogsAndKill()
		p.t.Fatalf("caddy did not exit within 20s of SIGTERM")
	}
	if !p.cmd.ProcessState.Exited() || p.cmd.ProcessState.ExitCode() != 0 {
		p.t.Fatalf("caddy exit state: %s, want exit code 0", p.cmd.ProcessState)
	}

	// The address must be releasable and rebindable immediately: bind it from
	// this test, then release it for the next instance.
	ln, err := net.Listen("tcp", p.httpAddr)
	if err != nil {
		p.t.Fatalf("listen address %s not released after stop: %v", p.httpAddr, err)
	}
	_ = ln.Close()

	if p.t.Failed() {
		p.t.Logf("caddy logs:\n%s", p.logs.String())
	}
}

func (p *caddyProc) kill() error {
	if p.cmd.ProcessState != nil {
		return nil
	}
	_ = p.cmd.Process.Signal(syscall.SIGKILL)
	return p.cmd.Wait()
}

// expectProcessExited waits for a (startup-failed) process to terminate on its
// own and reports the exit code.
func (p *caddyProc) expectProcessExited(wantCode int) {
	p.t.Helper()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		p.dumpLogsAndKill()
		p.t.Fatalf("caddy did not exit within 20s")
	}
	if !p.cmd.ProcessState.Exited() {
		p.t.Fatalf("expected caddy to have exited")
	}
	if got := p.cmd.ProcessState.ExitCode(); got != wantCode {
		p.t.Fatalf("caddy exit code: got %d, want %d\n%s", got, wantCode, p.logs.String())
	}
}

func restartMatrixClient(h2 bool) *http.Client {
	tr := &http.Transport{DisableCompression: true}
	if h2 {
		tr.ForceAttemptHTTP2 = true
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only client
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

func baseURLFor(p *caddyProc, h2 bool) string {
	if h2 {
		return p.httpsURL
	}
	return p.httpURL
}

// countRecorded reports how many requests for path using method the backup
// recorded, so POST and HEAD failovers on the same path can be counted
// independently.
func countRecorded(backup *failoverUpstream, path, method string) int {
	n := 0
	for _, rec := range backup.recordings(path) {
		if rec.method == method {
			n++
		}
	}
	return n
}

// assertHeadFailover sends a HEAD request the first node drops before any
// final response. The backup must receive exactly one HEAD, and the client
// must get the backup's final headers with no body but the same Content-Length
// the corresponding GET body would have.
func assertHeadFailover(t *testing.T, client *http.Client, baseURL string, wantProto int, backup *failoverUpstream) {
	t.Helper()
	before := countRecorded(backup, "/retry-before", http.MethodHead)

	resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodHead, baseURL+"/retry-before"))
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	// empty body for HEAD, but length semantics equal the GET body "ok201"
	requireBackupFinalResponse(t, resp, interim, body, readErr, wantProto, "")

	if got := countRecorded(backup, "/retry-before", http.MethodHead) - before; got != 1 {
		t.Errorf("backup received %d new HEAD requests, want exactly 1", got)
	}
}

// assertOneFailoverRequest sends one POST with unique per-round content, asserts
// the client receives exactly one complete backup response, and asserts the
// backup saw exactly one request this round whose method, query, headers, byte
// count, Content-Length and body are byte-for-byte the request just sent (not
// anything from a previous round or process).
func assertOneFailoverRequest(t *testing.T, client *http.Client, baseURL string, wantProto int,
	backup *failoverUpstream, round int,
) recordedRequest {
	t.Helper()
	reqBody := fmt.Sprintf(`{"round":%d}`, round)
	trace := fmt.Sprintf("trace-%d", round)

	before := backup.hitCount("/retry-before")

	req, err := http.NewRequest(http.MethodPost, baseURL+"/retry-before?a=1&b=2", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trace", trace)

	resp, interim, _ := tracedDo(t, client, req)
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	requireBackupFinalResponse(t, resp, interim, body, readErr, wantProto, "ok201")

	recs := backup.recordings("/retry-before")
	if got := len(recs) - before; got != 1 {
		t.Fatalf("round %d: backup received %d new requests, want exactly 1", round, got)
	}
	want := recordedRequest{
		method:        http.MethodPost,
		path:          "/retry-before",
		rawQuery:      "a=1&b=2",
		contentLength: int64(len(reqBody)),
		contentType:   "application/json",
		xTrace:        trace,
		bodyBytes:     len(reqBody),
		body:          []byte(reqBody),
	}
	got := recs[len(recs)-1]
	if got.method != want.method || got.rawQuery != want.rawQuery || got.contentType != want.contentType ||
		got.xTrace != want.xTrace || got.contentLength != want.contentLength || got.bodyBytes != want.bodyBytes ||
		!bytes.Equal(got.body, want.body) {
		t.Errorf("round %d: backup request is not a verbatim replay of this round:\n got  %+v\n want %+v",
			round, got, want)
	}
	return got
}

// assertInterimThenFailover verifies that an interim 103 from the first node is
// forwarded in order, the node then dies before a final response, and the
// failover still yields the backup's single final response - the interim
// response does not pin the request to the failed first node.
func assertInterimThenFailover(t *testing.T, client *http.Client, baseURL string, wantProto int,
	first, backup *failoverUpstream,
) {
	t.Helper()
	beforeFirst := first.hitCount("/retry-info")
	beforeBackup := backup.hitCount("/retry-info")

	resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/retry-info"))
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	requireProtocol(t, resp, wantProto)

	if len(interim) != 1 || interim[0].code != http.StatusEarlyHints {
		t.Fatalf("interim responses: got %v, want a single 103 from the first node", interim)
	}
	if !strings.Contains(interim[0].link, "style.css") {
		t.Errorf("103 Link: got %q, want the first node's style.css hint", interim[0].link)
	}
	if readErr != nil {
		t.Fatalf("reading final body: %v", readErr)
	}
	// the interim 103 remains visible, but the single FINAL response must be
	// the backup's: 201, X-Trace t-7, body ok201 and matching GET length
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("final status: got %d, want 201", resp.StatusCode)
	}
	if string(body) != "ok201" {
		t.Errorf("final body: got %q, want ok201", body)
	}
	if resp.Header.Get("X-Trace") != "t-7" {
		t.Errorf("final X-Trace: got %q, want t-7", resp.Header.Get("X-Trace"))
	}
	if resp.ContentLength != int64(len("ok201")) {
		t.Errorf("final Content-Length: got %d, want %d", resp.ContentLength, len("ok201"))
	}
	if got := first.hitCount("/retry-info") - beforeFirst; got != 1 {
		t.Errorf("first upstream hits: got %d new, want 1", got)
	}
	if got := backup.hitCount("/retry-info") - beforeBackup; got != 1 {
		t.Errorf("backup upstream hits: got %d new, want 1", got)
	}
}

// assertBothFail sends a request both nodes fail before a final response: the
// client must see exactly one clean gateway error, with nothing leaked from
// either failed node.
func assertBothFail(t *testing.T, client *http.Client, baseURL string, wantProto int,
	first, backup *failoverUpstream,
) {
	t.Helper()
	beforeFirst := first.hitCount("/all-fail")
	beforeBackup := backup.hitCount("/all-fail")

	resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/all-fail"))
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	requireProtocol(t, resp, wantProto)

	if len(interim) != 2 || interim[0].code != http.StatusEarlyHints || interim[1].code != http.StatusEarlyHints {
		t.Fatalf("interim responses: got %v, want [103 103] in arrival order", interim)
	}
	if !strings.Contains(interim[0].link, "style.css") || !strings.Contains(interim[1].link, "other.css") {
		t.Errorf("103 order/content wrong: %v", interim)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502", resp.StatusCode)
	}
	if readErr != nil {
		t.Errorf("502 body should read cleanly: %v", readErr)
	}
	if h := resp.Header.Get("X-Origin"); h != "" {
		t.Errorf("failed node header X-Origin leaked into the 502: %q", h)
	}
	if bytes.Contains(body, []byte("style.css")) || bytes.Contains(body, []byte("other.css")) {
		t.Errorf("502 body contains failed node data: %q", body)
	}
	if got := first.hitCount("/all-fail") - beforeFirst; got != 1 {
		t.Errorf("first upstream hits: got %d new, want 1", got)
	}
	if got := backup.hitCount("/all-fail") - beforeBackup; got != 1 {
		t.Errorf("backup upstream hits: got %d new, want 1", got)
	}
}

// assertNoFailoverAfterFinal sends a request the first node answers with a
// FINAL status and headers (then truncates the body). Because a final
// response was already produced, the proxy must never splice in the backup:
// the client keeps the first node's status/header and gets a truncated
// transfer, and the backup is never contacted.
func assertNoFailoverAfterFinal(t *testing.T, client *http.Client, baseURL string, wantProto int, backup *failoverUpstream) {
	t.Helper()
	before := backup.hitCount("/final5xx")

	resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/final5xx"))
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	requireProtocol(t, resp, wantProto)

	if len(interim) != 0 {
		t.Errorf("interim responses: got %v, want none", interim)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d, want the first node's final 503", resp.StatusCode)
	}
	if resp.Header.Get("X-Origin") != "first" {
		t.Errorf("X-Origin: got %q, want the first node's final header (no backup splice)",
			resp.Header.Get("X-Origin"))
	}
	if !bytes.HasPrefix(body, []byte("unav")) {
		t.Errorf("body prefix: got %q, want it to start with the first node's 'unav'", body)
	}
	if readErr == nil {
		t.Errorf("expected a truncated transfer error, got a clean read")
	}
	if got := backup.hitCount("/final5xx") - before; got != 0 {
		t.Errorf("backup must not be contacted after a final response, got %d new hits", got)
	}
}

// TestReverseProxyFailoverAcrossRestarts is the process-boundary matrix. For
// each protocol (HTTP/1.1 and HTTP/2 over TLS), a fresh caddy binary is run
// for several rounds, each round: clean stop, restart on the identical listen
// addresses with the identical config, then a request with unique content. The
// backup must receive exactly one complete, verbatim copy of *this* round's
// request every time; no retry budget, deadline, body or response header may
// survive from the previous process.
func TestReverseProxyFailoverAcrossRestarts(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "js" || runtime.GOOS == "plan9" {
		t.Skip("cross-process failover tests use POSIX signals")
	}
	bin := buildCaddyBinary(t)

	const rounds = 3
	for _, tc := range []struct {
		name      string
		h2        bool
		wantProto int
	}{
		{name: "HTTP/1.1", h2: false, wantProto: 1},
		{name: "HTTP/2 over TLS", h2: true, wantProto: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := newFailoverUpstream(t, "first")
			backup := newFailoverUpstream(t, "backup")

			httpPort := freePort(t)
			httpsPort := freePort(t)
			cfg := failoverCaddyfile(httpPort, httpsPort, first.addr(), backup.addr(), true)

			// one shared state directory across the restarts proves disk/config
			// state is never mistaken for fresh in-memory retry state
			stateDir := t.TempDir()

			for round := 1; round <= rounds; round++ {
				t.Run(fmt.Sprintf("round-%d", round), func(t *testing.T) {
					p := startCaddy(t, bin, stateDir, cfg, httpPort, httpsPort)

					client := restartMatrixClient(tc.h2)
					base := baseURLFor(p, tc.h2)

					// primary fails before any final response: exactly one
					// failover carrying this round's exact request
					assertOneFailoverRequest(t, client, base, tc.wantProto, backup, round)

					// HEAD must behave like GET for failover order and length
					// but return no body to the client
					assertHeadFailover(t, client, base, tc.wantProto, backup)

					// interim response then failure still fails over in order
					assertInterimThenFailover(t, client, base, tc.wantProto, first, backup)

					// once a FINAL response was produced, the backup is never
					// spliced in (identically after every restart)
					assertNoFailoverAfterFinal(t, client, base, tc.wantProto, backup)

					// one round also checks both nodes failing -> single 502
					if round == 2 {
						assertBothFail(t, client, base, tc.wantProto, first, backup)
					}

					// cumulative accounting: one POST failover per round so far,
					// driven entirely by this and prior rounds (never inherited)
					if got := countRecorded(backup, "/retry-before", http.MethodPost); got != round {
						t.Errorf("after round %d: backup saw %d POST failover requests total, want %d",
							round, got, round)
					}

					p.stop()
				})
			}
		})
	}
}

// TestReverseProxyFailoverDisabledAcrossRestarts starts a two-upstream proxy
// whose retry budget is explicitly absent. Before and after a full
// stop/restart on the same address, a first-node failure must surface as a
// single 502 and the backup must never be contacted - disabling retries must
// behave identically across the process boundary.
func TestReverseProxyFailoverDisabledAcrossRestarts(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "js" || runtime.GOOS == "plan9" {
		t.Skip("cross-process failover tests use POSIX signals")
	}
	bin := buildCaddyBinary(t)

	first := newFailoverUpstream(t, "first")
	backup := newFailoverUpstream(t, "backup")

	httpPort := freePort(t)
	httpsPort := freePort(t)
	cfg := failoverCaddyfile(httpPort, httpsPort, first.addr(), backup.addr(), false)
	stateDir := t.TempDir()

	expectNoFailover := func(t *testing.T, p *caddyProc) {
		t.Helper()
		beforeFirst := first.hitCount("/retry-before")
		beforeBackup := backup.hitCount("/retry-before")

		req, err := http.NewRequest(http.MethodPost, p.httpURL+"/retry-before?z=9", strings.NewReader(`{"n":1}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, interim, _ := tracedDo(t, restartMatrixClient(false), req)
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		if len(interim) != 0 {
			t.Errorf("interim responses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status: got %d, want 502", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("502 body should read cleanly: %v", readErr)
		}
		if bytes.Contains(body, []byte(`{"n":1}`)) {
			t.Errorf("502 body must not leak the request body: %q", body)
		}
		if got := first.hitCount("/retry-before") - beforeFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		if got := backup.hitCount("/retry-before") - beforeBackup; got != 0 {
			t.Errorf("backup must never be contacted with retries disabled, got %d new hits", got)
		}
	}

	// before restart
	p := startCaddy(t, bin, stateDir, cfg, httpPort, httpsPort)
	expectNoFailover(t, p)
	if got := backup.hitCount("/retry-before"); got != 0 {
		t.Fatalf("backup contacted before restart with retries disabled: %d hits", got)
	}
	p.stop()

	// after restart on the same address: still disabled, backup still untouched
	p = startCaddy(t, bin, stateDir, cfg, httpPort, httpsPort)
	expectNoFailover(t, p)
	if got := backup.hitCount("/retry-before"); got != 0 {
		t.Fatalf("backup contacted after restart despite retries disabled: %d total hits", got)
	}
	p.stop()
}

// TestReverseProxyFailedStartupLeavesNoInstance starts caddy with an invalid
// Caddyfile. Startup must fail, the process must exit with the startup-failure
// code, and the configured listen address must never accept a connection or
// leave a half-alive instance behind. A healthy instance must then be able to
// bind that same address immediately.
func TestReverseProxyFailedStartupLeavesNoInstance(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "js" || runtime.GOOS == "plan9" {
		t.Skip("cross-process failover tests use POSIX signals")
	}
	bin := buildCaddyBinary(t)

	first := newFailoverUpstream(t, "first")
	backup := newFailoverUpstream(t, "backup")

	httpPort := freePort(t)
	httpsPort := freePort(t)
	stateDir := t.TempDir()
	addr := fmt.Sprintf("127.0.0.1:%d", httpPort)

	// syntactically valid file but an unknown directive -> adaptation failure
	const badCfg = `
	{
		skip_install_trust
		admin off
	}
	http://127.0.0.1:%d {
		this_directive_does_not_exist
	}
	`
	p := startCaddyRaw(t, bin, stateDir, fmt.Sprintf(badCfg, httpPort), httpPort, httpsPort, addr)
	p.expectProcessExited(1) // caddy.ExitCodeFailedStartup

	// nothing must be accepting on the address after the failed start
	conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatalf("a half-alive instance is still accepting connections on %s", addr)
	}

	// the very same address must immediately serve a healthy new instance
	goodCfg := failoverCaddyfile(httpPort, httpsPort, first.addr(), backup.addr(), true)
	p2 := startCaddy(t, bin, stateDir, goodCfg, httpPort, httpsPort)

	client := restartMatrixClient(false)
	assertOneFailoverRequest(t, client, p2.httpURL, 1, backup, 1)
	p2.stop()
}

// startCaddyRaw launches caddy with an arbitrary config without waiting for
// readiness, so a deliberately broken startup can be asserted.
func startCaddyRaw(t *testing.T, bin, dir, cfg string, httpPort, httpsPort int, httpAddr string) *caddyProc {
	t.Helper()
	configPath := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write Caddyfile: %v", err)
	}
	p := &caddyProc{
		t:          t,
		configPath: configPath,
		httpAddr:   httpAddr,
		httpURL:    fmt.Sprintf("http://127.0.0.1:%d", httpPort),
		httpsURL:   fmt.Sprintf("https://localhost:%d", httpsPort),
	}
	p.cmd = exec.Command(bin, "run", "--config", configPath, "--adapter", "caddyfile")
	p.cmd.Stdout = &p.logs
	p.cmd.Stderr = &p.logs
	p.cmd.Env = append(os.Environ(),
		"XDG_CONFIG_HOME="+filepath.Join(dir, "config"),
		"XDG_DATA_HOME="+filepath.Join(dir, "data"),
	)
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("start caddy: %v\n%s", err, p.logs.String())
	}
	t.Cleanup(func() {
		if p.cmd.ProcessState == nil {
			_ = p.kill()
		}
	})
	return p
}
