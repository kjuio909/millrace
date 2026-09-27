package integration

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const caddyBinaryName = "caddy"

// repoRoot is the repository root (the test binary runs in
// caddytest/integration).
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// binaryName returns the platform-specific caddy binary name.
func binaryName() string {
	if runtime.GOOS == "windows" {
		return caddyBinaryName + ".exe"
	}
	return caddyBinaryName
}

// adminHostPort extracts the host:port from an admin endpoint URL.
func adminHostPort(adminURL string) string {
	u, err := url.Parse(adminURL)
	if err != nil {
		return strings.TrimPrefix(adminURL, "http://")
	}
	return u.Host
}

// This file verifies that the reverse_proxy failover state stays isolated
// across the strongest possible boundary: a full process restart reusing the
// exact same listen address. The request-boundary matrix (retry budgets,
// deadlines, bodies, headers and upstream counters never leaking between
// requests in one process) lives in reverseproxy_failover_test.go; here a
// real `caddy` binary is built, started, stopped cleanly and restarted on the
// same ports, so the upstream counters - which live in the test process and
// therefore survive every caddy restart - can prove that no retry budget,
// deadline, request body or response state crosses a process boundary.

// caddyInstance is one running `caddy run` subprocess.
type caddyInstance struct {
	cmd       *exec.Cmd
	logPath   string
	waitDone  chan error
	adminURL  string
	stoppedMu sync.Mutex
	stopped   bool
}

// buildCaddyBinary compiles the in-tree cmd/caddy binary once and returns its
// path. The subprocess must contain the standard modules (Caddyfile adapter,
// reverse_proxy, file storage, internal TLS), which cmd/caddy imports.
func buildCaddyBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping cross-process restart test in short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}

	bin := filepath.Join(t.TempDir(), binaryName())
	build := exec.Command("go", "build", "-o", bin, "./cmd/caddy")
	build.Dir = repoRoot(t)
	var buildErr bytes.Buffer
	build.Stderr = &buildErr
	if err := build.Run(); err != nil {
		t.Fatalf("building caddy binary: %v\n%s", err, buildErr.String())
	}
	return bin
}

// isolatedCaddyEnv gives the subprocess its own HOME/XDG/AppData roots under
// runDir, so the internal CA, autosave and locks never touch the developer
// machine and never bleed between (failed) starts.
func isolatedCaddyEnv(runDir, suffix string) []string {
	root := filepath.Join(runDir, suffix)
	home := filepath.Join(root, "home")
	env := os.Environ()
	if runtime.GOOS == "windows" {
		env = append(env,
			"USERPROFILE="+home,
			"APPDATA="+filepath.Join(root, "appdata"),
			"LOCALAPPDATA="+filepath.Join(root, "localappdata"),
		)
	} else {
		env = append(env,
			"HOME="+home,
			"XDG_DATA_HOME="+filepath.Join(root, "data"),
			"XDG_CONFIG_HOME="+filepath.Join(root, "config"),
			"XDG_STATE_HOME="+filepath.Join(root, "state"),
		)
	}
	return env
}

// writeRestartCaddyConfig writes the Caddyfile used across a whole restart
// matrix: a fixed admin address, a zero grace period (so a stopped process
// releases its sockets promptly) and the given site block.
func writeRestartCaddyConfig(t *testing.T, dir, name, adminAddr, siteBlock string) string {
	t.Helper()
	cfg := fmt.Sprintf(`
	{
		skip_install_trust
		admin %s
		grace_period 1ns
	}
	%s
	`, adminAddr, siteBlock)
	cfgPath := filepath.Join(dir, name)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return cfgPath
}

// startCaddy launches `caddy run` with the given config and isolated data and
// config directories, then waits until the site answers a request. The
// returned instance must be stopped with stopCaddy.
func startCaddy(t *testing.T, bin, cfgPath, runDir, adminURL, readyURL string, h2 bool) *caddyInstance {
	t.Helper()

	logFile, err := os.Create(filepath.Join(runDir, "caddy.log"))
	if err != nil {
		t.Fatalf("creating log file: %v", err)
	}

	cmd := exec.Command(bin, "run", "--config", cfgPath, "--adapter", "caddyfile")
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

	inst.waitReady(t, readyURL, h2)
	return inst
}

// startCaddyExpectingFailure launches `caddy run` with a configuration that
// cannot be loaded and asserts the process exits unsuccessfully on its own,
// leaving no half-alive instance: nothing must be accepting requests on the
// site port afterwards.
func startCaddyExpectingFailure(t *testing.T, bin, cfgPath, runDir, siteHostPort string) {
	t.Helper()

	logFile, err := os.Create(filepath.Join(runDir, "caddy-failed.log"))
	if err != nil {
		t.Fatalf("creating log file: %v", err)
	}
	cmd := exec.Command(bin, "run", "--config", cfgPath, "--adapter", "caddyfile")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = isolatedCaddyEnv(runDir, "state-fail")
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("starting caddy: %v", err)
	}

	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait(); logFile.Close() }()

	select {
	case err := <-waitErr:
		if err == nil {
			t.Fatalf("caddy with an invalid config exited successfully; want a nonzero exit")
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("caddy with an invalid config did not exit; a failed startup left a live process")
	}

	// the failed instance must not be serving: the site port must refuse
	// connections rather than be held by a half-alive process
	conn, dialErr := net.DialTimeout("tcp", siteHostPort, time.Second)
	if dialErr == nil {
		conn.Close()
		t.Fatalf("site port %s is still accepting connections after a failed startup", siteHostPort)
	}
}

// waitReady polls the site until a fully successful request is served, proving
// the new instance (and only it) owns the listen address.
func (p *caddyInstance) waitReady(t *testing.T, readyURL string, h2 bool) {
	t.Helper()
	client := newFailoverClient(h2)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.waitDone:
			t.Fatalf("caddy exited before becoming ready: %v\n%s", err, p.tailLog())
		default:
		}
		resp, err := client.Get(readyURL + "/ok")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("caddy did not become ready within 60s\n%s", p.tailLog())
}

// stopCaddy asks the instance to shut down cleanly through its admin API and
// waits for the process to actually exit, so the same address can be rebound
// and no residual process can serve the next instance's traffic.
func (p *caddyInstance) stopCaddy(t *testing.T) {
	t.Helper()
	p.stoppedMu.Lock()
	if p.stopped {
		p.stoppedMu.Unlock()
		return
	}
	p.stopped = true
	p.stoppedMu.Unlock()

	// the connection may be cut as the process exits mid-response; that is
	// expected, so a POST error is not fatal as long as the process exits
	if resp, err := http.Post(p.adminURL+"/stop", "application/json", nil); err == nil {
		resp.Body.Close()
	}

	select {
	case err := <-p.waitDone:
		if err != nil {
			t.Fatalf("caddy stopped unsuccessfully: %v\n%s", err, p.tailLog())
		}
	case <-time.After(30 * time.Second):
		_ = p.cmd.Process.Kill()
		t.Fatalf("caddy did not exit within 30s of a clean stop")
	}
}

func (p *caddyInstance) tailLog() string {
	b, err := os.ReadFile(p.logPath)
	if err != nil {
		return fmt.Sprintf("(unreadable log %s: %v)", p.logPath, err)
	}
	const max = 4000
	if len(b) > max {
		b = b[len(b)-max:]
	}
	return string(b)
}

// restartRound is one full restart cycle: stop the previous instance
// (if any), immediately start a new one with the same config on the same
// listen address, then run a complete request matrix whose bodies are unique
// to this round. All assertions are deltas against the test-process upstream
// counters, which survive the caddy restart, so any inherited retry budget,
// body or response header would be detected.
type restartRound struct {
	number int
	body   string
	query  string
	trace  string
}

func runRestartRound(t *testing.T, bin, cfgPath, runDir, adminURL, baseURL string, h2 bool, wantProto int,
	first, backup *failoverUpstream, prev *caddyInstance, rd restartRound,
) *caddyInstance {
	t.Helper()

	if prev != nil {
		prev.stopCaddy(t)
		// the stopped process must not be lingering on its admin port
		if conn, err := net.DialTimeout("tcp", adminHostPort(adminURL), 500*time.Millisecond); err == nil {
			conn.Close()
			t.Fatalf("admin port still accepting connections after clean stop")
		}
	}

	// restart immediately with the same configuration and the same listen
	// address; this must bind successfully and must not race a zombie
	inst := startCaddy(t, bin, cfgPath, runDir, adminURL, baseURL, h2)

	client := newFailoverClient(h2)

	// POST: first node dies before the final response; the backup must see
	// exactly this round's request, byte for byte, exactly once - not the body
	// or query of a previous round and not more than one attempt.
	t.Run(fmt.Sprintf("round%d POST failover exact replay", rd.number), func(t *testing.T) {
		baseFirst := first.hitCount("/retry-before")
		baseRecs := len(backup.recordings("/retry-before"))

		req, err := http.NewRequest(http.MethodPost, baseURL+"/retry-before?"+rd.query, strings.NewReader(rd.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Trace", rd.trace)

		resp, interim, _ := tracedDo(t, client, req)
		gotBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireBackupFinalResponse(t, resp, interim, gotBody, readErr, wantProto, "ok201")

		if got := first.hitCount("/retry-before") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		requireExactReplay(t, backup, "/retry-before", baseRecs, recordedRequest{
			method:        http.MethodPost,
			rawQuery:      rd.query,
			contentLength: int64(len(rd.body)),
			contentType:   "application/json",
			xTrace:        rd.trace,
			body:          []byte(rd.body),
		})
	})

	// GET and HEAD fail over the same way; HEAD returns no body but keeps the
	// GET length semantics, and every method reaches the backup exactly once.
	t.Run(fmt.Sprintf("round%d GET failover", rd.number), func(t *testing.T) {
		baseFirst := first.hitCount("/retry-before")
		baseRecs := len(backup.recordings("/retry-before"))

		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/retry-before"))
		gotBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireBackupFinalResponse(t, resp, interim, gotBody, readErr, wantProto, "ok201")
		if got := first.hitCount("/retry-before") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		requireExactReplay(t, backup, "/retry-before", baseRecs, recordedRequest{method: http.MethodGet})
	})

	t.Run(fmt.Sprintf("round%d HEAD failover length semantics", rd.number), func(t *testing.T) {
		baseFirst := first.hitCount("/retry-before")
		baseRecs := len(backup.recordings("/retry-before"))

		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodHead, baseURL+"/retry-before"))
		gotBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireBackupFinalResponse(t, resp, interim, gotBody, readErr, wantProto, "")
		if got := first.hitCount("/retry-before") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		requireExactReplay(t, backup, "/retry-before", baseRecs, recordedRequest{method: http.MethodHead})
	})

	// interim 103 then failure: ordering is preserved after a restart too.
	t.Run(fmt.Sprintf("round%d interim then failover", rd.number), func(t *testing.T) {
		baseBackup := backup.hitCount("/retry-info")

		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/retry-info"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)
		if len(interim) != 1 || interim[0].code != http.StatusEarlyHints {
			t.Fatalf("interim responses: got %v, want a single 103", interim)
		}
		if resp.StatusCode != http.StatusCreated || string(body) != "ok201" || readErr != nil {
			t.Fatalf("got %d %q (err=%v), want 201 ok201 clean", resp.StatusCode, body, readErr)
		}
		if got := backup.hitCount("/retry-info") - baseBackup; got != 1 {
			t.Errorf("backup upstream hits: got %d new, want 1", got)
		}
	})

	// the first node answers successfully: fixed order is preserved and the
	// backup is never contacted, in every round.
	t.Run(fmt.Sprintf("round%d first node success keeps order", rd.number), func(t *testing.T) {
		baseBackup := backup.hitCount("/ok")

		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/ok"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)
		if len(interim) != 0 {
			t.Errorf("interim responses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusOK || string(body) != "ok" || readErr != nil {
			t.Fatalf("got %d %q (err=%v), want 200 ok clean", resp.StatusCode, body, readErr)
		}
		if got := backup.hitCount("/ok") - baseBackup; got != 0 {
			t.Errorf("backup must not be contacted when the first node succeeds after a restart, got %d new hits", got)
		}
	})

	// the first node already produced a final response (and then truncated its
	// body): that response must be kept and never spliced with the backup.
	t.Run(fmt.Sprintf("round%d final response not spliced with backup", rd.number), func(t *testing.T) {
		baseFirst := first.hitCount("/partial")
		baseBackup := backup.hitCount("/partial")

		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/partial"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)
		if len(interim) != 0 {
			t.Errorf("interim responses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d, want 200 from the first node", resp.StatusCode)
		}
		if resp.Header.Get("X-Origin") != "first" {
			t.Errorf("X-Origin: got %q, want first (no backup splicing)", resp.Header.Get("X-Origin"))
		}
		if !bytes.HasPrefix(body, []byte("part1")) {
			t.Errorf("body: got %q, want the first node's part1 prefix", body)
		}
		if readErr == nil {
			t.Errorf("expected a truncated transfer error, got a clean read")
		}
		if got := first.hitCount("/partial") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		if got := backup.hitCount("/partial") - baseBackup; got != 0 {
			t.Errorf("backup must not be retried after a final response across a restart, got %d new hits", got)
		}
	})

	// both nodes fail: still a single clean gateway error, no leaked node data.
	t.Run(fmt.Sprintf("round%d both fail single 502", rd.number), func(t *testing.T) {
		baseFirst := first.hitCount("/all-fail")
		baseBackup := backup.hitCount("/all-fail")

		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/all-fail"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)
		if len(interim) != 2 {
			t.Errorf("interim responses: got %v, want the two 103s in order", interim)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status: got %d, want 502", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("502 body should read cleanly: %v", readErr)
		}
		if h := resp.Header.Get("X-Origin"); h != "" {
			t.Errorf("failed node header X-Origin leaked: %q", h)
		}
		if bytes.Contains(body, []byte("part1")) {
			t.Errorf("502 body contains an upstream fragment: %q", body)
		}
		if got := first.hitCount("/all-fail") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		if got := backup.hitCount("/all-fail") - baseBackup; got != 1 {
			t.Errorf("backup upstream hits: got %d new, want 1", got)
		}
	})

	// retries explicitly disabled for this route: the backup must never be
	// contacted for it, in any round, before or after any restart.
	t.Run(fmt.Sprintf("round%d no-retry never reaches backup", rd.number), func(t *testing.T) {
		baseFirst := first.hitCount("/no-retry")
		baseBackup := backup.hitCount("/no-retry")

		req, err := http.NewRequest(http.MethodPost, baseURL+"/no-retry?z=9", strings.NewReader(rd.body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, interim, _ := tracedDo(t, client, req)
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)
		if len(interim) != 0 {
			t.Errorf("interim responses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status: got %d, want 502", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("502 body should read cleanly: %v", readErr)
		}
		if bytes.Contains(body, []byte(rd.body)) {
			t.Errorf("502 body must not contain the request body: %q", body)
		}
		if got := first.hitCount("/no-retry") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		if got := backup.hitCount("/no-retry") - baseBackup; got != 0 {
			t.Errorf("backup must not be contacted on /no-retry after a restart, got %d new hits", got)
		}
	})

	return inst
}

// TestReverseProxyFailoverAcrossProcessRestarts drives the complete
// stop/restart matrix on a real caddy binary for plaintext HTTP/1.1 and TLS
// HTTP/2 sites. The two upstreams live in the test process and outlive every
// caddy restart, so their cumulative counters prove that each restart starts
// from zero: each round has its own distinct body, and the backup may observe
// exactly one copy of that round's request per failover - never a previous
// round's body/query, never a spent retry budget, and never a response from a
// failed node.
func TestReverseProxyFailoverAcrossProcessRestarts(t *testing.T) {
	bin := buildCaddyBinary(t)

	for _, tc := range []struct {
		name         string
		siteAddr     string // host:port of the caddy site
		siteHead     string // site block header line
		adminAddr    string // admin endpoint listen address
		adminURL     string
		h2           bool
		wantProto    int
		siteHostPort string
	}{
		{
			name:         "HTTP/1.1",
			siteAddr:     "127.0.0.1:9086",
			siteHead:     "http://127.0.0.1:9086",
			adminAddr:    "127.0.0.1:2998",
			adminURL:     "http://127.0.0.1:2998",
			h2:           false,
			wantProto:    1,
			siteHostPort: "127.0.0.1:9086",
		},
		{
			name:         "HTTP/2 over TLS",
			siteAddr:     "localhost:9449",
			siteHead:     "https://localhost:9449",
			adminAddr:    "127.0.0.1:2997",
			adminURL:     "http://127.0.0.1:2997",
			h2:           true,
			wantProto:    2,
			siteHostPort: "127.0.0.1:9449",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// fresh upstreams per protocol so the two matrices stay
			// independent, yet shared across all restarts of this matrix
			first := newFailoverUpstream(t, "first")
			backup := newFailoverUpstream(t, "backup")

			runDir := t.TempDir()
			baseURL := func() string {
				if tc.h2 {
					return "https://" + tc.siteAddr
				}
				return "http://" + tc.siteAddr
			}()

			blocks := failoverSiteBlocks(first.addr(), backup.addr())
			siteBlock := tc.siteHead + " {\n"
			if tc.h2 {
				siteBlock += "\ttls internal\n"
			}
			siteBlock += blocks + "\n}\n"
			cfgPath := writeRestartCaddyConfig(t, runDir, "Caddyfile", tc.adminAddr, siteBlock)

			rounds := []restartRound{
				{number: 1, body: `{"n":1}`, query: "a=1&b=2", trace: "t-7"},
				{number: 2, body: `{"n":2}`, query: "a=2&b=3", trace: "t-8"},
				{number: 3, body: `{"n":3}`, query: "a=3&b=4", trace: "t-9"},
			}

			var inst *caddyInstance
			t.Cleanup(func() {
				if inst != nil {
					inst.stopCaddy(t)
				}
			})
			for _, rd := range rounds {
				inst = runRestartRound(t, bin, cfgPath, runDir, tc.adminURL, baseURL, tc.h2, tc.wantProto,
					first, backup, inst, rd)
			}

			// after the last healthy round, a start with an unloadable
			// configuration must fail on its own and leave nothing serving;
			// the same address must then be bindable again by a healthy
			// instance.
			inst.stopCaddy(t)

			badCfg := filepath.Join(runDir, "Caddyfile.bad")
			if err := os.WriteFile(badCfg, []byte(fmt.Sprintf(`
			{
				skip_install_trust
				admin %s
			}
			%s {
				this_directive_does_not_exist
			}
			`, tc.adminAddr, tc.siteHead)), 0o600); err != nil {
				t.Fatalf("writing bad Caddyfile: %v", err)
			}
			startCaddyExpectingFailure(t, bin, badCfg, runDir, tc.siteHostPort)

			// the failed start must not have held onto the admin endpoint either
			if conn, err := net.DialTimeout("tcp", adminHostPort(tc.adminURL), time.Second); err == nil {
				conn.Close()
				t.Fatalf("admin port still accepting connections after a failed startup")
			}

			// the failed start poisoned nothing: the same config and address
			// start again, and failover behaves exactly as in every other round
			inst = startCaddy(t, bin, cfgPath, runDir, tc.adminURL, baseURL, tc.h2)
			client := newFailoverClient(tc.h2)
			func() {
				baseRecs := len(backup.recordings("/retry-before"))
				req, err := http.NewRequest(http.MethodPost, baseURL+"/retry-before?after=fail", strings.NewReader(`{"n":4}`))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Trace", "t-10")
				resp, interim, _ := tracedDo(t, client, req)
				body, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				requireBackupFinalResponse(t, resp, interim, body, readErr, tc.wantProto, "ok201")
				requireExactReplay(t, backup, "/retry-before", baseRecs, recordedRequest{
					method:        http.MethodPost,
					rawQuery:      "after=fail",
					contentLength: int64(len(`{"n":4}`)),
					contentType:   "application/json",
					xTrace:        "t-10",
					body:          []byte(`{"n":4}`),
				})
			}()
			inst.stopCaddy(t)
		})
	}
}
