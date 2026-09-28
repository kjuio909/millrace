//go:build !windows

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
	"syscall"
	"testing"
	"time"
)

// This file pins the observable readiness and failure boundaries of the only
// foreground entry point an automation caller uses:
//
//	caddy run --config <file> --adapter caddyfile
//
// Acceptance relies exclusively on externally observable signals - the
// process exit status, stderr and plain HTTP requests - never on internal
// state. The three outcomes a caller must distinguish are:
//
//   - not ready yet: the process is alive but the configured contract is not
//     being served yet (a connection failure during startup is a startup
//     phase signal, never a site 4xx/5xx);
//   - startup failed: the process exits non-zero in bounded time, stderr
//     carries the parse/initialisation/bind root cause and no listener
//     remains;
//   - business error: a ready service that stays up answers a request with an
//     upstream-generated 5xx.
//
// In addition, a request held open in the previous generation across a
// stop/restart on the same address finishes on the generation that accepted
// it, while the new generation answers new requests with only its own
// markers; repeated stops, failed starts and restarts are deterministic and
// leave the address reusable.

const (
	rrHoldPrefix = "A-inflight-prefix--"
	rrHoldSuffix = "A-inflight-suffix--"
)

// rrUpstream is a test-controlled HTTP/1.1 upstream. /hold answers with a
// chunked 200, flushes a marker header and body prefix, then parks the
// hijacked connection until released. /biz500 answers with a plain 500 so a
// business error can be told apart from a startup failure.
type rrUpstream struct {
	ln net.Listener

	mu   sync.Mutex
	held []net.Conn
}

func newRRUpstream(t *testing.T) *rrUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for upstream: %v", err)
	}
	u := &rrUpstream{ln: ln}
	srv := &http.Server{Handler: http.HandlerFunc(u.handle)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return u
}

func (u *rrUpstream) addr() string { return u.ln.Addr().String() }

func (u *rrUpstream) heldCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.held)
}

// releaseAll finalizes every parked /hold response with the A suffix and
// closes its connection.
func (u *rrUpstream) releaseAll() {
	u.mu.Lock()
	conns := u.held
	u.held = nil
	u.mu.Unlock()
	for _, conn := range conns {
		fmt.Fprintf(conn, "%x\r\n%s\r\n", len(rrHoldSuffix), rrHoldSuffix)
		_, _ = io.WriteString(conn, "0\r\n\r\n")
		_ = conn.Close()
	}
}

func (u *rrUpstream) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/hold":
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			panic(err)
		}
		_, _ = io.WriteString(rw,
			"HTTP/1.1 200 OK\r\n"+
				"X-Hold-Marker: hold-A\r\n"+
				"Transfer-Encoding: chunked\r\n"+
				"\r\n")
		fmt.Fprintf(rw, "%x\r\n%s\r\n", len(rrHoldPrefix), rrHoldPrefix)
		_ = rw.Flush()

		u.mu.Lock()
		u.held = append(u.held, conn)
		u.mu.Unlock()

		// park until releaseAll; after a Hijack the stdlib server no longer
		// touches this connection
		_, _ = io.Copy(io.Discard, rw)

	case "/biz500":
		w.Header().Set("X-Up-Err", "boom")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "up-500")

	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// rrProc is one running `caddy run` foreground process.
type rrProc struct {
	cmd     *exec.Cmd
	logPath string
	exited  chan struct{}
	exitErr error
}

func rrFreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocating port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// rrCaddyfile builds a plaintext wildcard HTTP site on the given port whose
// /version answers 200 with X-Version: <mark> and the two-byte body
// "<mark>\n" (a literal line break inside the quoted respond argument, per
// the readiness contract), and which proxies every other path (including
// /hold) to the test upstream. The site listens on the wildcard so it is
// reachable over 127.0.0.1; the admin endpoint is disabled so the foreground
// process is driven purely by signals.
func rrCaddyfile(port int, upstream, mark string) string {
	return fmt.Sprintf(`{
	skip_install_trust
	admin off
}
:%d {
	handle /version {
		header X-Version %s
		header X-Only-%s yes
		respond "%s
"
	}
	reverse_proxy %s
}
`, port, mark, mark, mark, upstream)
}

// rrHoldWildcard occupies the given port with a non-SO_REUSEPORT listener at
// wildcard specificity (the same [::] wildcard caddy binds), which reliably
// makes caddy's bind fail on both Linux and macOS.
func rrHoldWildcard(t *testing.T, port int) net.Listener {
	t.Helper()
	if ln, err := net.Listen("tcp6", fmt.Sprintf("[::]:%d", port)); err == nil {
		return ln
	}
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Skipf("cannot occupy wildcard port %d for the bind-conflict case: %v", port, err)
	}
	return ln
}

func rrWriteConfig(t *testing.T, dir, name, contents string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

func rrStart(t *testing.T, bin, cfgPath, runDir string) *rrProc {
	t.Helper()
	stem := strings.TrimSuffix(filepath.Base(cfgPath), filepath.Ext(cfgPath))
	logFile, err := os.Create(filepath.Join(runDir, stem+".log"))
	if err != nil {
		t.Fatalf("creating log file: %v", err)
	}
	cmd := exec.Command(bin, "run", "--config", cfgPath, "--adapter", "caddyfile")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = isolatedCaddyEnv(runDir, "state")
	if err := cmd.Start(); err != nil {
		logFile.Close()
		t.Fatalf("starting caddy: %v", err)
	}
	p := &rrProc{cmd: cmd, logPath: logFile.Name(), exited: make(chan struct{})}
	go func() {
		p.exitErr = cmd.Wait()
		close(p.exited)
		logFile.Close()
	}()
	return p
}

func (p *rrProc) alive() bool {
	select {
	case <-p.exited:
		return false
	default:
		return true
	}
}

func (p *rrProc) tail(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(p.logPath)
	if err != nil {
		return "(unreadable log)"
	}
	const max = 3000
	if len(b) > max {
		b = b[len(b)-max:]
	}
	return string(b)
}

// terminate sends SIGTERM. A repeat call after the process has exited is a
// deterministic error (the process no longer exists), never a panic.
func (p *rrProc) terminate() error { return p.cmd.Process.Signal(syscall.SIGTERM) }

func (p *rrProc) waitExit(t *testing.T, timeout time.Duration, label string) {
	t.Helper()
	select {
	case <-p.exited:
	case <-time.After(timeout):
		_ = p.cmd.Process.Kill()
		t.Fatalf("%s: process did not exit within %s\n%s", label, timeout, p.tail(t))
	}
}

// rrExpectReady polls until the full readiness contract holds at once: the
// process is alive, the port serves and /version answers 200, X-Version and
// the generation-exclusive X-Only-<mark> header, and the exact body. Process
// creation or a briefly-open port never count; a connection failure while the
// process is still starting is the startup ("not ready yet") phase, not an
// HTTP status.
func rrExpectReady(t *testing.T, p *rrProc, baseURL, mark string) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	wantBody := mark + "\n"
	deadline := time.Now().Add(60 * time.Second)
	var lastOdd string
	for time.Now().Before(deadline) {
		if !p.alive() {
			t.Fatalf("process exited before becoming ready\n%s", p.tail(t))
		}
		resp, err := client.Get(baseURL + "/version")
		if err != nil {
			time.Sleep(50 * time.Millisecond) // not ready yet
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// exactly one exclusive marker header must be present and it must be
		// this generation's; no previous generation header may leak
		onlyMark := resp.Header.Get("X-Only-" + mark)
		foreign := otherOnlyHeader(resp.Header, mark)
		if resp.StatusCode == http.StatusOK &&
			resp.Header.Get("X-Version") == mark &&
			onlyMark == "yes" && foreign == "" &&
			string(body) == wantBody {
			return
		}
		lastOdd = fmt.Sprintf("status=%d X-Version=%q X-Only-%s=%q foreign=%q body=%q",
			resp.StatusCode, resp.Header.Get("X-Version"), mark, onlyMark, foreign, string(body))
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("readiness contract never held (200 + X-Version %q + exclusive header + %q): %s\n%s",
		mark, wantBody, lastOdd, p.tail(t))
}

// otherOnlyHeader reports any X-Only-<x> response header whose <x> is not the
// expected mark, proving no exclusive header from a different generation
// leaked onto this response.
func otherOnlyHeader(h http.Header, mark string) string {
	for name := range h {
		if strings.HasPrefix(name, "X-Only-") {
			if got := strings.TrimPrefix(name, "X-Only-"); got != mark || h.Get(name) != "yes" {
				return name + "=" + h.Get(name)
			}
		}
	}
	return ""
}

// rrExpectStartupFailure runs a config that must not start: the process exits
// non-zero in bounded time and stderr names one of the parse/init/bind root
// causes. Port cleanup is asserted separately (rrAssertPortClosed) because a
// bind-conflict case intentionally keeps an unrelated holder on the address.
func rrExpectStartupFailure(t *testing.T, bin, cfgPath, runDir string, rootCauses ...string) {
	t.Helper()
	p := rrStart(t, bin, cfgPath, runDir)
	p.waitExit(t, 20*time.Second, "invalid config startup")
	if p.exitErr == nil {
		t.Fatalf("invalid config exited successfully; want non-zero\n%s", p.tail(t))
	}
	log := p.tail(t)
	for _, cause := range rootCauses {
		if strings.Contains(log, cause) {
			return
		}
	}
	t.Fatalf("stderr names none of the root causes %v:\n%s", rootCauses, log)
}

func rrAssertPortClosed(t *testing.T, hostPort string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", hostPort, time.Second)
	if err == nil {
		conn.Close()
		t.Fatalf("%s still accepts connections after startup failure", hostPort)
	}
}

func rrWaitUntil(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestCaddyRunReadinessAndFailureBoundaries drives `caddy run --adapter
// caddyfile` exactly as an automation caller would and asserts the three
// distinguishable outcomes plus cross-restart isolation.
func TestCaddyRunReadinessAndFailureBoundaries(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subprocess boundaries test in short mode")
	}
	bin := buildCaddyBinary(t)
	upstream := newRRUpstream(t)

	sitePort := rrFreePort(t)
	siteHostPort := fmt.Sprintf("127.0.0.1:%d", sitePort)
	baseURL := "http://" + siteHostPort

	runDir := t.TempDir()
	cfgA := rrWriteConfig(t, runDir, "a.Caddyfile", rrCaddyfile(sitePort, upstream.addr(), "A"))
	cfgB := rrWriteConfig(t, runDir, "b.Caddyfile", rrCaddyfile(sitePort, upstream.addr(), "B"))

	// 1. readiness, and a business 500 is not a startup failure.
	t.Run("readiness contract and business 500", func(t *testing.T) {
		a := rrStart(t, bin, cfgA, runDir)
		t.Cleanup(func() {
			if a.alive() {
				_ = a.terminate()
				a.waitExit(t, 10*time.Second, "cleanup")
			}
		})
		rrExpectReady(t, a, baseURL, "A")

		resp, err := http.Get(baseURL + "/biz500")
		if err != nil {
			t.Fatalf("GET /biz500: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("business error status: got %d, want 500", resp.StatusCode)
		}
		if resp.Header.Get("X-Up-Err") != "boom" || string(body) != "up-500" {
			t.Fatalf("business error not passed through: header=%q body=%q",
				resp.Header.Get("X-Up-Err"), string(body))
		}
		if !a.alive() {
			t.Fatal("a business 500 killed the ready process")
		}
		// the service is still serving its contract: a business error did
		// not change readiness state
		rrExpectReady(t, a, baseURL, "A")
	})

	// 2. startup failures exit non-zero in bounded time, name the root cause,
	// leave no listener and do not prevent the address from being reclaimed.
	t.Run("startup failures are bounded and clean", func(t *testing.T) {
		failDir := t.TempDir()

		// truncated Caddyfile syntax: the block is never closed, so parsing
		// hits EOF before any listener exists
		trunc := rrWriteConfig(t, failDir, "trunc.Caddyfile",
			fmt.Sprintf("http://%s {\n\thandle /version {\n\t\theader X-Version A\n", siteHostPort))
		rrExpectStartupFailure(t, bin, trunc, failDir, "unexpected EOF", "syntax error", "unexpected token")
		rrAssertPortClosed(t, siteHostPort)

		// unknown directive
		unknown := rrWriteConfig(t, failDir, "unknown.Caddyfile",
			fmt.Sprintf("http://%s {\n\tbaddirective_xyz foo\n}\n", siteHostPort))
		rrExpectStartupFailure(t, bin, unknown, failDir, "unrecognized directive")
		rrAssertPortClosed(t, siteHostPort)

		// bind conflict: a non-reusing wildcard listener owns the same
		// wildcard caddy binds; caddy must fail rather than silently share.
		// While the holder is alive the port is (correctly) held by it; once
		// it closes, the failed caddy must have left nothing behind.
		bindConflict := func() {
			holder := rrHoldWildcard(t, sitePort)
			rrExpectStartupFailure(t, bin, cfgA, failDir, "address already in use", "bind:")
			holder.Close()
			rrAssertPortClosed(t, siteHostPort)
		}
		bindConflict()

		// after the failed start the address is reclaimed by a valid instance
		ok := rrStart(t, bin, cfgA, runDir)
		rrExpectReady(t, ok, baseURL, "A")
		_ = ok.terminate()
		ok.waitExit(t, 10*time.Second, "reclaim instance")
		rrAssertPortClosed(t, siteHostPort)

		// a second failed start, then another successful start, stays
		// deterministic and leaves the address reusable
		bindConflict()
		retry := rrStart(t, bin, cfgA, runDir)
		rrExpectReady(t, retry, baseURL, "A")
		_ = retry.terminate()
		retry.waitExit(t, 10*time.Second, "post-failure instance")
		rrAssertPortClosed(t, siteHostPort)
	})

	// 3. a request in flight across a stop/restart stays on the old
	// generation; new requests only see the new generation; the address is
	// reusable and a repeat stop is deterministic.
	t.Run("held request across restart stays isolated", func(t *testing.T) {
		a := rrStart(t, bin, cfgA, runDir)
		t.Cleanup(func() {
			if a.alive() {
				_ = a.terminate()
				a.waitExit(t, 10*time.Second, "cleanup A")
			}
		})
		rrExpectReady(t, a, baseURL, "A")

		holdClient := &http.Client{Timeout: 0}
		type holdResult struct {
			status int
			marker string
			rest   []byte
			err    error
		}
		resultCh := make(chan holdResult, 1)
		go func() {
			resp, err := holdClient.Get(baseURL + "/hold")
			if err != nil {
				resultCh <- holdResult{err: err}
				return
			}
			prefix := make([]byte, len(rrHoldPrefix))
			if _, err := io.ReadFull(resp.Body, prefix); err != nil {
				resultCh <- holdResult{err: err}
				return
			}
			if string(prefix) != rrHoldPrefix {
				resultCh <- holdResult{err: fmt.Errorf("prefix: got %q", prefix)}
				return
			}
			rest, _ := io.ReadAll(resp.Body)
			resultCh <- holdResult{
				status: resp.StatusCode,
				marker: resp.Header.Get("X-Hold-Marker"),
				rest:   rest,
			}
		}()

		// wait until the A prefix has been delivered and the connection is
		// parked at the upstream, proving the request is in flight on A
		rrWaitUntil(t, func() bool { return upstream.heldCount() > 0 },
			"held request never parked at upstream")

		// stop A with the request still open, then immediately start B on the
		// same address
		if err := a.terminate(); err != nil {
			t.Fatalf("SIGTERM A: %v", err)
		}
		b := rrStart(t, bin, cfgB, runDir)
		t.Cleanup(func() {
			if b.alive() {
				_ = b.terminate()
				b.waitExit(t, 10*time.Second, "cleanup B")
			}
		})
		rrExpectReady(t, b, baseURL, "B")

		// new requests, over fresh connections, only ever see B: status,
		// version header, exclusive B-only header, no A-only header and the B
		// body - nothing from the previous generation leaks
		for i := 0; i < 10; i++ {
			resp, err := http.Get(baseURL + "/version")
			if err != nil {
				t.Fatalf("post-restart probe %d: %v", i, err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK ||
				resp.Header.Get("X-Version") != "B" ||
				resp.Header.Get("X-Only-B") != "yes" ||
				resp.Header.Get("X-Only-A") != "" ||
				string(body) != "B\n" {
				t.Fatalf("probe %d leaked prior generation / wrong contract: "+
					"status=%d X-Version=%q X-Only-B=%q X-Only-A=%q body=%q",
					i, resp.StatusCode, resp.Header.Get("X-Version"),
					resp.Header.Get("X-Only-B"), resp.Header.Get("X-Only-A"), string(body))
			}
		}

		// release the parked upstream response: the held client must receive
		// exactly the remainder of generation A's answer, with no B content
		upstream.releaseAll()
		select {
		case res := <-resultCh:
			if res.err != nil {
				t.Fatalf("held request did not finish on generation A: %v", res.err)
			}
			if res.status != http.StatusOK {
				t.Fatalf("held status: got %d, want 200", res.status)
			}
			if res.marker != "hold-A" {
				t.Fatalf("held marker: got %q, want hold-A", res.marker)
			}
			if string(res.rest) != rrHoldSuffix {
				t.Fatalf("held suffix: got %q, want %q", res.rest, rrHoldSuffix)
			}
			if bytes.Contains(res.rest, []byte("B")) {
				t.Fatalf("held response spliced with B content: %q", res.rest)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("held request never completed after release")
		}

		// A drains fully once its held request completes and exits cleanly; it
		// never answered with B
		a.waitExit(t, 15*time.Second, "generation A after held request drained")

		// B shuts down cleanly; a repeat stop on the exited process is a
		// deterministic no-op/error rather than a hang
		if err := b.terminate(); err != nil {
			t.Fatalf("SIGTERM B: %v", err)
		}
		b.waitExit(t, 10*time.Second, "generation B")
		if err := b.terminate(); err == nil {
			t.Fatal("a repeat SIGTERM on the exited process unexpectedly succeeded")
		}

		// the same address is reusable, immediately and repeatedly, alternating
		// configs
		for round, cfgMark := range []struct{ cfg, mark string }{
			{cfgA, "A"}, {cfgB, "B"}, {cfgA, "A"},
		} {
			r := rrStart(t, bin, cfgMark.cfg, runDir)
			rrExpectReady(t, r, baseURL, cfgMark.mark)
			_ = r.terminate()
			r.waitExit(t, 10*time.Second, fmt.Sprintf("rebind round %d", round+1))
		}
	})
}
