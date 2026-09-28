package integration

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This file verifies the failure boundaries around POST /load and process
// startup against a real `caddy` subprocess:
//
//   - every malformed load (empty body, null, truncated JSON, JSON with
//     trailing data, a public field of the wrong type, or a config that fails
//     validation) is refused with the admin API's JSON error expression in
//     finite time, and the last known good configuration keeps answering with
//     byte-identical status, headers and body; the configured admin listener
//     never migrates to or briefly falls back to the default endpoint;
//   - a refused load does not consume a later, valid load;
//   - malformed initial configurations (syntax error, unknown Caddyfile
//     directive/global option, listen address conflict) make the process exit
//     non-zero in finite time with an identifiable root cause on stderr,
//     without keeping any listener, and the address is reclaimable by a
//     valid configuration afterwards;
//   - an upstream 500 served by an already-ready site is a business result,
//     not a readiness or startup failure.
//
// The malformed-load matrix runs on both a plaintext HTTP/1.1 site (native
// JSON loads) and an HTTPS site configured with `tls internal` (valid loads
// submitted as Caddyfiles), so the protocol cannot change the boundary.

const (
	clAdminAddr = "127.0.0.1:2988"
	clAdminURL  = "http://" + clAdminAddr
	clSiteAddr  = "127.0.0.1:9090"
	clSiteURL   = "http://" + clSiteAddr

	clH2AdminAddr = "127.0.0.1:2989"
	clH2AdminURL  = "http://" + clH2AdminAddr
	clH2SiteAddr  = "localhost:9455"
	clH2SiteURL   = "https://" + clH2SiteAddr
)

// exactResponse captures everything a client can observe from one response,
// so two configuration rounds can be compared exactly.
type exactResponse struct {
	status int
	header http.Header
	body   string
	proto  int
}

func getExact(t *testing.T, client *http.Client, url string) exactResponse {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading %s body: %v", url, err)
	}
	return exactResponse{
		status: resp.StatusCode,
		header: resp.Header.Clone(),
		body:   string(body),
		proto:  resp.ProtoMajor,
	}
}

// assertExactResponse compares two responses in full; the Date header is the
// only per-response value the server cannot hold constant and is excluded.
func assertExactResponse(t *testing.T, got, want exactResponse, wantProto int, where string) {
	t.Helper()
	if got.status != want.status {
		t.Errorf("%s: status: got %d, want %d", where, got.status, want.status)
	}
	if got.body != want.body {
		t.Errorf("%s: body: got %q, want %q", where, got.body, want.body)
	}
	if got.proto != wantProto {
		t.Errorf("%s: protocol: got HTTP/%d, want HTTP/%d", where, got.proto, wantProto)
	}
	wantHeader := want.header.Clone()
	gotHeader := got.header.Clone()
	wantHeader.Del("Date")
	gotHeader.Del("Date")
	if len(gotHeader) != len(wantHeader) {
		t.Errorf("%s: response header set: got %v, want %v", where, gotHeader, wantHeader)
		return
	}
	for name, values := range wantHeader {
		if gotValues := gotHeader.Values(name); strings.Join(gotValues, ",") != strings.Join(values, ",") {
			t.Errorf("%s: header %q: got %v, want %v", where, name, gotValues, values)
		}
	}
}

// postLoadRaw submits a raw body to /load and returns the status code and
// response body, using a fresh connection for every call so connection state
// can never leak between rounds.
func postLoadRaw(t *testing.T, adminURL, contentType string, body []byte) (int, string) {
	t.Helper()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(adminURL+"/load", contentType, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /load: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading /load error response: %v", err)
	}
	return resp.StatusCode, string(respBody)
}

// dialRefuses reports that nothing is accepting TCP connections on addr
// within a short deadline, used to prove a failed instance kept no listener.
func dialRefuses(t *testing.T, addr string) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return true
		}
		conn.Close()
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

type invalidLoadCase struct {
	name        string
	contentType string
	body        string
	// wantErr is a substring the admin error response must contain
	wantErr string
}

func invalidJSONLoadCases(validJSONB string) []invalidLoadCase {
	return []invalidLoadCase{
		{
			name:        "empty body",
			contentType: "application/json",
			body:        "",
			wantErr:     "request body is empty",
		},
		{
			name:        "whitespace only",
			contentType: "application/json",
			body:        "   \n\t ",
			wantErr:     "request body is empty",
		},
		{
			name:        "null document",
			contentType: "application/json",
			body:        "null",
			wantErr:     "configuration must be a JSON object, got null",
		},
		{
			name:        "truncated JSON",
			contentType: "application/json",
			body:        `{"apps":`,
			wantErr:     "unexpected end of JSON input",
		},
		{
			name:        "trailing data after JSON",
			contentType: "application/json",
			body:        validJSONB + "GARBAGE",
			wantErr:     "after top-level value",
		},
		{
			// http_port is a public, documented field of the http app;
			// handing it a string exercises the same decode-error path as
			// any third-party field typo
			name:        "wrong field type",
			contentType: "application/json",
			body:        `{"apps":{"http":{"http_port":"not-a-number","servers":{"srv0":{"listen":["` + clSiteAddr + `"]}}}}}`,
			wantErr:     "cannot unmarshal string",
		},
		{
			name:        "duplicate listener validation",
			contentType: "application/json",
			body: fmt.Sprintf(`{"apps":{"http":{"servers":{
				"one":{"listen":[%q],"routes":[]},
				"two":{"listen":[%q],"routes":[]}
			}}}}`, clSiteAddr, clSiteAddr),
			wantErr: "listener address repeated",
		},
	}
}

func invalidCaddyfileLoadCases(validCaddyfileB string) []invalidLoadCase {
	return []invalidLoadCase{
		{
			// an empty POST must be refused before adaptation regardless
			// of the adapter, so it can never blank out the running config
			name:        "empty body",
			contentType: "text/caddyfile",
			body:        "",
			wantErr:     "request body is empty",
		},
		{
			name:        "null as JSON",
			contentType: "application/json",
			body:        "null",
			wantErr:     "configuration must be a JSON object, got null",
		},
		{
			name:        "truncated Caddyfile",
			contentType: "text/caddyfile",
			body: fmt.Sprintf(`%s {
	tls internal
	handle /version {
		respond "A"
`, clH2SiteAddr),
			wantErr: "unexpected EOF",
		},
		{
			name:        "unknown Caddyfile directive",
			contentType: "text/caddyfile",
			body: fmt.Sprintf(`%s {
	tls internal
	bogus_directive_xyz
}`, clH2SiteAddr),
			wantErr: "unrecognized directive",
		},
		{
			// a directive appearing after a complete site block (rather
			// than inside one) makes adaptation fail; nothing partial may
			// be applied before the error is returned
			name:        "trailing directive after site block",
			contentType: "text/caddyfile",
			body:        validCaddyfileB + `respond "x"` + "\n",
			wantErr:     "directives must appear in a site block",
		},
		{
			name:        "duplicate listener validation",
			contentType: "application/json",
			body: fmt.Sprintf(`{"apps":{"http":{"servers":{
				"one":{"listen":[%q],"routes":[]},
				"two":{"listen":[%q],"routes":[]}
			}}}}`, clH2SiteAddr, clH2SiteAddr),
			wantErr: "listener address repeated",
		},
	}
}

// runMalformedLoadMatrix drives one protocol matrix: start A, snapshot its
// exact /version answer, submit every invalid payload (checking the site and
// admin endpoints after each), then prove B and A still load successfully.
func runMalformedLoadMatrix(t *testing.T, bin string, h2 bool,
	adminURL, siteURL, adminAddr, siteAddr string,
	cfgA, cfgB string, contentTypeAB string,
	cases []invalidLoadCase) {
	t.Helper()

	runDir := t.TempDir()
	ext := ".json"
	adapter := ""
	if h2 {
		ext = ".Caddyfile"
		adapter = "caddyfile"
	}
	cfgPath := filepath.Join(runDir, "initial"+ext)
	if err := os.WriteFile(cfgPath, []byte(cfgA), 0o600); err != nil {
		t.Fatalf("writing initial config: %v", err)
	}

	inst := startReloadCaddy(t, bin, cfgPath, adapter, runDir, adminURL, siteURL, h2, http.StatusCreated)
	t.Cleanup(func() { inst.stopCaddy(t) })

	wantProto := 1
	if h2 {
		wantProto = 2
	}
	wantA := versionExpectation{status: http.StatusCreated, variant: "A", body: versionABody}
	wantB := versionExpectation{status: http.StatusAccepted, variant: "B", body: versionBBody}

	// snapshot the exact A answer on both a fresh and a reused connection
	freshClient := newFailoverClient(h2)
	reusedClient := newFailoverClient(h2)
	baseline := getExact(t, freshClient, siteURL+"/version")
	getExact(t, reusedClient, siteURL+"/version").assertExact(t, baseline, wantProto, "A baseline on reused connection")

	for i, tc := range cases {
		status, respBody := postLoadRaw(t, adminURL, tc.contentType, []byte(tc.body))
		if status != http.StatusBadRequest {
			t.Fatalf("%s (#%d): POST /load status: got %d, want 400; body: %s", tc.name, i, status, respBody)
		}
		if !strings.Contains(respBody, tc.wantErr) {
			t.Fatalf("%s (#%d): POST /load error: got %q, want it to contain %q", tc.name, i, respBody, tc.wantErr)
		}

		// the site must answer exactly A on brand-new connections ...
		where := fmt.Sprintf("after rejected load %q", tc.name)
		got := getExact(t, freshClient, siteURL+"/version")
		assertExactResponse(t, got, baseline, wantProto, where+" (new connection)")
		got.assertExpectation(t, wantA, wantProto, where+" (new connection)")
		// ... and on the keep-alive connection that predates the failure
		got = getExact(t, reusedClient, siteURL+"/version")
		assertExactResponse(t, got, baseline, wantProto, where+" (reused connection)")
		got.assertExpectation(t, wantA, wantProto, where+" (reused connection)")

		// the configured admin endpoint must still answer, and the
		// configuration it reports must still be the old one: this proves
		// the endpoint neither briefly fell back to the default
		// configuration nor migrated to the default admin address (a
		// migrated endpoint would no longer answer here at all)
		adminClient := &http.Client{Timeout: 5 * time.Second}
		resp, err := adminClient.Get(adminURL + "/config/")
		if err != nil {
			t.Fatalf("%s: configured admin endpoint unreachable after rollback: %v", tc.name, err)
		}
		servedCfg, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: admin /config/ status: got %d, want 200", tc.name, resp.StatusCode)
		}
		if !strings.Contains(string(servedCfg), adminAddr) {
			t.Errorf("%s: running config after rollback no longer names admin %s:\n%s", tc.name, adminAddr, servedCfg)
		}
		// the bad document must never have replaced the stored config
		if strings.Contains(string(servedCfg), "bogus_directive_xyz") {
			t.Errorf("%s: rejected Caddyfile content leaked into the running config:\n%s", tc.name, servedCfg)
		}
	}

	// failures must not consume later successful loads: B then A
	assertLoadSucceeds(t, adminURL, contentTypeAB, cfgB, "load B after failures")
	gotB := getExact(t, freshClient, siteURL+"/version")
	gotB.assertExpectation(t, wantB, wantProto, "B after failures")

	assertLoadSucceeds(t, adminURL, contentTypeAB, cfgA, "reload A after failures")
	getExact(t, freshClient, siteURL+"/version").assertExpectation(t, wantA, wantProto, "A after failures")
}

func (r exactResponse) assertExpectation(t *testing.T, want versionExpectation, wantProto int, where string) {
	t.Helper()
	if r.status != want.status {
		t.Errorf("%s: status: got %d, want %d", where, r.status, want.status)
	}
	if got := r.header.Get("X-Variant"); got != want.variant {
		t.Errorf("%s: X-Variant: got %q, want %q", where, got, want.variant)
	}
	if r.body != want.body {
		t.Errorf("%s: body: got %q, want %q", where, r.body, want.body)
	}
	if r.proto != wantProto {
		t.Errorf("%s: protocol: got HTTP/%d, want HTTP/%d", where, r.proto, wantProto)
	}
}

func (r exactResponse) assertExact(t *testing.T, want exactResponse, wantProto int, where string) {
	t.Helper()
	assertExactResponse(t, r, want, wantProto, where)
}

// TestConfigLoadMalformedPayloadsRollback verifies the malformed-load
// matrix on both the plaintext HTTP/1.1 and the tls internal HTTPS site.
func TestConfigLoadMalformedPayloadsRollback(t *testing.T) {
	bin := buildCaddyBinary(t)

	// Plaintext HTTP/1.1: valid A/B loads are native JSON.
	upstream := newReloadHoldUpstream(t) // unused here but keeps builders uniform
	jsonA := reloadJSONA(clAdminAddr, clSiteAddr, upstream.addr())
	jsonB := reloadJSONB(clAdminAddr, clSiteAddr)

	t.Run("HTTP/1.1 plaintext", func(t *testing.T) {
		runMalformedLoadMatrix(t, bin, false,
			clAdminURL, clSiteURL, clAdminAddr, clSiteAddr,
			jsonA, jsonB, "application/json",
			invalidJSONLoadCases(jsonB))
	})

	// HTTPS with tls internal: valid A/B loads are Caddyfiles.
	caddyfileA := reloadCaddyfileA(clH2AdminAddr, clH2SiteAddr, upstream.addr())
	caddyfileB := reloadCaddyfileB(clH2AdminAddr, clH2SiteAddr)

	t.Run("HTTP/2 over TLS internal", func(t *testing.T) {
		runMalformedLoadMatrix(t, bin, true,
			clH2AdminURL, clH2SiteURL, clH2AdminAddr, clH2SiteAddr,
			caddyfileA, caddyfileB, "text/caddyfile",
			invalidCaddyfileLoadCases(caddyfileB))
	})
}

// runCaddyAwaitingExit starts `caddy run` with the given config and requires
// it to exit on its own within the deadline, returning the exit code and the
// combined stdout/stderr output. It fails the test if the process has to be
// killed (a startup failure must terminate in finite time).
func runCaddyAwaitingExit(t *testing.T, bin, cfgPath, adapter, runDir string, deadline time.Duration) (int, string) {
	t.Helper()
	args := []string{"run", "--config", cfgPath}
	if adapter != "" {
		args = append(args, "--adapter", adapter)
	}
	cmd := exec.Command(bin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Env = isolatedCaddyEnv(runDir, "state")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting caddy: %v", err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	select {
	case err := <-waitDone:
		exitCode := 0
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				t.Fatalf("waiting for caddy: %v", err)
			}
		}
		return exitCode, out.String()
	case <-time.After(deadline):
		_ = cmd.Process.Kill()
		t.Fatalf("caddy did not exit within %s of a bad startup config\n%s", deadline, out.String())
		return 0, ""
	}
}

// writeStartupConfig writes one startup fixture and returns its path.
func writeStartupConfig(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return p
}

// TestCaddyStartupFailures covers the three startup-time root causes: a
// syntax error, an unknown directive, and a listen address conflict. Each
// must end the process non-zero with an identifiable cause on stderr and no
// lingering listener; the conflicting address must be reclaimable.
func TestCaddyStartupFailures(t *testing.T) {
	bin := buildCaddyBinary(t)

	t.Run("syntax error exits non-zero", func(t *testing.T) {
		runDir := t.TempDir()
		cfgPath := writeStartupConfig(t, runDir, "bad.json",
			`{
				"admin": {"listen": "127.0.0.1:2986"},
				"apps": {`)
		code, out := runCaddyAwaitingExit(t, bin, cfgPath, "", runDir, 30*time.Second)
		if code == 0 {
			t.Fatalf("exit code: got 0, want non-zero\n%s", out)
		}
		if !strings.Contains(out, "unexpected end of JSON input") {
			t.Fatalf("stderr does not identify the syntax error root cause:\n%s", out)
		}
		if !dialRefuses(t, "127.0.0.1:2986") {
			t.Errorf("failed instance left its admin listener bound")
		}
	})

	t.Run("unknown directive exits non-zero", func(t *testing.T) {
		runDir := t.TempDir()
		cfgBody := `{
	skip_install_trust
	admin 127.0.0.1:2985
}
:9093 {
	bogus_directive_xyz
}
`
		cfgPath := writeStartupConfig(t, runDir, "bad.Caddyfile", cfgBody)
		code, out := runCaddyAwaitingExit(t, bin, cfgPath, "caddyfile", runDir, 30*time.Second)
		if code == 0 {
			t.Fatalf("exit code: got 0, want non-zero\n%s", out)
		}
		if !strings.Contains(out, "unrecognized directive: bogus_directive_xyz") {
			t.Fatalf("stderr does not identify the unknown directive root cause:\n%s", out)
		}
		if !dialRefuses(t, "127.0.0.1:2985") {
			t.Errorf("failed instance left its admin listener bound")
		}
		if !dialRefuses(t, "127.0.0.1:9093") {
			t.Errorf("failed instance left its site listener bound")
		}
	})

	t.Run("unknown global option exits non-zero", func(t *testing.T) {
		runDir := t.TempDir()
		cfgBody := `{
	skip_install_trust
	admin 127.0.0.1:2984
	bogus_global_option_xyz
}
:9094 {
	respond "A"
}
`
		cfgPath := writeStartupConfig(t, runDir, "bad.Caddyfile", cfgBody)
		code, out := runCaddyAwaitingExit(t, bin, cfgPath, "caddyfile", runDir, 30*time.Second)
		if code == 0 {
			t.Fatalf("exit code: got 0, want non-zero\n%s", out)
		}
		if !strings.Contains(out, "unrecognized global option: bogus_global_option_xyz") {
			t.Fatalf("stderr does not identify the unknown global option root cause:\n%s", out)
		}
		if !dialRefuses(t, "127.0.0.1:2984") {
			t.Errorf("failed instance left its admin listener bound")
		}
	})

	t.Run("listen address conflict exits non-zero and address is reclaimable", func(t *testing.T) {
		const (
			siteAddr  = "127.0.0.1:9095"
			adminAddr = "127.0.0.1:2983"
		)

		// a plain (non-SO_REUSEPORT) holder owns the site address
		holder, err := net.Listen("tcp", siteAddr)
		if err != nil {
			t.Fatalf("holding %s: %v", siteAddr, err)
		}
		defer holder.Close()
		go func() {
			for {
				conn, err := holder.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()

		runDir := t.TempDir()
		cfg := fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {"http": {"servers": {"srv0": {
		"listen": [%q],
		"routes": [{
			"match": [{"path": ["/version"]}],
			"handle": [{
				"handler": "static_response",
				"status_code": 200,
				"headers": {"X-Variant": ["A"]},
				"body": "A"
			}]
		}]
	}}}}
}`, adminAddr, siteAddr)
		cfgPath := writeStartupConfig(t, runDir, "conflict.json", cfg)

		code, out := runCaddyAwaitingExit(t, bin, cfgPath, "", runDir, 30*time.Second)
		if code == 0 {
			t.Fatalf("exit code: got 0, want non-zero\n%s", out)
		}
		if !strings.Contains(out, "address already in use") {
			t.Fatalf("stderr does not identify the address conflict root cause:\n%s", out)
		}
		// the failed instance must not keep its own admin listener ...
		if !dialRefuses(t, adminAddr) {
			t.Errorf("failed instance left its admin listener bound")
		}
		// ... and once the holder is gone a valid config reclaims the address
		holder.Close()

		validDir := t.TempDir()
		validPath := writeStartupConfig(t, validDir, "valid.json", cfg)
		inst := startReloadCaddy(t, bin, validPath, "", validDir,
			"http://"+adminAddr, "http://"+siteAddr, false, http.StatusOK)
		t.Cleanup(func() { inst.stopCaddy(t) })

		resp, err := newFailoverClient(false).Get("http://" + siteAddr + "/version")
		if err != nil {
			t.Fatalf("valid config could not reclaim %s: %v", siteAddr, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK || string(body) != "A" {
			t.Fatalf("reclaimed site: got %d %q, want 200 A", resp.StatusCode, string(body))
		}
	})
}

// TestOnlineStartFailureRollback covers a failure that happens not while
// decoding/provisioning but while an app is starting: the new configuration
// declares a listener held by an unrelated, non-SO_REUSEPORT socket. The
// load must be rejected, the last good configuration must keep serving, its
// admin endpoint must stay on its address, and a later valid load must
// still succeed.
func TestOnlineStartFailureRollback(t *testing.T) {
	bin := buildCaddyBinary(t)

	const (
		adminAddr = "127.0.0.1:2981"
		adminURL  = "http://" + adminAddr
		siteAddr  = "127.0.0.1:9098"
		siteURL   = "http://" + siteAddr
		bindAddr  = "127.0.0.1:9099"
	)

	// an unrelated socket owns bindAddr without SO_REUSEPORT, so the new
	// server cannot bind it at Start time
	holder, err := net.Listen("tcp", bindAddr)
	if err != nil {
		t.Fatalf("holding %s: %v", bindAddr, err)
	}
	defer holder.Close()
	go func() {
		for {
			conn, err := holder.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	runDir := t.TempDir()
	cfgA := reloadJSONA(adminAddr, siteAddr, "127.0.0.1:1") // upstream unused by this config
	cfgPath := writeStartupConfig(t, runDir, "initial.json", cfgA)
	inst := startReloadCaddy(t, bin, cfgPath, "", runDir, adminURL, siteURL, false, http.StatusCreated)
	t.Cleanup(func() { inst.stopCaddy(t) })

	client := newFailoverClient(false)
	wantA := versionExpectation{status: http.StatusCreated, variant: "A", body: versionABody}
	wantB := versionExpectation{status: http.StatusAccepted, variant: "B", body: versionBBody}
	getExact(t, client, siteURL+"/version").assertExpectation(t, wantA, 1, "initial A")

	// new config keeps the admin address but moves the site onto the held
	// port; its http app cannot Start, so the whole load is rejected
	badStart := fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {"http": {"servers": {"srv0": {
		"listen": [%q],
		"routes": []
	}}}}
}`, adminAddr, bindAddr)
	status, respBody := postLoadRaw(t, adminURL, "application/json", []byte(badStart))
	if status != http.StatusBadRequest {
		t.Fatalf("POST /load status: got %d, want 400; body: %s", status, respBody)
	}
	if !strings.Contains(respBody, "address already in use") {
		t.Fatalf("POST /load error: got %q, want it to contain an address-in-use cause", respBody)
	}

	// the last good configuration keeps serving on its original address ...
	getExact(t, client, siteURL+"/version").assertExpectation(t, wantA, 1, "A after Start failure")
	// ... and its admin endpoint stayed put and still reports A
	adminClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := adminClient.Get(adminURL + "/config/")
	if err != nil {
		t.Fatalf("admin endpoint unreachable after Start failure rollback: %v", err)
	}
	servedCfg, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(servedCfg), siteAddr) {
		t.Fatalf("running config after Start failure no longer serves %s:\n%s", siteAddr, servedCfg)
	}

	// a later valid load is not consumed by the failure
	assertLoadSucceeds(t, adminURL, "application/json", reloadJSONB(adminAddr, siteAddr), "load B after Start failure")
	getExact(t, client, siteURL+"/version").assertExpectation(t, wantB, 1, "B after Start failure")
}

// TestUpstream500IsBusinessResult proves that once a site is ready, a route
// that proxies to an upstream answering 500 is an ordinary business result:
// the process stays up, /version keeps its A answer, and a subsequent valid
// load still succeeds.
func TestUpstream500IsBusinessResult(t *testing.T) {
	bin := buildCaddyBinary(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream-fail", http.StatusInternalServerError)
	}))
	defer upstream.Close()

	const (
		adminAddr = "127.0.0.1:2982"
		adminURL  = "http://" + adminAddr
		siteAddr  = "127.0.0.1:9096"
		siteURL   = "http://" + siteAddr
	)
	upstreamHostPort := strings.TrimPrefix(upstream.URL, "http://")

	cfg := fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {"http": {"servers": {"srv0": {
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
				"match": [{"path": ["/fail"]}],
				"handle": [{
					"handler": "reverse_proxy",
					"upstreams": [{"dial": %q}]
				}]
			}
		]
	}}}}
}`, adminAddr, siteAddr, versionABody, upstreamHostPort)

	runDir := t.TempDir()
	cfgPath := writeStartupConfig(t, runDir, "initial.json", cfg)
	inst := startReloadCaddy(t, bin, cfgPath, "", runDir, adminURL, siteURL, false, http.StatusCreated)
	t.Cleanup(func() { inst.stopCaddy(t) })

	client := newFailoverClient(false)

	// readiness is established via the约定 /version answer, not by
	// every route returning 2xx
	getExact(t, client, siteURL+"/version").assertExpectation(t,
		versionExpectation{status: http.StatusCreated, variant: "A", body: versionABody}, 1, "ready /version")

	// an upstream 500 is a business result: it must surface verbatim
	resp, err := client.Get(siteURL + "/fail")
	if err != nil {
		t.Fatalf("GET /fail: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("/fail status: got %d, want 500", resp.StatusCode)
	}
	if strings.TrimSpace(string(body)) != "upstream-fail" {
		t.Fatalf("/fail body: got %q, want upstream-fail", strings.TrimSpace(string(body)))
	}

	// the process remains alive and ready after the business failure ...
	getExact(t, client, siteURL+"/version").assertExpectation(t,
		versionExpectation{status: http.StatusCreated, variant: "A", body: versionABody}, 1, "/version after 500")

	// ... and configuration management is unaffected
	assertLoadSucceeds(t, adminURL, "application/json", reloadJSONB(adminAddr, siteAddr), "load B after upstream 500")
	getExact(t, client, siteURL+"/version").assertExpectation(t,
		versionExpectation{status: http.StatusAccepted, variant: "B", body: versionBBody}, 1, "/version after B load")
}
