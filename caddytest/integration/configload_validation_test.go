package integration

import (
	"encoding/json"
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

// This file verifies the failure boundaries around POST /load and initial
// startup that complement the success/switch matrix in configreload_test.go:
//
//   - malformed payloads (empty body, null, truncated JSON, trailing data) and
//     field type mismatches are rejected with the admin API's JSON error
//     envelope; the previously running configuration keeps answering with the
//     exact same status, variant header and body, and a later valid load is not
//     consumed;
//   - a 500 returned by an upstream of an already-ready instance is a business
//     result, not a startup or readiness failure;
//   - at startup, a JSON syntax error, an unknown Caddyfile directive or a
//     listen-address conflict make the process exit non-zero within a bounded
//     time with a recognizable cause on stderr, no listener is left behind,
//     and the address can be claimed again by a valid configuration.

const (
	loadValidationAdmin = "127.0.0.1:2993"
	loadValidationSite  = "127.0.0.1:9089"
)

// loadValidationJSONA is a ready plaintext configuration: /version answers a
// fixed static A response and /up500 proxies to an upstream the test controls.
func loadValidationJSONA(adminAddr, siteAddr, upstreamAddr string) string {
	return fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {
		"http": {
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
							"match": [{"path": ["/up500"]}],
							"handle": [{
								"handler": "reverse_proxy",
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

// loadValidationJSONB changes /version to B.
func loadValidationJSONB(adminAddr, siteAddr string) string {
	return fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {
		"http": {
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

// postLoadExact submits a raw body to /load and returns the status, the parsed
// {"error": ...} message (empty on success) and the Content-Type header.
func postLoadExact(t *testing.T, adminURL string, body string) (int, string, string) {
	t.Helper()
	resp, err := http.Post(adminURL+"/load", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /load: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var envelope struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &envelope)
	return resp.StatusCode, envelope.Error, resp.Header.Get("Content-Type")
}

func TestLoadValidationKeepsLastGoodConfig(t *testing.T) {
	bin := buildCaddyBinary(t)

	upstream := newReloadHoldUpstream(t)
	runDir := t.TempDir()
	cfgPath := filepath.Join(runDir, "initial.json")
	cfgA := loadValidationJSONA(loadValidationAdmin, loadValidationSite, upstream.addr())
	if err := os.WriteFile(cfgPath, []byte(cfgA), 0o600); err != nil {
		t.Fatalf("writing initial config: %v", err)
	}

	adminURL := "http://" + loadValidationAdmin
	baseURL := "http://" + loadValidationSite
	inst := startReloadCaddy(t, bin, cfgPath, "", runDir, adminURL, baseURL, false, http.StatusCreated)
	t.Cleanup(func() { inst.stopCaddy(t) })

	client := newFailoverClient(false)

	fetchVersion(t, client, baseURL).assertMatches(t, versionA, 1, "ready A")

	// malformed payloads must all be rejected through the admin API's JSON
	// error envelope and leave A serving byte-for-byte the same answer
	badCases := []struct {
		name    string
		body    string
		wantSub string // substring required in the error message
	}{
		{"empty body", "", "empty"},
		{"whitespace only", "  \n\t ", "empty"},
		{"null", "null", "null"},
		{"padded null", "  null \n", "null"},
		{"truncated JSON", `{"admin":`, "decoding request body"},
		{"trailing data", `{}x`, "decoding request body"},
		{"field type mismatch", `{"apps": 5}`, "apps"},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			status, msg, contentType := postLoadExact(t, adminURL, tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("status: got %d, want 400 (body=%q)", status, msg)
			}
			if !strings.Contains(contentType, "application/json") {
				t.Errorf("error content-type: got %q, want application/json", contentType)
			}
			if msg == "" {
				t.Fatal("expected a non-empty error message")
			}
			if !strings.Contains(msg, tc.wantSub) {
				t.Errorf("error %q does not mention %q", msg, tc.wantSub)
			}

			// the failed load must not unload or half-load anything:
			// status, variant header and body stay exactly as before,
			// both on a fresh and a reused connection
			fetchVersion(t, client, baseURL).assertMatches(t, versionA, 1, "after "+tc.name)
			fetchVersion(t, newFailoverClient(false), baseURL).assertMatches(t, versionA, 1, "after "+tc.name+" new conn")

			// the admin endpoint stays connectible and answers
			if resp, err := http.Get(adminURL + "/config/"); err != nil || resp.StatusCode != http.StatusOK {
				t.Errorf("admin endpoint not healthy after rejected load: resp=%v err=%v", resp, err)
			} else {
				resp.Body.Close()
			}
		})
	}

	// failed loads must not consume a later valid load
	assertLoadSucceeds(t, adminURL, "application/json", loadValidationJSONB(loadValidationAdmin, loadValidationSite), "load B after failures")
	fetchVersion(t, client, baseURL).assertMatches(t, versionB, 1, "B after failures")
	assertLoadSucceeds(t, adminURL, "application/json", cfgA, "load A again")
	fetchVersion(t, client, baseURL).assertMatches(t, versionA, 1, "A restored")
}

func TestReadyInstanceUpstream500IsBusinessResult(t *testing.T) {
	bin := buildCaddyBinary(t)

	// upstream that answers 500 on every request
	up500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(up500.Close)

	runDir := t.TempDir()
	cfgPath := filepath.Join(runDir, "initial.json")
	cfgA := loadValidationJSONA(loadValidationAdmin, loadValidationSite, strings.TrimPrefix(up500.URL, "http://"))
	if err := os.WriteFile(cfgPath, []byte(cfgA), 0o600); err != nil {
		t.Fatalf("writing initial config: %v", err)
	}

	adminURL := "http://" + loadValidationAdmin
	baseURL := "http://" + loadValidationSite
	inst := startReloadCaddy(t, bin, cfgPath, "", runDir, adminURL, baseURL, false, http.StatusCreated)
	t.Cleanup(func() { inst.stopCaddy(t) })

	resp, err := newFailoverClient(false).Get(baseURL + "/up500")
	if err != nil {
		t.Fatalf("GET /up500: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("upstream error status: got %d, want 500 (body=%q)", resp.StatusCode, body)
	}

	// the instance is still alive and serving its own endpoints: an upstream
	// 500 is a business result, never a startup/readiness failure
	fetchVersion(t, newFailoverClient(false), baseURL).assertMatches(t, versionA, 1, "still ready after upstream 500")
}

// runCaddyExpectStartupFailure launches `caddy run` with the given config and
// asserts it exits non-zero within a bounded time, leaves a recognizable cause
// in its combined output, and does not keep listening on adminAddr.
func runCaddyExpectStartupFailure(t *testing.T, bin, runDir, cfgPath, adapter, adminAddr, wantCause string) {
	t.Helper()
	args := []string{"run", "--config", cfgPath}
	if adapter != "" {
		args = append(args, "--adapter", adapter)
	}
	cmd := exec.Command(bin, args...)
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Env = isolatedCaddyEnv(runDir, "state")
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting caddy: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("caddy exited successfully with an invalid %s config; output:\n%s", cfgPath, out.String())
		}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("caddy did not exit within 30s with an invalid config; output:\n%s", out.String())
	}

	if wantCause != "" && !strings.Contains(out.String(), wantCause) {
		t.Errorf("startup output %q does not mention %q", out.String(), wantCause)
	}

	if adminAddr != "" {
		assertAddrFree(t, adminAddr)
	}
}

// assertAddrFree dials the address and fails if something accepts connections.
func assertAddrFree(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return // nothing listening
		}
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("a failed instance is still listening on %s", addr)
}

func TestStartupFailuresExitAndReleaseAddress(t *testing.T) {
	bin := buildCaddyBinary(t)

	t.Run("json syntax error", func(t *testing.T) {
		runDir := t.TempDir()
		cfgPath := filepath.Join(runDir, "bad.json")
		if err := os.WriteFile(cfgPath, []byte(`{ not json`), 0o600); err != nil {
			t.Fatal(err)
		}
		runCaddyExpectStartupFailure(t, bin, runDir, cfgPath, "", "", "not valid JSON")
	})

	t.Run("unknown directive", func(t *testing.T) {
		runDir := t.TempDir()
		cfgPath := filepath.Join(runDir, "bad.Caddyfile")
		caddyfile := `{
	skip_install_trust
	admin 127.0.0.1:2994
}
:9094 {
	this_directive_does_not_exist
}
`
		if err := os.WriteFile(cfgPath, []byte(caddyfile), 0o600); err != nil {
			t.Fatal(err)
		}
		runCaddyExpectStartupFailure(t, bin, runDir, cfgPath, "caddyfile", "127.0.0.1:2994", "unrecognized directive")
	})

	t.Run("listen conflict then reuse", func(t *testing.T) {
		runDir := t.TempDir()
		adminAddr := "127.0.0.1:2995"

		// occupy the site address from the test process, which does not set
		// SO_REUSEPORT, so Caddy genuinely cannot bind it
		occupant, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("occupant listen: %v", err)
		}
		siteAddr := occupant.Addr().String()
		go func() {
			for {
				conn, err := occupant.Accept()
				if err != nil {
					return
				}
				conn.Close()
			}
		}()

		cfgPath := filepath.Join(runDir, "conflict.json")
		cfg := fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {"http": {"servers": {"srv0": {
		"listen": [%q],
		"routes": [{"handle": [{"handler": "static_response", "body": "caddy"}]}]
	}}}}
}`, adminAddr, siteAddr)
		if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}

		runCaddyExpectStartupFailure(t, bin, runDir, cfgPath, "", adminAddr, "bind: address already in use")

		// release the address; a valid instance must now be able to claim it
		occupant.Close()

		goodCfgPath := filepath.Join(runDir, "good.json")
		if err := os.WriteFile(goodCfgPath, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		adminURL := "http://" + adminAddr
		inst := startReloadCaddy(t, bin, goodCfgPath, "", runDir, adminURL, "http://"+siteAddr, false, http.StatusOK)
		t.Cleanup(func() { inst.stopCaddy(t) })
	})
}
