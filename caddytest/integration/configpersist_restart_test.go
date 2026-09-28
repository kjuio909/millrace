package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This file verifies the persistence boundary of POST /load across a full
// process restart on a real `caddy` subprocess:
//
//   - only a fully successful load is persisted, atomically, so a restart on
//     the same listen address (--resume) restores the last API-success
//     version, not the version in the startup file;
//   - rejected loads (empty body, null, truncated JSON, trailing data, wrong
//     field type) never overwrite the persisted document, and no temporary
//     autosave file is left behind;
//   - with persistence turned off (admin.config.persist:false / the
//     Caddyfile `persist_config off` global option), online loads still take
//     effect but nothing is written, and a restart from the startup file
//     returns to that file's version rather than the API-success version;
//   - exactly one instance serves the address across every stop/start.
//
// It runs for a plaintext HTTP/1.1 site (native JSON loads) and an HTTPS
// `tls internal` site (valid loads submitted as Caddyfiles, which are adapted
// to JSON before being persisted, so resume is protocol-independent).

// autosavePath returns the on-disk autosave document the isolated subprocess
// uses, given the run directory passed to isolatedCaddyEnv.
func autosavePath(runDir string) string {
	return filepath.Join(runDir, "state", "config", "caddy", "autosave.json")
}

// startPersistCaddy launches `caddy run` with the supplied extra arguments
// (e.g. a config file/adapter, or --resume), isolated under runDir, and waits
// until /version answers wantReadyStatus.
func startPersistCaddy(t *testing.T, bin, runDir string, args []string, env []string, adminURL, baseURL string, h2 bool, wantReadyStatus int) *caddyInstance {
	t.Helper()

	logFile, err := os.Create(filepath.Join(runDir, "caddy-persist.log"))
	if err != nil {
		t.Fatalf("creating log file: %v", err)
	}
	cmd := exec.Command(bin, append([]string{"run"}, args...)...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = env
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

// assertPortRefuses proves nothing is accepting TCP connections on addr, i.e.
// no zombie/double instance survived the stop.
func assertPortRefuses(t *testing.T, addr, where string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return
		}
		conn.Close()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: %s still accepting connections after stop", where, addr)
}

// badPersistLoad is one malformed /load document that must never replace the
// running or the persisted configuration.
type badPersistLoad struct{ name, body string }

// badPersistLoads are malformed documents none of which may replace the
// persisted (or running) configuration.
func badPersistLoads(validB, siteAddr string) []badPersistLoad {
	return []badPersistLoad{
		{"empty body", ""},
		{"null document", "null"},
		{"truncated JSON", `{"apps":`},
		{"trailing data", validB + "GARBAGE"},
		{"wrong field type", `{"apps":{"http":{"http_port":"not-a-number","servers":{"srv0":{"listen":["` + siteAddr + `"]}}}}}`},
	}
}

// persistCase parameterizes one protocol matrix.
type persistCase struct {
	name      string
	h2        bool
	wantProto int
	siteAddr  string
	adminAddr string

	// valid A/B configs as submitted over the API and as startup files
	cfgA    string
	cfgB    string
	cfgAOff string
	cfgBOff string

	contentType string // Content-Type used when submitting A and B
	adapter     string // adapter for the startup files ("" for native JSON)
	ext         string
}

// TestConfigPersistenceAcrossRestart drives the persistence matrix for
// plaintext HTTP/1.1 (JSON) and HTTPS tls internal (Caddyfile) sites.
func TestConfigPersistenceAcrossRestart(t *testing.T) {
	bin := buildCaddyBinary(t)

	const (
		// plaintext matrix
		site1  = "127.0.0.1:9071"
		admin1 = "127.0.0.1:2971"
		// HTTPS matrix
		site2  = "localhost:9461"
		admin2 = "127.0.0.1:2972"
	)

	upstream := newReloadHoldUpstream(t) // keeps builders uniform; /hold unused

	jsonA := reloadJSONA(admin1, site1, upstream.addr())
	jsonB := reloadJSONB(admin1, site1)
	jsonAOff := withPersistOffJSON(t, jsonA)
	jsonBOff := withPersistOffJSON(t, jsonB)

	caddyA := reloadCaddyfileA(admin2, site2, upstream.addr())
	caddyB := reloadCaddyfileB(admin2, site2)
	caddyAOff := withPersistOffCaddyfile(caddyA)
	caddyBOff := withPersistOffCaddyfile(caddyB)

	for _, tc := range []persistCase{
		{
			name:        "HTTP/1.1 plaintext",
			h2:          false,
			wantProto:   1,
			siteAddr:    site1,
			adminAddr:   admin1,
			cfgA:        jsonA,
			cfgB:        jsonB,
			cfgAOff:     jsonAOff,
			cfgBOff:     jsonBOff,
			contentType: "application/json",
			adapter:     "",
			ext:         ".json",
		},
		{
			name:        "HTTP/2 over TLS internal",
			h2:          true,
			wantProto:   2,
			siteAddr:    site2,
			adminAddr:   admin2,
			cfgA:        caddyA,
			cfgB:        caddyB,
			cfgAOff:     caddyAOff,
			cfgBOff:     caddyBOff,
			contentType: "text/caddyfile",
			adapter:     "caddyfile",
			ext:         ".Caddyfile",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runPersistMatrix(t, bin, tc)
			runPersistOffMatrix(t, bin, tc)
		})
	}
}

// runPersistMatrix covers persistence ON: online B survives rejected loads
// and is the version a fresh --resume process serves.
func runPersistMatrix(t *testing.T, bin string, tc persistCase) {
	t.Helper()
	adminURL := "http://" + tc.adminAddr
	baseURL := "http://" + tc.siteAddr
	if tc.h2 {
		baseURL = "https://" + tc.siteAddr
	}

	runDir := t.TempDir()
	env := isolatedCaddyEnv(runDir, "state")
	savePath := autosavePath(runDir)

	// start from a startup file containing A
	cfgPath := filepath.Join(runDir, "initial"+tc.ext)
	if err := os.WriteFile(cfgPath, []byte(tc.cfgA), 0o600); err != nil {
		t.Fatalf("writing initial config: %v", err)
	}
	startArgs := []string{"--config", cfgPath}
	if tc.adapter != "" {
		startArgs = append(startArgs, "--adapter", tc.adapter)
	}
	inst := startPersistCaddy(t, bin, runDir, startArgs, env, adminURL, baseURL, tc.h2, http.StatusCreated)
	getExact(t, newFailoverClient(tc.h2), baseURL+"/version").
		assertExpectation(t, versionA, tc.wantProto, "startup serves file version A")

	// the initial load of A is persisted
	assertAutosaveVariant(t, savePath, "A", "after startup")

	// successfully load B online
	assertLoadSucceeds(t, adminURL, tc.contentType, tc.cfgB, "online load B")
	getExact(t, newFailoverClient(tc.h2), baseURL+"/version").
		assertExpectation(t, versionB, tc.wantProto, "after online B")
	assertAutosaveVariant(t, savePath, "B", "after online B")

	// every rejected load keeps B running and persisted, byte for byte
	before, err := os.ReadFile(savePath)
	if err != nil {
		t.Fatalf("reading autosave before bad loads: %v", err)
	}
	for i, bad := range badPersistLoads(tc.cfgB, tc.siteAddr) {
		status, respBody := postLoadRaw(t, adminURL, "application/json", []byte(bad.body))
		if status != http.StatusBadRequest {
			t.Fatalf("%s: bad load %q (#%d) status: got %d, want 400; body: %s", tc.name, bad.name, i, status, respBody)
		}
		getExact(t, newFailoverClient(tc.h2), baseURL+"/version").
			assertExpectation(t, versionB, tc.wantProto, fmt.Sprintf("B after rejected %s", bad.name))
		after, err := os.ReadFile(savePath)
		if err != nil {
			t.Fatalf("reading autosave after bad load %q: %v", bad.name, err)
		}
		if string(after) != string(before) {
			t.Fatalf("%s: rejected load %q overwrote the persisted document", tc.name, bad.name)
		}
	}
	// an atomic writer must not leave temporary documents behind
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(savePath), ".autosave.json.tmp-*"))
	if len(leftovers) != 0 {
		t.Fatalf("%s: leftover temporary autosave files: %v", tc.name, leftovers)
	}

	// a valid load still succeeds after the failures
	assertLoadSucceeds(t, adminURL, tc.contentType, tc.cfgA, "online reload A after bad loads")
	getExact(t, newFailoverClient(tc.h2), baseURL+"/version").
		assertExpectation(t, versionA, tc.wantProto, "A after bad loads")
	assertAutosaveVariant(t, savePath, "A", "after reloading A")

	// load B again so the persisted document differs from the startup file A,
	// then stop and resume: the restarted instance MUST serve B
	assertLoadSucceeds(t, adminURL, tc.contentType, tc.cfgB, "online load B before restart")
	getExact(t, newFailoverClient(tc.h2), baseURL+"/version").
		assertExpectation(t, versionB, tc.wantProto, "B immediately before stop")

	inst.stopCaddy(t)
	assertPortRefuses(t, tc.siteAddr, tc.name+" site")
	assertPortRefuses(t, tc.adminAddr, tc.name+" admin")

	resumed := startPersistCaddy(t, bin, runDir, []string{"--resume"}, env, adminURL, baseURL, tc.h2, http.StatusAccepted)
	t.Cleanup(func() { resumed.stopCaddy(t) })
	getExact(t, newFailoverClient(tc.h2), baseURL+"/version").
		assertExpectation(t, versionB, tc.wantProto, "resumed process serves persisted B, not file A")
	assertAutosaveVariant(t, savePath, "B", "after resume")

	resumed.stopCaddy(t)
	assertPortRefuses(t, tc.siteAddr, tc.name+" site after resume stop")
	assertPortRefuses(t, tc.adminAddr, tc.name+" admin after resume stop")
}

// runPersistOffMatrix covers persistence OFF: online loads are effective but
// never written, and a fresh start from the file returns to the file version.
func runPersistOffMatrix(t *testing.T, bin string, tc persistCase) {
	t.Helper()
	adminURL := "http://" + tc.adminAddr
	baseURL := "http://" + tc.siteAddr
	if tc.h2 {
		baseURL = "https://" + tc.siteAddr
	}

	runDir := t.TempDir()
	// a distinct state suffix guarantees no autosave from the ON matrix can
	// be read
	env := isolatedCaddyEnv(runDir, "state-off")
	savePath := filepath.Join(runDir, "state-off", "config", "caddy", "autosave.json")

	cfgPath := filepath.Join(runDir, "off"+tc.ext)
	if err := os.WriteFile(cfgPath, []byte(tc.cfgAOff), 0o600); err != nil {
		t.Fatalf("writing persist-off config: %v", err)
	}
	startArgs := []string{"--config", cfgPath}
	if tc.adapter != "" {
		startArgs = append(startArgs, "--adapter", tc.adapter)
	}
	inst := startPersistCaddy(t, bin, runDir, startArgs, env, adminURL, baseURL, tc.h2, http.StatusCreated)
	t.Cleanup(func() { inst.stopCaddy(t) })

	getExact(t, newFailoverClient(tc.h2), baseURL+"/version").
		assertExpectation(t, versionA, tc.wantProto, "persist-off startup serves A")
	if _, err := os.Stat(savePath); !os.IsNotExist(err) {
		t.Fatalf("%s: autosave written despite persist off at startup: %v", tc.name, err)
	}

	// online load is still effective with persistence disabled
	assertLoadSucceeds(t, adminURL, tc.contentType, tc.cfgBOff, "online load B with persist off")
	getExact(t, newFailoverClient(tc.h2), baseURL+"/version").
		assertExpectation(t, versionB, tc.wantProto, "online B with persist off")
	if _, err := os.Stat(savePath); !os.IsNotExist(err) {
		t.Fatalf("%s: autosave written despite persist off after online load: %v", tc.name, err)
	}

	// rejected loads must keep serving B
	status, _ := postLoadRaw(t, adminURL, "application/json", []byte(`{"apps":`))
	if status != http.StatusBadRequest {
		t.Fatalf("%s: truncated load with persist off: got %d, want 400", tc.name, status)
	}
	getExact(t, newFailoverClient(tc.h2), baseURL+"/version").
		assertExpectation(t, versionB, tc.wantProto, "B after rejected load with persist off")
	if _, err := os.Stat(savePath); !os.IsNotExist(err) {
		t.Fatalf("%s: autosave created by a rejected persist-off load: %v", tc.name, err)
	}

	// restart from the SAME startup file (no --resume): it must serve the
	// file version A, never the API-success version B
	inst.stopCaddy(t)
	assertPortRefuses(t, tc.siteAddr, tc.name+" persist-off site")

	restarted := startPersistCaddy(t, bin, runDir, startArgs, env, adminURL, baseURL, tc.h2, http.StatusCreated)
	t.Cleanup(func() { restarted.stopCaddy(t) })
	getExact(t, newFailoverClient(tc.h2), baseURL+"/version").
		assertExpectation(t, versionA, tc.wantProto, "restart returns to file version A, not online B")
	if _, err := os.Stat(savePath); !os.IsNotExist(err) {
		t.Fatalf("%s: autosave exists after persist-off restart: %v", tc.name, err)
	}
}

// assertAutosaveVariant decodes the persisted document, verifies it is a
// complete JSON config and that it carries the expected X-Variant marker,
// proving a restart would resume exactly that version.
func assertAutosaveVariant(t *testing.T, path, want, where string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: reading persisted config %s: %v", where, path, err)
	}
	if !json.Valid(raw) {
		t.Fatalf("%s: persisted config is not valid, complete JSON: %q", where, string(raw))
	}
	if !strings.Contains(string(raw), `"X-Variant":["`+want+`"]`) {
		t.Fatalf("%s: persisted config does not carry variant %s:\n%s", where, want, string(raw))
	}
}

// withPersistOffJSON returns a native JSON config identical to cfg but with
// admin.config.persist explicitly set to false.
func withPersistOffJSON(t *testing.T, cfg string) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(cfg), &doc); err != nil {
		t.Fatalf("decoding config to disable persist: %v", err)
	}
	admin, _ := doc["admin"].(map[string]any)
	if admin == nil {
		admin = map[string]any{}
	}
	admin["config"] = map[string]any{"persist": false}
	doc["admin"] = admin
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-encoding persist-off config: %v", err)
	}
	return string(out)
}

// withPersistOffCaddyfile adds the `persist_config off` global option to a
// Caddyfile that already starts its global options block with
// skip_install_trust.
func withPersistOffCaddyfile(cfg string) string {
	return strings.Replace(cfg, "skip_install_trust\n", "skip_install_trust\n\tpersist_config off\n", 1)
}
