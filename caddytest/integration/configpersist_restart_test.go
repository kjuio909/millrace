package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This file verifies the persistence boundary across process restarts:
//
//   - with persistence enabled (the default), a configuration pushed via
//     POST /load is the version a later process comes back up as - even when
//     it is started with the older startup file - while the failed/invalid
//     loads never overwrite that persisted version;
//   - with persistence disabled (admin.config.persist = false, or the
//     Caddyfile `persist_config off` global option), online loads still take
//     effect immediately, but a restart returns to that round's startup file
//     and neither a previously autosaved version nor a stale autosave file is
//     ever restored;
//   - only one process ever serves the listen address across stop/restart
//     cycles.
//
// The matrix runs on a plaintext HTTP/1.1 listener (native JSON) and on an
// HTTPS listener configured with `tls internal` (Caddyfile loads).

// persistJSONA/persistJSONB are the version A/B configurations for the
// plaintext matrix; with persist == false the admin config explicitly turns
// persistence off, which is the only difference between the two startup
// documents a restart can be given.
func persistJSONA(adminAddr, siteAddr, upstreamAddr string, persist bool) string {
	return fmt.Sprintf(`{
	"admin": {"listen": %q%s},
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
}`, adminAddr, persistAdminJSON(persist), siteAddr, versionABody, upstreamAddr)
}

func persistJSONB(adminAddr, siteAddr string, persist bool) string {
	return fmt.Sprintf(`{
	"admin": {"listen": %q%s},
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
}`, adminAddr, persistAdminJSON(persist), siteAddr, versionBBody)
}

func persistAdminJSON(persist bool) string {
	if persist {
		return ""
	}
	return `, "config": {"persist": false}`
}

// persistCaddyfileA/persistCaddyfileB are the version A/B configurations for
// the tls internal matrix; `persist_config off` is again the only switch.
func persistCaddyfileA(adminAddr, siteAddr, upstreamAddr string, persist bool) string {
	return fmt.Sprintf(`{
	skip_install_trust
	admin %s%s
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
`, adminAddr, persistCaddyfileOption(persist), siteAddr, versionABody, upstreamAddr)
}

func persistCaddyfileB(adminAddr, siteAddr string, persist bool) string {
	return fmt.Sprintf(`{
	skip_install_trust
	admin %s%s
	grace_period 60s
}
%s {
	tls internal
	handle /version {
		header X-Variant B
		respond %q 202
	}
}
`, adminAddr, persistCaddyfileOption(persist), siteAddr, versionBBody)
}

func persistCaddyfileOption(persist bool) string {
	if persist {
		return ""
	}
	return "\n\tpersist_config off"
}

// autosavePathFor mirrors the path the isolated caddy process uses
// (XDG_CONFIG_HOME/caddy/autosave.json on POSIX).
func autosavePathFor(runDir string) string {
	return filepath.Join(runDir, "state", "config", "caddy", "autosave.json")
}

func seedStaleAutosave(t *testing.T, runDir, body string) {
	t.Helper()
	p := autosavePathFor(runDir)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("creating autosave directory: %v", err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("seeding stale autosave: %v", err)
	}
}

// assertNothingListening proves the stopped process released the address: no
// second instance may still be serving it.
func assertNothingListening(t *testing.T, addrs ...string) {
	t.Helper()
	for _, addr := range addrs {
		if !dialRefuses(t, addr) {
			t.Fatalf("address %s still accepts connections after the process stopped", addr)
		}
	}
}

// adaptConfig runs `caddy adapt` on a Caddyfile document and returns the
// native JSON it produces; the persisted autosave is always native JSON, even
// when the online load was submitted as a Caddyfile.
func adaptConfig(t *testing.T, bin, runDir, caddyfile string) string {
	t.Helper()
	cmd := exec.Command(bin, "adapt", "--config", "-", "--adapter", "caddyfile", "--pretty", "false")
	cmd.Stdin = strings.NewReader(caddyfile)
	cmd.Env = isolatedCaddyEnv(runDir, "adapt")
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("adapting stale autosave fixture: %v\n%s", err, errOut.String())
	}
	return out.String()
}

// runPersistRestart drives both the persistence-enabled and
// persistence-disabled restart cycles for one protocol.
func runPersistRestart(t *testing.T, bin string, h2 bool,
	adminURL, siteURL, adminAddr, siteAddr, contentType, initialExt string,
	cfgA, cfgB func(persist bool) string) {
	t.Helper()

	wantProto := 1
	if h2 {
		wantProto = 2
	}
	adapter := ""
	if h2 {
		adapter = "caddyfile"
	}
	wantA := versionExpectation{status: 201, variant: "A", body: versionABody}
	wantB := versionExpectation{status: 202, variant: "B", body: versionBBody}

	// persistence enabled: the online version survives a restart that is
	// launched with the older startup file
	t.Run("persist enabled restores last loaded version", func(t *testing.T) {
		runDir := t.TempDir()
		cfgPath := filepath.Join(runDir, "initial"+initialExt)
		if err := os.WriteFile(cfgPath, []byte(cfgA(true)), 0o600); err != nil {
			t.Fatalf("writing initial config: %v", err)
		}

		inst := startReloadCaddy(t, bin, cfgPath, adapter, runDir, adminURL, siteURL, h2, 201)
		client := newFailoverClient(h2)

		fetchVersion(t, client, siteURL).assertMatches(t, wantA, wantProto, "startup A")

		// push B online; it takes over immediately
		assertLoadSucceeds(t, adminURL, contentType, cfgB(true), "load B")
		fetchVersion(t, client, siteURL).assertMatches(t, wantB, wantProto, "after online B")

		// stop and relaunch with the very same A startup file on the same
		// addresses; the persisted B must be restored
		inst.stopCaddy(t)
		assertNothingListening(t, adminAddr, siteAddr)

		inst = startReloadCaddy(t, bin, cfgPath, adapter, runDir, adminURL, siteURL, h2, 202)
		t.Cleanup(func() { inst.stopCaddy(t) })
		fetchVersion(t, client, siteURL).assertMatches(t, wantB, wantProto, "after restart started with A file")

		// an invalid load is rejected and the restored B keeps serving; the
		// persisted version is not replaced by the bad document
		assertLoadRejected(t, adminURL, reloadJSONBad(adminAddr, siteAddr), "bad load after restore")
		fetchVersion(t, client, siteURL).assertMatches(t, wantB, wantProto, "B after rejected load")

		// a valid load is still accepted
		assertLoadSucceeds(t, adminURL, contentType, cfgA(true), "load A after restore")
		fetchVersion(t, client, siteURL).assertMatches(t, wantA, wantProto, "A after valid load")

		// another restart now restores A, the latest successful version
		inst.stopCaddy(t)
		assertNothingListening(t, adminAddr, siteAddr)
		inst = startReloadCaddy(t, bin, cfgPath, adapter, runDir, adminURL, siteURL, h2, 201)
		fetchVersion(t, client, siteURL).assertMatches(t, wantA, wantProto, "after second restart")
	})

	// persistence disabled: online loads take effect, but every restart
	// returns to the startup file; stale or newer persisted versions are
	// never restored and the stale autosave is discarded
	t.Run("persist disabled returns to startup file", func(t *testing.T) {
		runDir := t.TempDir()

		// poison the state directory with a B autosave from a hypothetical
		// previous, persistence-enabled round; online loads of a Caddyfile
		// are adapted to native JSON first, so the persisted document is
		// always JSON - it must never be resurrected
		staleB := cfgB(true)
		if h2 {
			staleB = adaptConfig(t, bin, runDir, staleB)
		}
		seedStaleAutosave(t, runDir, staleB)

		cfgPath := filepath.Join(runDir, "initial-off"+initialExt)
		if err := os.WriteFile(cfgPath, []byte(cfgA(false)), 0o600); err != nil {
			t.Fatalf("writing initial config: %v", err)
		}

		inst := startReloadCaddy(t, bin, cfgPath, adapter, runDir, adminURL, siteURL, h2, 201)
		client := newFailoverClient(h2)
		fetchVersion(t, client, siteURL).assertMatches(t, wantA, wantProto, "startup A despite stale autosave")

		// an online load is effective while the process runs
		assertLoadSucceeds(t, adminURL, contentType, cfgB(false), "load B with persist off")
		fetchVersion(t, client, siteURL).assertMatches(t, wantB, wantProto, "online B with persist off")

		// restarting the A startup file must come back as A, not the loaded B
		inst.stopCaddy(t)
		assertNothingListening(t, adminAddr, siteAddr)
		inst = startReloadCaddy(t, bin, cfgPath, adapter, runDir, adminURL, siteURL, h2, 201)
		t.Cleanup(func() { inst.stopCaddy(t) })
		fetchVersion(t, client, siteURL).assertMatches(t, wantA, wantProto, "restart ignores online B")

		// a second success/stop/restart cycle stays isolated the same way:
		// no old recovery data resurfaces
		assertLoadSucceeds(t, adminURL, contentType, cfgB(false), "load B again with persist off")
		fetchVersion(t, client, siteURL).assertMatches(t, wantB, wantProto, "online B again")
		inst.stopCaddy(t)
		assertNothingListening(t, adminAddr, siteAddr)
		inst = startReloadCaddy(t, bin, cfgPath, adapter, runDir, adminURL, siteURL, h2, 201)
		fetchVersion(t, client, siteURL).assertMatches(t, wantA, wantProto, "second restart still A")

		// failures online do not consume a later valid load, same as usual
		assertLoadRejected(t, adminURL, reloadJSONBad(adminAddr, siteAddr), "bad load with persist off")
		fetchVersion(t, client, siteURL).assertMatches(t, wantA, wantProto, "A after rejected load")
		assertLoadSucceeds(t, adminURL, contentType, cfgB(false), "load B after failure")
		fetchVersion(t, client, siteURL).assertMatches(t, wantB, wantProto, "B after failure")
	})
}

// TestConfigPersistenceAcrossRestarts drives the persistence matrix for the
// plaintext HTTP/1.1 listener and the tls internal HTTPS listener.
func TestConfigPersistenceAcrossRestarts(t *testing.T) {
	bin := buildCaddyBinary(t)

	upstream := newReloadHoldUpstream(t) // keeps the A builders uniform

	t.Run("HTTP/1.1 plaintext", func(t *testing.T) {
		const (
			adminAddr = "127.0.0.1:2979"
			adminURL  = "http://" + adminAddr
			siteAddr  = "127.0.0.1:9081"
			siteURL   = "http://" + siteAddr
		)
		runPersistRestart(t, bin, false, adminURL, siteURL, adminAddr, siteAddr,
			"application/json", ".json",
			func(persist bool) string {
				return persistJSONA(adminAddr, siteAddr, upstream.addr(), persist)
			},
			func(persist bool) string {
				return persistJSONB(adminAddr, siteAddr, persist)
			})
	})

	t.Run("HTTP/2 over TLS internal", func(t *testing.T) {
		const (
			adminAddr = "127.0.0.1:2978"
			adminURL  = "http://" + adminAddr
			siteAddr  = "localhost:9457"
			siteURL   = "https://" + siteAddr
		)
		runPersistRestart(t, bin, true, adminURL, siteURL, adminAddr, siteAddr,
			"text/caddyfile", ".Caddyfile",
			func(persist bool) string {
				return persistCaddyfileA(adminAddr, siteAddr, upstream.addr(), persist)
			},
			func(persist bool) string {
				return persistCaddyfileB(adminAddr, siteAddr, persist)
			})
	})
}
