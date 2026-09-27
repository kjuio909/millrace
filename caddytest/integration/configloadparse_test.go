package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// This file verifies the parse-failure semantics of the admin API's
// POST /load endpoint against a real `caddy` subprocess:
//
//   - a submitted document that cannot be parsed into a configuration
//     (JSON truncated inside an object or a string, a field value whose
//     type does not match the configuration schema, a syntactically
//     complete JSON document followed by trailing garbage, an empty
//     body, or a JSON null) is rejected with a non-success status and
//     the admin API's JSON error semantics;
//   - the rejection never disturbs the most recently accepted
//     configuration: /version keeps answering with the exact same
//     status, headers and body, the listen address stays connectable,
//     and a business request that is already in flight during the
//     failed submission completes with exactly the response of the
//     configuration that accepted it;
//   - a failed submission leaves nothing behind: the original valid
//     configuration can be re-submitted afterwards, and success and
//     failure rounds can alternate without state leaking from one
//     round into the next.
//
// Everything is asserted exclusively through public HTTP requests:
// statuses, response headers, bodies, connection availability and
// ordering. No internal state is read and no fault is injected.

// versionSnapshot is the complete observable /version answer of one
// configuration: status line, every response header and the body.
type versionSnapshot struct {
	status int
	header http.Header
	body   string
	proto  int
}

// snapshotVersion records the exact /version answer the currently
// running configuration gives, so it can be compared byte-for-byte
// after a failed config submission.
func snapshotVersion(t *testing.T, client *http.Client, baseURL string) versionSnapshot {
	t.Helper()
	resp, err := client.Get(baseURL + "/version")
	if err != nil {
		t.Fatalf("GET /version: %v", err)
	}
	defer resp.Body.Close()
	body := readAllAndClose(t, resp)
	header := resp.Header.Clone()
	// Date is the only header that legitimately changes between
	// two identical responses
	header.Del("Date")
	return versionSnapshot{
		status: resp.StatusCode,
		header: header,
		body:   string(body),
		proto:  resp.ProtoMajor,
	}
}

// assertVersionUnchanged requires the current /version answer to be
// identical to the snapshot in status, every header and the body.
func assertVersionUnchanged(t *testing.T, client *http.Client, baseURL string, want versionSnapshot, where string) {
	t.Helper()
	got := snapshotVersion(t, client, baseURL)
	if got.status != want.status {
		t.Errorf("%s: /version status: got %d, want %d", where, got.status, want.status)
	}
	if !reflect.DeepEqual(got.header, want.header) {
		t.Errorf("%s: /version headers changed:\ngot:  %v\nwant: %v", where, got.header, want.header)
	}
	if got.body != want.body {
		t.Errorf("%s: /version body: got %q, want %q", where, got.body, want.body)
	}
	if got.proto != want.proto {
		t.Errorf("%s: /version protocol: got HTTP/%d, want HTTP/%d", where, got.proto, want.proto)
	}
}

// assertProbeOnlyLastGood requires that, while a rejected submission
// was in flight, every probe request was answered by the last-good
// configuration (variant want) and no request failed or was answered
// in any other shape.
func assertProbeOnlyLastGood(t *testing.T, p *switchProbe, want versionExpectation, where string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.errs {
		t.Errorf("%s: request failed while the rejected load was in flight: %s", where, e)
	}
	for _, o := range p.odd {
		t.Errorf("%s: answer that is neither A nor B while the rejected load was in flight: %s", where, o)
	}
	switch want {
	case versionA:
		if p.aCount == 0 {
			t.Errorf("%s: probe never observed the last-good (A) answer", where)
		}
		if p.bCount != 0 {
			t.Errorf("%s: probe observed %d B answers from a config that was never accepted", where, p.bCount)
		}
	case versionB:
		if p.bCount == 0 {
			t.Errorf("%s: probe never observed the last-good (B) answer", where)
		}
		if p.aCount != 0 {
			t.Errorf("%s: probe observed %d A answers from a config that was no longer current", where, p.aCount)
		}
	}
}

// postLoadExpectReject submits an unparseable configuration and
// requires the admin API to refuse it with a client-error status and
// its own JSON error semantics: an application/json body carrying an
// "error" member, not anything produced by a site route.
func postLoadExpectReject(t *testing.T, adminURL, body, label string) {
	t.Helper()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(adminURL+"/load", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s: POST /load: %v", label, err)
	}
	defer resp.Body.Close()
	respBody := readAllAndClose(t, resp)
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("%s: POST /load status: got %d, want a 4xx rejection; body: %s", label, resp.StatusCode, respBody)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("%s: POST /load error Content-Type: got %q, want application/json", label, ct)
	}
	var errObj map[string]any
	if err := json.Unmarshal(respBody, &errObj); err != nil {
		t.Fatalf("%s: POST /load error body is not JSON: %v; body: %s", label, err, respBody)
	}
	if msg, ok := errObj["error"].(string); !ok || msg == "" {
		t.Errorf("%s: POST /load error body has no \"error\" message: %s", label, respBody)
	}
}

// readAllAndClose drains resp.Body and returns its contents.
func readAllAndClose(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}
	return body
}

// parseFailureBodies builds the malformed submissions: JSON truncated
// inside an object and inside a string, field values whose types do
// not match the configuration schema (both at the top level and deep
// inside an app), a complete JSON document followed by non-empty
// garbage, an empty body and a JSON null.
func parseFailureBodies(t *testing.T, validCfg string) []struct {
	name string
	body string
} {
	t.Helper()

	// cut the valid document inside an object and inside a string value
	midObject := strings.Index(validCfg, `"servers"`)
	midString := strings.Index(validCfg, "variant-a-payload") + 4
	if midObject <= 0 || midString <= 4 {
		t.Fatalf("could not locate truncation points in the valid config")
	}

	// type mismatches, derived from the valid config so everything
	// else stays exactly as the running configuration expects
	var topLevel map[string]any
	if err := json.Unmarshal([]byte(validCfg), &topLevel); err != nil {
		t.Fatalf("decoding valid config: %v", err)
	}
	shallow, err := json.Marshal(map[string]any{
		"admin": 12345, // admin must be an object
		"apps":  topLevel["apps"],
	})
	if err != nil {
		t.Fatalf("encoding shallow type mismatch: %v", err)
	}

	var deepCfg map[string]any
	if err := json.Unmarshal([]byte(validCfg), &deepCfg); err != nil {
		t.Fatalf("decoding valid config: %v", err)
	}
	deepCfg["apps"].(map[string]any)["http"].(map[string]any)["servers"] = "not-an-object"
	deep, err := json.Marshal(deepCfg)
	if err != nil {
		t.Fatalf("encoding deep type mismatch: %v", err)
	}

	return []struct {
		name string
		body string
	}{
		{"truncated mid-object", validCfg[:midObject]},
		{"truncated mid-string", validCfg[:midString]},
		{"shallow type mismatch", string(shallow)},
		{"deep type mismatch", string(deep)},
		{"trailing garbage", validCfg + "\nthis-is-not-json"},
		{"empty body", ""},
		{"json null", "null"},
	}
}

// TestConfigLoadParseFailureIsolation drives the parse-failure matrix
// on a real caddy binary serving a plaintext HTTP/1.1 listener:
//
//  1. A is started and serves A on /version; its exact answer (status,
//     all headers, body) is snapshot.
//  2. For every malformed submission: a /hold request is opened and
//     its A prefix received; the malformed body is submitted while
//     probes hammer /version; the submission must be rejected with the
//     admin API's JSON error semantics; /version must still answer
//     exactly the snapshot; the address must have stayed connectable
//     throughout; and the held request, once released, must complete
//     as exactly the A response.
//  3. The original valid configuration is re-submitted and accepted.
//  4. Successful loads and malformed submissions alternate; after
//     every rejection the last-good configuration keeps serving, and
//     every subsequent successful load still takes effect.
func TestConfigLoadParseFailureIsolation(t *testing.T) {
	bin := buildCaddyBinary(t)

	upstream := newReloadHoldUpstream(t)

	adminAddr := "127.0.0.1:2993"
	siteAddr := "127.0.0.1:9089"
	adminURL := "http://" + adminAddr
	baseURL := "http://" + siteAddr

	cfgA := reloadJSONA(adminAddr, siteAddr, upstream.addr())
	cfgB := reloadJSONB(adminAddr, siteAddr)
	malformed := parseFailureBodies(t, cfgA)

	runDir := t.TempDir()
	cfgPath := filepath.Join(runDir, "initial.json")
	if err := os.WriteFile(cfgPath, []byte(cfgA), 0o600); err != nil {
		t.Fatalf("writing initial config: %v", err)
	}

	inst := startReloadCaddy(t, bin, cfgPath, "", runDir, adminURL, baseURL, false, versionA.status)
	t.Cleanup(func() { inst.stopCaddy(t) })

	// the held stream must outlive ordinary request deadlines
	holdClient := newFailoverClient(false)
	holdClient.Timeout = 0
	client := newFailoverClient(false)

	// 1. snapshot the exact answer of the last-good configuration
	snapA := snapshotVersion(t, client, baseURL)
	if snapA.status != versionA.status || snapA.body != versionABody {
		t.Fatalf("initial /version: got %d %q, want %d %q", snapA.status, snapA.body, versionA.status, versionABody)
	}

	// 2. every malformed submission is rejected and changes nothing
	for _, bad := range malformed {
		t.Run(bad.name, func(t *testing.T) {
			// open a business request and keep it in flight; its
			// response must come entirely from the configuration
			// that accepted it
			held := startInflightHold(t, holdClient, baseURL)
			held.waitPrefix(t)

			probe := startSwitchProbe(t, baseURL, false)
			// let the probe demonstrably observe A before submitting
			time.Sleep(100 * time.Millisecond)
			postLoadExpectReject(t, adminURL, bad.body, bad.name)
			time.Sleep(100 * time.Millisecond)
			probe.stop()
			assertProbeOnlyLastGood(t, probe, versionA, bad.name)

			// the listen address answers exactly as before, on the
			// shared connection and on brand-new ones
			assertVersionUnchanged(t, client, baseURL, snapA, bad.name)
			assertVersionUnchanged(t, newFailoverClient(false), baseURL, snapA, bad.name+" (new connection)")

			// the in-flight request neither completed nor changed
			held.assertStillOpen(t, bad.name)
			upstream.releaseAll()
			held.waitAndAssertComplete(t, 1)
		})
	}

	// 3. the original valid configuration is still accepted
	assertLoadSucceeds(t, adminURL, "application/json", cfgA, "re-submit original config")
	assertOnlyVariant(t, baseURL, false, 1, versionA, "after re-submitting original config")

	// 4. success and failure rounds alternate; each round is isolated
	for i, bad := range malformed {
		label := fmt.Sprintf("round %d (%s)", i, bad.name)

		assertLoadSucceeds(t, adminURL, "application/json", cfgB, label+": load B")
		assertOnlyVariant(t, baseURL, false, 1, versionB, label+": B active")
		snapB := snapshotVersion(t, client, baseURL)

		postLoadExpectReject(t, adminURL, bad.body, label)
		assertVersionUnchanged(t, client, baseURL, snapB, label+": B survives rejection")
		assertOnlyVariant(t, baseURL, false, 1, versionB, label+": B still active")

		assertLoadSucceeds(t, adminURL, "application/json", cfgA, label+": load A")
		assertOnlyVariant(t, baseURL, false, 1, versionA, label+": A active")
		assertVersionUnchanged(t, client, baseURL, snapA, label+": A identical to first round")
	}
}
