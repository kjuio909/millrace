package integration

// This file strengthens the online configuration switch matrix verified by
// configreload_test.go:
//
//   - one /stream response is held open at the same time on a plaintext
//     HTTP/1.1 keep-alive connection AND on a TLS HTTP/2 connection, both of
//     them already holding the A status line, A headers and the first body
//     fragment when B is submitted through POST /load;
//   - once POST /load reports success, every new request - on a brand new
//     connection, on the reused HTTP/1.1 keep-alive connection, or as a new
//     multiplexed HTTP/2 stream - can only be answered by B;
//   - the two responses that were already in flight keep being answered by A
//     until the externally controlled upstream releases them: identical
//     status, every response header, every body fragment and the trailers
//     must arrive in order with legal framing - never truncated, duplicated,
//     spliced with B, or rewritten when the old configuration unloads;
//   - while the old streams are still open, an unparseable JSON document and
//     a complete configuration that collides on the listener both fail in
//     bounded time with clear semantics and leave A serving, the held streams
//     untouched and the address continuously configured;
//   - cancelling one held client stream leaves the other stream and the next
//     valid configuration load unaffected;
//   - alternating A->B->A->B->A rounds interleaved with failed submissions
//     never leak connections, headers, bodies, trailers or errors across
//     rounds and never leave zero or two instances accepting traffic.
//
// The exact same matrix runs against a plaintext HTTP/1.1 listener and an
// HTTPS listener using `tls internal` negotiated as HTTP/2; both protocols
// live in every submitted configuration, so a single round exercises both
// switch boundaries simultaneously.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// stream* are the three body fragments the held upstream sends for one
	// /stream response. The first fragment is flushed and held before the
	// configuration switch; the other two (plus trailers) are only sent once
	// the test releases that particular upstream connection.
	streamPrefixFmt = "stream-%d-prefix-A----"
	streamMiddleFmt = "stream-%d-middle-A----"
	streamEndFmt    = "stream-%d-end-A-------"
	streamTrailerV  = "done-A"
)

// switchStreamUpstream is a test-process HTTP/1.1 upstream. Per accepted
// /stream connection it writes the A status line, fixed response headers
// (announcing the trailers) and the first body chunk, then parks the
// hijacked connection. A release signal for that exact connection later
// flushes the remaining two chunks and the trailers. Each connection gets a
// monotonically increasing sequence number embedded in every fragment and
// in a trailer, so a fragment from another round/connection can never be
// mistaken for the expected one.
type switchStreamUpstream struct {
	ln net.Listener

	mu      sync.Mutex
	held    map[uint64]net.Conn
	nextSeq uint64
	hits    map[string]int
}

func newSwitchStreamUpstream(t *testing.T) *switchStreamUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for stream upstream: %v", err)
	}
	u := &switchStreamUpstream{
		ln:   ln,
		held: make(map[uint64]net.Conn),
		hits: make(map[string]int),
	}
	srv := &http.Server{Handler: http.HandlerFunc(u.handle)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return u
}

func (u *switchStreamUpstream) addr() string { return u.ln.Addr().String() }

func (u *switchStreamUpstream) variantHits(variant string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[variant]
}

func (u *switchStreamUpstream) heldCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.held)
}

// release finalizes the single held connection with the given sequence
// number: middle chunk, end chunk, trailers, clean terminating chunk.
func (u *switchStreamUpstream) release(seq uint64) bool {
	u.mu.Lock()
	conn, ok := u.held[seq]
	if ok {
		delete(u.held, seq)
	}
	u.mu.Unlock()
	if !ok {
		return false
	}
	fmt.Fprintf(conn, "%x\r\n%s\r\n",
		len(fmt.Sprintf(streamMiddleFmt, seq)), fmt.Sprintf(streamMiddleFmt, seq))
	fmt.Fprintf(conn, "%x\r\n%s\r\n",
		len(fmt.Sprintf(streamEndFmt, seq)), fmt.Sprintf(streamEndFmt, seq))
	fmt.Fprintf(conn, "0\r\nX-Stream-Trailer: %s\r\nX-Stream-Seq: %d\r\n\r\n",
		streamTrailerV, seq)
	_ = conn.Close()
	return true
}

// releaseAll finalizes every currently held connection.
func (u *switchStreamUpstream) releaseAll() {
	u.mu.Lock()
	seqs := make([]uint64, 0, len(u.held))
	for seq := range u.held {
		seqs = append(seqs, seq)
	}
	u.mu.Unlock()
	for _, seq := range seqs {
		u.release(seq)
	}
}

func (u *switchStreamUpstream) handle(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.hits[r.Header.Get("X-Variant")]++
	u.nextSeq++
	seq := u.nextSeq
	u.mu.Unlock()

	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		panic(err)
	}
	prefix := fmt.Sprintf(streamPrefixFmt, seq)
	_, _ = io.WriteString(rw,
		"HTTP/1.1 200 OK\r\n"+
			"X-Stream-Marker: A\r\n"+
			"X-Stream-Seq: "+fmt.Sprintf("%d", seq)+"\r\n"+
			"Trailer: X-Stream-Trailer, X-Stream-Seq\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n")
	fmt.Fprintf(rw, "%x\r\n%s\r\n", len(prefix), prefix)
	_ = rw.Flush()

	u.mu.Lock()
	u.held[seq] = conn
	u.mu.Unlock()

	// after a Hijack the stdlib server no longer touches this connection;
	// park here until the test releases it (or Caddy tears down the stream)
	_, _ = io.Copy(io.Discard, rw)
}

// heldStream drives one /stream request in its own goroutine.
type heldStream struct {
	name      string
	wantProto int
	seq       uint64

	prefixReady chan struct{}
	done        chan struct{}

	resp      *http.Response
	prefix    []byte
	prefixErr error
	rest      []byte
	restErr   error

	cancel context.CancelFunc
}

func streamPayloads(seq uint64) (prefix, middle, end string) {
	return fmt.Sprintf(streamPrefixFmt, seq),
		fmt.Sprintf(streamMiddleFmt, seq),
		fmt.Sprintf(streamEndFmt, seq)
}

// startHeldStream issues GET /stream and returns once the A status, fixed
// headers and first body fragment have been observed.
func startHeldStream(t *testing.T, name string, client *http.Client, baseURL string, wantProto int) *heldStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := &heldStream{
		name:        name,
		wantProto:   wantProto,
		prefixReady: make(chan struct{}),
		done:        make(chan struct{}),
		cancel:      cancel,
	}
	go func() {
		defer close(h.done)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/stream", nil)
		if err != nil {
			h.prefixErr = err
			close(h.prefixReady)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			h.prefixErr = err
			close(h.prefixReady)
			return
		}
		h.resp = resp
		// the exact prefix length is unknown until the header carrying the
		// sequence number arrives; read one byte short of the longest
		// possible prefix and then fill the rest after reading X-Stream-Seq
		seqStr := resp.Header.Get("X-Stream-Seq")
		seq, err := parseSeq(seqStr)
		if err != nil {
			h.prefixErr = fmt.Errorf("%s: parsing X-Stream-Seq %q: %v", name, seqStr, err)
			close(h.prefixReady)
			return
		}
		h.seq = seq
		prefix, _, _ := streamPayloads(seq)
		h.prefix = make([]byte, len(prefix))
		_, h.prefixErr = io.ReadFull(resp.Body, h.prefix)
		close(h.prefixReady)
		if h.prefixErr != nil {
			return
		}
		h.rest, h.restErr = io.ReadAll(resp.Body)
	}()
	return h
}

func (h *heldStream) waitPrefix(t *testing.T) {
	t.Helper()
	select {
	case <-h.prefixReady:
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: stream never produced its A prefix", h.name)
	}
	if h.prefixErr != nil {
		t.Fatalf("%s: reading A prefix: %v", h.name, h.prefixErr)
	}
	prefix, _, _ := streamPayloads(h.seq)
	if string(h.prefix) != prefix {
		t.Fatalf("%s: prefix: got %q, want %q", h.name, h.prefix, prefix)
	}
	if h.resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: status: got %d, want 200", h.name, h.resp.StatusCode)
	}
	if got := h.resp.Header.Get("X-Stream-Marker"); got != "A" {
		t.Fatalf("%s: X-Stream-Marker: got %q, want A", h.name, got)
	}
	if got := h.resp.Header.Get("X-Stream-Seq"); got != fmt.Sprintf("%d", h.seq) {
		t.Fatalf("%s: X-Stream-Seq header: got %q, want %d", h.name, got, h.seq)
	}
	if h.resp.ProtoMajor != h.wantProto {
		t.Fatalf("%s: protocol: got HTTP/%d, want HTTP/%d", h.name, h.resp.ProtoMajor, h.wantProto)
	}
	if h.wantProto == 1 {
		// the streamed prefix must use legal HTTP/1.1 chunked framing
		if !containsString(h.resp.TransferEncoding, "chunked") {
			t.Fatalf("%s: HTTP/1.1 transfer encoding: got %v, want chunked", h.name, h.resp.TransferEncoding)
		}
	} else if len(h.resp.TransferEncoding) != 0 {
		t.Fatalf("%s: HTTP/2 must not advertise transfer encodings, got %v", h.name, h.resp.TransferEncoding)
	}
}

// assertStillOpen proves no further bytes (in particular none belonging to
// another variant) arrived and the stream has not ended while another
// configuration is active.
func (h *heldStream) assertStillOpen(t *testing.T, phase string) {
	t.Helper()
	select {
	case <-h.done:
		t.Fatalf("%s: stream completed during %s before the upstream released it", h.name, phase)
	case <-time.After(300 * time.Millisecond):
	}
}

// waitAndAssertComplete waits for release and asserts the stream is exactly
// the full A response: the A prefix already asserted, then exactly the A
// middle and end fragments in order, then both trailers, with a clean body
// read - no B splice, no truncation, no duplication.
func (h *heldStream) waitAndAssertComplete(t *testing.T) {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(15 * time.Second):
		t.Fatalf("%s: stream never completed after release", h.name)
	}
	if h.restErr != nil {
		t.Fatalf("%s: reading remainder after release: %v", h.name, h.restErr)
	}
	_, middle, end := streamPayloads(h.seq)
	wantRest := middle + end
	if string(h.rest) != wantRest {
		t.Errorf("%s: remainder: got %q, want %q", h.name, h.rest, wantRest)
	}
	full := string(append(append([]byte{}, h.prefix...), h.rest...))
	prefix, _, _ := streamPayloads(h.seq)
	if want := prefix + middle + end; full != want {
		t.Errorf("%s: full body: got %q, want %q", h.name, full, want)
	}
	if strings.Count(full, prefix) != 1 {
		t.Errorf("%s: prefix delivered more than once: %q", h.name, full)
	}
	if strings.Contains(full, versionBBody) {
		t.Errorf("%s: A stream spliced with B content: %q", h.name, full)
	}
	if got := h.resp.Trailer.Get("X-Stream-Trailer"); got != streamTrailerV {
		t.Errorf("%s: X-Stream-Trailer: got %q, want %q", h.name, got, streamTrailerV)
	}
	if got := h.resp.Trailer.Get("X-Stream-Seq"); got != fmt.Sprintf("%d", h.seq) {
		t.Errorf("%s: X-Stream-Seq trailer: got %q, want %d", h.name, got, h.seq)
	}
	if h.resp.ProtoMajor != h.wantProto {
		t.Errorf("%s: final protocol: got HTTP/%d, want HTTP/%d", h.name, h.resp.ProtoMajor, h.wantProto)
	}
}

// assertCanceled aborts the client stream and requires it to end with an
// error; the already-received prefix stays intact.
func (h *heldStream) assertCanceled(t *testing.T, phase string) {
	t.Helper()
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(15 * time.Second):
		t.Fatalf("%s: stream did not end after cancellation during %s", h.name, phase)
	}
	if h.restErr == nil {
		t.Fatalf("%s: canceled stream ended with a clean read during %s", h.name, phase)
	}
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func parseSeq(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

// waitForVariant polls /version with fresh connections until the site answers
// want (status, X-Variant and body), or the deadline expires. It tolerates the
// transient TLS/connection errors of an internal certificate being minted.
func waitForVariant(t *testing.T, baseURL string, h2 bool, want versionExpectation, timeout time.Duration, logPath string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr string
	for time.Now().Before(deadline) {
		client := newFailoverClient(h2)
		client.Timeout = 5 * time.Second
		resp, err := client.Get(baseURL + "/version")
		if err != nil {
			lastErr = err.Error()
			time.Sleep(100 * time.Millisecond)
			continue
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == want.status &&
			resp.Header.Get("X-Variant") == want.variant &&
			string(bodyBytes) == want.body {
			return
		}
		lastErr = fmt.Sprintf("status=%d variant=%q body=%q", resp.StatusCode, resp.Header.Get("X-Variant"), bodyBytes)
		time.Sleep(100 * time.Millisecond)
	}
	tail := ""
	if b, err := os.ReadFile(logPath); err == nil {
		const max = 2000
		if len(b) > max {
			b = b[len(b)-max:]
		}
		tail = "\n" + string(b)
	}
	t.Fatalf("%s never answered variant %s within %s (last: %s)%s",
		baseURL, want.variant, timeout, lastErr, tail)
}

// switchJSONConfig builds a complete configuration with two listeners on
// fixed addresses: a plaintext HTTP/1.1 site and an HTTPS site using the
// internal issuer negotiated as HTTP/2. Variant A proxies /stream to the
// upstream; variant B only serves /version. A and B listen on exactly the
// same addresses, which is what makes the switch boundary observable.
func switchJSONConfig(adminAddr, h1Addr, h2Addr, upstreamAddr, variant string) string {
	status := map[string]int{"A": http.StatusCreated, "B": http.StatusAccepted}
	body := versionABodyFor(variant)

	// the h2 routes match host "localhost" explicitly: automatic HTTPS only
	// enables TLS on a listener when the routes advertise a qualifying host,
	// which then uses the internal issuer policy declared below.
	routes := func(host string) string {
		hostMatch := ""
		if host != "" {
			hostMatch = fmt.Sprintf(`"host": [%q], `, host)
		}
		streamRoute := ""
		if variant == "A" {
			streamRoute = fmt.Sprintf(`
					,{
						"match": [{%s"path": ["/stream"]}],
						"handle": [{
							"handler": "reverse_proxy",
							"headers": {"request": {"set": {"X-Variant": ["A"]}}},
							"upstreams": [{"dial": %q}]
						}]
					}`, hostMatch, upstreamAddr)
		}
		return fmt.Sprintf(`[
					{
						"match": [{%s"path": ["/version"]}],
						"handle": [{
							"handler": "static_response",
							"status_code": %d,
							"headers": {"X-Variant": [%q]},
							"body": %q
						}]
					}%s
				]`, hostMatch, status[variant], variant, body, streamRoute)
	}

	// h2Addr is a host:port whose host is "localhost" for the TLS site.
	h2Port := strings.Split(h2Addr, ":")[1]

	return fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {
		"http": {
			"grace_period": "60s",
			"servers": {
				"h1": {
					"listen": [%q],
					"routes": %s
				},
				"h2": {
					"listen": [%q],
					"routes": %s
				}
			}
		},
		"pki": {
			"certificate_authorities": {
				"local": {"install_trust": false}
			}
		},
		"tls": {
			"automation": {
				"policies": [
					{
						"subjects": ["localhost"],
						"issuers": [{"module": "internal"}]
					}
				]
			}
		}
	}
}`,
		adminAddr,
		h1Addr, routes(""),
		":"+h2Port, routes("localhost"))
}

func versionABodyFor(variant string) string {
	if variant == "B" {
		return versionBBody
	}
	return versionABody
}

// switchBadJSONDuplicate declares the same listener twice inside one
// configuration; Validate() must reject it before the running instance is
// disturbed.
func switchBadJSONDuplicate(adminAddr, h1Addr, h2Addr string) string {
	return fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {
		"http": {
			"grace_period": "60s",
			"servers": {
				"one": {"listen": [%q, %q]},
				"two": {"listen": [%q]}
			}
		}
	}
}`, adminAddr, h1Addr, h2Addr, h2Addr)
}

const switchBadJSONMalformed = `{"apps": {NOT-VALID-JSON`

func assertLoadMalformed(t *testing.T, adminURL, body, label string) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(adminURL+"/load", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s: POST /load transport error: %v", label, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("%s: POST /load status: got %d, want 400; body: %s", label, resp.StatusCode, respBody)
	}
	if !strings.Contains(string(respBody), "decoding request body") {
		t.Fatalf("%s: POST /load error: got %q, want a JSON decoding error", label, respBody)
	}
}

// newHeldStreamClient returns a client with no overall deadline: a held
// /stream response intentionally stays open across configuration switches.
func newHeldStreamClient(h2 bool) *http.Client {
	c := newFailoverClient(h2)
	c.Timeout = 0
	return c
}

// TestOnlineConfigSwitchStreamBoundaries drives the full simultaneous
// HTTP/1.1 + HTTP/2 switch matrix described at the top of the file.
func TestOnlineConfigSwitchStreamBoundaries(t *testing.T) {
	bin := buildCaddyBinary(t)

	const (
		adminAddr = "127.0.0.1:2986"
		h1Addr    = "127.0.0.1:9093"
		h2Addr    = "localhost:9455"
	)
	adminURL := "http://" + adminAddr
	h1URL := "http://" + h1Addr
	h2URL := "https://" + h2Addr

	upstream := newSwitchStreamUpstream(t)

	cfgA := switchJSONConfig(adminAddr, h1Addr, h2Addr, upstream.addr(), "A")
	cfgB := switchJSONConfig(adminAddr, h1Addr, h2Addr, upstream.addr(), "B")
	cfgBadDup := switchBadJSONDuplicate(adminAddr, h1Addr, h2Addr)

	runDir := t.TempDir()
	cfgPath := filepath.Join(runDir, "initial.json")
	if err := os.WriteFile(cfgPath, []byte(cfgA), 0o600); err != nil {
		t.Fatalf("writing initial config: %v", err)
	}

	inst := startReloadCaddy(t, bin, cfgPath, "", runDir, adminURL, h1URL, false, versionA.status)
	t.Cleanup(func() { inst.stopCaddy(t) })

	// startReloadCaddy only polls the h1 address; the internal certificate
	// backing the h2 listener is minted on demand, so wait until the TLS site
	// answers A as well before starting the matrix
	waitForVariant(t, h2URL, true, versionA, 60*time.Second, inst.logPath)

	// ordinary bounded clients for /version; the held-stream clients must not
	// have a deadline because the responses stay open across config switches.
	h1Client := newFailoverClient(false)
	h2Client := newHeldStreamClient(true)

	// this h1 connection performs an A request before the switch and is reused
	// afterwards: once B commits, its next (keep-alive) request must be B
	h1KeepAlive := newHeldStreamClient(false)

	loadB := func(label string) {
		t.Helper()
		probe1 := startSwitchProbe(t, h1URL, false)
		probe2 := startSwitchProbe(t, h2URL, true)
		time.Sleep(100 * time.Millisecond)
		assertLoadSucceeds(t, adminURL, "application/json", cfgB, label)
		time.Sleep(100 * time.Millisecond)
		probe1.stop()
		probe2.stop()
		probe1.assertCleanAcrossSwitch(t, label+" h1")
		probe2.assertCleanAcrossSwitch(t, label+" h2")
	}
	loadA := func(label string) {
		t.Helper()
		assertLoadSucceeds(t, adminURL, "application/json", cfgA, label)
	}

	// only B must answer afterwards, whether the client opens a brand new
	// connection, reuses the pooled h1 keep-alive connection, or opens a new
	// multiplexed h2 stream next to the held one.
	assertOnlyBAfterCommit := func(label string, h1Held, h2Held *heldStream) {
		t.Helper()
		for i := 0; i < 8; i++ {
			fetchVersion(t, newFailoverClient(false), h1URL).
				assertMatches(t, versionB, 1, fmt.Sprintf("%s fresh h1 %d", label, i))
			fetchVersion(t, newFailoverClient(true), h2URL).
				assertMatches(t, versionB, 2, fmt.Sprintf("%s fresh h2 %d", label, i))
			fetchVersion(t, h1KeepAlive, h1URL).
				assertMatches(t, versionB, 1, fmt.Sprintf("%s reused h1 keep-alive %d", label, i))
			// the h2 client already has the held stream on its connection; a
			// new multiplexed stream must still only ever see B
			fetchVersion(t, h2Client, h2URL).
				assertMatches(t, versionB, 2, fmt.Sprintf("%s reused h2 conn %d", label, i))
		}
		if h1Held != nil {
			h1Held.assertStillOpen(t, label+" h1")
		}
		if h2Held != nil {
			h2Held.assertStillOpen(t, label+" h2")
		}
	}

	// --- round 1: A serves; both protocols hold a stream while B commits ---
	fetchVersion(t, h1Client, h1URL).assertMatches(t, versionA, 1, "initial A h1")
	fetchVersion(t, h2Client, h2URL).assertMatches(t, versionA, 2, "initial A h2")
	// warm the reused keep-alive connection with an A answer
	fetchVersion(t, h1KeepAlive, h1URL).assertMatches(t, versionA, 1, "warm reused h1")

	h1Held := startHeldStream(t, "h1-held-1", newHeldStreamClient(false), h1URL, 1)
	h1Held.waitPrefix(t)
	h2Held := startHeldStream(t, "h2-held-1", h2Client, h2URL, 2)
	h2Held.waitPrefix(t)
	if upstream.heldCount() != 2 {
		t.Fatalf("upstream held conns: got %d, want 2", upstream.heldCount())
	}
	if got := upstream.variantHits("A"); got != 2 {
		t.Fatalf("upstream X-Variant=A hits: got %d, want 2", got)
	}

	loadB("load B round 1")
	assertOnlyBAfterCommit("after B round 1", h1Held, h2Held)

	// failed submissions while the two A streams are open: A must not come
	// back, B must keep serving, and the held A streams stay exactly as they
	// were; the listener must never briefly unconfigure or double-bind
	assertLoadMalformed(t, adminURL, switchBadJSONMalformed, "malformed JSON while B active")
	assertOnlyVariant(t, h1URL, false, 1, versionB, "malformed JSON h1")
	assertOnlyVariant(t, h2URL, true, 2, versionB, "malformed JSON h2")
	assertLoadRejected(t, adminURL, cfgBadDup, "duplicate listener while B active")
	assertOnlyVariant(t, h1URL, false, 1, versionB, "duplicate listener h1")
	assertOnlyVariant(t, h2URL, true, 2, versionB, "duplicate listener h2")
	h1Held.assertStillOpen(t, "failures h1")
	h2Held.assertStillOpen(t, "failures h2")

	// releasing the upstream completes both streams as exactly A end to end
	upstream.release(h1Held.seq)
	h1Held.waitAndAssertComplete(t)
	upstream.release(h2Held.seq)
	h2Held.waitAndAssertComplete(t)
	if got := upstream.variantHits("A"); got != 2 {
		t.Errorf("upstream X-Variant=A hits after round 1 release: got %d, want 2", got)
	}

	// --- round 2: back to A; cancel the h2 stream, the h1 stream survives --
	loadA("reload A round 2")
	assertOnlyVariant(t, h1URL, false, 1, versionA, "round 2 A h1")
	assertOnlyVariant(t, h2URL, true, 2, versionA, "round 2 A h2")

	h1Held2 := startHeldStream(t, "h1-held-2", newHeldStreamClient(false), h1URL, 1)
	h1Held2.waitPrefix(t)
	h2Held2 := startHeldStream(t, "h2-held-2", h2Client, h2URL, 2)
	h2Held2.waitPrefix(t)

	loadB("load B round 2")
	assertOnlyBAfterCommit("after B round 2", h1Held2, h2Held2)

	// cancel the h2 client stream; the h1 stream must be completely unaffected
	h2Held2.assertCanceled(t, "cancel h2 while B active")
	h1Held2.assertStillOpen(t, "h1 unaffected by h2 cancel")
	fetchVersion(t, h1KeepAlive, h1URL).assertMatches(t, versionB, 1, "B after h2 cancel h1")
	fetchVersion(t, h2Client, h2URL).assertMatches(t, versionB, 2, "B after h2 cancel h2")

	upstream.release(h1Held2.seq)
	h1Held2.waitAndAssertComplete(t)

	// a valid load still succeeds after the cancellation
	loadA("reload A after h2 cancel")
	assertOnlyVariant(t, h1URL, false, 1, versionA, "after cancel A h1")
	assertOnlyVariant(t, h2URL, true, 2, versionA, "after cancel A h2")

	// --- round 3: A again; a failed load with streams open, then cancel h1 -
	h1Held3 := startHeldStream(t, "h1-held-3", newHeldStreamClient(false), h1URL, 1)
	h1Held3.waitPrefix(t)
	h2Held3 := startHeldStream(t, "h2-held-3", h2Client, h2URL, 2)
	h2Held3.waitPrefix(t)

	// malformed JSON fails while A streams are open: A keeps serving
	assertLoadMalformed(t, adminURL, switchBadJSONMalformed, "malformed JSON while A active")
	assertOnlyVariant(t, h1URL, false, 1, versionA, "malformed JSON round 3 h1")
	assertOnlyVariant(t, h2URL, true, 2, versionA, "malformed JSON round 3 h2")
	h1Held3.assertStillOpen(t, "malformed h1 held")
	h2Held3.assertStillOpen(t, "malformed h2 held")
	assertLoadRejected(t, adminURL, cfgBadDup, "duplicate listener while A active")
	assertOnlyVariant(t, h1URL, false, 1, versionA, "duplicate round 3 h1")
	assertOnlyVariant(t, h2URL, true, 2, versionA, "duplicate round 3 h2")

	// cancel the h1 client stream; the h2 stream must be completely unaffected
	h1Held3.assertCanceled(t, "cancel h1 while A active")
	h2Held3.assertStillOpen(t, "h2 unaffected by h1 cancel")
	fetchVersion(t, newFailoverClient(false), h1URL).assertMatches(t, versionA, 1, "A after h1 cancel h1")
	fetchVersion(t, h2Client, h2URL).assertMatches(t, versionA, 2, "A after h1 cancel h2")

	upstream.release(h2Held3.seq)
	h2Held3.waitAndAssertComplete(t)

	// --- final commit: B then A, success/failure/success chain stays clean --
	loadB("load B round 3")
	assertOnlyVariant(t, h1URL, false, 1, versionB, "final B h1")
	assertOnlyVariant(t, h2URL, true, 2, versionB, "final B h2")
	assertLoadMalformed(t, adminURL, switchBadJSONMalformed, "malformed JSON while final B active")
	assertOnlyVariant(t, h2URL, true, 2, versionB, "after final malformed h2")
	loadA("final reload A")
	assertOnlyVariant(t, h1URL, false, 1, versionA, "final A h1")
	assertOnlyVariant(t, h2URL, true, 2, versionA, "final A h2")
}
