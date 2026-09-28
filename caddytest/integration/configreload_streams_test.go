package integration

import (
	"context"
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

// This file completes the online configuration switch contract started in
// configreload_test.go. While that file keeps one held response open at a
// time, the spec requires the stronger case in which TWO in-flight streams -
// one plaintext HTTP/1.1 keep-alive request and one TLS HTTP/2 stream on the
// very same caddy instance - are held at once across a switch:
//
//   - both streams have already received the A status line, the fixed response
//     headers and the first body segment before B is submitted;
//   - after B commits, brand-new connections, subsequent requests on the
//     existing keep-alive clients and new HTTP/2 streams only ever see B;
//   - both held streams still finish as exactly A: every remaining body
//     segment, in order and length, plus the trailing header, with no B bytes,
//     no truncation and no duplicated prefix, over HTTP/1.1 and HTTP/2 alike;
//   - a malformed (unparseable) JSON document and a complete but conflicting
//     configuration (two servers claiming one listener) are both refused in
//     finite time while streams are held, and A keeps serving new requests and
//     the held streams unchanged;
//   - cancelling one of the two held streams must not disturb the other one,
//     which still completes as exactly A with its trailer, and a further
//     valid configuration still loads afterwards;
//   - alternating A->B, B->A and failed rounds never leak responses, headers,
//     trailers or errors across rounds; exactly one instance answers each
//     address the whole time.

const (
	streamH1Addr    = "127.0.0.1:9094"
	streamH2Addr    = "localhost:9464"
	streamAdminAddr = "127.0.0.1:2994"
	streamAdminURL  = "http://" + streamAdminAddr

	streamH1URL = "http://" + streamH1Addr
	streamH2URL = "https://" + streamH2Addr

	// the held upstream answers /stream with one fixed response header set and
	// this first segment, parks the connection, then (on release) writes the
	// next two segments and the trailing header.
	streamMarkerHeader = "X-Stream-Marker"
	streamMarkerValue  = "fixed-marker"
	streamVariantHdr   = "X-Served-Variant"
	streamTrailerName  = "X-Stream-Trailer"

	streamSeg0 = "stream-first-segment-"
	streamSeg1 = "stream-second-segment"
	streamSeg2 = "stream-third-segment-"
)

func streamTrailerValue(variant string) string { return "done-" + variant }

// streamUpstream is an HTTP/1.1 upstream that caddy reverse-proxies /stream
// to. Every response is written by hand over a hijacked connection so the
// test decides exactly when each chunk and the trailer leave the upstream,
// independently of anything caddy is doing.
type streamUpstream struct {
	ln   net.Listener
	srv  *http.Server
	mu   sync.Mutex
	held map[int]*heldUpstreamConn
	next int
	hits map[string]int
}

type heldUpstreamConn struct {
	id      int
	variant string
	conn    net.Conn
}

func newStreamUpstream(t *testing.T) *streamUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for stream upstream: %v", err)
	}
	u := &streamUpstream{
		ln:   ln,
		held: make(map[int]*heldUpstreamConn),
		hits: make(map[string]int),
	}
	u.srv = &http.Server{Handler: http.HandlerFunc(u.handle)}
	go u.srv.Serve(ln)
	t.Cleanup(func() { u.srv.Close(); ln.Close() })
	return u
}

func (u *streamUpstream) addr() string { return u.ln.Addr().String() }

func (u *streamUpstream) hit(variant string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[variant]
}

// handle writes the status line, the fixed headers and the first segment,
// flushes, then parks the connection until releaseAll.
func (u *streamUpstream) handle(w http.ResponseWriter, r *http.Request) {
	variant := r.Header.Get("X-Variant")
	u.mu.Lock()
	u.hits[variant]++
	u.next++
	id := u.next
	u.mu.Unlock()

	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		panic(err)
	}
	_, _ = io.WriteString(rw,
		"HTTP/1.1 200 OK\r\n"+
			streamMarkerHeader+": "+streamMarkerValue+"\r\n"+
			streamVariantHdr+": "+variant+"\r\n"+
			"Trailer: "+streamTrailerName+"\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n")
	fmt.Fprintf(rw, "%x\r\n%s\r\n", len(streamSeg0), streamSeg0)
	_ = rw.Flush()

	u.mu.Lock()
	u.held[id] = &heldUpstreamConn{id: id, variant: variant, conn: conn}
	u.mu.Unlock()

	// park until the other end closes the connection or the server stops
	_, _ = io.Copy(io.Discard, rw)
}

// releaseAll finalizes every parked response: the second and third segments,
// the terminating chunk with the trailing header, then closes the connection.
// Writes to a connection caddy already aborted (because the client cancelled)
// are expected to fail and are ignored.
func (u *streamUpstream) releaseAll() {
	u.mu.Lock()
	conns := u.held
	u.held = make(map[int]*heldUpstreamConn)
	u.mu.Unlock()
	for _, hc := range conns {
		fmt.Fprintf(hc.conn, "%x\r\n%s\r\n", len(streamSeg1), streamSeg1)
		fmt.Fprintf(hc.conn, "%x\r\n%s\r\n", len(streamSeg2), streamSeg2)
		_, _ = io.WriteString(hc.conn, "0\r\n")
		fmt.Fprintf(hc.conn, "%s: %s\r\n\r\n", streamTrailerName, streamTrailerValue(hc.variant))
		_ = hc.conn.Close()
	}
}

// heldStream is one /stream request running in its own goroutine while the
// test drives switches. cancelAndWait aborts the request; otherwise
// waitAndAssertComplete requires the full A response including the trailer.
type heldStream struct {
	name      string
	wantProto int

	ctx    context.Context
	cancel context.CancelFunc

	headersReady chan struct{}
	done         chan struct{}

	resp      *http.Response
	headerErr error
	seg0      []byte
	seg0Err   error
	rest      []byte
	trailers  http.Header
	restErr   error
}

func startHeldStream(t *testing.T, client *http.Client, baseURL, name string, wantProto int) *heldStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := &heldStream{
		name:         name,
		wantProto:    wantProto,
		ctx:          ctx,
		cancel:       cancel,
		headersReady: make(chan struct{}),
		done:         make(chan struct{}),
	}
	go func() {
		defer close(h.done)
		req, err := http.NewRequestWithContext(h.ctx, http.MethodGet, baseURL+"/stream", nil)
		if err != nil {
			h.headerErr = err
			close(h.headersReady)
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			h.headerErr = err
			close(h.headersReady)
			return
		}
		h.resp = resp
		h.seg0 = make([]byte, len(streamSeg0))
		_, h.seg0Err = io.ReadFull(resp.Body, h.seg0)
		close(h.headersReady)
		if h.seg0Err != nil {
			return
		}
		h.rest, h.restErr = io.ReadAll(resp.Body)
		if h.restErr == nil {
			h.trailers = resp.Trailer.Clone()
		}
	}()
	return h
}

// waitPrefix waits for the fixed headers and the first A segment to arrive.
func (h *heldStream) waitPrefix(t *testing.T, variant string) {
	t.Helper()
	select {
	case <-h.headersReady:
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: held stream never produced its headers/prefix", h.name)
	}
	if h.headerErr != nil {
		t.Fatalf("%s: opening held stream: %v", h.name, h.headerErr)
	}
	if h.seg0Err != nil {
		t.Fatalf("%s: reading held stream prefix: %v", h.name, h.seg0Err)
	}
	if h.resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: status: got %d, want 200", h.name, h.resp.StatusCode)
	}
	if h.resp.ProtoMajor != h.wantProto {
		t.Fatalf("%s: protocol: got HTTP/%d, want HTTP/%d", h.name, h.resp.ProtoMajor, h.wantProto)
	}
	if got := h.resp.Header.Get(streamMarkerHeader); got != streamMarkerValue {
		t.Fatalf("%s: marker header: got %q, want %q", h.name, got, streamMarkerValue)
	}
	if got := h.resp.Header.Get(streamVariantHdr); got != variant {
		t.Fatalf("%s: variant header: got %q, want %q", h.name, got, variant)
	}
	if string(h.seg0) != streamSeg0 {
		t.Fatalf("%s: prefix: got %q, want %q", h.name, h.seg0, streamSeg0)
	}
}

// assertStillOpen proves the held stream has not ended and picked up no extra
// bytes (in particular none from B) while another configuration is active.
func (h *heldStream) assertStillOpen(t *testing.T, phase string) {
	t.Helper()
	select {
	case <-h.done:
		t.Fatalf("%s: held stream completed during %s before the upstream was released", h.name, phase)
	case <-time.After(500 * time.Millisecond):
	}
}

// waitAndAssertComplete waits for release and requires the exact A response:
// segments two and three in order, nothing else, then the A trailer.
func (h *heldStream) waitAndAssertComplete(t *testing.T, variant string) {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(15 * time.Second):
		t.Fatalf("%s: held stream never completed after release", h.name)
	}
	if h.restErr != nil {
		t.Fatalf("%s: reading held stream to completion: %v", h.name, h.restErr)
	}
	wantRest := streamSeg1 + streamSeg2
	if string(h.rest) != wantRest {
		t.Errorf("%s: remainder: got %q, want %q", h.name, h.rest, wantRest)
	}
	full := string(h.seg0) + string(h.rest)
	if want := streamSeg0 + streamSeg1 + streamSeg2; full != want {
		t.Errorf("%s: full body: got %q, want %q", h.name, full, want)
	}
	if strings.Count(full, streamSeg0) != 1 {
		t.Errorf("%s: first segment was delivered more than once: %q", h.name, full)
	}
	if strings.Contains(full, versionBBody) {
		t.Errorf("%s: held stream spliced with B body: %q", h.name, full)
	}
	if got := h.trailers.Get(streamTrailerName); got != streamTrailerValue(variant) {
		t.Errorf("%s: trailer %s: got %q, want %q", h.name, streamTrailerName, got, streamTrailerValue(variant))
	}
	if h.resp.ProtoMajor != h.wantProto {
		t.Errorf("%s: protocol after completion: got HTTP/%d, want HTTP/%d", h.name, h.resp.ProtoMajor, h.wantProto)
	}
}

// waitForCancellation requires the aborted stream to end with an error while
// its already-delivered A prefix stays exactly the A prefix.
func (h *heldStream) waitForCancellation(t *testing.T) {
	t.Helper()
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(15 * time.Second):
		t.Fatalf("%s: cancelled stream never ended", h.name)
	}
	if h.restErr == nil && h.headerErr == nil && h.seg0Err == nil {
		t.Fatalf("%s: cancelled stream ended without a read error", h.name)
	}
	if string(h.seg0) != streamSeg0 {
		t.Errorf("%s: cancelled stream prefix was rewritten: got %q, want %q", h.name, h.seg0, streamSeg0)
	}
}

// streamCaddyfile builds a configuration with one plaintext h1 site and one
// tls-internal h2 site; both answer /version per the variant and proxy
// /stream to the test upstream, tagging it with the variant.
func streamCaddyfile(variant, upstreamAddr string) string {
	status := 201
	body := versionABody
	if variant == "B" {
		status = 202
		body = versionBBody
	}
	site := func(addr string, tlsInternal bool) string {
		var b strings.Builder
		if !tlsInternal {
			addr = "http://" + addr
		}
		b.WriteString(addr + " {\n")
		if tlsInternal {
			b.WriteString("\ttls internal\n")
		}
		fmt.Fprintf(&b, "\thandle /version {\n\t\theader %s %s\n\t\trespond %q %d\n\t}\n", "X-Variant", variant, body, status)
		fmt.Fprintf(&b, "\thandle /stream {\n\t\treverse_proxy %s {\n\t\t\theader_up X-Variant %s\n\t\t}\n\t}\n", upstreamAddr, variant)
		b.WriteString("}\n")
		return b.String()
	}
	return fmt.Sprintf(`{
	skip_install_trust
	admin %s
	grace_period 60s
}
%s%s`, streamAdminAddr, site(streamH1Addr, false), site(streamH2Addr, true))
}

// streamConflictJSON is a complete, parseable config that must fail
// validation: two servers claim the same plaintext listener. It is the
// "listener conflict" failure required by the spec.
func streamConflictJSON() string {
	return fmt.Sprintf(`{
	"admin": {"listen": %q},
	"apps": {
		"http": {
			"servers": {
				"one": {"listen": [%q], "routes": []},
				"two": {"listen": [%q], "routes": []}
			}
		}
	}
}`, streamAdminAddr, streamH1Addr, streamH1Addr)
}

func assertLoadMalformedJSON(t *testing.T, label string) {
	t.Helper()
	status, body := postLoad(t, streamAdminURL, "application/json", strings.NewReader(`{"apps": {`))
	if status != http.StatusBadRequest {
		t.Fatalf("%s: POST /load status: got %d, want 400; body: %s", label, status, body)
	}
	if !strings.Contains(body, "decoding request body") {
		t.Fatalf("%s: POST /load error: got %q, want a JSON decoding error", label, body)
	}
}

func assertLoadConflict(t *testing.T, label string) {
	t.Helper()
	status, body := postLoad(t, streamAdminURL, "application/json", strings.NewReader(streamConflictJSON()))
	if status != http.StatusBadRequest {
		t.Fatalf("%s: POST /load status: got %d, want 400; body: %s", label, status, body)
	}
	if !strings.Contains(body, "listener address repeated") {
		t.Fatalf("%s: POST /load error: got %q, want it to mention a repeated listener address", label, body)
	}
}

// assertReusedClientGetsVariant drives /version on a client whose existing
// connection carried an earlier variant's held stream. After that stream ends
// the old server is shutting down and closes the connection once it is idle, so
// a subsequent request - transparently re-dialed by the transport - must land
// on the live instance and answer the new variant. A request that races the
// idle close is retried; the settled answer is what must be correct.
func assertReusedClientGetsVariant(t *testing.T, client *http.Client, baseURL string, want versionExpectation, wantProto int, where string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last versionResult
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/version")
		if err != nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		last = versionResult{
			status:  resp.StatusCode,
			variant: resp.Header.Get("X-Variant"),
			body:    string(body),
			proto:   resp.ProtoMajor,
		}
		if last.status == want.status && last.variant == want.variant && last.body == want.body && last.proto == wantProto {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s: reused connection's subsequent request settled on %+v, want %+v over HTTP/%d", where, last, want, wantProto)
}

// assertVariantBothProtocols issues /version over fresh h1 and h2 clients
// (so pooled keep-alive state cannot hide a stale answer) and requires the
// given variant on both, on the expected protocol.
func assertVariantBothProtocols(t *testing.T, want versionExpectation, where string) {
	t.Helper()
	h1 := newFailoverClient(false)
	h2 := newFailoverClient(true)
	fetchVersion(t, h1, streamH1URL).assertMatches(t, want, 1, where+" (h1 new connection)")
	fetchVersion(t, h2, streamH2URL).assertMatches(t, want, 2, where+" (h2 new stream)")

	// subsequent requests on the same keep-alive clients must give the same
	// answer: an old listener cannot still be serving the previous variant,
	// and the connection pool must transparently land on the live instance.
	for i := 0; i < 4; i++ {
		fetchVersion(t, h1, streamH1URL).assertMatches(t, want, 1, fmt.Sprintf("%s (h1 pooled #%d)", where, i))
		fetchVersion(t, h2, streamH2URL).assertMatches(t, want, 2, fmt.Sprintf("%s (h2 pooled #%d)", where, i))
	}
}

// startStreamCaddy launches caddy with the initial Caddyfile and waits until
// both protocols answer the expected variant.
func startStreamCaddy(t *testing.T, bin, initialCfg string, want versionExpectation) *caddyInstance {
	t.Helper()
	runDir := t.TempDir()
	cfgPath := filepath.Join(runDir, "initial.Caddyfile")
	if err := os.WriteFile(cfgPath, []byte(initialCfg), 0o600); err != nil {
		t.Fatalf("writing initial config: %v", err)
	}

	logFile, err := os.Create(filepath.Join(runDir, "caddy.log"))
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
	inst := &caddyInstance{
		cmd:      cmd,
		logPath:  logFile.Name(),
		waitDone: make(chan error, 1),
		adminURL: streamAdminURL,
	}
	go func() { inst.waitDone <- cmd.Wait(); logFile.Close() }()
	// if readiness never happens, do not leave a live (or zombie) instance
	// holding the test ports and confusing the next run
	t.Cleanup(func() { inst.stopCaddy(t) })

	h1Client := newFailoverClient(false)
	h2Client := newFailoverClient(true)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-inst.waitDone:
			t.Fatalf("caddy exited before becoming ready: %v\n%s", err, inst.tailLog())
		default:
		}
		ready := 0
		if r, err := h1Client.Get(streamH1URL + "/version"); err == nil {
			_, _ = io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.StatusCode == want.status {
				ready++
			}
		}
		if r, err := h2Client.Get(streamH2URL + "/version"); err == nil {
			_, _ = io.Copy(io.Discard, r.Body)
			r.Body.Close()
			if r.StatusCode == want.status {
				ready++
			}
		}
		if ready == 2 {
			return inst
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("caddy did not become ready on h1 and h2 within 60s\n%s", inst.tailLog())
	return nil
}

// TestConfigReloadDualProtocolStreams drives the in-flight boundary for an
// HTTP/1.1 and an HTTP/2 stream held simultaneously on one instance, across
// successful switches, both kinds of rejected loads, a mid-stream
// cancellation and several alternating rounds.
func TestConfigReloadDualProtocolStreams(t *testing.T) {
	bin := buildCaddyBinary(t)
	upstream := newStreamUpstream(t)

	cfgA := streamCaddyfile("A", upstream.addr())
	cfgB := streamCaddyfile("B", upstream.addr())

	inst := startStreamCaddy(t, bin, cfgA, versionA)
	t.Cleanup(func() { inst.stopCaddy(t) })

	// clients: the held streams never time out, the ordinary clients do.
	holdH1Client := newFailoverClient(false)
	holdH1Client.Timeout = 0
	holdH2Client := newFailoverClient(true)
	holdH2Client.Timeout = 0

	// 1. A serves both protocols.
	assertVariantBothProtocols(t, versionA, "initial A")

	// 2. hold one h1 request and one h2 stream, wait for both A prefixes.
	h1Hold := startHeldStream(t, holdH1Client, streamH1URL, "h1-held", 1)
	h2Hold := startHeldStream(t, holdH2Client, streamH2URL, "h2-held", 2)
	h1Hold.waitPrefix(t, "A")
	h2Hold.waitPrefix(t, "A")
	if got := upstream.hit("A"); got != 2 {
		t.Fatalf("upstream A hits before switch: got %d, want 2", got)
	}
	if got := upstream.hit("B"); got != 0 {
		t.Fatalf("upstream unexpectedly hit B %d times before any B load", got)
	}

	// 3. load B while both addresses are probed; from the 200 onwards only B
	// answers new requests, on new and pooled connections, both protocols.
	probeH1 := startSwitchProbe(t, streamH1URL, false)
	probeH2 := startSwitchProbe(t, streamH2URL, true)
	time.Sleep(100 * time.Millisecond)
	assertLoadSucceeds(t, streamAdminURL, "text/caddyfile", cfgB, "load B with two held streams")
	time.Sleep(100 * time.Millisecond)
	probeH1.stop()
	probeH2.stop()
	probeH1.assertCleanAcrossSwitch(t, "h1 load B")
	probeH2.assertCleanAcrossSwitch(t, "h2 load B")
	assertVariantBothProtocols(t, versionB, "after B load")

	// both held A streams are still exactly where they were.
	h1Hold.assertStillOpen(t, "B active")
	h2Hold.assertStillOpen(t, "B active")

	// 4. release the upstream: both streams finish as exactly A, trailer and
	//    all, over their original protocol.
	upstream.releaseAll()
	h1Hold.waitAndAssertComplete(t, "A")
	h2Hold.waitAndAssertComplete(t, "A")
	if got := upstream.hit("B"); got != 0 {
		t.Errorf("upstream was hit through B %d times while A streams were held; held streams must keep using A", got)
	}

	// 4b. the very connections that carried the A streams must answer B on
	//     their next request: the old server closes an idle keep-alive
	//     connection during shutdown and the client transparently reconnects
	//     to the B instance, over the same protocol.
	assertReusedClientGetsVariant(t, holdH1Client, streamH1URL, versionB, 1, "reused h1 keep-alive after held A stream")
	assertReusedClientGetsVariant(t, holdH2Client, streamH2URL, versionB, 2, "reused h2 connection after held A stream")

	// 5. back to A for the failure/cancellation round.
	assertLoadSucceeds(t, streamAdminURL, "text/caddyfile", cfgA, "reload A")
	assertVariantBothProtocols(t, versionA, "after A reload")

	// 6. hold a fresh h1 request and a fresh h2 stream under A.
	h1Hold2 := startHeldStream(t, holdH1Client, streamH1URL, "h1-held-2", 1)
	h2Hold2 := startHeldStream(t, holdH2Client, streamH2URL, "h2-held-2", 2)
	h1Hold2.waitPrefix(t, "A")
	h2Hold2.waitPrefix(t, "A")
	hitsABefore := upstream.hit("A")
	if hitsABefore != 4 {
		t.Fatalf("upstream A hits after second hold: got %d, want 4", hitsABefore)
	}

	// 6a. unparseable JSON while streams are held: refused in finite time,
	//     A keeps serving new requests, the held streams are untouched.
	assertLoadMalformedJSON(t, "malformed JSON while A streams held")
	assertVariantBothProtocols(t, versionA, "after malformed JSON")
	h1Hold2.assertStillOpen(t, "after malformed JSON")
	h2Hold2.assertStillOpen(t, "after malformed JSON")

	// 6b. complete config with a listener conflict, same guarantees.
	assertLoadConflict(t, "listener conflict while A streams held")
	assertVariantBothProtocols(t, versionA, "after conflict")
	h1Hold2.assertStillOpen(t, "after conflict")
	h2Hold2.assertStillOpen(t, "after conflict")

	// 6c. cancel the h2 stream only: it aborts with its A prefix intact, and
	//     the h1 stream is not affected at all.
	h2Hold2.waitForCancellation(t)
	h1Hold2.assertStillOpen(t, "after cancelling the h2 stream")

	// new requests are still served by A; a new h2 stream works too.
	assertVariantBothProtocols(t, versionA, "after h2 cancellation")

	// 6d. commit B while the h1 A stream is still held: new requests get B,
	//     the held h1 stream stays open and unchanged.
	probeH1b := startSwitchProbe(t, streamH1URL, false)
	probeH2b := startSwitchProbe(t, streamH2URL, true)
	time.Sleep(100 * time.Millisecond)
	assertLoadSucceeds(t, streamAdminURL, "text/caddyfile", cfgB, "reload B with h1 held")
	time.Sleep(100 * time.Millisecond)
	probeH1b.stop()
	probeH2b.stop()
	probeH1b.assertCleanAcrossSwitch(t, "h1 load B (h1 held)")
	probeH2b.assertCleanAcrossSwitch(t, "h2 load B (h1 held)")
	assertVariantBothProtocols(t, versionB, "after B load with h1 held")
	h1Hold2.assertStillOpen(t, "B active with h1 held")

	// 6e. release: the surviving h1 stream completes as exactly A with its
	//     trailer, regardless of the cancelled h2 stream.
	upstream.releaseAll()
	h1Hold2.waitAndAssertComplete(t, "A")

	// the h1 keep-alive connection that carried that stream now answers B on
	// its next request, proving connection reuse never pins a client to the
	// unloaded A instance.
	assertReusedClientGetsVariant(t, holdH1Client, streamH1URL, versionB, 1, "reused h1 keep-alive after surviving held stream")

	// 6f. a valid config still loads after a mid-stream cancellation.
	assertLoadSucceeds(t, streamAdminURL, "text/caddyfile", cfgA, "valid load after cancellation")
	assertVariantBothProtocols(t, versionA, "after valid load post-cancellation")

	// 7. alternating A->B->A rounds, each probed across the boundary: nothing
	//    from an earlier round may leak into a later one.
	for i, cfg := range []string{cfgB, cfgA, cfgB, cfgA} {
		want := versionB
		label := "A->B"
		if i%2 == 1 {
			want = versionA
			label = "B->A"
		}
		p1 := startSwitchProbe(t, streamH1URL, false)
		p2 := startSwitchProbe(t, streamH2URL, true)
		time.Sleep(60 * time.Millisecond)
		assertLoadSucceeds(t, streamAdminURL, "text/caddyfile", cfg, fmt.Sprintf("alternation %d (%s)", i, label))
		time.Sleep(60 * time.Millisecond)
		p1.stop()
		p2.stop()
		p1.assertCleanAcrossSwitch(t, fmt.Sprintf("h1 alternation %d (%s)", i, label))
		p2.assertCleanAcrossSwitch(t, fmt.Sprintf("h2 alternation %d (%s)", i, label))
		assertVariantBothProtocols(t, want, fmt.Sprintf("after alternation %d (%s)", i, label))
	}

	// a final rejected load in between valid rounds still cannot leak.
	assertLoadMalformedJSON(t, "final malformed JSON")
	assertVariantBothProtocols(t, versionA, "after final malformed JSON")
}
