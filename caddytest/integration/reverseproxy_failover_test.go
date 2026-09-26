package integration

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// captureConn is a net.Conn that records every byte read from it, so tests
// can compare the exact request bytes an upstream received.
type captureConn struct {
	net.Conn
	buf *bytes.Buffer
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.buf.Write(p[:n])
	}
	return n, err
}

// failoverScriptedUpstream is a raw TCP upstream with deterministic,
// path-based behavior used to simulate failures at precise points of the
// response lifecycle:
//
//	/retry-before: reads the request, then closes without any response bytes
//	/retry-info:   writes a 103 provisional response, then closes
//	/partial:      writes final status+headers and a body prefix, then closes
//	/ok:           writes a complete 200 response
//	/empty:        writes a 200 response with Content-Length: 0
type failoverScriptedUpstream struct {
	addr string
	hits atomic.Int32

	mu          sync.Mutex
	rawRequests [][]byte // raw request bytes, one entry per connection
}

func newFailoverScriptedUpstream(t *testing.T) *failoverScriptedUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	u := &failoverScriptedUpstream{addr: ln.Addr().String()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go u.serve(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return u
}

func (u *failoverScriptedUpstream) serve(conn net.Conn) {
	defer conn.Close()
	raw := new(bytes.Buffer)
	cc := &captureConn{Conn: conn, buf: raw}

	u.hits.Add(1)
	req, err := http.ReadRequest(bufio.NewReader(cc))
	if err != nil {
		return
	}
	// consume the entire request body, so the proxy observes a complete
	// request before the scripted failure happens
	_, _ = io.Copy(io.Discard, req.Body)

	u.mu.Lock()
	u.rawRequests = append(u.rawRequests, raw.Bytes())
	u.mu.Unlock()

	switch req.URL.Path {
	case "/retry-before":
		// close without writing any response bytes
	case "/retry-info":
		fmt.Fprintf(cc, "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n")
		// close before any final response
	case "/partial":
		// declare 11 bytes but only produce the "part1" prefix (5 bytes)
		fmt.Fprintf(cc, "HTTP/1.1 200 OK\r\nX-Origin: first\r\nContent-Length: 11\r\n\r\npart1")
		// close mid-body
	case "/ok":
		body := "ok-from-first"
		fmt.Fprintf(cc, "HTTP/1.1 200 OK\r\nX-Origin: first\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	case "/empty":
		fmt.Fprintf(cc, "HTTP/1.1 200 OK\r\nX-Origin: first\r\nContent-Length: 0\r\n\r\n")
	}
}

func (u *failoverScriptedUpstream) rawRequest(i int) []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	if i >= len(u.rawRequests) {
		return nil
	}
	return u.rawRequests[i]
}

// failoverBackupUpstream is a real HTTP server that validates the requests
// it receives and records them along with their raw wire bytes.
type failoverBackupUpstream struct {
	addr string
	hits atomic.Int32

	mu          sync.Mutex
	rawRequests [][]byte
	paths       []string
}

func newFailoverBackupUpstream(t *testing.T) *failoverBackupUpstream {
	t.Helper()
	u := &failoverBackupUpstream{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	u.addr = ln.Addr().String()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u.hits.Add(1)
			u.mu.Lock()
			u.paths = append(u.paths, r.URL.Path)
			u.mu.Unlock()

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "read body: "+err.Error(), http.StatusInternalServerError)
				return
			}

			switch r.URL.Path {
			case "/retry-before":
				// echo the request exactly as received, so the client can
				// verify the proxy rebuilt it identically: same method,
				// full query string, headers, body bytes, and length
				w.Header().Set("X-Origin", "second")
				w.Header().Set("X-Echo-Method", r.Method)
				w.Header().Set("X-Echo-Query", r.URL.RawQuery)
				w.Header().Set("X-Echo-Content-Type", r.Header.Get("Content-Type"))
				w.Header().Set("X-Echo-Trace", r.Header.Get("X-Trace"))
				w.Header().Set("X-Echo-Content-Length", strconv.FormatInt(r.ContentLength, 10))
				w.WriteHeader(http.StatusCreated)
				w.Write(body)
			case "/retry-info":
				w.Header().Set("X-Origin", "second")
				w.Write([]byte("final-from-second"))
			default:
				w.Header().Set("X-Origin", "second")
				w.Write([]byte("unexpected-on-second"))
			}
		}),
	}

	// wrap connections so the raw request bytes are captured
	go srv.Serve(&captureListener{Listener: ln, upstream: u})
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return u
}

// captureListener wraps accepted connections with captureConn and registers
// each connection's buffer on the upstream for later inspection.
type captureListener struct {
	net.Listener
	upstream *failoverBackupUpstream
}

func (l *captureListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	raw := new(bytes.Buffer)
	l.upstream.mu.Lock()
	l.upstream.rawRequests = append(l.upstream.rawRequests, nil)
	idx := len(l.upstream.rawRequests) - 1
	l.upstream.mu.Unlock()
	return &registeredCaptureConn{captureConn{Conn: conn, buf: raw}, l.upstream, idx}, nil
}

type registeredCaptureConn struct {
	captureConn
	u   *failoverBackupUpstream
	idx int
}

func (c *registeredCaptureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.u.mu.Lock()
		c.u.rawRequests[c.idx] = append(c.u.rawRequests[c.idx], p[:n]...)
		c.u.mu.Unlock()
	}
	return n, err
}

func (u *failoverBackupUpstream) rawRequest(i int) []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	if i >= len(u.rawRequests) {
		return nil
	}
	return u.rawRequests[i]
}

// failoverCaddyfile returns a Caddyfile config proxying to the two given
// upstream addresses in fixed order with a retry budget of one.
func failoverCaddyfile(first, second string) string {
	return fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
	}
	http://localhost:9080 {
		reverse_proxy %s %s {
			lb_policy first
			lb_retries 1
		}
	}
	`, first, second)
}

// TestReverseProxyFailoverRetryBefore verifies that a POST whose first
// upstream vanishes before any final response headers is retried exactly
// once on the second upstream, which receives the identical request (same
// metadata, byte sequence, and length), and that the client receives a
// single complete 201 response.
func TestReverseProxyFailoverRetryBefore(t *testing.T) {
	first := newFailoverScriptedUpstream(t)
	second := newFailoverBackupUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(failoverCaddyfile(first.addr, second.addr), "caddyfile")

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9080/retry-before?a=1&b=2",
		strings.NewReader(`{"n":1}`))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trace", "t-7")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("failed reading response body: %v", err)
	}

	// the client receives a single, complete 201 from the second upstream,
	// echoing the request exactly as the second upstream received it
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want %d (body: %s)", resp.StatusCode, http.StatusCreated, body)
	}
	if got := resp.Header.Get("X-Origin"); got != "second" {
		t.Errorf("X-Origin: got %q, want %q", got, "second")
	}
	for header, want := range map[string]string{
		"X-Echo-Method":         http.MethodPost,
		"X-Echo-Query":          "a=1&b=2",
		"X-Echo-Content-Type":   "application/json",
		"X-Echo-Trace":          "t-7",
		"X-Echo-Content-Length": "7",
	} {
		if got := resp.Header.Get(header); got != want {
			t.Errorf("%s: got %q, want %q (rebuilt request differs)", header, got, want)
		}
	}
	if string(body) != `{"n":1}` {
		t.Errorf("body: got %q, want %q", body, `{"n":1}`)
	}

	// each upstream was contacted exactly once: fixed order, no looping
	if got := first.hits.Load(); got != 1 {
		t.Errorf("first upstream hits: got %d, want 1", got)
	}
	if got := second.hits.Load(); got != 1 {
		t.Fatalf("second upstream hits: got %d, want 1", got)
	}

	// the second upstream received exactly the same request bytes the
	// first one did: the proxy rebuilt the request identically
	firstRaw := first.rawRequest(0)
	secondRaw := second.rawRequest(0)
	if len(firstRaw) == 0 || len(secondRaw) == 0 {
		t.Fatalf("missing raw request capture: first=%d bytes, second=%d bytes", len(firstRaw), len(secondRaw))
	}
	if !bytes.Equal(firstRaw, secondRaw) {
		t.Errorf("rebuilt request bytes differ:\nfirst upstream got:\n%s\nsecond upstream got:\n%s", firstRaw, secondRaw)
	}
}

// TestReverseProxyFailoverRetryInfo verifies that a 103 provisional response
// is forwarded to the client promptly and in order but does not count as a
// final response: the request is still retried when the first upstream then
// fails, and the single final response comes from the second upstream.
func TestReverseProxyFailoverRetryInfo(t *testing.T) {
	first := newFailoverScriptedUpstream(t)
	second := newFailoverBackupUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(failoverCaddyfile(first.addr, second.addr), "caddyfile")

	// capture provisional (1xx) responses on the client side
	var provisionalMu sync.Mutex
	var provisional []int
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			provisionalMu.Lock()
			defer provisionalMu.Unlock()
			provisional = append(provisional, code)
			return nil
		},
	}

	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/retry-info", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("failed reading response body: %v", err)
	}

	// the 103 arrived before the final response, exactly once
	provisionalMu.Lock()
	gotProvisional := append([]int(nil), provisional...)
	provisionalMu.Unlock()
	if len(gotProvisional) != 1 || gotProvisional[0] != http.StatusEarlyHints {
		t.Errorf("provisional responses: got %v, want [103]", gotProvisional)
	}

	// the single final response comes from the second upstream
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("X-Origin"); got != "second" {
		t.Errorf("X-Origin: got %q, want %q", got, "second")
	}
	if string(body) != "final-from-second" {
		t.Errorf("body: got %q, want %q", body, "final-from-second")
	}

	if got := first.hits.Load(); got != 1 {
		t.Errorf("first upstream hits: got %d, want 1", got)
	}
	if got := second.hits.Load(); got != 1 {
		t.Errorf("second upstream hits: got %d, want 1", got)
	}
}

// TestReverseProxyFailoverPartial verifies that once the first upstream has
// produced a final response (status, headers, and a body prefix), a mid-body
// failure is terminal: the request is not retried, responses are not
// concatenated, and the client keeps the already-produced content, ending
// with the transport error.
func TestReverseProxyFailoverPartial(t *testing.T) {
	first := newFailoverScriptedUpstream(t)
	second := newFailoverBackupUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(failoverCaddyfile(first.addr, second.addr), "caddyfile")

	resp, err := http.Get("http://localhost:9080/partial")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	// the final status and headers came from the first upstream
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("X-Origin"); got != "first" {
		t.Errorf("X-Origin: got %q, want %q", got, "first")
	}

	// the client receives the already-produced body prefix, then the
	// transport error (the declared length is never completed)
	body, readErr := io.ReadAll(resp.Body)
	if string(body) != "part1" {
		t.Errorf("body: got %q, want %q (must not be concatenated with a retried response)", body, "part1")
	}
	if readErr == nil {
		t.Errorf("expected a transport error ending the truncated response, got nil")
	}

	// the second upstream must not be contacted at all
	if got := first.hits.Load(); got != 1 {
		t.Errorf("first upstream hits: got %d, want 1", got)
	}
	if got := second.hits.Load(); got != 0 {
		t.Errorf("second upstream hits: got %d, want 0 (no retry after a final response started)", got)
	}
}

// TestReverseProxyFailoverBothDown verifies that when both upstreams fail
// before producing a final response, the client receives a single 502 with
// no leftover headers or body from the failed upstreams, and that each
// upstream was tried exactly once.
func TestReverseProxyFailoverBothDown(t *testing.T) {
	first := newFailoverScriptedUpstream(t)
	second := newFailoverScriptedUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(failoverCaddyfile(first.addr, second.addr), "caddyfile")

	// both upstreams fail before any final response for /retry-before
	req, err := http.NewRequest(http.MethodPost, "http://localhost:9080/retry-before?a=1&b=2",
		strings.NewReader(`{"n":1}`))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trace", "t-7")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("failed reading response body: %v", err)
	}

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	if got := resp.Header.Get("X-Origin"); got != "" {
		t.Errorf("X-Origin: got %q, want empty (no leftover headers from failed upstreams)", got)
	}
	if len(body) != 0 {
		t.Errorf("body: got %q, want empty (no leftover body from failed upstreams)", body)
	}
	if got := first.hits.Load(); got != 1 {
		t.Errorf("first upstream hits: got %d, want 1", got)
	}
	if got := second.hits.Load(); got != 1 {
		t.Errorf("second upstream hits: got %d, want 1", got)
	}

	// for /retry-info, the 103 provisional responses from both failed
	// attempts are still forwarded, in order, and the only final response
	// is the single 502
	var provisionalMu sync.Mutex
	var provisional []int
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			provisionalMu.Lock()
			defer provisionalMu.Unlock()
			provisional = append(provisional, code)
			return nil
		},
	}
	infoReq, err := http.NewRequest(http.MethodGet, "http://localhost:9080/retry-info", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	infoReq = infoReq.WithContext(httptrace.WithClientTrace(infoReq.Context(), trace))

	infoResp, err := http.DefaultClient.Do(infoReq)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.Copy(io.Discard, infoResp.Body)
	infoResp.Body.Close()

	provisionalMu.Lock()
	gotProvisional := append([]int(nil), provisional...)
	provisionalMu.Unlock()
	// both upstreams emit a 103 before failing; both are forwarded in
	// order, but neither counts as the final response
	if len(gotProvisional) != 2 || gotProvisional[0] != http.StatusEarlyHints || gotProvisional[1] != http.StatusEarlyHints {
		t.Errorf("provisional responses: got %v, want [103 103]", gotProvisional)
	}
	if infoResp.StatusCode != http.StatusBadGateway {
		t.Errorf("status: got %d, want %d", infoResp.StatusCode, http.StatusBadGateway)
	}
}

// TestReverseProxyFailoverSequentialIsolation verifies that consecutive
// requests through the same proxy are fully isolated: each request gets a
// fresh retry budget and upstream selection, and status, length, and
// transfer encoding do not leak between requests.
func TestReverseProxyFailoverSequentialIsolation(t *testing.T) {
	first := newFailoverScriptedUpstream(t)
	second := newFailoverBackupUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(failoverCaddyfile(first.addr, second.addr), "caddyfile")

	client := &http.Client{}

	// 1. failover with a body: 201 from the second upstream
	req, err := http.NewRequest(http.MethodPost, "http://localhost:9080/retry-before?a=1&b=2",
		strings.NewReader(`{"n":1}`))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trace", "t-7")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request 1 failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusCreated || string(body) != `{"n":1}` {
		t.Fatalf("request 1: got status=%d body=%q err=%v, want 201 %q", resp.StatusCode, body, err, `{"n":1}`)
	}

	// 2. plain success on the first upstream: 200 with full body
	resp, err = client.Get("http://localhost:9080/ok")
	if err != nil {
		t.Fatalf("request 2 failed: %v", err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "ok-from-first" {
		t.Fatalf("request 2: got status=%d body=%q err=%v, want 200 %q", resp.StatusCode, body, err, "ok-from-first")
	}
	if got := resp.Header.Get("X-Origin"); got != "first" {
		t.Errorf("request 2: X-Origin: got %q, want %q (fresh selection must start at the first upstream)", got, "first")
	}
	if resp.ContentLength != int64(len("ok-from-first")) {
		t.Errorf("request 2: Content-Length: got %d, want %d", resp.ContentLength, len("ok-from-first"))
	}

	// 3. provisional response then failover: 103 + 200 from second
	resp, err = client.Get("http://localhost:9080/retry-info")
	if err != nil {
		t.Fatalf("request 3 failed: %v", err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "final-from-second" {
		t.Fatalf("request 3: got status=%d body=%q err=%v, want 200 %q", resp.StatusCode, body, err, "final-from-second")
	}

	// 4. empty body response on the first upstream
	resp, err = client.Get("http://localhost:9080/empty")
	if err != nil {
		t.Fatalf("request 4 failed: %v", err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || len(body) != 0 {
		t.Fatalf("request 4: got status=%d body=%q err=%v, want 200 with empty body", resp.StatusCode, body, err)
	}
	if resp.ContentLength != 0 {
		t.Errorf("request 4: Content-Length: got %d, want 0", resp.ContentLength)
	}
	if len(resp.TransferEncoding) != 0 {
		t.Errorf("request 4: Transfer-Encoding: got %v, want none", resp.TransferEncoding)
	}

	// 5. partial response: not retried, client keeps the prefix
	resp, err = client.Get("http://localhost:9080/partial")
	if err != nil {
		t.Fatalf("request 5 failed: %v", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "part1" || readErr == nil {
		t.Fatalf("request 5: got status=%d body=%q readErr=%v, want 200 %q with transport error",
			resp.StatusCode, body, readErr, "part1")
	}

	// 6. plain success again: the retry budget and upstream selection of
	// previous requests must not affect this one
	resp, err = client.Get("http://localhost:9080/ok")
	if err != nil {
		t.Fatalf("request 6 failed: %v", err)
	}
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "ok-from-first" {
		t.Fatalf("request 6: got status=%d body=%q err=%v, want 200 %q", resp.StatusCode, body, err, "ok-from-first")
	}

	// total upstream hits: /retry-before (1+1), /ok x2 (2+0), /retry-info
	// (1+1), /empty (1+0), /partial (1+0)
	if got := first.hits.Load(); got != 6 {
		t.Errorf("first upstream hits: got %d, want 6", got)
	}
	if got := second.hits.Load(); got != 2 {
		t.Errorf("second upstream hits: got %d, want 2", got)
	}
}

// TestReverseProxyNoRetrySingleAttempt verifies that without retry
// configuration, the proxy keeps its original single-attempt behavior: a
// failure before the final response yields a 502 and the second upstream is
// never contacted.
func TestReverseProxyNoRetrySingleAttempt(t *testing.T) {
	first := newFailoverScriptedUpstream(t)
	second := newFailoverBackupUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
	}
	http://localhost:9080 {
		reverse_proxy %s %s {
			lb_policy first
		}
	}
	`, first.addr, second.addr), "caddyfile")

	req, err := http.NewRequest(http.MethodPost, "http://localhost:9080/retry-before?a=1&b=2",
		strings.NewReader(`{"n":1}`))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trace", "t-7")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}
	if got := first.hits.Load(); got != 1 {
		t.Errorf("first upstream hits: got %d, want 1", got)
	}
	if got := second.hits.Load(); got != 0 {
		t.Errorf("second upstream hits: got %d, want 0 (no retries configured)", got)
	}
}
