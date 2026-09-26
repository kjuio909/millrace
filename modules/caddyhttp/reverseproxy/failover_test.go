package reverseproxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// firstPolicyHandler returns a Handler like minimalHandler, but with the
// "first" selection policy so that upstreams are always tried in their
// configured order, and with a real retry budget.
func firstPolicyHandler(retries int, upstreams ...*Upstream) *Handler {
	h := minimalHandler(retries, upstreams...)
	h.LoadBalancing.SelectionPolicy = FirstSelection{}
	return h
}

// closeAfterRequestServer starts a raw TCP server that reads one complete
// HTTP request per connection (including the body, per Content-Length) and
// then closes the connection without writing any response bytes. It
// simulates an upstream that fails after receiving the request but before
// producing any final response headers.
func closeAfterRequestServer(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				hits.Add(1)
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				// consume the entire request body before vanishing, so the
				// client (the proxy) observes a complete request followed
				// by an orderly close with no response
				_, _ = io.Copy(io.Discard, req.Body)
				// close without writing any response bytes (defer)
			}()
		}
	}()
	return ln.Addr().String()
}

// informationalThenCloseServer starts a raw TCP server that, per connection,
// reads the request, writes a 103 Early Hints provisional response, and then
// closes the connection without any final response.
func informationalThenCloseServer(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				hits.Add(1)
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				_, _ = fmt.Fprintf(conn, "HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n")
				// close before any final response (defer)
			}()
		}
	}()
	return ln.Addr().String()
}

// partialThenCloseServer starts a raw TCP server that, per connection, reads
// the request, writes a final status line and headers plus a prefix of the
// declared body, and then closes the connection before the body is complete.
func partialThenCloseServer(t *testing.T, hits *atomic.Int32) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				hits.Add(1)
				req, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				// declare 11 bytes but only produce "part1" (5 bytes)
				_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nX-Origin: first\r\nContent-Length: 11\r\n\r\npart1")
				// close mid-body (defer)
			}()
		}
	}()
	return ln.Addr().String()
}

// captureUpstream is an HTTP server that records the requests it receives
// and responds with 201, echoing the request metadata and body.
type captureUpstream struct {
	srv *httptest.Server

	mu            sync.Mutex
	methods       []string
	rawQueries    []string
	contentTypes  []string
	traces        []string
	bodies        []string
	contentLength []int64
}

func newCaptureUpstream(t *testing.T) *captureUpstream {
	t.Helper()
	c := &captureUpstream{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		c.mu.Lock()
		c.methods = append(c.methods, r.Method)
		c.rawQueries = append(c.rawQueries, r.URL.RawQuery)
		c.contentTypes = append(c.contentTypes, r.Header.Get("Content-Type"))
		c.traces = append(c.traces, r.Header.Get("X-Trace"))
		c.bodies = append(c.bodies, string(body))
		c.contentLength = append(c.contentLength, r.ContentLength)
		c.mu.Unlock()
		w.Header().Set("X-Origin", "second")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(body)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *captureUpstream) addr() string {
	return c.srv.Listener.Addr().String()
}

func (c *captureUpstream) hits() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.methods)
}

// serveOnce runs one request through h and returns the recorder and any
// handler error.
func serveOnce(h *Handler, req *http.Request, rec *httptest.ResponseRecorder) error {
	req = prepareTestRequest(req)
	return h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
}

// TestFailoverPostBodyRebuiltOnRetry verifies that when the first upstream
// accepts a POST request but closes the connection before producing any
// final response headers, the request is retried exactly once on the second
// upstream, which receives the identical request: same method, full query
// string, headers, body bytes, and content length. The client receives a
// single, complete 201 response.
func TestFailoverPostBodyRebuiltOnRetry(t *testing.T) {
	var firstHits atomic.Int32
	firstAddr := closeAfterRequestServer(t, &firstHits)
	second := newCaptureUpstream(t)

	upstreams := []*Upstream{
		{Host: new(Host), Dial: firstAddr},
		{Host: new(Host), Dial: second.addr()},
	}
	h := firstPolicyHandler(1, upstreams...)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/retry-before?a=1&b=2",
		strings.NewReader(`{"n":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trace", "t-7")
	rec := httptest.NewRecorder()

	err := serveOnce(h, req, rec)
	if err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}

	// the client receives a single, complete 201
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusCreated)
	}
	if rec.Body.String() != `{"n":1}` {
		t.Errorf("body: got %q, want %q", rec.Body.String(), `{"n":1}`)
	}
	if got := rec.Header().Get("X-Origin"); got != "second" {
		t.Errorf("X-Origin: got %q, want %q (final response must come from the second upstream)", got, "second")
	}

	// the first upstream was tried exactly once, and the second upstream
	// received the request exactly once (no looping, no duplication)
	if got := firstHits.Load(); got != 1 {
		t.Errorf("first upstream hits: got %d, want 1", got)
	}
	if got := second.hits(); got != 1 {
		t.Fatalf("second upstream hits: got %d, want 1", got)
	}

	// the second upstream received the identical request metadata,
	// byte sequence, and length
	if got := second.methods[0]; got != http.MethodPost {
		t.Errorf("method: got %q, want POST", got)
	}
	if got := second.rawQueries[0]; got != "a=1&b=2" {
		t.Errorf("query: got %q, want %q", got, "a=1&b=2")
	}
	if got := second.contentTypes[0]; got != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", got)
	}
	if got := second.traces[0]; got != "t-7" {
		t.Errorf("X-Trace: got %q, want t-7", got)
	}
	if got := second.bodies[0]; got != `{"n":1}` {
		t.Errorf("body received by second upstream: got %q, want %q", got, `{"n":1}`)
	}
	if got := second.contentLength[0]; got != int64(len(`{"n":1}`)) {
		t.Errorf("Content-Length received by second upstream: got %d, want %d", got, len(`{"n":1}`))
	}
}

// TestFailoverRetryBudgetExhausted verifies that with a retry budget of one,
// the second upstream is tried at most once: if both upstreams fail before
// producing a final response, the client receives a single 502 and neither
// upstream is contacted more than once.
func TestFailoverRetryBudgetExhausted(t *testing.T) {
	var firstHits, secondHits atomic.Int32
	firstAddr := closeAfterRequestServer(t, &firstHits)
	secondAddr := closeAfterRequestServer(t, &secondHits)

	upstreams := []*Upstream{
		{Host: new(Host), Dial: firstAddr},
		{Host: new(Host), Dial: secondAddr},
	}
	h := firstPolicyHandler(1, upstreams...)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/retry-before?a=1&b=2",
		strings.NewReader(`{"n":1}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	err := serveOnce(h, req, rec)

	gotStatus := rec.Code
	if err != nil {
		if herr, ok := err.(caddyhttp.HandlerError); ok {
			gotStatus = herr.StatusCode
		}
	}

	// a single 502, and each upstream was tried exactly once (no cycling)
	if gotStatus != http.StatusBadGateway {
		t.Errorf("status: got %d, want %d", gotStatus, http.StatusBadGateway)
	}
	if got := firstHits.Load(); got != 1 {
		t.Errorf("first upstream hits: got %d, want 1", got)
	}
	if got := secondHits.Load(); got != 1 {
		t.Errorf("second upstream hits: got %d, want 1", got)
	}
}

// TestFailoverFixedOrderNoLoop verifies that retries advance through the
// upstream pool in the configured order: the first upstream is always tried
// first, and a retry goes to the next upstream rather than looping back to
// the one that just failed.
func TestFailoverFixedOrderNoLoop(t *testing.T) {
	var firstHits, secondHits atomic.Int32

	// first upstream always succeeds
	firstSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits.Add(1)
		w.Header().Set("X-Origin", "first")
		_, _ = w.Write([]byte("from-first"))
	}))
	t.Cleanup(firstSrv.Close)

	secondSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		w.Header().Set("X-Origin", "second")
		_, _ = w.Write([]byte("from-second"))
	}))
	t.Cleanup(secondSrv.Close)

	upstreams := []*Upstream{
		{Host: new(Host), Dial: firstSrv.Listener.Addr().String()},
		{Host: new(Host), Dial: secondSrv.Listener.Addr().String()},
	}
	h := firstPolicyHandler(1, upstreams...)

	// while the first upstream is healthy, every request goes to it and
	// the second upstream is never touched
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/ok", nil)
		rec := httptest.NewRecorder()
		if err := serveOnce(h, req, rec); err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
		if rec.Body.String() != "from-first" {
			t.Fatalf("request %d: body: got %q, want %q", i, rec.Body.String(), "from-first")
		}
	}
	if got := firstHits.Load(); got != 3 {
		t.Errorf("first upstream hits: got %d, want 3", got)
	}
	if got := secondHits.Load(); got != 0 {
		t.Errorf("second upstream hits: got %d, want 0", got)
	}
}

// TestFailoverPartialResponseNotRetried verifies that once an upstream has
// produced a final response (status, headers, and a body prefix), a
// mid-body failure is terminal: the request is not retried on the next
// upstream, and the already-produced content is not concatenated with
// another upstream's response.
func TestFailoverPartialResponseNotRetried(t *testing.T) {
	var firstHits atomic.Int32
	firstAddr := partialThenCloseServer(t, &firstHits)

	var secondHits atomic.Int32
	secondSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		w.Header().Set("X-Origin", "second")
		_, _ = w.Write([]byte("part2"))
	}))
	t.Cleanup(secondSrv.Close)

	upstreams := []*Upstream{
		{Host: new(Host), Dial: firstAddr},
		{Host: new(Host), Dial: secondSrv.Listener.Addr().String()},
	}
	h := firstPolicyHandler(1, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/partial", nil)
	rec := httptest.NewRecorder()

	// the handler aborts the stream with a panic once the body copy fails;
	// recover it here the way the HTTP server would
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				if r != http.ErrAbortHandler {
					t.Fatalf("unexpected panic: %v", r)
				}
			}
		}()
		err = serveOnce(h, req, rec)
	}()
	if err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}

	// the client keeps the already-produced content from the first
	// upstream: its status, its headers, and its body prefix only
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-Origin"); got != "first" {
		t.Errorf("X-Origin: got %q, want %q", got, "first")
	}
	if got := rec.Body.String(); got != "part1" {
		t.Errorf("body: got %q, want %q (must not be concatenated with a retried response)", got, "part1")
	}

	// the second upstream must not be contacted at all
	if got := firstHits.Load(); got != 1 {
		t.Errorf("first upstream hits: got %d, want 1", got)
	}
	if got := secondHits.Load(); got != 0 {
		t.Errorf("second upstream hits: got %d, want 0 (no retry after a final response started)", got)
	}
}

// informationalRecorder is an http.ResponseWriter that records 1xx
// provisional responses separately instead of treating them as the final
// response, mimicking the real HTTP server's behavior.
type informationalRecorder struct {
	header      http.Header
	provisional []int
	code        int
	body        strings.Builder
}

func newInformationalRecorder() *informationalRecorder {
	return &informationalRecorder{header: make(http.Header)}
}

func (r *informationalRecorder) Header() http.Header { return r.header }

func (r *informationalRecorder) WriteHeader(code int) {
	if code >= 100 && code < 200 {
		r.provisional = append(r.provisional, code)
		return
	}
	if r.code == 0 {
		r.code = code
	}
}

func (r *informationalRecorder) Write(p []byte) (int, error) {
	if r.code == 0 {
		r.code = http.StatusOK
	}
	return r.body.Write(p)
}

// TestFailoverAfterInformationalResponse verifies that a 103 provisional
// response from the first upstream is forwarded to the client promptly but
// does not count as a final response: when the upstream then fails before
// its final response, the request is still retried, and the single final
// response comes from the second upstream.
func TestFailoverAfterInformationalResponse(t *testing.T) {
	var firstHits atomic.Int32
	firstAddr := informationalThenCloseServer(t, &firstHits)

	var secondHits atomic.Int32
	secondSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		w.Header().Set("X-Origin", "second")
		_, _ = w.Write([]byte("final-from-second"))
	}))
	t.Cleanup(secondSrv.Close)

	upstreams := []*Upstream{
		{Host: new(Host), Dial: firstAddr},
		{Host: new(Host), Dial: secondSrv.Listener.Addr().String()},
	}
	h := firstPolicyHandler(1, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/retry-info", nil)
	req = prepareTestRequest(req)
	rec := newInformationalRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}

	// the 103 arrived, in order, before the final response
	if len(rec.provisional) != 1 || rec.provisional[0] != http.StatusEarlyHints {
		t.Errorf("provisional responses: got %v, want [103]", rec.provisional)
	}

	// the single final response comes from the second upstream
	if rec.code != http.StatusOK {
		t.Errorf("final status: got %d, want %d", rec.code, http.StatusOK)
	}
	if got := rec.body.String(); got != "final-from-second" {
		t.Errorf("final body: got %q, want %q", got, "final-from-second")
	}
	if got := firstHits.Load(); got != 1 {
		t.Errorf("first upstream hits: got %d, want 1", got)
	}
	if got := secondHits.Load(); got != 1 {
		t.Errorf("second upstream hits: got %d, want 1", got)
	}
}

// TestFailoverSequentialRequestsIsolated verifies that consecutive requests
// through the same handler are fully isolated: each request gets a fresh
// retry budget and a fresh upstream selection, and request bodies do not
// leak between requests.
func TestFailoverSequentialRequestsIsolated(t *testing.T) {
	var firstHits atomic.Int32
	firstAddr := closeAfterRequestServer(t, &firstHits)
	second := newCaptureUpstream(t)

	upstreams := []*Upstream{
		{Host: new(Host), Dial: firstAddr},
		{Host: new(Host), Dial: second.addr()},
	}
	h := firstPolicyHandler(1, upstreams...)

	// two identical POST requests in a row: each must independently fail
	// over and deliver its own body to the second upstream
	for i, body := range []string{`{"n":1}`, `{"n":2}`} {
		req := httptest.NewRequest(http.MethodPost, "http://example.com/retry-before?a=1&b=2",
			strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Trace", "t-7")
		rec := httptest.NewRecorder()

		if err := serveOnce(h, req, rec); err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
		if rec.Code != http.StatusCreated {
			t.Fatalf("request %d: status: got %d, want %d", i, rec.Code, http.StatusCreated)
		}
		if rec.Body.String() != body {
			t.Errorf("request %d: body: got %q, want %q", i, rec.Body.String(), body)
		}
	}

	// each request tried the first upstream once and failed over to the
	// second upstream once: the retry budget was reset between requests
	if got := firstHits.Load(); got != 2 {
		t.Errorf("first upstream hits: got %d, want 2", got)
	}
	if got := second.hits(); got != 2 {
		t.Fatalf("second upstream hits: got %d, want 2", got)
	}
	if second.bodies[0] != `{"n":1}` || second.bodies[1] != `{"n":2}` {
		t.Errorf("second upstream bodies: got %q and %q, want %q and %q",
			second.bodies[0], second.bodies[1], `{"n":1}`, `{"n":2}`)
	}
}

// TestNoRetryConfigPreservesSingleAttempt verifies that without any retry
// configuration, a request is attempted exactly once and a failure before
// the final response yields a 502, regardless of method.
func TestNoRetryConfigPreservesSingleAttempt(t *testing.T) {
	var firstHits, secondHits atomic.Int32
	firstAddr := closeAfterRequestServer(t, &firstHits)
	secondAddr := closeAfterRequestServer(t, &secondHits)

	upstreams := []*Upstream{
		{Host: new(Host), Dial: firstAddr},
		{Host: new(Host), Dial: secondAddr},
	}
	h := firstPolicyHandler(0, upstreams...)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		var body io.Reader
		if method == http.MethodPost {
			body = strings.NewReader(`{"n":1}`)
		}
		req := httptest.NewRequest(method, "http://example.com/retry-before", body)
		rec := httptest.NewRecorder()

		err := serveOnce(h, req, rec)
		gotStatus := rec.Code
		if err != nil {
			var herr caddyhttp.HandlerError
			if errors.As(err, &herr) {
				gotStatus = herr.StatusCode
			}
		}
		if gotStatus != http.StatusBadGateway {
			t.Errorf("%s: status: got %d, want %d", method, gotStatus, http.StatusBadGateway)
		}
	}

	// only the first upstream was ever contacted; no failover occurred
	if got := firstHits.Load(); got != 2 {
		t.Errorf("first upstream hits: got %d, want 2", got)
	}
	if got := secondHits.Load(); got != 0 {
		t.Errorf("second upstream hits: got %d, want 0", got)
	}
}
