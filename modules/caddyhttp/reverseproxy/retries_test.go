package reverseproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// prepareTestRequest injects the context values that ServeHTTP and
// proxyLoopIteration require (caddy.ReplacerCtxKey, VarsCtxKey, etc.) using
// the same helper that the real HTTP server uses.
//
// A zero-value Server is passed so that caddyhttp.ServerCtxKey is set to a
// non-nil pointer; reverseProxy dereferences it to check ShouldLogCredentials.
func prepareTestRequest(req *http.Request) *http.Request {
	repl := caddy.NewReplacer()
	return caddyhttp.PrepareRequest(req, repl, nil, &caddyhttp.Server{})
}

// closeOnCloseReader is an io.ReadCloser whose Close method actually makes
// subsequent reads fail, mimicking the behaviour of a real HTTP request body
// (as opposed to io.NopCloser, whose Close is a no-op and would mask the bug
// we are testing).
type closeOnCloseReader struct {
	mu     sync.Mutex
	r      *strings.Reader
	closed bool
}

func newCloseOnCloseReader(s string) *closeOnCloseReader {
	return &closeOnCloseReader{r: strings.NewReader(s)}
}

func (c *closeOnCloseReader) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errors.New("http: invalid Read on closed Body")
	}
	return c.r.Read(p)
}

func (c *closeOnCloseReader) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

// deadUpstreamAddr returns a TCP address that is guaranteed to refuse
// connections: we bind a listener, note its address, close it immediately,
// and return the address. Any dial to that address will get ECONNREFUSED.
func deadUpstreamAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create dead upstream listener: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// testTransport wraps http.Transport to:
//  1. Set the URL scheme to "http" when it is empty (matching what
//     HTTPTransport.SetScheme does in production; cloneRequest strips the
//     scheme intentionally so a plain *http.Transport would fail with
//     "unsupported protocol scheme").
//  2. Wrap dial errors as DialError so that tryAgain correctly identifies them
//     as safe-to-retry regardless of request method (as HTTPTransport does in
//     production via its custom dialer).
type testTransport struct{ *http.Transport }

func (t testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	resp, err := t.Transport.RoundTrip(req)
	if err != nil {
		// Wrap dial errors as DialError to match production behaviour.
		// Without this wrapping, tryAgain treats ECONNREFUSED on a POST
		// request as non-retryable (only GET is retried by default when
		// the error is not a DialError).
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			return nil, DialError{err}
		}
	}
	return resp, err
}

// minimalHandler returns a Handler with only the fields required by ServeHTTP
// set directly, bypassing Provision (which requires a full Caddy runtime).
// RoundRobinSelection is used so that successive iterations of the proxy loop
// advance through the upstream pool in a predictable order.
func minimalHandler(retries int, upstreams ...*Upstream) *Handler {
	return &Handler{
		logger:    zap.NewNop(),
		Transport: testTransport{&http.Transport{}},
		Upstreams: upstreams,
		LoadBalancing: &LoadBalancing{
			Retries:         retries,
			SelectionPolicy: &RoundRobinSelection{},
			// RetryMatch intentionally nil: dial errors are always retried
			// regardless of RetryMatch or request method.
		},
		// ctx, connections, connectionsMu, events: zero/nil values are safe
		// for the code paths exercised by these tests (TryInterval=0 so
		// ctx.Done() is never consulted; no WebSocket hijacking; no passive
		// health-check event emission).
	}
}

// TestDialErrorBodyRetry verifies that a POST request whose body has NOT been
// pre-buffered via request_buffers can still be retried after a dial error.
//
// Before the fix, a dial error caused Go's transport to close the shared body
// (via cloneRequest's shallow copy), so the retry attempt would read from an
// already-closed io.ReadCloser and produce:
//
//	http: invalid Read on closed Body → HTTP 502
//
// After the fix the handler wraps the body in noCloseBody when retries are
// configured, preventing the transport's Close() from propagating to the
// shared body. Since dial errors never read any bytes, the body remains at
// position 0 for the retry.
func TestDialErrorBodyRetry(t *testing.T) {
	// Good upstream: echoes the request body with 200 OK.
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	t.Cleanup(goodServer.Close)

	const requestBody = "hello, retry"

	tests := []struct {
		name       string
		method     string
		body       string
		retries    int
		wantStatus int
		wantBody   string
	}{
		{
			// Core regression case: POST with a body, no request_buffers,
			// dial error on first upstream → retry to second upstream succeeds.
			name:       "POST body retried after dial error",
			method:     http.MethodPost,
			body:       requestBody,
			retries:    1,
			wantStatus: http.StatusOK,
			wantBody:   requestBody,
		},
		{
			// Dial errors are always retried regardless of method, but there
			// is no body to re-read, so GET has always worked. Keep it as a
			// sanity check that we did not break the no-body path.
			name:       "GET without body retried after dial error",
			method:     http.MethodGet,
			body:       "",
			retries:    1,
			wantStatus: http.StatusOK,
			wantBody:   "",
		},
		{
			// Without any retry configuration the handler must give up on the
			// first dial error and return a 502. Confirms no wrapping occurs
			// in the no-retry path.
			name:       "no retries configured returns 502 on dial error",
			method:     http.MethodPost,
			body:       requestBody,
			retries:    0,
			wantStatus: http.StatusBadGateway,
			wantBody:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dead := deadUpstreamAddr(t)

			// Build the upstream pool. RoundRobinSelection starts its
			// counter at 0 and increments before returning, so with a
			// two-element pool it picks index 1 first, then index 0.
			// Put the good upstream at index 0 and the dead one at
			// index 1 so that:
			//   attempt 1 → pool[1] = dead → DialError (ECONNREFUSED)
			//   attempt 2 → pool[0] = good → 200
			upstreams := []*Upstream{
				{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
				{Host: new(Host), Dial: dead},
			}
			if tc.retries == 0 {
				// For the "no retries" case use only the dead upstream so
				// there is nowhere to retry to.
				upstreams = []*Upstream{
					{Host: new(Host), Dial: dead},
				}
			}

			h := minimalHandler(tc.retries, upstreams...)

			// Use closeOnCloseReader so that Close() truly prevents further
			// reads, matching real http.body semantics. io.NopCloser would
			// mask the bug because its Close is a no-op.
			var bodyReader io.ReadCloser
			if tc.body != "" {
				bodyReader = newCloseOnCloseReader(tc.body)
			}
			req := httptest.NewRequest(tc.method, "http://example.com/", bodyReader)
			if bodyReader != nil {
				// httptest.NewRequest wraps the reader in NopCloser; replace
				// it with our close-aware reader so Close() is propagated.
				req.Body = bodyReader
				req.ContentLength = int64(len(tc.body))
			}
			req = prepareTestRequest(req)

			rec := httptest.NewRecorder()
			err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				return nil
			}))

			// For error cases (e.g. 502) ServeHTTP returns a HandlerError
			// rather than writing the status itself.
			gotStatus := rec.Code
			if err != nil {
				if herr, ok := err.(caddyhttp.HandlerError); ok {
					gotStatus = herr.StatusCode
				}
			}

			if gotStatus != tc.wantStatus {
				t.Errorf("status: got %d, want %d (err=%v)", gotStatus, tc.wantStatus, err)
			}
			if tc.wantBody != "" && rec.Body.String() != tc.wantBody {
				t.Errorf("body: got %q, want %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}

// TestFirstPolicyRetrySkipsFailedUpstream verifies that a retry does not
// re-select the upstream that just failed, even when the selection policy is
// "first" (which always returns the first available upstream). Without the
// per-request exclusion set, the first policy would select the same dead
// upstream on every attempt, exhausting the retry budget with a 502 instead
// of failing over to the second, ordered upstream.
func TestFirstPolicyRetrySkipsFailedUpstream(t *testing.T) {
	// Good upstream: returns 200 OK.
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(goodServer.Close)

	dead := deadUpstreamAddr(t)

	// Fixed order: first upstream is dead, second is the good one.
	upstreams := []*Upstream{
		{Host: new(Host), Dial: dead},
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
	}

	h := minimalHandler(1, upstreams...)
	h.LoadBalancing.SelectionPolicy = FirstSelection{}

	req := prepareTestRequest(httptest.NewRequest(http.MethodPost, "http://example.com/", nil))
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	gotStatus := rec.Code
	if err != nil {
		if herr, ok := err.(caddyhttp.HandlerError); ok {
			gotStatus = herr.StatusCode
		}
	}
	if gotStatus != http.StatusOK {
		t.Fatalf("status: got %d, want %d (err=%v)", gotStatus, http.StatusOK, err)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body: got %q, want %q", rec.Body.String(), "ok")
	}
}

// TestFirstPolicyRetryBudgetExhausted verifies that retries do not loop back
// to already-tried upstreams and that with one retry and two failing
// upstreams the client gets a terminal 502 after exactly one failover.
func TestFirstPolicyRetryBudgetExhausted(t *testing.T) {
	// Fixed order: both upstreams refuse connections.
	upstreams := []*Upstream{
		{Host: new(Host), Dial: deadUpstreamAddr(t)},
		{Host: new(Host), Dial: deadUpstreamAddr(t)},
	}

	h := minimalHandler(1, upstreams...)
	h.LoadBalancing.SelectionPolicy = FirstSelection{}

	req := prepareTestRequest(httptest.NewRequest(http.MethodPost, "http://example.com/", nil))
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	gotStatus := rec.Code
	if err != nil {
		if herr, ok := err.(caddyhttp.HandlerError); ok {
			gotStatus = herr.StatusCode
		}
	}
	if gotStatus != http.StatusBadGateway {
		t.Fatalf("status: got %d, want %d (err=%v)", gotStatus, http.StatusBadGateway, err)
	}
}

// newExpressionMatcher provisions a MatchExpression for use in tests
func newExpressionMatcher(t *testing.T, expr string) *caddyhttp.MatchExpression {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	m := &caddyhttp.MatchExpression{Expr: expr}
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("failed to provision expression %q: %v", expr, err)
	}
	return m
}

// minimalHandlerWithRetryMatch is like minimalHandler but also configures
// RetryMatch so that response-based retry can be tested
func minimalHandlerWithRetryMatch(retries int, retryMatch caddyhttp.MatcherSets, upstreams ...*Upstream) *Handler {
	h := minimalHandler(retries, upstreams...)
	h.LoadBalancing.RetryMatch = retryMatch
	return h
}

// TestResponseRetryStatusCode verifies that when an upstream returns a status
// code matching a retry_match expression, the request is retried on the next
// upstream
func TestResponseRetryStatusCode(t *testing.T) {
	// Bad upstream: returns 502
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(badServer.Close)

	// Good upstream: returns 200
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(goodServer.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, "{http.reverse_proxy.status_code} in [502, 503]"),
		},
	}

	// RoundRobin picks index 1 first, then 0
	upstreams := []*Upstream{
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
		{Host: new(Host), Dial: badServer.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	gotStatus := rec.Code
	if err != nil {
		if herr, ok := err.(caddyhttp.HandlerError); ok {
			gotStatus = herr.StatusCode
		}
	}

	if gotStatus != http.StatusOK {
		t.Errorf("status: got %d, want %d (err=%v)", gotStatus, http.StatusOK, err)
	}
}

// TestResponseRetryHeader verifies that response header matching triggers
// retries via a CEL expression checking {rp.header.*}
func TestResponseRetryHeader(t *testing.T) {
	// Bad upstream: returns 200 but with X-Upstream-Retry header
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Retry", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("bad"))
	}))
	t.Cleanup(badServer.Close)

	// Good upstream: returns 200 without retry header
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("good"))
	}))
	t.Cleanup(goodServer.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, `{http.reverse_proxy.header.X-Upstream-Retry} == "true"`),
		},
	}

	// RoundRobin picks index 1 first, then 0
	upstreams := []*Upstream{
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
		{Host: new(Host), Dial: badServer.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "good" {
		t.Errorf("body: got %q, want %q (retried to wrong upstream)", rec.Body.String(), "good")
	}
}

// TestResponseRetryNoMatchNoRetry verifies that when no retry_match entries
// match the response, the original response is returned without retrying
func TestResponseRetryNoMatchNoRetry(t *testing.T) {
	var hits atomic.Int32

	// Server that returns 500 - but retry_match only matches 502/503
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, "{http.reverse_proxy.status_code} in [502, 503]"),
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	// Only one hit - no retry since 500 doesn't match [502, 503]
	if hits.Load() != 1 {
		t.Errorf("upstream hits: got %d, want 1 (should not have retried)", hits.Load())
	}
}

// TestResponseRetryExhaustedPreservesStatusCode verifies that when retries
// are exhausted, the actual upstream status code (e.g. 503) is reported
// to the client, not a generic 502
func TestResponseRetryExhaustedPreservesStatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable) // 503
	}))
	t.Cleanup(server.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, "{http.reverse_proxy.status_code} == 503"),
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	gotStatus := rec.Code
	if err != nil {
		if herr, ok := err.(caddyhttp.HandlerError); ok {
			gotStatus = herr.StatusCode
		}
	}

	// Must return 503 (actual upstream status), not 502 (generic proxy error)
	if gotStatus != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want %d (status code not preserved)", gotStatus, http.StatusServiceUnavailable)
	}
}

// TestResponseRetryHeaderCleanup verifies that stale response header
// placeholders from a previous upstream attempt are cleaned up before the
// next retry evaluation. Without cleanup, a header like X-Retry: true from
// upstream A would leak into the retry match for upstream B even if B does
// not set that header
func TestResponseRetryHeaderCleanup(t *testing.T) {
	// First upstream: returns 200 with X-Retry header (triggers retry)
	firstServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Retry", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("first"))
	}))
	t.Cleanup(firstServer.Close)

	// Second upstream: returns 200 WITHOUT X-Retry header (should NOT retry)
	secondServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("second"))
	}))
	t.Cleanup(secondServer.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, `{http.reverse_proxy.header.X-Retry} == "true"`),
		},
	}

	// RoundRobin picks index 1 first, then 0
	upstreams := []*Upstream{
		{Host: new(Host), Dial: secondServer.Listener.Addr().String()},
		{Host: new(Host), Dial: firstServer.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get "second" - the first upstream's X-Retry header must not
	// leak into the second upstream's retry evaluation
	if rec.Body.String() != "second" {
		t.Errorf("body: got %q, want %q (stale header leaked between retries)", rec.Body.String(), "second")
	}
}

// TestRequestOnlyMatcherDoesNotRetryResponses verifies that a pure request
// matcher like method PUT in lb_retry_match does NOT trigger response-based
// retries. Only expression matchers (which can reference response data)
// should trigger response retries
func TestRequestOnlyMatcherDoesNotRetryResponses(t *testing.T) {
	var hits atomic.Int32

	// Server returns 200 OK for all requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)

	// method PUT matcher - should NOT trigger response retries
	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			caddyhttp.MatchMethod{"PUT"},
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodPut, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should hit only once - no retry for 200 OK even though method matches
	if hits.Load() != 1 {
		t.Errorf("upstream hits: got %d, want 1 (should not retry successful responses)", hits.Load())
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
}

// brokenUpstreamAddr returns the address of a TCP listener that accepts
// connections but immediately closes them, causing a transport error (not
// a dial error). This simulates an upstream that is reachable but broken
func brokenUpstreamAddr(t *testing.T) string {
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
			conn.Close()
		}
	}()
	return ln.Addr().String()
}

// TestTransportErrorPlaceholder verifies that the is_transport_error
// placeholder is set to true during transport error evaluation in tryAgain()
// and that expression matchers using {rp.is_transport_error} can match it
func TestTransportErrorPlaceholder(t *testing.T) {
	broken := brokenUpstreamAddr(t)

	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	t.Cleanup(goodServer.Close)

	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, "{http.reverse_proxy.is_transport_error} == true"),
		},
	}

	// RoundRobin picks index 1 first (broken), then 0 (good)
	upstreams := []*Upstream{
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
		{Host: new(Host), Dial: broken},
	}

	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	gotStatus := rec.Code
	if err != nil {
		if herr, ok := err.(caddyhttp.HandlerError); ok {
			gotStatus = herr.StatusCode
		}
	}

	// POST transport error should be retried because is_transport_error matched
	if gotStatus != http.StatusOK {
		t.Errorf("status: got %d, want %d (transport error should have been retried)", gotStatus, http.StatusOK)
	}
}

// TestTransportErrorPlaceholderNotSetForResponses verifies that the
// is_transport_error placeholder is NOT set when evaluating response
// matchers, so {rp.is_transport_error} is false for response retries
func TestTransportErrorPlaceholderNotSetForResponses(t *testing.T) {
	var hits atomic.Int32

	// Server returns 502 - but the matcher only checks is_transport_error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	// Only matches transport errors, not response errors
	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, "{http.reverse_proxy.is_transport_error} == true"),
		},
	}

	upstreams := []*Upstream{
		{Host: new(Host), Dial: server.Listener.Addr().String()},
		{Host: new(Host), Dial: server.Listener.Addr().String()},
	}

	h := minimalHandlerWithRetryMatch(2, retryMatch, upstreams...)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()

	_ = h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	// Should hit only once - is_transport_error is false during response
	// evaluation so the 502 is NOT retried
	if hits.Load() != 1 {
		t.Errorf("upstream hits: got %d, want 1 (is_transport_error should be false for responses)", hits.Load())
	}
}

// TestRetryMatchAllowsExpressionMixedWithOtherMatchers verifies that
// lb_retry_match accepts a block mixing expression with other matchers
func TestRetryMatchAllowsExpressionMixedWithOtherMatchers(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name: "expression alone",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					expression ` + "`{rp.status_code} in [502, 503]`" + `
				}
			}`,
		},
		{
			name: "method alone",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					method PUT
				}
			}`,
		},
		{
			name: "expression mixed with method",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					method POST
					expression ` + "`{rp.status_code} in [502, 503]`" + `
				}
			}`,
		},
		{
			name: "expression mixed with path",
			input: `reverse_proxy localhost:9080 {
				lb_retry_match {
					path /api*
					expression ` + "`{rp.status_code} == 502`" + `
				}
			}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{}
			d := caddyfile.NewTestDispenser(tc.input)
			err := h.UnmarshalCaddyfile(d)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestSubrouteErrorFallbackWithBody is similar to TestDialErrorBodyRetry but
// mimics Subroute's Error handler rather than testing retries specifically
func TestSubrouteErrorFallbackWithBody(t *testing.T) {
	// Good upstream: echoes the request body with 200 OK.
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, err = w.Write(body)
		if err != nil {
			t.Errorf("error writing in good server: %v", err)
		}
	}))
	t.Cleanup(goodServer.Close)

	// Handler which will dial error
	badProxy := minimalHandler(0, &Upstream{Host: new(Host), Dial: deadUpstreamAddr(t)})

	bodyReader := newCloseOnCloseReader("hello world")
	req := httptest.NewRequest("POST", "http://localhost/", bodyReader)
	// httptest.NewRequest wraps the reader in NopCloser; replace
	// it with our close-aware reader so Close() is propagated.
	req.Body = bodyReader

	req = prepareTestRequest(req)
	rec := httptest.NewRecorder()
	err := badProxy.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))
	if err == nil {
		t.Fatalf("Expected error from badProxy.ServeHTTP")
	}

	// Simulate the Subroute's Error handler by calling another handler with the
	// same request and recorder
	goodProxy := minimalHandler(0, &Upstream{Host: new(Host), Dial: goodServer.Listener.Addr().String()})
	err = goodProxy.ServeHTTP(rec, req, caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return nil
	}))

	if err != nil {
		t.Fatalf("Expected no error from goodProxy.ServeHTTP, got: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusOK)
	}
	expectedBody := "hello world"
	if rec.Body.String() != expectedBody {
		t.Errorf("body: got %q, want %q", rec.Body.String(), expectedBody)
	}
}

// bodyConsumingUpstream starts an HTTP server that fully receives (consumes)
// the request body and then hijacks the connection and closes it without
// sending any response. Unlike a refused dial, the request body has already
// been read off the wire, so a retry can only replay it if the proxy
// buffered it beforehand.
func bodyConsumingUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		conn.Close()
	}))
}

// noopNext is a terminal handler used in ServeHTTP tests.
func noopNext(_ http.ResponseWriter, _ *http.Request) error { return nil }

// TestRetryEnabledDecision pins the rule that enables request body
// buffering automatically: a retry budget exists when either a positive
// number of retries or a whole-attempt time limit is configured.
func TestRetryEnabledDecision(t *testing.T) {
	for i, tc := range []struct {
		name string
		lb   LoadBalancing
		want bool
	}{
		{name: "no budget", lb: LoadBalancing{}, want: false},
		{name: "retries only", lb: LoadBalancing{Retries: 1}, want: true},
		{name: "try duration only", lb: LoadBalancing{TryDuration: caddy.Duration(time.Second)}, want: true},
		{name: "both", lb: LoadBalancing{Retries: 2, TryDuration: caddy.Duration(time.Second)}, want: true},
	} {
		if got := tc.lb.retryEnabled(); got != tc.want {
			t.Errorf("%d (%s): retryEnabled = %v, want %v", i, tc.name, got, tc.want)
		}
	}
}

// TestTryDurationDeadlineBetweenAttempts verifies that once the
// whole-attempt time limit has elapsed, tryAgain refuses another attempt
// even if the retry count has not been exhausted and an interval is set.
func TestTryDurationDeadlineBetweenAttempts(t *testing.T) {
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	lb := LoadBalancing{
		Retries:     10,
		TryDuration: caddy.Duration(50 * time.Millisecond),
		// an interval larger than the remaining budget must never push a
		// new attempt past the deadline
		TryInterval: caddy.Duration(time.Hour),
	}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)

	// deadline already in the past: stop immediately without a long wait
	startInPast := time.Now().Add(-100 * time.Millisecond)
	start := time.Now()
	if lb.tryAgain(caddyCtx, startInPast, 1, DialError{}, req, zap.NewNop()) {
		t.Errorf("tryAgain after the deadline elapsed = true, want false")
	}

	// from now, the wait must be capped at the remaining ~50ms (not the
	// configured hour), after which the deadline is reached and no new
	// attempt may start
	begin := time.Now()
	if lb.tryAgain(caddyCtx, start, 1, DialError{}, req, zap.NewNop()) {
		t.Errorf("tryAgain after waiting up to the deadline = true, want false")
	}
	if waited := time.Since(begin); waited > 500*time.Millisecond {
		t.Errorf("tryAgain waited %v, want it capped near the 50ms deadline", waited)
	}
}

// TestTryDurationAllowsAttemptWithinBudget verifies the complementary case:
// with time remaining after the interval, another attempt is allowed.
func TestTryDurationAllowsAttemptWithinBudget(t *testing.T) {
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)

	lb := LoadBalancing{
		Retries:     10,
		TryDuration: caddy.Duration(time.Second),
		TryInterval: caddy.Duration(10 * time.Millisecond),
	}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/", nil)
	if !lb.tryAgain(caddyCtx, time.Now(), 1, DialError{}, req, zap.NewNop()) {
		t.Errorf("tryAgain within budget = false, want true")
	}
}

// TestBufferedBodyReplayedAfterUpstreamConsumedBody verifies that when an
// upstream accepts the connection and fully consumes the request body before
// dropping it (a transport error, not a dial error), buffering lets the
// retry reach the backup with the body replayed exactly once, byte-for-byte
// and with the same length, method, query and headers. This is the case the
// non-buffered bodyNopCloserIfNotRead path cannot handle.
func TestBufferedBodyReplayedAfterUpstreamConsumedBody(t *testing.T) {
	const reqBody = `{"k":"v"}`

	var gotMu sync.Mutex
	var got struct {
		count                           int
		method, rawQuery, xTrace, ctype string
		contentLength                   int64
		body                            []byte
	}
	// Good backup: records the request and answers 201 + X-Trace + ok201.
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gotMu.Lock()
		got.count++
		got.method = r.Method
		got.rawQuery = r.URL.RawQuery
		got.xTrace = r.Header.Get("X-Trace")
		got.ctype = r.Header.Get("Content-Type")
		got.contentLength = r.ContentLength
		got.body = body
		gotMu.Unlock()

		w.Header().Set("X-Trace", "t-7")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok201"))
	}))
	t.Cleanup(goodServer.Close)

	// First node consumes the body then disconnects before any response.
	badServer := bodyConsumingUpstream(t)
	t.Cleanup(badServer.Close)

	upstreams := []*Upstream{
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
		{Host: new(Host), Dial: badServer.Listener.Addr().String()},
	}
	// A connection established and then dropped is a transport error, not a
	// dial error, so retrying a POST requires an explicit retry_match, just
	// like the Caddyfile lb_retry_match used in the integration config.
	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, "{http.reverse_proxy.is_transport_error} == true"),
		},
	}
	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)
	// RequestBuffers is what Provision sets automatically (-1 = unlimited)
	// whenever a retry budget is configured; see LoadBalancing.retryEnabled.
	h.RequestBuffers = -1

	req := httptest.NewRequest(http.MethodPost, "http://example.com/retry-body?a=1&b=2", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trace", "t-7")
	req = prepareTestRequest(req)

	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(noopNext))
	if err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201", rec.Code)
	}
	if rec.Header().Get("X-Trace") != "t-7" {
		t.Errorf("X-Trace: got %q, want t-7", rec.Header().Get("X-Trace"))
	}
	if rec.Body.String() != "ok201" {
		t.Errorf("body: got %q, want ok201", rec.Body.String())
	}

	gotMu.Lock()
	defer gotMu.Unlock()
	if got.count != 1 {
		t.Fatalf("backup received %d requests, want exactly 1", got.count)
	}
	if got.method != http.MethodPost {
		t.Errorf("backup method: got %q, want POST", got.method)
	}
	if got.rawQuery != "a=1&b=2" {
		t.Errorf("backup query: got %q, want a=1&b=2", got.rawQuery)
	}
	if got.ctype != "application/json" {
		t.Errorf("backup Content-Type: got %q, want application/json", got.ctype)
	}
	if got.xTrace != "t-7" {
		t.Errorf("backup X-Trace: got %q, want t-7", got.xTrace)
	}
	if got.contentLength != int64(len(reqBody)) {
		t.Errorf("backup Content-Length: got %d, want %d", got.contentLength, len(reqBody))
	}
	if string(got.body) != reqBody {
		t.Errorf("backup body: got %q, want %q", got.body, reqBody)
	}
}

// TestUnbufferedBodyNotReplayedAfterConsumed documents the boundary of the
// non-buffered path: when an upstream consumes the request body before
// failing and buffering is disabled, the body cannot be rewound and the
// request fails (this is why Provision enables buffering with a retry
// budget). A refused dial before any byte still retries, but a consumed
// streaming body cannot.
func TestUnbufferedBodyNotReplayedAfterConsumed(t *testing.T) {
	var backupMu sync.Mutex
	var backupBodies [][]byte
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		backupMu.Lock()
		backupBodies = append(backupBodies, body)
		backupMu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(goodServer.Close)
	badServer := bodyConsumingUpstream(t)
	t.Cleanup(badServer.Close)

	upstreams := []*Upstream{
		{Host: new(Host), Dial: goodServer.Listener.Addr().String()},
		{Host: new(Host), Dial: badServer.Listener.Addr().String()},
	}
	// allow the transport-error retry for POST explicitly so the resulting
	// failure is caused by the un-rewindable body, not the method policy
	retryMatch := caddyhttp.MatcherSets{
		caddyhttp.MatcherSet{
			newExpressionMatcher(t, "{http.reverse_proxy.is_transport_error} == true"),
		},
	}
	h := minimalHandlerWithRetryMatch(1, retryMatch, upstreams...)
	// deliberately leave RequestBuffers == 0 (buffering disabled)

	req := prepareTestRequest(httptest.NewRequest(http.MethodPost, "http://example.com/",
		newCloseOnCloseReader("payload")))
	rec := httptest.NewRecorder()
	serveErr := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(noopNext))

	gotStatus := rec.Code
	if serveErr != nil {
		if herr, ok := serveErr.(caddyhttp.HandlerError); ok {
			gotStatus = herr.StatusCode
		}
	}
	if gotStatus != http.StatusBadGateway {
		t.Errorf("status: got %d, want 502 (consumed unbuffered body cannot replay)", gotStatus)
	}
	// any request that reached the backup must not carry the original,
	// already-consumed body: there is nothing left to replay
	backupMu.Lock()
	defer backupMu.Unlock()
	for i, b := range backupBodies {
		if string(b) == "payload" {
			t.Errorf("backup request %d received the original body %q without buffering", i, b)
		}
	}
}
