package integration

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
)

// backupBody is the fixed final response body the backup upstream produces
// for the failover paths. Its length (5) is the reference for the length
// semantics asserted on GET and HEAD responses alike.
const backupBody = "ok201"

// recordedRequest captures what an upstream actually received on the wire.
type recordedRequest struct {
	method        string
	path          string
	rawQuery      string
	contentLength int64
	contentType   string
	xTrace        string
	body          []byte
}

// failoverUpstream is a real TCP HTTP/1.1 server with deterministic,
// path-based behaviour that simulates upstream failures at precise points of
// the response lifecycle.
type failoverUpstream struct {
	role   string // "first" or "backup"
	ln     net.Listener
	mu     sync.Mutex
	hits   map[string]int
	record []recordedRequest
}

func newFailoverUpstream(t *testing.T, role string) *failoverUpstream {
	t.Helper()
	u := &failoverUpstream{
		role: role,
		hits: make(map[string]int),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for %s upstream: %v", role, err)
	}
	u.ln = ln
	srv := &http.Server{Handler: http.HandlerFunc(u.handle)}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); ln.Close() })
	return u
}

func (u *failoverUpstream) addr() string { return u.ln.Addr().String() }

func (u *failoverUpstream) hitCount(path string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[path]
}

func (u *failoverUpstream) recordings(path string) []recordedRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	var out []recordedRequest
	for _, rec := range u.record {
		if rec.path == path {
			out = append(out, rec)
		}
	}
	return out
}

// writeRaw takes over the connection and writes a raw HTTP response, giving
// full control over framing (interim responses, truncated chunked bodies).
func (u *failoverUpstream) writeRaw(w http.ResponseWriter, lines ...string) net.Conn {
	conn, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		panic(err)
	}
	for _, l := range lines {
		fmt.Fprint(rw, l)
	}
	rw.Flush()
	return conn
}

func (u *failoverUpstream) handle(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.hits[r.URL.Path]++
	u.mu.Unlock()

	if u.role == "first" {
		switch r.URL.Path {
		case "/retry-before", "/no-retry":
			// disconnect before any final (or interim) response header
			conn := u.writeRaw(w)
			conn.Close()
			return

		case "/retry-info", "/all-fail":
			// send an interim 103, then drop before any final response
			conn := u.writeRaw(w,
				"HTTP/1.1 103 Early Hints\r\n",
				"Link: </style.css>; rel=preload; as=style\r\n",
				"\r\n")
			time.Sleep(20 * time.Millisecond)
			conn.Close()
			return

		case "/partial":
			// full final status + headers, then a chunked body prefix and
			// an abrupt close without the terminating chunk
			conn := u.writeRaw(w,
				"HTTP/1.1 200 OK\r\n",
				"X-Origin: first\r\n",
				"Content-Type: text/plain\r\n",
				"Transfer-Encoding: chunked\r\n",
				"\r\n",
				"5\r\npart1\r\n")
			time.Sleep(20 * time.Millisecond)
			conn.Close()
			return

		case "/final-drop-4xx", "/final-drop-5xx":
			// a complete final error response, then the connection drops;
			// the final status was already produced, so no retry is allowed
			status := "HTTP/1.1 409 Conflict\r\n"
			if r.URL.Path == "/final-drop-5xx" {
				status = "HTTP/1.1 503 Service Unavailable\r\n"
			}
			conn := u.writeRaw(w,
				status,
				"X-Origin: first\r\n",
				"Content-Length: 0\r\n",
				"\r\n")
			time.Sleep(20 * time.Millisecond)
			conn.Close()
			return

		case "/slow-fail":
			// hold the connection beyond the proxy's try-duration budget,
			// then drop it without any response; the budget must already be
			// exhausted, so no new attempt may be started afterwards
			conn := u.writeRaw(w)
			time.Sleep(2 * time.Second)
			conn.Close()
			return
		}
	}

	if u.role == "backup" {
		switch r.URL.Path {
		case "/all-fail":
			conn := u.writeRaw(w,
				"HTTP/1.1 103 Early Hints\r\n",
				"Link: </other.css>; rel=preload; as=style\r\n",
				"\r\n")
			time.Sleep(20 * time.Millisecond)
			conn.Close()
			return

		case "/retry-before", "/retry-info":
			body, _ := io.ReadAll(r.Body)
			u.mu.Lock()
			u.record = append(u.record, recordedRequest{
				method:        r.Method,
				path:          r.URL.Path,
				rawQuery:      r.URL.RawQuery,
				contentLength: r.ContentLength,
				contentType:   r.Header.Get("Content-Type"),
				xTrace:        r.Header.Get("X-Trace"),
				body:          body,
			})
			u.mu.Unlock()

			// exactly one final response: 201, the traced header and a
			// fixed body; for HEAD the server suppresses the body bytes
			// but keeps the same Content-Length semantics as GET
			if ct := r.Header.Get("Content-Type"); ct != "" {
				w.Header().Set("Content-Type", ct)
			} else {
				w.Header().Set("Content-Type", "text/plain")
			}
			if xt := r.Header.Get("X-Trace"); xt != "" {
				w.Header().Set("X-Trace", xt)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, backupBody)
			return
		}
	}

	switch r.URL.Path {
	case "/ok":
		_, _ = io.WriteString(w, "ok")
	case "/empty":
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// tracedDo performs a request while recording the interim (1xx) statuses
// observed on the client connection, in arrival order, along with the time at
// which the first interim status arrived (relative to the request start).
func tracedDo(t *testing.T, client *http.Client, req *http.Request) (*http.Response, []int, time.Duration) {
	t.Helper()
	var (
		mu             sync.Mutex
		interim        []int
		firstInterimAt time.Duration
	)
	start := time.Now()
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
			mu.Lock()
			if len(interim) == 0 {
				firstInterimAt = time.Since(start)
			}
			interim = append(interim, code)
			mu.Unlock()
			return nil
		},
	}
	resp, err := client.Do(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	if err != nil {
		t.Fatalf("request %s failed: %v", req.URL.Path, err)
	}
	mu.Lock()
	got := append([]int(nil), interim...)
	at := firstInterimAt
	mu.Unlock()
	return resp, got, at
}

// newFailoverClient builds a client for the given protocol: HTTP/1.1 over
// cleartext, or HTTP/2 over TLS (the test server uses a certificate from the
// internal CA, which the client does not need to verify here).
func newFailoverClient(h2 bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialContext:        dialer.DialContext,
		DisableCompression: true,
	}
	if h2 {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only client
		tr.ForceAttemptHTTP2 = true
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
}

func mustNewRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// failoverCaddyfile returns the shared site configuration: two upstreams
// listed in fixed order, one retry, a retry match limited to transport
// errors (i.e. the first node dropped before producing a final response),
// and a try-duration budget covering the whole failover. The /no-retry
// route explicitly disables failover. The identical handler chain is
// served over cleartext HTTP/1.1 and over TLS with HTTP/2.
func failoverCaddyfile(first, backup string) string {
	proxyBlock := fmt.Sprintf(`reverse_proxy %s %s {
			lb_policy first
			lb_retries 1
			lb_try_duration 1s
			request_buffers unlimited
			lb_retry_match {
				expression `+"`{rp.is_transport_error} == true`"+`
			}
		}`, first, backup)
	noRetryBlock := fmt.Sprintf(`reverse_proxy %s`, first)

	return fmt.Sprintf(`
	{
		skip_install_trust
		auto_https disable_redirects
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
	}
	http://127.0.0.1:9080 {
		handle /no-retry* {
			%s
		}
		handle {
			%s
		}
	}
	https://localhost:9443 {
		tls internal
		handle /no-retry* {
			%s
		}
		handle {
			%s
		}
	}
	`, noRetryBlock, proxyBlock, noRetryBlock, proxyBlock)
}

// TestReverseProxyFailoverSemantics exercises the requirement that one client
// request produces exactly one logical response when a proxy with two
// fixed-order upstreams, a one-retry budget and a whole-attempt time limit
// fails over. The same suite runs over HTTP/1.1 and over TLS with HTTP/2.
func TestReverseProxyFailoverSemantics(t *testing.T) {
	first := newFailoverUpstream(t, "first")
	backup := newFailoverUpstream(t, "backup")

	tester := caddytest.NewTester(t)
	tester.InitServer(failoverCaddyfile(first.addr(), backup.addr()), "caddyfile")

	t.Run("HTTP/1.1", func(t *testing.T) {
		runFailoverSuite(t, "http://127.0.0.1:9080", newFailoverClient(false), first, backup, 1)
	})
	t.Run("HTTP/2 over TLS", func(t *testing.T) {
		runFailoverSuite(t, "https://localhost:9443", newFailoverClient(true), first, backup, 2)
	})
}

// runFailoverSuite runs the full failover matrix against one protocol
// endpoint. wantProto is the expected HTTP major version on every response,
// proving each protocol uses its legal transport representation.
func runFailoverSuite(t *testing.T, base string, client *http.Client, first, backup *failoverUpstream, wantProto int) {
	t.Helper()

	assertProto := func(resp *http.Response) {
		t.Helper()
		if resp.ProtoMajor != wantProto {
			t.Errorf("protocol: got %s, want HTTP/%d transport", resp.Proto, wantProto)
		}
	}

	// 1) POST /retry-before?a=1&b=2: first node dies before any final
	// header; the backup must answer once with 201 and must have received
	// the exact same method, query, headers, body bytes and length.
	t.Run("POST retried before any response", func(t *testing.T) {
		const body = `{"n":1}`
		beforeFirst := first.hitCount("/retry-before")
		beforeRecs := len(backup.recordings("/retry-before"))

		req, err := http.NewRequest(http.MethodPost, base+"/retry-before?a=1&b=2", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Trace", "t-7")

		resp, interim, _ := tracedDo(t, client, req)
		defer resp.Body.Close()
		gotBody, readErr := io.ReadAll(resp.Body)

		assertProto(resp)
		if len(interim) != 0 {
			t.Errorf("interim statuses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status: got %d, want 201", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("reading final body: %v", readErr)
		}
		if string(gotBody) != backupBody {
			t.Errorf("client body: got %q, want %q (only the backup's one complete response)", gotBody, backupBody)
		}
		if resp.Header.Get("X-Trace") != "t-7" {
			t.Errorf("response X-Trace: got %q, want t-7", resp.Header.Get("X-Trace"))
		}
		if resp.ContentLength != int64(len(backupBody)) {
			t.Errorf("response Content-Length: got %d, want %d", resp.ContentLength, len(backupBody))
		}

		if got := first.hitCount("/retry-before"); got != beforeFirst+1 {
			t.Errorf("first upstream hits: got %d, want %d (exactly one attempt)", got, beforeFirst+1)
		}
		recs := backup.recordings("/retry-before")
		if len(recs) != beforeRecs+1 {
			t.Fatalf("backup upstream received %d requests, want exactly one new one", len(recs)-beforeRecs)
		}
		rec := recs[len(recs)-1]
		if rec.method != http.MethodPost {
			t.Errorf("backup method: got %q, want POST", rec.method)
		}
		if rec.rawQuery != "a=1&b=2" {
			t.Errorf("backup raw query: got %q, want a=1&b=2", rec.rawQuery)
		}
		if rec.contentType != "application/json" {
			t.Errorf("backup Content-Type: got %q, want application/json", rec.contentType)
		}
		if rec.xTrace != "t-7" {
			t.Errorf("backup X-Trace: got %q, want t-7", rec.xTrace)
		}
		if rec.contentLength != int64(len(body)) {
			t.Errorf("backup Content-Length: got %d, want %d", rec.contentLength, len(body))
		}
		if string(rec.body) != body {
			t.Errorf("backup body: got %q, want %q", rec.body, body)
		}
	})

	// 2) GET with a query string fails over the same way.
	t.Run("GET retried before any response", func(t *testing.T) {
		beforeRecs := len(backup.recordings("/retry-before"))

		req := mustNewRequest(t, http.MethodGet, base+"/retry-before?x=y")
		req.Header.Set("X-Trace", "t-7")
		resp, interim, _ := tracedDo(t, client, req)
		gotBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		assertProto(resp)
		if len(interim) != 0 {
			t.Errorf("interim statuses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status: got %d, want 201", resp.StatusCode)
		}
		if readErr != nil || string(gotBody) != backupBody {
			t.Errorf("body: got %q (err=%v), want %q", gotBody, readErr, backupBody)
		}
		if resp.ContentLength != int64(len(backupBody)) {
			t.Errorf("response Content-Length: got %d, want %d", resp.ContentLength, len(backupBody))
		}

		recs := backup.recordings("/retry-before")
		if len(recs) != beforeRecs+1 {
			t.Fatalf("backup upstream received %d requests, want exactly one new one", len(recs)-beforeRecs)
		}
		rec := recs[len(recs)-1]
		if rec.method != http.MethodGet {
			t.Errorf("backup method: got %q, want GET", rec.method)
		}
		if rec.rawQuery != "x=y" {
			t.Errorf("backup raw query: got %q, want x=y", rec.rawQuery)
		}
		if rec.xTrace != "t-7" {
			t.Errorf("backup X-Trace: got %q, want t-7", rec.xTrace)
		}
		if rec.contentLength != 0 || len(rec.body) != 0 {
			t.Errorf("backup body: got length %d and %d bytes, want none", rec.contentLength, len(rec.body))
		}
	})

	// 3) HEAD fails over too; the response carries no body, but the length
	// semantics match the corresponding GET (same Content-Length).
	t.Run("HEAD retried before any response", func(t *testing.T) {
		beforeRecs := len(backup.recordings("/retry-before"))

		req := mustNewRequest(t, http.MethodHead, base+"/retry-before")
		req.Header.Set("X-Trace", "t-7")
		resp, interim, _ := tracedDo(t, client, req)
		gotBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		assertProto(resp)
		if len(interim) != 0 {
			t.Errorf("interim statuses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status: got %d, want 201", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("reading HEAD body: %v", readErr)
		}
		if len(gotBody) != 0 {
			t.Errorf("HEAD body: got %q, want empty", gotBody)
		}
		if resp.ContentLength != int64(len(backupBody)) {
			t.Errorf("HEAD Content-Length: got %d, want %d (same as GET)", resp.ContentLength, len(backupBody))
		}

		recs := backup.recordings("/retry-before")
		if len(recs) != beforeRecs+1 {
			t.Fatalf("backup upstream received %d requests, want exactly one new one", len(recs)-beforeRecs)
		}
		if rec := recs[len(recs)-1]; rec.method != http.MethodHead {
			t.Errorf("backup method: got %q, want HEAD", rec.method)
		}
	})

	// 4) Normal success served by the first node: no failover.
	t.Run("successful response first node", func(t *testing.T) {
		beforeBackup := backup.hitCount("/ok")
		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, base+"/ok"))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		assertProto(resp)
		if len(interim) != 0 {
			t.Errorf("interim statuses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("got %d %q, want 200 ok", resp.StatusCode, body)
		}
		if got := backup.hitCount("/ok"); got != beforeBackup {
			t.Errorf("backup upstream hits for /ok: got %d, want %d (untouched)", got, beforeBackup)
		}
	})

	// 5) Empty body response keeps length/encoding clean.
	t.Run("empty body response", func(t *testing.T) {
		resp, _, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, base+"/empty"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		assertProto(resp)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d, want 200", resp.StatusCode)
		}
		if len(body) != 0 || readErr != nil {
			t.Fatalf("body: got %q (err=%v), want empty clean body", body, readErr)
		}
	})

	// 6) /retry-info: the 103 must arrive, in order and promptly, but it is
	// not a final response and does not consume the final-response slot;
	// the failover still happens and only the backup's final response
	// reaches the client.
	t.Run("103 interim forwarded then retried", func(t *testing.T) {
		beforeFirst := first.hitCount("/retry-info")
		beforeBackup := backup.hitCount("/retry-info")

		req := mustNewRequest(t, http.MethodGet, base+"/retry-info")
		req.Header.Set("X-Trace", "t-7")
		resp, interim, first103At := tracedDo(t, client, req)
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		assertProto(resp)
		if len(interim) != 1 || interim[0] != http.StatusEarlyHints {
			t.Fatalf("interim statuses: got %v, want [103]", interim)
		}
		// the 103 must have been forwarded promptly (before failover), not
		// held back until the backup responded
		if first103At <= 0 || first103At >= 2*time.Second {
			t.Errorf("103 arrival timing: got %v, want a small positive duration", first103At)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("final status: got %d, want 201 (exactly one final response)", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("reading final body: %v", readErr)
		}
		if string(body) != backupBody {
			t.Errorf("final body: got %q, want %q", body, backupBody)
		}
		if got := first.hitCount("/retry-info"); got != beforeFirst+1 {
			t.Errorf("first upstream hits: got %d, want %d", got, beforeFirst+1)
		}
		if got := backup.hitCount("/retry-info"); got != beforeBackup+1 {
			t.Errorf("backup upstream hits: got %d, want %d", got, beforeBackup+1)
		}
	})

	// 7) /partial: once a final status, headers and a body prefix were
	// produced, there must be no second attempt and no splicing; the client
	// keeps what was produced and the transfer ends with an error.
	t.Run("partial final response is not retried", func(t *testing.T) {
		beforeFirst := first.hitCount("/partial")
		beforeBackup := backup.hitCount("/partial")

		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, base+"/partial"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		assertProto(resp)
		if len(interim) != 0 {
			t.Errorf("interim statuses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d, want 200", resp.StatusCode)
		}
		if resp.Header.Get("X-Origin") != "first" {
			t.Errorf("X-Origin: got %q, want first", resp.Header.Get("X-Origin"))
		}
		if !bytes.HasPrefix(body, []byte("part1")) {
			t.Errorf("body prefix: got %q, want it to start with part1", body)
		}
		if readErr == nil {
			t.Errorf("expected truncated transfer error, got clean read")
		}
		if got := first.hitCount("/partial"); got != beforeFirst+1 {
			t.Errorf("first upstream hits: got %d, want %d", got, beforeFirst+1)
		}
		if got := backup.hitCount("/partial"); got != beforeBackup {
			t.Errorf("backup upstream must not be retried, got %d hits", got)
		}
	})

	// 8) A final error status (4xx or 5xx) followed by a disconnect is a
	// completed response, not a transport error: it must be delivered
	// as-is and never retried.
	t.Run("final error status then drop is not retried", func(t *testing.T) {
		for _, tc := range []struct {
			path       string
			wantStatus int
		}{
			{"/final-drop-4xx", http.StatusConflict},
			{"/final-drop-5xx", http.StatusServiceUnavailable},
		} {
			beforeBackup := backup.hitCount(tc.path)
			resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, base+tc.path))
			_, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()

			assertProto(resp)
			if len(interim) != 0 {
				t.Errorf("%s: interim statuses: got %v, want none", tc.path, interim)
			}
			if resp.StatusCode != tc.wantStatus {
				t.Errorf("%s: status: got %d, want %d", tc.path, resp.StatusCode, tc.wantStatus)
			}
			if readErr != nil {
				t.Errorf("%s: final response was complete, want clean read, got %v", tc.path, readErr)
			}
			if resp.Header.Get("X-Origin") != "first" {
				t.Errorf("%s: X-Origin: got %q, want first", tc.path, resp.Header.Get("X-Origin"))
			}
			if got := backup.hitCount(tc.path); got != beforeBackup {
				t.Errorf("%s: backup upstream must not be retried, got %d hits", tc.path, got)
			}
		}
	})

	// 9) /no-retry explicitly forbids failover: the first node drops the
	// connection before any response, the client gets a plain 502 and the
	// backup is never contacted.
	t.Run("no-retry route never fails over", func(t *testing.T) {
		beforeFirst := first.hitCount("/no-retry")

		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, base+"/no-retry"))
		_, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		assertProto(resp)
		if len(interim) != 0 {
			t.Errorf("interim statuses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status: got %d, want 502", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("502 body should read cleanly: %v", readErr)
		}
		if got := first.hitCount("/no-retry"); got != beforeFirst+1 {
			t.Errorf("first upstream hits: got %d, want %d", got, beforeFirst+1)
		}
		if got := backup.hitCount("/no-retry"); got != 0 {
			t.Errorf("backup upstream must never be contacted on /no-retry, got %d hits", got)
		}
	})

	// 10) The try-duration budget covers the whole failover: the first node
	// holds the connection past the deadline before dropping it, so no new
	// attempt may be started. The next request must get a fresh budget and
	// an unpolluted body/metadata channel.
	t.Run("try duration budget prevents new attempt", func(t *testing.T) {
		start := time.Now()
		resp, _, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, base+"/slow-fail"))
		elapsed := time.Since(start)
		_, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		assertProto(resp)
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status: got %d, want 502", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("502 body should read cleanly: %v", readErr)
		}
		if elapsed < 1500*time.Millisecond {
			t.Errorf("elapsed: got %v, want the proxy to have waited for the slow first node", elapsed)
		}
		if got := backup.hitCount("/slow-fail"); got != 0 {
			t.Errorf("backup upstream must not be tried after the budget expired, got %d hits", got)
		}

		// the exhausted budget, the previous request body and response
		// metadata must not leak into the next request
		const body = `{"n":1}`
		req, err := http.NewRequest(http.MethodPost, base+"/retry-before?a=1&b=2", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Trace", "t-7")
		resp2, _, _ := tracedDo(t, client, req)
		gotBody, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusCreated || string(gotBody) != backupBody {
			t.Fatalf("request after budget exhaustion: got %d %q, want 201 %q", resp2.StatusCode, gotBody, backupBody)
		}
	})

	// 11) Both nodes fail before a final response: single clean 502, no
	// leftover final headers/body or conflicting lengths from either failed
	// node, and the interim responses already forwarded remain, in order.
	t.Run("both upstreams fail yields single 502 with 103s in order", func(t *testing.T) {
		beforeFirst := first.hitCount("/all-fail")
		beforeBackup := backup.hitCount("/all-fail")

		resp, interim, first103At := tracedDo(t, client, mustNewRequest(t, http.MethodGet, base+"/all-fail"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		assertProto(resp)
		if len(interim) != 2 || interim[0] != http.StatusEarlyHints || interim[1] != http.StatusEarlyHints {
			t.Fatalf("interim statuses: got %v, want [103 103] in order", interim)
		}
		// the first interim response must already have been streamed to
		// the client promptly, before the terminal 502
		if first103At <= 0 || first103At >= 2*time.Second {
			t.Errorf("first 103 arrival timing: got %v, want a small positive duration", first103At)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("final status: got %d, want 502", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("502 body should read cleanly: %v", readErr)
		}
		if h := resp.Header.Get("X-Origin"); h != "" {
			t.Errorf("failed node final header X-Origin leaked: %q", h)
		}
		if strings.Contains(string(body), "part1") {
			t.Errorf("502 body contains upstream body fragment: %q", body)
		}
		if resp.ContentLength >= 0 && resp.ContentLength != int64(len(body)) {
			t.Errorf("502 Content-Length %d conflicts with actual body length %d", resp.ContentLength, len(body))
		}
		if got := first.hitCount("/all-fail"); got != beforeFirst+1 {
			t.Errorf("first upstream hits: got %d, want %d", got, beforeFirst+1)
		}
		if got := backup.hitCount("/all-fail"); got != beforeBackup+1 {
			t.Errorf("backup upstream hits: got %d, want %d", got, beforeBackup+1)
		}
	})

	// 12) Alternating across success, early-disconnect, double-failure,
	// empty-body and with-body paths keeps every request's retry budget,
	// body, status, length and encoding isolated from its neighbours.
	t.Run("alternating requests stay isolated", func(t *testing.T) {
		// success on the first node
		resp, _, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, base+"/ok"))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("ok: got %d %q, want 200 ok", resp.StatusCode, body)
		}

		// early disconnect with a body: full replay to the backup
		const postBody = `{"n":1}`
		req, err := http.NewRequest(http.MethodPost, base+"/retry-before?a=1&b=2", strings.NewReader(postBody))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Trace", "t-7")
		resp, _, _ = tracedDo(t, client, req)
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusCreated || string(body) != backupBody {
			t.Fatalf("retry-before: got %d %q, want 201 %q", resp.StatusCode, body, backupBody)
		}

		// double failure: single 502
		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, base+"/all-fail"))
		_, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway || readErr != nil {
			t.Fatalf("all-fail: got %d (err=%v), want clean 502", resp.StatusCode, readErr)
		}
		if len(interim) != 2 {
			t.Fatalf("all-fail: interim statuses: got %v, want [103 103]", interim)
		}

		// empty body
		resp, _, _ = tracedDo(t, client, mustNewRequest(t, http.MethodGet, base+"/empty"))
		body, readErr = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(body) != 0 || readErr != nil {
			t.Fatalf("empty: got %d %q (err=%v), want 200 with empty body", resp.StatusCode, body, readErr)
		}

		// interim response then failover again
		req = mustNewRequest(t, http.MethodGet, base+"/retry-info")
		req.Header.Set("X-Trace", "t-7")
		resp, interim, _ = tracedDo(t, client, req)
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if len(interim) != 1 || interim[0] != http.StatusEarlyHints {
			t.Fatalf("retry-info: interim statuses: got %v, want [103]", interim)
		}
		if resp.StatusCode != http.StatusCreated || string(body) != backupBody {
			t.Fatalf("retry-info: got %d %q, want 201 %q", resp.StatusCode, body, backupBody)
		}

		// and the first node still serves ordinary requests afterwards
		resp, _, _ = tracedDo(t, client, mustNewRequest(t, http.MethodGet, base+"/ok"))
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("ok again: got %d %q, want 200 ok", resp.StatusCode, body)
		}
	})
}

// TestReverseProxyNoRetrySingleNodeBehaviour verifies that without retries
// configured the proxy keeps its original single-node behaviour: a failure is
// surfaced immediately, never failing over even though a second healthy
// upstream exists elsewhere, while ordinary and truncated responses behave
// unchanged.
func TestReverseProxyNoRetrySingleNodeBehaviour(t *testing.T) {
	first := newFailoverUpstream(t, "first")
	backup := newFailoverUpstream(t, "backup")

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9082
		https_port 9445
		grace_period 1ns
	}
	http://127.0.0.1:9082 {
		reverse_proxy %s
	}
	`, first.addr()), "caddyfile")

	client := newFailoverClient(false)

	// success path is untouched
	resp, _, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, "http://127.0.0.1:9082/ok"))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("got %d %q, want 200 ok", resp.StatusCode, body)
	}

	// disconnect before the response: plain 502, no retry anywhere
	req, err := http.NewRequest(http.MethodPost,
		"http://127.0.0.1:9082/retry-before?a=1&b=2", strings.NewReader(`{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trace", "t-7")
	resp, _, _ = tracedDo(t, client, req)
	b502, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502", resp.StatusCode)
	}
	if bytes.Contains(b502, []byte(`{"n":1}`)) {
		t.Errorf("502 body must not contain upstream body: %q", b502)
	}
	if got := first.hitCount("/retry-before"); got != 1 {
		t.Errorf("first upstream hits: got %d, want 1 (no retries)", got)
	}
	if got := backup.hitCount("/retry-before"); got != 0 {
		t.Errorf("backup must never be contacted without retry config: got %d hits", got)
	}

	// truncated final response still delivered as-is with a transfer error
	resp, _, _ = tracedDo(t, client, mustNewRequest(t, http.MethodGet, "http://127.0.0.1:9082/partial"))
	pbody, perr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.HasPrefix(pbody, []byte("part1")) || perr == nil {
		t.Fatalf("got status=%d body=%q err=%v, want 200 with part1 prefix and transfer error",
			resp.StatusCode, pbody, perr)
	}
	if got := backup.hitCount("/partial"); got != 0 {
		t.Errorf("backup must never be contacted without retry config: got %d hits", got)
	}
}
