package integration

import (
	"bytes"
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
		case "/retry-before", "/all-fail":
			if r.URL.Path == "/all-fail" {
				// send an interim 103, then drop before any final response
				conn := u.writeRaw(w,
					"HTTP/1.1 103 Early Hints\r\n",
					"Link: </style.css>; rel=preload; as=style\r\n",
					"\r\n")
				time.Sleep(20 * time.Millisecond)
				conn.Close()
				return
			}
			// disconnect before any final (or interim) response header
			conn := u.writeRaw(w)
			conn.Close()
			return

		case "/retry-info":
			conn := u.writeRaw(w,
				"HTTP/1.1 103 Early Hints\r\n",
				"Link: </style.css>; rel=preload; as=style\r\n",
				"\r\n")
			time.Sleep(20 * time.Millisecond)
			conn.Close() // no final response ever arrives
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

			// 201 Created, echoing the request metadata and body back
			if ct := r.Header.Get("Content-Type"); ct != "" {
				w.Header().Set("Content-Type", ct)
			} else {
				w.Header().Set("Content-Type", "application/json")
			}
			if xt := r.Header.Get("X-Trace"); xt != "" {
				w.Header().Set("X-Trace", xt)
			}
			w.WriteHeader(http.StatusCreated)
			if len(body) > 0 {
				_, _ = w.Write(body)
			} else {
				_, _ = w.Write([]byte(`{"n":1}`))
			}
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

func newFailoverClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:        dialer.DialContext,
			DisableCompression: true,
		},
	}
}

// TestReverseProxyFailoverSemantics exercises the requirement that one client
// request produces exactly one logical response when a proxy with two
// fixed-order upstreams and a one-retry budget fails over.
func TestReverseProxyFailoverSemantics(t *testing.T) {
	first := newFailoverUpstream(t, "first")
	backup := newFailoverUpstream(t, "backup")

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(`
	{
		skip_install_trust
		admin localhost:2999
		http_port 9080
		https_port 9443
		grace_period 1ns
	}
	http://127.0.0.1:9080 {
		reverse_proxy %s %s {
			lb_policy first
			lb_retries 1
			request_buffers unlimited
			lb_retry_match {
				expression `+"`{rp.is_transport_error} == true`"+`
			}
		}
	}
	`, first.addr(), backup.addr()), "caddyfile")

	client := newFailoverClient()

	// 1) POST /retry-before?a=1&b=2: first node dies before any final
	// header; backup must answer once with 201 and the exact request
	// metadata, byte sequence and length.
	t.Run("POST retried before any response", func(t *testing.T) {
		const body = `{"n":1}`
		req, err := http.NewRequest(http.MethodPost,
			"http://127.0.0.1:9080/retry-before?a=1&b=2", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Trace", "t-7")

		resp, interim, _ := tracedDo(t, client, req)
		defer resp.Body.Close()
		gotBody, readErr := io.ReadAll(resp.Body)

		if len(interim) != 0 {
			t.Errorf("interim statuses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("status: got %d, want 201", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("reading final body: %v", readErr)
		}
		if string(gotBody) != body {
			t.Errorf("client body: got %q, want %q", gotBody, body)
		}
		if resp.Header.Get("Content-Type") != "application/json" {
			t.Errorf("response Content-Type: got %q, want application/json", resp.Header.Get("Content-Type"))
		}
		if resp.Header.Get("X-Trace") != "t-7" {
			t.Errorf("response X-Trace: got %q, want t-7", resp.Header.Get("X-Trace"))
		}
		if resp.ContentLength != int64(len(body)) {
			t.Errorf("response Content-Length: got %d, want %d", resp.ContentLength, len(body))
		}

		// each upstream involved exactly once
		if got := first.hitCount("/retry-before"); got != 1 {
			t.Errorf("first upstream hits: got %d, want 1", got)
		}
		recs := backup.recordings("/retry-before")
		if len(recs) != 1 {
			t.Fatalf("backup upstream received %d requests, want exactly 1", len(recs))
		}
		rec := recs[0]
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

	// 2) Normal success served by the first node: no failover.
	t.Run("successful response first node", func(t *testing.T) {
		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, "http://127.0.0.1:9080/ok"))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if len(interim) != 0 {
			t.Errorf("interim statuses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("got %d %q, want 200 ok", resp.StatusCode, body)
		}
		if got := backup.hitCount("/ok"); got != 0 {
			t.Errorf("backup upstream hits for /ok: got %d, want 0", got)
		}
	})

	// 3) Empty body response keeps length/encoding clean.
	t.Run("empty body response", func(t *testing.T) {
		resp, _, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, "http://127.0.0.1:9080/empty"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d, want 200", resp.StatusCode)
		}
		if len(body) != 0 || readErr != nil {
			t.Fatalf("body: got %q (err=%v), want empty clean body", body, readErr)
		}
	})

	// 4) /retry-info: 103 must arrive, in order and promptly, but is not a
	// final response; the failover still happens and only the backup's
	// final response reaches the client.
	t.Run("103 interim forwarded then retried", func(t *testing.T) {
		resp, interim, first103At := tracedDo(t, client, mustNewRequest(t, http.MethodGet, "http://127.0.0.1:9080/retry-info"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		if len(interim) != 1 || interim[0] != http.StatusEarlyHints {
			t.Fatalf("interim statuses: got %v, want [103]", interim)
		}
		// the 103 must have been forwarded promptly (before failover), not
		// held back until the backup responded
		if first103At <= 0 || first103At >= 2*time.Second {
			t.Errorf("103 arrival timing: got %v, want a small positive duration", first103At)
		}
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("final status: got %d, want 201", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("reading final body: %v", readErr)
		}
		if string(body) != `{"n":1}` {
			t.Errorf("final body: got %q, want {\"n\":1}", body)
		}
		if got := first.hitCount("/retry-info"); got != 1 {
			t.Errorf("first upstream hits: got %d, want 1", got)
		}
		if got := backup.hitCount("/retry-info"); got != 1 {
			t.Errorf("backup upstream hits: got %d, want 1", got)
		}
	})

	// 5) /partial: once a final status, headers and body prefix were
	// produced, there must be no second request and no splicing; the
	// client keeps what was produced and the transfer ends with an error.
	t.Run("partial final response is not retried", func(t *testing.T) {
		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, "http://127.0.0.1:9080/partial"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

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
		if got := first.hitCount("/partial"); got != 1 {
			t.Errorf("first upstream hits: got %d, want 1", got)
		}
		if got := backup.hitCount("/partial"); got != 0 {
			t.Errorf("backup upstream must not be retried, got %d hits", got)
		}
	})

	// 6) Interleaving requests keeps every request's retry budget, body,
	// status, length and encoding isolated. Re-run the POST failover after
	// the other conversations; the backup must again see one full body.
	t.Run("repeated POST failover stays isolated", func(t *testing.T) {
		const body = `{"n":1}`
		req, err := http.NewRequest(http.MethodPost,
			"http://127.0.0.1:9080/retry-before?a=1&b=2", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Trace", "t-7")
		resp, interim, _ := tracedDo(t, client, req)
		gotBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if len(interim) != 0 {
			t.Errorf("interim statuses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusCreated || string(gotBody) != body {
			t.Fatalf("got %d %q, want 201 %q", resp.StatusCode, gotBody, body)
		}
		if got := first.hitCount("/retry-before"); got != 2 {
			t.Errorf("first upstream hits: got %d, want 2 (one per request)", got)
		}
		recs := backup.recordings("/retry-before")
		if len(recs) != 2 {
			t.Fatalf("backup received %d requests, want 2 (budget reset per request)", len(recs))
		}
		for i, rec := range recs {
			if string(rec.body) != body || rec.contentLength != int64(len(body)) ||
				rec.rawQuery != "a=1&b=2" || rec.contentType != "application/json" || rec.xTrace != "t-7" {
				t.Errorf("backup request %d not an exact replay: %+v", i, rec)
			}
		}
	})

	// 7) Both nodes fail before a final response: single clean 502, no
	// leftover final headers/body from either failed node, interim
	// responses already forwarded remain in order.
	t.Run("both upstreams fail yields single 502 with 103s in order", func(t *testing.T) {
		resp, interim, first103At := tracedDo(t, client, mustNewRequest(t, http.MethodGet, "http://127.0.0.1:9080/all-fail"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

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
		if got := first.hitCount("/all-fail"); got != 1 {
			t.Errorf("first upstream hits: got %d, want 1", got)
		}
		if got := backup.hitCount("/all-fail"); got != 1 {
			t.Errorf("backup upstream hits: got %d, want 1", got)
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

	client := newFailoverClient()

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

func mustNewRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
