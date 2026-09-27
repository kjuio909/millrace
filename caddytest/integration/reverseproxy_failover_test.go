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
	"slices"
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

		case "/final4xx":
			// a final 4xx status and a chunked body prefix, then an abrupt
			// close without the terminating chunk: the final status was
			// already produced, so the disconnect afterwards must not
			// trigger a failover
			conn := u.writeRaw(w,
				"HTTP/1.1 403 Forbidden\r\n",
				"X-Origin: first\r\n",
				"Content-Type: text/plain\r\n",
				"Transfer-Encoding: chunked\r\n",
				"\r\n",
				"4\r\nforb\r\n")
			time.Sleep(20 * time.Millisecond)
			conn.Close()
			return

		case "/final5xx":
			// same as /final4xx, but with a final 5xx status
			conn := u.writeRaw(w,
				"HTTP/1.1 503 Service Unavailable\r\n",
				"X-Origin: first\r\n",
				"Content-Type: text/plain\r\n",
				"Transfer-Encoding: chunked\r\n",
				"\r\n",
				"4\r\nunav\r\n")
			time.Sleep(20 * time.Millisecond)
			conn.Close()
			return

		case "/slow":
			// hold the request open beyond the proxy's whole-attempt time
			// budget, then drop it without any response; by the time the
			// failure surfaces the budget is exhausted, so the proxy must
			// not start a new attempt
			time.Sleep(2 * time.Second)
			conn := u.writeRaw(w)
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

			// the backup always answers with the same single complete
			// response: 201, X-Trace: t-7 and the body "ok201"
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("X-Trace", "t-7")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("ok201"))
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

// interimResponse records one 1xx response observed on the client
// connection, in arrival order.
type interimResponse struct {
	code int
	link string
}

// tracedDo performs a request while recording the interim (1xx) responses
// observed on the client connection, in arrival order, along with the time
// at which the first interim response arrived (relative to the request
// start).
func tracedDo(t *testing.T, client *http.Client, req *http.Request) (*http.Response, []interimResponse, time.Duration) {
	t.Helper()
	var (
		mu             sync.Mutex
		interim        []interimResponse
		firstInterimAt time.Duration
	)
	start := time.Now()
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			mu.Lock()
			if len(interim) == 0 {
				firstInterimAt = time.Since(start)
			}
			interim = append(interim, interimResponse{code: code, link: header.Get("Link")})
			mu.Unlock()
			return nil
		},
	}
	resp, err := client.Do(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	if err != nil {
		t.Fatalf("request %s failed: %v", req.URL.Path, err)
	}
	mu.Lock()
	got := append([]interimResponse(nil), interim...)
	at := firstInterimAt
	mu.Unlock()
	return resp, got, at
}

// newFailoverClient builds a client for the plaintext HTTP/1.1 site or,
// when h2 is true, for the TLS site with HTTP/2 negotiated via ALPN.
func newFailoverClient(h2 bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		DialContext:        dialer.DialContext,
		DisableCompression: true,
	}
	if h2 {
		tr.ForceAttemptHTTP2 = true
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only client
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: tr,
	}
}

// failoverSiteBlocks returns the handle blocks shared by the plaintext
// HTTP/1.1 site and the TLS HTTP/2 site: a /no-retry route on which failover
// is explicitly disabled, and a catch-all route proxying to the two
// upstreams in fixed order with a one-retry budget, a whole-attempt time
// limit, and a retry matcher limited to transport errors.
func failoverSiteBlocks(firstAddr, backupAddr string) string {
	return fmt.Sprintf(`
	handle /no-retry* {
		reverse_proxy %s %s {
			lb_policy first
		}
	}
	handle {
		reverse_proxy %s %s {
			lb_policy first
			lb_retries 1
			lb_try_duration 1s
			lb_try_interval 25ms
			request_buffers unlimited
			lb_retry_match {
				expression `+"`{rp.is_transport_error} == true`"+`
			}
		}
	}
`, firstAddr, backupAddr, firstAddr, backupAddr)
}

// requireProtocol asserts that the response arrived over the expected
// protocol, using that protocol's legal transport representation.
func requireProtocol(t *testing.T, resp *http.Response, wantProto int) {
	t.Helper()
	if resp.ProtoMajor != wantProto {
		t.Errorf("response protocol: got HTTP/%d, want HTTP/%d", resp.ProtoMajor, wantProto)
	}
	if wantProto == 2 {
		if resp.TLS == nil {
			t.Errorf("expected the HTTP/2 response to arrive over TLS")
		}
		if len(resp.TransferEncoding) != 0 {
			t.Errorf("HTTP/2 response must not carry transfer encodings, got %v", resp.TransferEncoding)
		}
	}
}

// requireBackupFinalResponse asserts the single complete response the client
// must see after a failover: the backup's 201, its X-Trace header, its exact
// body (empty for HEAD) and a Content-Length matching the GET semantics.
func requireBackupFinalResponse(t *testing.T, resp *http.Response, interim []interimResponse, body []byte, readErr error, wantProto int, wantBody string) {
	t.Helper()
	requireProtocol(t, resp, wantProto)
	if len(interim) != 0 {
		t.Errorf("interim responses: got %v, want none", interim)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status: got %d, want 201", resp.StatusCode)
	}
	if readErr != nil {
		t.Fatalf("reading final body: %v", readErr)
	}
	if string(body) != wantBody {
		t.Errorf("client body: got %q, want %q", body, wantBody)
	}
	if resp.Header.Get("X-Trace") != "t-7" {
		t.Errorf("response X-Trace: got %q, want t-7", resp.Header.Get("X-Trace"))
	}
	if resp.ContentLength != int64(len("ok201")) {
		t.Errorf("response Content-Length: got %d, want %d", resp.ContentLength, len("ok201"))
	}
}

// requireExactReplay asserts that the backup received exactly one new
// request since baseRecs and that it is byte-for-byte identical to the
// request the first node received.
func requireExactReplay(t *testing.T, backup *failoverUpstream, path string, baseRecs int, want recordedRequest) {
	t.Helper()
	recs := backup.recordings(path)
	if len(recs)-baseRecs != 1 {
		t.Fatalf("backup upstream received %d new requests, want exactly 1", len(recs)-baseRecs)
	}
	rec := recs[len(recs)-1]
	if rec.method != want.method {
		t.Errorf("backup method: got %q, want %q", rec.method, want.method)
	}
	if rec.rawQuery != want.rawQuery {
		t.Errorf("backup raw query: got %q, want %q", rec.rawQuery, want.rawQuery)
	}
	if rec.contentType != want.contentType {
		t.Errorf("backup Content-Type: got %q, want %q", rec.contentType, want.contentType)
	}
	if rec.xTrace != want.xTrace {
		t.Errorf("backup X-Trace: got %q, want %q", rec.xTrace, want.xTrace)
	}
	if rec.contentLength != want.contentLength {
		t.Errorf("backup Content-Length: got %d, want %d", rec.contentLength, want.contentLength)
	}
	if !bytes.Equal(rec.body, want.body) {
		t.Errorf("backup body: got %q, want %q", rec.body, want.body)
	}
}

// runFailoverMatrix exercises the full failover behaviour against one site
// (baseURL) with one client. wantProto is the expected HTTP major version of
// every response (1 for the plaintext site, 2 for the TLS site). The same
// matrix runs against both protocols from TestReverseProxyFailoverSemantics,
// so every assertion must hold identically; hit counts are asserted as
// deltas so the two runs stay independent of each other.
func runFailoverMatrix(t *testing.T, baseURL string, client *http.Client, wantProto int, first, backup *failoverUpstream) {
	t.Helper()

	// POST /retry-before?a=1&b=2: the first node dies before any final
	// header; the backup must answer once with 201 and the client must see
	// exactly that one complete response, while the backup receives the
	// exact request metadata, byte sequence and length.
	t.Run("POST with query retried before any response", func(t *testing.T) {
		const reqBody = `{"n":1}`
		baseFirst := first.hitCount("/retry-before")
		baseRecs := len(backup.recordings("/retry-before"))

		req, err := http.NewRequest(http.MethodPost, baseURL+"/retry-before?a=1&b=2", strings.NewReader(reqBody))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Trace", "t-7")

		resp, interim, _ := tracedDo(t, client, req)
		defer resp.Body.Close()
		gotBody, readErr := io.ReadAll(resp.Body)
		requireBackupFinalResponse(t, resp, interim, gotBody, readErr, wantProto, "ok201")

		if got := first.hitCount("/retry-before") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		requireExactReplay(t, backup, "/retry-before", baseRecs, recordedRequest{
			method:        http.MethodPost,
			rawQuery:      "a=1&b=2",
			contentLength: int64(len(reqBody)),
			contentType:   "application/json",
			xTrace:        "t-7",
			body:          []byte(reqBody),
		})
	})

	// GET /retry-before: same failover, without a request body.
	t.Run("GET retried before any response", func(t *testing.T) {
		baseFirst := first.hitCount("/retry-before")
		baseRecs := len(backup.recordings("/retry-before"))

		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/retry-before"))
		gotBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireBackupFinalResponse(t, resp, interim, gotBody, readErr, wantProto, "ok201")

		if got := first.hitCount("/retry-before") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		requireExactReplay(t, backup, "/retry-before", baseRecs, recordedRequest{
			method: http.MethodGet,
		})
	})

	// HEAD /retry-before: same failover; the client must see no body, but
	// the length semantics must match the corresponding GET.
	t.Run("HEAD retried before any response", func(t *testing.T) {
		baseFirst := first.hitCount("/retry-before")
		baseRecs := len(backup.recordings("/retry-before"))

		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodHead, baseURL+"/retry-before"))
		gotBody, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireBackupFinalResponse(t, resp, interim, gotBody, readErr, wantProto, "")

		if got := first.hitCount("/retry-before") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		requireExactReplay(t, backup, "/retry-before", baseRecs, recordedRequest{
			method: http.MethodHead,
		})
	})

	// Normal success served by the first node: no failover.
	t.Run("successful response first node", func(t *testing.T) {
		baseBackup := backup.hitCount("/ok")
		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/ok"))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)
		if len(interim) != 0 {
			t.Errorf("interim responses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("got %d %q, want 200 ok", resp.StatusCode, body)
		}
		if got := backup.hitCount("/ok") - baseBackup; got != 0 {
			t.Errorf("backup upstream hits for /ok: got %d new, want 0", got)
		}
	})

	// Empty body response keeps length/encoding clean.
	t.Run("empty body response", func(t *testing.T) {
		resp, _, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/empty"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status: got %d, want 200", resp.StatusCode)
		}
		if len(body) != 0 || readErr != nil {
			t.Fatalf("body: got %q (err=%v), want empty clean body", body, readErr)
		}
	})

	// /retry-info: the 103 must arrive, in order and promptly, but it is not
	// a final response; the failover still happens and only the backup's
	// final response reaches the client.
	t.Run("103 interim forwarded then retried", func(t *testing.T) {
		baseFirst := first.hitCount("/retry-info")
		baseBackup := backup.hitCount("/retry-info")

		resp, interim, first103At := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/retry-info"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)

		if len(interim) != 1 || interim[0].code != http.StatusEarlyHints {
			t.Fatalf("interim responses: got %v, want a single 103", interim)
		}
		if !strings.Contains(interim[0].link, "style.css") {
			t.Errorf("103 Link header: got %q, want the first node's style.css hint", interim[0].link)
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
		if string(body) != "ok201" {
			t.Errorf("final body: got %q, want ok201", body)
		}
		if resp.Header.Get("X-Trace") != "t-7" {
			t.Errorf("response X-Trace: got %q, want t-7", resp.Header.Get("X-Trace"))
		}
		if got := first.hitCount("/retry-info") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		if got := backup.hitCount("/retry-info") - baseBackup; got != 1 {
			t.Errorf("backup upstream hits: got %d new, want 1", got)
		}
	})

	// /partial: once a final status, headers and a body prefix were
	// produced, there must be no second request and no splicing; the client
	// keeps what was produced and the transfer ends with an error.
	t.Run("partial final response is not retried", func(t *testing.T) {
		baseFirst := first.hitCount("/partial")
		baseBackup := backup.hitCount("/partial")

		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/partial"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)

		if len(interim) != 0 {
			t.Errorf("interim responses: got %v, want none", interim)
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
		if wantProto == 1 && !slices.Contains(resp.TransferEncoding, "chunked") {
			t.Errorf("HTTP/1.1 truncated response should use chunked framing, got %v", resp.TransferEncoding)
		}
		if got := first.hitCount("/partial") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		if got := backup.hitCount("/partial") - baseBackup; got != 0 {
			t.Errorf("backup upstream must not be retried, got %d new hits", got)
		}
	})

	// /final4xx and /final5xx: a final status (here 403 and 503) followed by
	// a disconnect must not be retried either; the client keeps the final
	// status and the transfer error, and the backup stays untouched.
	for _, tc := range []struct {
		path   string
		status int
		prefix string
	}{
		{"/final4xx", http.StatusForbidden, "forb"},
		{"/final5xx", http.StatusServiceUnavailable, "unav"},
	} {
		t.Run("final status then disconnect is not retried "+tc.path, func(t *testing.T) {
			baseFirst := first.hitCount(tc.path)
			baseBackup := backup.hitCount(tc.path)

			resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+tc.path))
			body, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			requireProtocol(t, resp, wantProto)

			if len(interim) != 0 {
				t.Errorf("interim responses: got %v, want none", interim)
			}
			if resp.StatusCode != tc.status {
				t.Fatalf("status: got %d, want %d", resp.StatusCode, tc.status)
			}
			if resp.Header.Get("X-Origin") != "first" {
				t.Errorf("X-Origin: got %q, want first", resp.Header.Get("X-Origin"))
			}
			if !bytes.HasPrefix(body, []byte(tc.prefix)) {
				t.Errorf("body prefix: got %q, want it to start with %s", body, tc.prefix)
			}
			if readErr == nil {
				t.Errorf("expected truncated transfer error, got clean read")
			}
			if got := first.hitCount(tc.path) - baseFirst; got != 1 {
				t.Errorf("first upstream hits: got %d new, want 1", got)
			}
			if got := backup.hitCount(tc.path) - baseBackup; got != 0 {
				t.Errorf("backup upstream must not be retried after a final status, got %d new hits", got)
			}
		})
	}

	// /no-retry: failover is explicitly disabled on this route, so a
	// failure of the first node surfaces as a plain 502 and the backup must
	// never be contacted.
	t.Run("no-retry path never contacts the backup", func(t *testing.T) {
		baseFirst := first.hitCount("/no-retry")
		baseBackup := backup.hitCount("/no-retry")

		req, err := http.NewRequest(http.MethodPost, baseURL+"/no-retry?z=9", strings.NewReader("payload"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "text/plain")

		resp, interim, _ := tracedDo(t, client, req)
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)

		if len(interim) != 0 {
			t.Errorf("interim responses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status: got %d, want 502", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("502 body should read cleanly: %v", readErr)
		}
		if bytes.Contains(body, []byte("payload")) {
			t.Errorf("502 body must not contain the request body: %q", body)
		}
		if got := first.hitCount("/no-retry") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		if got := backup.hitCount("/no-retry") - baseBackup; got != 0 {
			t.Errorf("backup upstream must not be contacted on /no-retry, got %d new hits", got)
		}
	})

	// /slow: the first node holds the request beyond the whole-attempt time
	// budget (lb_try_duration) before failing; by the time the failure
	// surfaces the budget is exhausted, so no new attempt may be started.
	// The exhausted budget of this request must not pollute the next one.
	t.Run("try duration budget prevents a new attempt", func(t *testing.T) {
		baseFirst := first.hitCount("/slow")
		baseBackup := backup.hitCount("/slow")

		start := time.Now()
		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/slow"))
		elapsed := time.Since(start)
		_, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)

		if len(interim) != 0 {
			t.Errorf("interim responses: got %v, want none", interim)
		}
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status: got %d, want 502", resp.StatusCode)
		}
		if readErr != nil {
			t.Errorf("502 body should read cleanly: %v", readErr)
		}
		// the first node held the request for ~2s, beyond the 1s try
		// duration, so the failure surfaced only after its full delay
		if elapsed < 1500*time.Millisecond {
			t.Errorf("request returned after %v, want at least the first node's delay", elapsed)
		}
		if got := first.hitCount("/slow") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		if got := backup.hitCount("/slow") - baseBackup; got != 0 {
			t.Errorf("backup upstream must not be attempted after the try duration elapsed, got %d new hits", got)
		}

		// a fresh request still gets its own full retry budget: the
		// failover works again immediately after the exhausted one
		const reqBody = `{"n":1}`
		req, err := http.NewRequest(http.MethodPost, baseURL+"/retry-before?a=1&b=2", strings.NewReader(reqBody))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Trace", "t-7")
		resp2, interim2, _ := tracedDo(t, client, req)
		gotBody, readErr2 := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		requireBackupFinalResponse(t, resp2, interim2, gotBody, readErr2, wantProto, "ok201")
	})

	// Both nodes fail before a final response: a single clean 502, no
	// leftover final headers/body from either failed node, and the interim
	// responses already forwarded remain, in arrival order.
	t.Run("both upstreams fail yields single 502 with 103s in order", func(t *testing.T) {
		baseFirst := first.hitCount("/all-fail")
		baseBackup := backup.hitCount("/all-fail")

		resp, interim, first103At := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/all-fail"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		requireProtocol(t, resp, wantProto)

		if len(interim) != 2 || interim[0].code != http.StatusEarlyHints || interim[1].code != http.StatusEarlyHints {
			t.Fatalf("interim responses: got %v, want [103 103] in order", interim)
		}
		// the first node's 103 must arrive before the backup's, proving the
		// interim responses were streamed in order as they happened
		if !strings.Contains(interim[0].link, "style.css") || !strings.Contains(interim[1].link, "other.css") {
			t.Errorf("103 order: got links %q then %q, want style.css then other.css",
				interim[0].link, interim[1].link)
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
		if got := first.hitCount("/all-fail") - baseFirst; got != 1 {
			t.Errorf("first upstream hits: got %d new, want 1", got)
		}
		if got := backup.hitCount("/all-fail") - baseBackup; got != 1 {
			t.Errorf("backup upstream hits: got %d new, want 1", got)
		}
	})

	// Alternating successful, early-disconnect, double-failure, empty-body
	// and truncated paths in one continuous run: every request's retry
	// budget, body, status, length and framing stay isolated from the
	// others.
	t.Run("interleaved requests stay isolated", func(t *testing.T) {
		baseRecs := len(backup.recordings("/retry-before"))

		// success on the first node
		resp, interim, _ := tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/ok"))
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "ok" || readErr != nil || len(interim) != 0 {
			t.Fatalf("/ok: got %d %q (readErr=%v, interim=%v), want 200 ok", resp.StatusCode, body, readErr, interim)
		}

		// early disconnect failing over to the backup
		postFailover := func() {
			t.Helper()
			const reqBody = `{"n":1}`
			req, err := http.NewRequest(http.MethodPost, baseURL+"/retry-before?a=1&b=2", strings.NewReader(reqBody))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Trace", "t-7")
			resp, interim, _ := tracedDo(t, client, req)
			gotBody, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			requireBackupFinalResponse(t, resp, interim, gotBody, readErr, wantProto, "ok201")
		}
		postFailover()

		// double failure
		resp, interim, _ = tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/all-fail"))
		body, readErr = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadGateway || readErr != nil {
			t.Errorf("/all-fail: got %d (readErr=%v), want a clean 502", resp.StatusCode, readErr)
		}
		if len(interim) != 2 || interim[0].code != http.StatusEarlyHints || interim[1].code != http.StatusEarlyHints {
			t.Errorf("/all-fail interim responses: got %v, want [103 103]", interim)
		}

		// empty body
		resp, _, _ = tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/empty"))
		body, readErr = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(body) != 0 || readErr != nil {
			t.Errorf("/empty: got %d %q (readErr=%v), want 200 with an empty, clean body", resp.StatusCode, body, readErr)
		}

		// truncated final response
		resp, _, _ = tracedDo(t, client, mustNewRequest(t, http.MethodGet, baseURL+"/partial"))
		body, readErr = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !bytes.HasPrefix(body, []byte("part1")) || readErr == nil {
			t.Errorf("/partial: got %d %q (readErr=%v), want 200 with the part1 prefix and a transfer error",
				resp.StatusCode, body, readErr)
		}

		// failover again: the budget and body of every request are isolated
		postFailover()

		recs := backup.recordings("/retry-before")
		if len(recs)-baseRecs != 2 {
			t.Fatalf("backup received %d new requests, want 2 (one per failover)", len(recs)-baseRecs)
		}
		for i, rec := range recs[len(recs)-2:] {
			if rec.method != http.MethodPost || string(rec.body) != `{"n":1}` ||
				rec.contentLength != int64(len(`{"n":1}`)) || rec.rawQuery != "a=1&b=2" ||
				rec.contentType != "application/json" || rec.xTrace != "t-7" {
				t.Errorf("backup request %d is not an exact replay: %+v", i, rec)
			}
		}
	})
}

// TestReverseProxyFailoverSemantics exercises the requirement that one
// client request produces exactly one logical response when a proxy with two
// fixed-order upstreams, a one-retry budget and a whole-attempt time limit
// fails over. The identical configuration and assertion matrix runs over
// plaintext HTTP/1.1 and over HTTP/2 on TLS.
func TestReverseProxyFailoverSemantics(t *testing.T) {
	first := newFailoverUpstream(t, "first")
	backup := newFailoverUpstream(t, "backup")

	blocks := failoverSiteBlocks(first.addr(), backup.addr())
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
%s
	}
	https://localhost:9443 {
		tls internal
%s
	}
	`, blocks, blocks), "caddyfile")

	t.Run("HTTP/1.1", func(t *testing.T) {
		runFailoverMatrix(t, "http://127.0.0.1:9080", newFailoverClient(false), 1, first, backup)
	})
	t.Run("HTTP/2 over TLS", func(t *testing.T) {
		runFailoverMatrix(t, "https://localhost:9443", newFailoverClient(true), 2, first, backup)
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

func mustNewRequest(t *testing.T, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
