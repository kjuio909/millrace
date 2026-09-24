package integration

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"testing"

	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestIntercept(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
			skip_install_trust
			admin localhost:2999
			http_port     9080
			https_port    9443
			grace_period  1ns
		}
	
		localhost:9080 {
			respond /intercept "I'm a teapot" 408
			header /intercept To-Intercept ok
			respond /no-intercept "I'm not a teapot"

			intercept {
				@teapot status 408
				handle_response @teapot {
					header /intercept intercepted {resp.header.To-Intercept}
					respond /intercept "I'm a combined coffee/tea pot that is temporarily out of coffee" 503
				}
			}	
		}
		`, "caddyfile")

	r, _ := tester.AssertGetResponse("http://localhost:9080/intercept", 503, "I'm a combined coffee/tea pot that is temporarily out of coffee")
	if r.Header.Get("intercepted") != "ok" {
		t.Fatalf(`header "intercepted" value is not "ok": %s`, r.Header.Get("intercepted"))
	}

	tester.AssertGetResponse("http://localhost:9080/no-intercept", 200, "I'm not a teapot")
}

func TestInterceptReplaceStatusWithMatcher(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		respond /error "boom" 500

		intercept {
			@err status 5xx
			replace_status @err 200
		}
	}
	`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/error", 200, "boom")
}

func TestInterceptReplaceStatusWithoutMatcher(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		respond /forbidden "denied" 403

		intercept {
			replace_status 200
		}
	}
	`, "caddyfile")

	tester.AssertGetResponse("http://localhost:9080/forbidden", 200, "denied")
}

func TestInterceptReplaceStatusNotMatched(t *testing.T) {
	tester := caddytest.NewTester(t)
	tester.InitServer(`{
		skip_install_trust
		admin localhost:2999
		http_port     9080
		https_port    9443
		grace_period  1ns
	}

	localhost:9080 {
		respond /ok "all good" 200

		intercept {
			@err status 5xx
			replace_status @err 503
		}
	}
	`, "caddyfile")

	// 200 does not match @err (5xx), so status should pass through unchanged
	tester.AssertGetResponse("http://localhost:9080/ok", 200, "all good")
}

// interceptTestUpstream mimics an HTTP/1.1 origin which responds with
// "oldbody" (7 bytes) and the X-Origin header on most paths.
func interceptTestUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/early":
			// informational response first, then the final one
			w.Header().Set("X-Origin", "old")
			w.WriteHeader(http.StatusEarlyHints)
			fmt.Fprint(w, "oldbody")
		case "/chunked":
			// no Content-Length; flushed, so it streams as chunked
			w.Header().Set("X-Origin", "old")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "chunk1")
			http.NewResponseController(w).Flush()
			fmt.Fprint(w, "chunk2")
		case "/plain":
			w.Header().Set("X-Origin", "old")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "plainbody")
		default:
			w.Header().Set("X-Origin", "old")
			fmt.Fprint(w, "oldbody")
		}
	}))
	t.Cleanup(upstream.Close)
	return upstream
}

const interceptProxyConfig = `
{
	skip_install_trust
	admin localhost:2999
	http_port     9080
	https_port    9443
	grace_period  1ns
}

localhost:9080 {
	%s
	reverse_proxy %s
}
`

func TestInterceptProxyReplaceStatus(t *testing.T) {
	upstream := interceptTestUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(interceptProxyConfig, `
	intercept {
		@deny status 200
		replace_status @deny 403
	}`, upstream.URL), "caddyfile")

	// only the status code is replaced; the original headers and body stay
	r, _ := tester.AssertGetResponse("http://localhost:9080/", 403, "oldbody")
	if got := r.Header.Get("X-Origin"); got != "old" {
		t.Fatalf(`expected original header X-Origin to be kept, got %q`, got)
	}
	if got := r.Header.Get("Content-Length"); got != "7" {
		t.Fatalf(`expected Content-Length of original body (7), got %q`, got)
	}
}

func TestInterceptProxyHandleResponseReplace(t *testing.T) {
	upstream := interceptTestUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(interceptProxyConfig, `
	intercept {
		@deny status 200
		handle_response @deny {
			respond "new" 403
		}
	}`, upstream.URL), "caddyfile")

	// the replacement response stands alone: no original headers or body
	r, _ := tester.AssertGetResponse("http://localhost:9080/", 403, "new")
	if got := r.Header.Get("X-Origin"); got != "" {
		t.Fatalf(`expected original header X-Origin to be dropped, got %q`, got)
	}
	if got := r.Header.Get("Content-Length"); got != "3" {
		t.Fatalf(`expected Content-Length of replacement body (3), got %q`, got)
	}
}

func TestInterceptProxyHandleResponseHeaderOnly(t *testing.T) {
	upstream := interceptTestUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(interceptProxyConfig, `
	intercept {
		@deny status 200
		handle_response @deny {
			header X-Edit yes
		}
	}`, upstream.URL), "caddyfile")

	// routes which don't produce a response fall through to the original one
	r, _ := tester.AssertGetResponse("http://localhost:9080/", 200, "oldbody")
	if got := r.Header.Get("X-Origin"); got != "old" {
		t.Fatalf(`expected original header X-Origin to be kept, got %q`, got)
	}
	if got := r.Header.Get("X-Edit"); got != "yes" {
		t.Fatalf(`expected header X-Edit to be added, got %q`, got)
	}
	if got := r.Header.Get("Content-Length"); got != "7" {
		t.Fatalf(`expected Content-Length of original body (7), got %q`, got)
	}
}

func TestInterceptProxyHandleResponseEmptyNoContent(t *testing.T) {
	upstream := interceptTestUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(interceptProxyConfig, `
	intercept {
		@deny status 200
		handle_response @deny {
			respond "" 204
		}
	}`, upstream.URL), "caddyfile")

	// an explicitly empty response must not reuse the original body
	tester.AssertGetResponse("http://localhost:9080/", 204, "")
}

func TestInterceptProxyReplaceStatusBadPlaceholder(t *testing.T) {
	upstream := interceptTestUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(interceptProxyConfig, `
	intercept {
		@deny status 200
		replace_status @deny {http.request.uri.query.sc}
	}`, upstream.URL), "caddyfile")

	// a valid placeholder value behaves like a static status code
	r, _ := tester.AssertGetResponse("http://localhost:9080/?sc=403", 403, "oldbody")
	if got := r.Header.Get("X-Origin"); got != "old" {
		t.Fatalf(`expected original header X-Origin to be kept, got %q`, got)
	}

	// an invalid placeholder value results in a plain 500, without the
	// original response headers or body
	r, _ = tester.AssertGetResponse("http://localhost:9080/?sc=abc", 500, "")
	if got := r.Header.Get("X-Origin"); got != "" {
		t.Fatalf(`expected original header X-Origin to be dropped, got %q`, got)
	}
}

func TestInterceptProxy1xxThenBadPlaceholder(t *testing.T) {
	upstream := interceptTestUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(interceptProxyConfig, `
	intercept {
		@deny status 200
		replace_status @deny {http.request.uri.query.sc}
	}`, upstream.URL), "caddyfile")

	// the upstream sends 103 Early Hints before its final response; the 1xx
	// is forwarded to the client as-is and cannot be retracted, but the
	// final response is still a clean 500 because "abc" is not a status code
	var got1xx []int
	req, err := http.NewRequest(http.MethodGet, "http://localhost:9080/early?sc=abc", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
			got1xx = append(got1xx, code)
			return nil
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	resp, err := tester.Client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	if len(got1xx) == 0 || got1xx[0] != http.StatusEarlyHints {
		t.Fatalf("expected to see 103 Early Hints before the final response, got %v", got1xx)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("expected final status 500, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Origin"); got != "" {
		t.Fatalf(`expected original header X-Origin to be dropped, got %q`, got)
	}
	if string(body) == "oldbody" {
		t.Fatal("expected the original body to be discarded")
	}
}

func TestInterceptProxyHeadRequest(t *testing.T) {
	upstream := interceptTestUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(interceptProxyConfig, `
	intercept {
		@deny status 200
		replace_status @deny 403
	}`, upstream.URL), "caddyfile")

	// HEAD responses carry the Content-Length of the body, but no body
	req, err := http.NewRequest(http.MethodHead, "http://localhost:9080/", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	r, _ := tester.AssertResponse(req, 403, "")
	if got := r.Header.Get("Content-Length"); got != "7" {
		t.Fatalf(`expected Content-Length of original body (7), got %q`, got)
	}
}

func TestInterceptProxyFlushWithoutContentLength(t *testing.T) {
	upstream := interceptTestUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(interceptProxyConfig, `
	intercept {
		@err status 5xx
		replace_status @err 200
	}`, upstream.URL), "caddyfile")

	// the response is not intercepted, so it streams; with no Content-Length
	// and a flush, the HTTP/1.1 downstream response must be chunked
	r, _ := tester.AssertGetResponse("http://localhost:9080/chunked", 200, "chunk1chunk2")
	if got := r.Header.Get("Content-Length"); got != "" {
		t.Fatalf(`expected no Content-Length, got %q`, got)
	}
	if len(r.TransferEncoding) != 1 || r.TransferEncoding[0] != "chunked" {
		t.Fatalf(`expected chunked transfer encoding, got %v`, r.TransferEncoding)
	}
}

func TestInterceptProxyAlternatingBufferedAndStreamed(t *testing.T) {
	upstream := interceptTestUpstream(t)

	tester := caddytest.NewTester(t)
	tester.InitServer(fmt.Sprintf(interceptProxyConfig, `
	intercept {
		@ok status 200
		replace_status @ok 403
	}`, upstream.URL), "caddyfile")

	// alternating intercepted (buffered) and pass-through (streamed)
	// requests must not leak response data into each other
	for i := 0; i < 3; i++ {
		r, _ := tester.AssertGetResponse("http://localhost:9080/replace", 403, "oldbody")
		if got := r.Header.Get("X-Origin"); got != "old" {
			t.Fatalf(`expected original header X-Origin to be kept, got %q`, got)
		}

		r, _ = tester.AssertGetResponse("http://localhost:9080/plain", 404, "plainbody")
		if got := r.Header.Get("X-Origin"); got != "old" {
			t.Fatalf(`expected original header X-Origin to be kept, got %q`, got)
		}
	}
}
