package integration

import (
	"io"
	"net"
	"net/http"
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

// TestInterceptReverseProxy exercises the intercept middleware in
// front of a reverse_proxy, mirroring the behavior of
// reverse_proxy's own handle_response/replace_status options:
// syntax parity, first-match-wins, and the exact bytes and headers
// that reach the HTTP/1.1 downstream client.
func TestInterceptReverseProxy(t *testing.T) {
	// upstream always answers with 200, "X-Origin: old" and the
	// 7-byte body "oldbody", except for a few specialized paths
	upstream := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/early", "/earlybad":
				// an informational response before the final one
				w.Header().Set("Link", "</style.css>; rel=preload; as=style")
				w.WriteHeader(http.StatusEarlyHints)

			case "/flush":
				// no Content-Length; flush immediately so the
				// response is streamed with chunked encoding
				w.WriteHeader(http.StatusOK)
				fl, _ := w.(http.Flusher)
				fl.Flush()
				_, _ = io.WriteString(w, "flush-body")
				fl.Flush()
				return
			}

			w.Header().Set("X-Origin", "old")
			w.WriteHeader(http.StatusOK)
			// writes are counted for Content-Length even on HEAD,
			// where the server suppresses the actual body
			_, _ = io.WriteString(w, "oldbody")
		}),
	}
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	go upstream.Serve(upstreamLn)
	t.Cleanup(func() { upstream.Close(); upstreamLn.Close() })
	upstreamAddr := upstreamLn.Addr().String()

	tester := caddytest.NewTester(t)
	tester.InitServer(`{
			skip_install_trust
			admin localhost:2999
			http_port     9080
			https_port    9443
			grace_period  1ns
		}

		http://localhost:9080 {
			# replace_status: swap the status code, keep the
			# original headers and body
			@replace path /replace /early /head /flush /first
			handle @replace {
				intercept {
					@deny status 200
					replace_status @deny 403

					# a second matching entry must never win
					@also status 2xx
					replace_status @also 404
				}
				reverse_proxy `+upstreamAddr+`
			}

			# an invalid replace_status placeholder after a 103:
			# the 1xx is already on the wire, the final response
			# is still a bare 500
			handle /earlybad {
				intercept {
					@deny status 200
					replace_status @deny {query.sc}
				}
				reverse_proxy `+upstreamAddr+`
			}

			# handle_response with a brand new response
			handle /new {
				intercept {
					@deny status 200
					handle_response @deny {
						respond "new" 403
					}
				}
				reverse_proxy `+upstreamAddr+`
			}

			# handle_response that only edits a header
			handle /edit {
				intercept {
					@deny status 200
					handle_response @deny {
						header X-Edit yes
					}
				}
				reverse_proxy `+upstreamAddr+`
			}

			# handle_response that answers 204 with an empty body;
			# the buffered original body must not be reused
			handle /empty {
				intercept {
					@deny status 200
					handle_response @deny {
						respond "" 204
					}
				}
				reverse_proxy `+upstreamAddr+`
			}

			# replace_status with an unparseable placeholder value
			handle /bad {
				intercept {
					@deny status 200
					replace_status @deny {query.sc}
				}
				reverse_proxy `+upstreamAddr+`
			}

			# no intercept at all
			handle /plain {
				reverse_proxy `+upstreamAddr+`
			}
		}
		`, "caddyfile")

	do := func(method, target string, trace *httptrace.ClientTrace) *http.Response {
		req, err := http.NewRequest(method, target, nil)
		if err != nil {
			t.Fatalf("building request: %v", err)
		}
		if trace != nil {
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
		}
		resp, err := tester.Client.Do(req)
		if err != nil {
			t.Fatalf("request %s: %v", target, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	body := func(resp *http.Response) string {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading body: %v", err)
		}
		return string(b)
	}

	// replace_status: 403 with the original body, its 7-byte
	// Content-Length and the original response header
	resp := do(http.MethodGet, "http://localhost:9080/replace", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("replace: expected status 403, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Length"); got != "7" {
		t.Errorf("replace: expected Content-Length 7, got %q", got)
	}
	if got := resp.Header.Get("X-Origin"); got != "old" {
		t.Errorf("replace: expected X-Origin 'old', got %q", got)
	}
	if got := body(resp); got != "oldbody" {
		t.Errorf("replace: expected body 'oldbody', got %q", got)
	}

	// handle_response writing its own response: 403/"new" with a
	// 3-byte Content-Length and none of the original headers
	resp = do(http.MethodGet, "http://localhost:9080/new", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("new: expected status 403, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Length"); got != "3" {
		t.Errorf("new: expected Content-Length 3, got %q", got)
	}
	if got := resp.Header.Get("X-Origin"); got != "" {
		t.Errorf("new: expected no X-Origin header, got %q", got)
	}
	if got := body(resp); got != "new" {
		t.Errorf("new: expected body 'new', got %q", got)
	}

	// handle_response only editing a header: original status,
	// body, Content-Length and headers, plus the new header
	resp = do(http.MethodGet, "http://localhost:9080/edit", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("edit: expected status 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Length"); got != "7" {
		t.Errorf("edit: expected Content-Length 7, got %q", got)
	}
	if got := resp.Header.Get("X-Origin"); got != "old" {
		t.Errorf("edit: expected X-Origin 'old', got %q", got)
	}
	if got := resp.Header.Get("X-Edit"); got != "yes" {
		t.Errorf("edit: expected X-Edit 'yes', got %q", got)
	}
	if got := body(resp); got != "oldbody" {
		t.Errorf("edit: expected body 'oldbody', got %q", got)
	}

	// handle_response answering 204 with an empty body must not
	// fall back to the buffered original body
	resp = do(http.MethodGet, "http://localhost:9080/empty", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("empty: expected status 204, got %d", resp.StatusCode)
	}
	if got := body(resp); got != "" {
		t.Errorf("empty: expected empty body, got %q", got)
	}
	if got := resp.Header.Get("X-Origin"); got != "" {
		t.Errorf("empty: expected no X-Origin header, got %q", got)
	}

	// invalid replace_status placeholder: buffered original
	// response is discarded, client gets a bare 500
	resp = do(http.MethodGet, "http://localhost:9080/bad?sc=abc", nil)
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("bad: expected status 500, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Origin"); got != "" {
		t.Errorf("bad: expected no X-Origin header, got %q", got)
	}
	if got := body(resp); got != "" {
		t.Errorf("bad: expected empty body, got %q", got)
	}

	// upstream sends 103 Early Hints before the 200; the client
	// must observe the 103 (it cannot be withdrawn) before the
	// replaced final status
	var saw1xx []int
	trace := &httptrace.ClientTrace{
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
			saw1xx = append(saw1xx, code)
			return nil
		},
	}
	resp = do(http.MethodGet, "http://localhost:9080/early", trace)
	if len(saw1xx) != 1 || saw1xx[0] != http.StatusEarlyHints {
		t.Errorf("early: expected to see 103 before the final response, got %v", saw1xx)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("early: expected final status 403, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Origin"); got != "old" {
		t.Errorf("early: expected X-Origin 'old', got %q", got)
	}
	if got := body(resp); got != "oldbody" {
		t.Errorf("early: expected body 'oldbody', got %q", got)
	}

	// 103 already forwarded, then an invalid replace_status
	// placeholder: the 1xx cannot be withdrawn but the final
	// response is still a bare 500 without the original body
	saw1xx = nil
	resp = do(http.MethodGet, "http://localhost:9080/earlybad?sc=abc", trace)
	if len(saw1xx) != 1 || saw1xx[0] != http.StatusEarlyHints {
		t.Errorf("earlybad: expected to see 103 before the final response, got %v", saw1xx)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("earlybad: expected final status 500, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Origin"); got != "" {
		t.Errorf("earlybad: expected no X-Origin header, got %q", got)
	}
	if got := body(resp); got != "" {
		t.Errorf("earlybad: expected empty body, got %q", got)
	}

	// first matching response handler wins: the second
	// replace_status entry must be ignored
	resp = do(http.MethodGet, "http://localhost:9080/first", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("first: expected status 403 from the first handler, got %d", resp.StatusCode)
	}
	if got := body(resp); got != "oldbody" {
		t.Errorf("first: expected body 'oldbody', got %q", got)
	}

	// HEAD: no body, but Content-Length advertises the entity length
	resp = do(http.MethodHead, "http://localhost:9080/head", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("head: expected status 403, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Length"); got != "7" {
		t.Errorf("head: expected Content-Length 7, got %q", got)
	}
	if got := body(resp); got != "" {
		t.Errorf("head: expected empty body, got %q", got)
	}

	// streamed response without Content-Length is chunked on the
	// HTTP/1.1 downstream connection
	resp = do(http.MethodGet, "http://localhost:9080/flush", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("flush: expected status 403, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Length"); got != "" {
		t.Errorf("flush: expected no Content-Length header, got %q", got)
	}
	if !slicesContains(resp.TransferEncoding, "chunked") {
		t.Errorf("flush: expected chunked transfer encoding, got %v", resp.TransferEncoding)
	}
	if got := body(resp); got != "flush-body" {
		t.Errorf("flush: expected body 'flush-body', got %q", got)
	}

	// intercepted and plain responses must not share buffer state
	for range 4 {
		resp = do(http.MethodGet, "http://localhost:9080/replace", nil)
		if got := body(resp); got != "oldbody" {
			t.Fatalf("alternate replace: expected body 'oldbody', got %q", got)
		}
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("alternate replace: expected status 403, got %d", resp.StatusCode)
		}

		resp = do(http.MethodGet, "http://localhost:9080/plain", nil)
		if got := body(resp); got != "oldbody" {
			t.Fatalf("alternate plain: expected body 'oldbody', got %q", got)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("alternate plain: expected status 200, got %d", resp.StatusCode)
		}
	}
}

func slicesContains(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}
