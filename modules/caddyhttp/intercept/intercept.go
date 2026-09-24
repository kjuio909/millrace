// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package intercept

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(Intercept{})
	httpcaddyfile.RegisterHandlerDirective("intercept", parseCaddyfile)
}

// Intercept is a middleware that intercepts then replaces or modifies the original response.
// It can, for instance, be used to implement X-Sendfile/X-Accel-Redirect-like features
// when using modules like FrankenPHP or Caddy Snake.
//
// EXPERIMENTAL: Subject to change or removal.
type Intercept struct {
	// List of handlers and their associated matchers to evaluate
	// after successful response generation.
	// The first handler that matches the original response will
	// be invoked.
	//
	// A handler configured with a status code (the
	// "replace_status" Caddyfile directive) swaps the status code
	// and streams the original response to the client unchanged,
	// including its headers and body.
	//
	// Otherwise, the configured routes (the "handle_response"
	// Caddyfile block) are invoked with a fresh response: the
	// original response headers and body are not written to the
	// client, and it is up to the routes to finish handling the
	// response. If the routes only adjust response headers
	// without writing their own status or body, the original
	// response is copied to the client with the adjusted headers.
	//
	// Three new placeholders are available in this handler chain:
	// - `{http.intercept.status_code}` The status code from the response
	// - `{http.intercept.header.*}` The headers from the response
	HandleResponse []caddyhttp.ResponseHandler `json:"handle_response,omitempty"`

	// Holds the named response matchers from the Caddyfile while adapting
	responseMatchers map[string]caddyhttp.ResponseMatcher

	// Holds the handle_response Caddyfile tokens while adapting
	handleResponseSegments []*caddyfile.Dispenser

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
//
// EXPERIMENTAL: Subject to change or removal.
func (Intercept) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.intercept",
		New: func() caddy.Module { return new(Intercept) },
	}
}

// Provision ensures that i is set up properly before use.
//
// EXPERIMENTAL: Subject to change or removal.
func (irh *Intercept) Provision(ctx caddy.Context) error {
	// set up any response routes
	for i, rh := range irh.HandleResponse {
		err := rh.Provision(ctx)
		if err != nil {
			return fmt.Errorf("provisioning response handler %d: %w", i, err)
		}
	}

	irh.logger = ctx.Logger()

	return nil
}

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// handling modes for a response, decided once when the final
// status code is first written
const (
	// no response handler matched; stream the response as-is
	modePassthrough int = iota
	// a replace_status handler matched; stream with replaced status
	modeReplaceStatus
	// a handle_response handler matched; buffer the response
	modeHandleResponse
)

// interceptedWriter is the response recorder handed to the next
// handler while the original response is being generated. 1xx
// responses are passed through to the client immediately, as are
// responses that no response handler matched. When a
// replace_status handler matched, the final status is swapped and
// the response is streamed to the client directly.
//
// EXPERIMENTAL: Subject to change or removal.
type interceptedWriter struct {
	caddyhttp.ResponseRecorder

	intercept *Intercept
	replacer  *caddy.Replacer

	decided bool
	mode    int

	handler      caddyhttp.ResponseHandler
	handlerIndex int

	// status code to write for a replace_status handler
	replaceStatus int

	// error returned by a replace_status handler with an invalid
	// status code, e.g. a placeholder that could not be replaced
	replaceErr error

	// whether the final status code was already written
	wroteHeader bool
}

// decide evaluates the response handlers against the final
// response, the first matching one winning. It is idempotent and
// runs exactly once per request.
//
// EXPERIMENTAL: Subject to change or removal.
func (iw *interceptedWriter) decide(status int, header http.Header) {
	if iw.decided {
		return
	}
	iw.decided = true

	for i, rh := range iw.intercept.HandleResponse {
		if rh.Match != nil && !rh.Match.Match(status, header) {
			continue
		}

		iw.handler = rh
		iw.handlerIndex = i

		// if configured to only change the status code, validate
		// it; on error the original response is buffered and
		// discarded so a plain 500 with none of the original
		// response is sent to the client
		if statusCodeStr := rh.StatusCode.String(); statusCodeStr != "" {
			sc, err := strconv.Atoi(iw.replacer.ReplaceAll(statusCodeStr, ""))
			if err != nil {
				iw.replaceErr = caddyhttp.Error(http.StatusInternalServerError, err)
				iw.mode = modeHandleResponse
				return
			}
			// a status code of zero leaves the original status
			// in place, mirroring reverse_proxy's replace_status
			if sc != 0 {
				iw.replaceStatus = sc
				iw.mode = modeReplaceStatus
				return
			}
			iw.mode = modePassthrough
			return
		}

		iw.mode = modeHandleResponse
		return
	}
}

// shouldBuffer is invoked by the recorder before the final status
// is written; informational responses always pass through, and the
// first matching response handler decides whether to buffer.
//
// EXPERIMENTAL: Subject to change or removal.
func (iw *interceptedWriter) shouldBuffer(status int, header http.Header) bool {
	// 1xx responses aren't final; pass them through and keep
	// waiting for the final response
	if status >= 100 && status <= 199 {
		return false
	}

	iw.decide(status, header)

	return iw.mode == modeHandleResponse
}

// WriteHeader replaces the status code when a replace_status
// handler matched; 1xx responses and subsequent duplicate writes
// are passed through unchanged.
//
// EXPERIMENTAL: Subject to change or removal.
func (iw *interceptedWriter) WriteHeader(statusCode int) {
	final := statusCode < 100 || statusCode > 199
	if final && !iw.wroteHeader {
		iw.wroteHeader = true
		iw.decide(statusCode, iw.Header())
		if iw.mode == modeReplaceStatus {
			iw.ResponseRecorder.WriteHeader(iw.replaceStatus)
			return
		}
	}

	iw.ResponseRecorder.WriteHeader(statusCode)
}

// Write makes sure the matching decision is also made for handlers
// that write a body without calling WriteHeader first.
//
// EXPERIMENTAL: Subject to change or removal.
func (iw *interceptedWriter) Write(data []byte) (int, error) {
	iw.WriteHeader(http.StatusOK)
	return iw.ResponseRecorder.Write(data)
}

// ReadFrom mirrors Write for handlers that copy data with io.Copy;
// the underlying recorder's ReadFrom would bypass WriteHeader, so
// make sure the matching decision happens first.
//
// EXPERIMENTAL: Subject to change or removal.
func (iw *interceptedWriter) ReadFrom(r io.Reader) (int64, error) {
	iw.WriteHeader(http.StatusOK)
	return iw.ResponseRecorder.(io.ReaderFrom).ReadFrom(r)
}

// Unwrap exposes the underlying recorder so that
// http.ResponseController (Flush, Hijack, etc.) keeps working
// while responses are streamed.
//
// EXPERIMENTAL: Subject to change or removal.
func (iw *interceptedWriter) Unwrap() http.ResponseWriter {
	return iw.ResponseRecorder
}

// EXPERIMENTAL: Subject to change or removal.
func (ir Intercept) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	rec := &interceptedWriter{
		intercept: &ir,
		replacer:  repl,
	}
	rec.ResponseRecorder = caddyhttp.NewResponseRecorder(w, buf, rec.shouldBuffer)

	if err := next.ServeHTTP(rec, r); err != nil {
		return err
	}
	if !rec.Buffered() {
		// either no handler matched, or a status code replacement
		// streamed the response directly
		return nil
	}

	// a replace_status handler was configured with an invalid
	// status code; drop the buffered original response and fail
	// with a plain 500
	if rec.replaceErr != nil {
		clear(rec.Header())
		return rec.replaceErr
	}

	// set up the replacer so that parts of the original response can be
	// used for routing decisions
	for field, value := range rec.Header() {
		repl.Set("http.intercept.header."+field, strings.Join(value, ","))
	}
	repl.Set("http.intercept.status_code", rec.Status())

	if c := ir.logger.Check(zapcore.DebugLevel, "handling response"); c != nil {
		c.Write(zap.Int("handler", rec.handlerIndex))
	}

	// the response recorder's header map is the client's header map,
	// which still carries the original response headers. Snapshot them
	// (Content-Length in particular) and start the response routes from
	// a clean, isolated header map: a route that writes its own response
	// must not inherit any of the original headers, while a route that
	// only adjusts headers leaves the original response intact
	origHeader := rec.Header().Clone()
	origContentLength := origHeader.Get("Content-Length")
	clear(rec.Header())

	// the routes write into an isolated header map, which is copied
	// to the client only when the routes actually write a response;
	// any response body is streamed directly to the client
	rw := &isolatedHeaderWriter{
		ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w},
		header:                http.Header{},
	}
	routeRecorder := caddyhttp.NewResponseRecorder(rw, nil, nil)
	if err := rec.handler.Routes.Compile(emptyHandler).ServeHTTP(routeRecorder, r); err != nil {
		return err
	}

	// the routes wrote their own final response; they are entirely
	// responsible for it, so the original response is discarded
	if routeRecorder.Status() != 0 {
		return nil
	}

	// the routes did not write a response themselves (they typically
	// only adjusted response headers); replay the original response
	// headers, with headers the routes set taking precedence per field
	dst := w.Header()
	for field, vals := range origHeader {
		dst[field] = vals
	}
	for field, vals := range rw.header {
		dst[field] = vals
	}

	status := rec.Status()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)

	// HEAD responses, and other responses which declared a length
	// without a body, keep the Content-Length from the original
	// response rather than copying a body they don't have
	if r.Method == http.MethodHead || (buf.Len() == 0 && origContentLength != "") {
		return nil
	}

	_, err := buf.WriteTo(w)
	return err
}

// isolatedHeaderWriter presents a response handler chain with its
// own header map, separate from the client's. The isolated headers
// are copied to the client only when the handler chain writes a
// final response; this keeps an original, intercepted response's
// headers from leaking into a replacement response.
//
// EXPERIMENTAL: Subject to change or removal.
type isolatedHeaderWriter struct {
	*caddyhttp.ResponseWriterWrapper
	header http.Header
}

// EXPERIMENTAL: Subject to change or removal.
func (iw *isolatedHeaderWriter) Header() http.Header {
	return iw.header
}

// WriteHeader copies the isolated headers onto the client's header
// map and writes the status code.
//
// EXPERIMENTAL: Subject to change or removal.
func (iw *isolatedHeaderWriter) WriteHeader(statusCode int) {
	dst := iw.ResponseWriterWrapper.Header()
	for field, vals := range iw.header {
		dst[field] = vals
	}
	iw.ResponseWriterWrapper.WriteHeader(statusCode)
}

// Unwrap exposes the underlying writer so that
// http.ResponseController (Flush, Hijack, etc.) keeps working.
//
// EXPERIMENTAL: Subject to change or removal.
func (iw *isolatedHeaderWriter) Unwrap() http.ResponseWriter {
	return iw.ResponseWriterWrapper
}

// this handler does nothing because everything we need is already buffered
var emptyHandler caddyhttp.Handler = caddyhttp.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) error {
	return nil
})

// UnmarshalCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	intercept [<matcher>] {
//	    # intercept original responses
//	    @name {
//	        status <code...>
//	        header <field> [<value>]
//	    }
//	    replace_status [<matcher>] <status_code>
//	    handle_response [<matcher>] {
//	        <directives...>
//	    }
//	}
//
// The FinalizeUnmarshalCaddyfile method should be called after this
// to finalize parsing of "handle_response" blocks, if possible.
//
// EXPERIMENTAL: Subject to change or removal.
func (i *Intercept) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// collect the response matchers defined as subdirectives
	// prefixed with "@" for use with "handle_response" blocks
	i.responseMatchers = make(map[string]caddyhttp.ResponseMatcher)

	d.Next() // consume the directive name
	for d.NextBlock(0) {
		// if the subdirective has an "@" prefix then we
		// parse it as a response matcher for use with "handle_response"
		if strings.HasPrefix(d.Val(), matcherPrefix) {
			err := caddyhttp.ParseNamedResponseMatcher(d.NewFromNextSegment(), i.responseMatchers)
			if err != nil {
				return err
			}
			continue
		}

		switch d.Val() {
		case "handle_response":
			// delegate the parsing of handle_response to the caller,
			// since we need the httpcaddyfile.Helper to parse subroutes.
			// See h.FinalizeUnmarshalCaddyfile
			i.handleResponseSegments = append(i.handleResponseSegments, d.NewFromNextSegment())

		case "replace_status":
			args := d.RemainingArgs()
			if len(args) != 1 && len(args) != 2 {
				return d.Errf("must have one or two arguments: an optional response matcher, and a status code")
			}

			responseHandler := caddyhttp.ResponseHandler{}

			if len(args) == 2 {
				if !strings.HasPrefix(args[0], matcherPrefix) {
					return d.Errf("must use a named response matcher, starting with '@'")
				}
				foundMatcher, ok := i.responseMatchers[args[0]]
				if !ok {
					return d.Errf("no named response matcher defined with name '%s'", args[0][1:])
				}
				responseHandler.Match = &foundMatcher
				responseHandler.StatusCode = caddyhttp.WeakString(args[1])
			} else if len(args) == 1 {
				responseHandler.StatusCode = caddyhttp.WeakString(args[0])
			}

			// make sure there's no block, cause it doesn't make sense
			if nesting := d.Nesting(); d.NextBlock(nesting) {
				return d.Errf("cannot define routes for 'replace_status', use 'handle_response' instead.")
			}

			i.HandleResponse = append(
				i.HandleResponse,
				responseHandler,
			)

		default:
			return d.Errf("unrecognized subdirective %s", d.Val())
		}
	}

	return nil
}

// FinalizeUnmarshalCaddyfile finalizes the Caddyfile parsing which
// requires having an httpcaddyfile.Helper to function, to parse subroutes.
//
// EXPERIMENTAL: Subject to change or removal.
func (i *Intercept) FinalizeUnmarshalCaddyfile(helper httpcaddyfile.Helper) error {
	for _, d := range i.handleResponseSegments {
		// consume the "handle_response" token
		d.Next()
		args := d.RemainingArgs()

		// TODO: Remove this check at some point in the future
		if len(args) == 2 {
			return d.Errf("configuring 'handle_response' for status code replacement is no longer supported. Use 'replace_status' instead.")
		}

		if len(args) > 1 {
			return d.Errf("too many arguments for 'handle_response': %s", args)
		}

		var matcher *caddyhttp.ResponseMatcher
		if len(args) == 1 {
			// the first arg should always be a matcher.
			if !strings.HasPrefix(args[0], matcherPrefix) {
				return d.Errf("must use a named response matcher, starting with '@'")
			}

			foundMatcher, ok := i.responseMatchers[args[0]]
			if !ok {
				return d.Errf("no named response matcher defined with name '%s'", args[0][1:])
			}
			matcher = &foundMatcher
		}

		// parse the block as routes
		handler, err := httpcaddyfile.ParseSegmentAsSubroute(helper.WithDispenser(d.NewFromNextSegment()))
		if err != nil {
			return err
		}
		subroute, ok := handler.(*caddyhttp.Subroute)
		if !ok {
			return helper.Errf("segment was not parsed as a subroute")
		}
		i.HandleResponse = append(
			i.HandleResponse,
			caddyhttp.ResponseHandler{
				Match:  matcher,
				Routes: subroute.Routes,
			},
		)
	}

	// move the handle_response entries without a matcher to the end.
	// we can't use sort.SliceStable because it will reorder the rest of the
	// entries which may be undesirable because we don't have a good
	// heuristic to use for sorting.
	withoutMatchers := []caddyhttp.ResponseHandler{}
	withMatchers := []caddyhttp.ResponseHandler{}
	for _, hr := range i.HandleResponse {
		if hr.Match == nil {
			withoutMatchers = append(withoutMatchers, hr)
		} else {
			withMatchers = append(withMatchers, hr)
		}
	}
	i.HandleResponse = append(withMatchers, withoutMatchers...)

	// clean up the bits we only needed for adapting
	i.handleResponseSegments = nil
	i.responseMatchers = nil

	return nil
}

const matcherPrefix = "@"

func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var ir Intercept
	if err := ir.UnmarshalCaddyfile(helper.Dispenser); err != nil {
		return nil, err
	}

	if err := ir.FinalizeUnmarshalCaddyfile(helper); err != nil {
		return nil, err
	}

	return ir, nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Intercept)(nil)
	_ caddyfile.Unmarshaler       = (*Intercept)(nil)
	_ caddyhttp.MiddlewareHandler = (*Intercept)(nil)
)
