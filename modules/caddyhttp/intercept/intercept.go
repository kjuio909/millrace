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
	// be invoked. The original response body will not be
	// written to the client;
	// it is up to the handler to finish handling the response.
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

// EXPERIMENTAL: Subject to change or removal.
type interceptedResponseHandler struct {
	caddyhttp.ResponseRecorder
	replacer      *caddy.Replacer
	handler       caddyhttp.ResponseHandler
	handlerIndex  int
	statusCode    int
	statusCodeErr error
}

// EXPERIMENTAL: Subject to change or removal.
func (irh interceptedResponseHandler) Unwrap() http.ResponseWriter {
	return irh.ResponseRecorder
}

// EXPERIMENTAL: Subject to change or removal.
func (ir Intercept) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	rec := interceptedResponseHandler{replacer: repl}
	rec.ResponseRecorder = caddyhttp.NewResponseRecorder(w, buf, func(status int, header http.Header) bool {
		// see if any response handler is configured for this original response
		for i, rh := range ir.HandleResponse {
			if rh.Match != nil && !rh.Match.Match(status, header) {
				continue
			}
			rec.handler = rh
			rec.handlerIndex = i

			// if configured to only change the status code,
			// buffer the response so we can substitute the status
			if statusCodeStr := rh.StatusCode.String(); statusCodeStr != "" {
				sc, err := strconv.Atoi(repl.ReplaceAll(statusCodeStr, ""))
				if err != nil {
					rec.statusCodeErr = err
					rec.statusCode = http.StatusInternalServerError
				} else {
					rec.statusCode = sc
				}

				return true
			}

			return rec.statusCode == 0
		}

		return false
	})

	if err := next.ServeHTTP(rec, r); err != nil {
		return err
	}
	if !rec.Buffered() {
		return nil
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

	// replace_status only: no routes to execute, just substitute the
	// status code and write the buffered original response as-is
	if rec.handler.Routes == nil {
		// an invalid status code (e.g. from a bad placeholder) means we
		// cannot honor the original response at all; strip the original
		// response headers so the error response doesn't leak them, and
		// discard the buffered body (1xx responses already sent to the
		// client can't be retracted, but the final status will be 500)
		if rec.statusCodeErr != nil {
			clear(w.Header())
			return caddyhttp.Error(http.StatusInternalServerError, rec.statusCodeErr)
		}

		if rec.statusCode == 0 {
			w.WriteHeader(rec.Status())
		} else {
			w.WriteHeader(rec.statusCode)
		}

		if buf.Len() > 0 {
			_, err := io.Copy(w, buf)

			return err
		}

		return nil
	}

	// the response recorder doesn't create a new copy of the original headers,
	// they're present in the original response writer; the routes we're about
	// to execute replace the original response, so the original headers must
	// not leak into their response (e.g. an original Content-Length would
	// corrupt a replacement body of a different length); but keep a copy so
	// the fallback handler can restore them if the routes don't produce a
	// response of their own
	originalHeaders := w.Header().Clone()
	clear(w.Header())

	// execute the routes configured for this response; the fallback handler
	// writes the original response if the routes don't, so that handlers
	// which only modify the response (e.g. the 'header' directive) don't
	// accidentally discard it
	if err := rec.handler.Routes.Compile(fallbackHandler(w, originalHeaders, rec.Status(), buf)).ServeHTTP(w, r); err != nil {
		// the error handler chain will write its own response; restore the
		// original headers so the response doesn't end up with none at all
		restoreHeaders(w, originalHeaders)
		return err
	}

	return nil
}

// restoreHeaders adds the headers from original back into w's header map,
// without overwriting any headers that were set in the meantime.
func restoreHeaders(w http.ResponseWriter, original http.Header) {
	for field, values := range original {
		if _, ok := w.Header()[field]; !ok {
			w.Header()[field] = values
		}
	}
}

// fallbackHandler returns a handler that writes the buffered original
// response (headers, status code and body) to w; it is used as the 'next'
// handler for intercept routes so that routes which don't produce their
// own response fall through to the original response. Headers set by the
// routes take precedence over the original ones.
func fallbackHandler(w http.ResponseWriter, original http.Header, status int, buf *bytes.Buffer) caddyhttp.Handler {
	return caddyhttp.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) error {
		restoreHeaders(w, original)
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		if buf.Len() > 0 {
			_, err := io.Copy(w, buf)
			return err
		}
		return nil
	})
}

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
