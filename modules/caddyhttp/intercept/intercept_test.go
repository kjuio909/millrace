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
	"net/http"
	"reflect"
	"testing"
)

func TestReplayTrailerVals(t *testing.T) {
	// reverse_proxy style: Trailer declaration with the value
	// stored under the plain field name after the headers were
	// written
	orig := http.Header{}
	orig.Add("Trailer", "X-Checksum")
	orig.Set("X-Checksum", "ok")

	dst := orig.Clone()
	route := http.Header{}
	vals := replayTrailerVals(dst, orig, route, false)

	if _, ok := vals["X-Checksum"]; !ok {
		t.Fatalf("expected X-Checksum to be replayed as a trailer, got %v", vals)
	}
	if got := dst.Get("X-Checksum"); got != "" {
		t.Fatalf("trailer value leaked into regular headers: %q", got)
	}
	if got := dst.Get(http.TrailerPrefix + "X-Checksum"); got != "ok" {
		t.Fatalf("expected magic-prefix trailer value 'ok', got %q", got)
	}
	if got := dst.Get("Trailer"); got != "X-Checksum" {
		t.Fatalf("expected the Trailer declaration to survive, got %q", got)
	}

	// a trailer set with the magic prefix only needs no
	// Trailer declaration
	magic := http.Header{}
	magic.Set(http.TrailerPrefix+"X-Checksum", "ok")
	dst = magic.Clone()
	vals = replayTrailerVals(dst, magic, http.Header{}, false)
	if got := dst.Get(http.TrailerPrefix + "X-Checksum"); got != "ok" {
		t.Fatalf("magic: expected magic-prefix value 'ok', got %q (vals=%v)", got, vals)
	}

	// HEAD: values are stripped but never re-attached, while the
	// declaration survives
	dst = orig.Clone()
	vals = replayTrailerVals(dst, orig, http.Header{}, true)
	if _, ok := vals["X-Checksum"]; !ok {
		t.Fatalf("head: expected the trailer field to be tracked, got %v", vals)
	}
	if got := dst.Get("X-Checksum"); got != "" {
		t.Fatalf("head: expected no regular X-Checksum header, got %q", got)
	}
	if got := dst.Get(http.TrailerPrefix + "X-Checksum"); got != "" {
		t.Fatalf("head: expected no magic-prefix trailer, got %q", got)
	}
	if got := dst.Get("Trailer"); got != "X-Checksum" {
		t.Fatalf("head: expected Trailer declaration to survive, got %q", got)
	}

	// a route that replaces the declaration drops the old value
	// rather than leaking it as a regular header
	routeDecl := http.Header{}
	routeDecl.Set("Trailer", "X-Other")
	dst = orig.Clone()
	dst.Set("Trailer", "X-Other")
	replayTrailerVals(dst, orig, routeDecl, false)
	if got := dst.Get("X-Checksum"); got != "" {
		t.Fatalf("redeclared: expected X-Checksum value dropped, got %q", got)
	}

	// a route that sets the trailer field name as a regular
	// header owns it; the original trailer value is not mixed in
	routeHeader := http.Header{}
	routeHeader.Set("X-Checksum", "route")
	dst = orig.Clone()
	dst.Set("X-Checksum", "route")
	replayTrailerVals(dst, orig, routeHeader, false)
	if got := dst.Values("X-Checksum"); !reflect.DeepEqual(got, []string{"route"}) {
		t.Fatalf("route header: expected only the route value, got %v", got)
	}
	if got := dst.Get(http.TrailerPrefix + "X-Checksum"); got != "" {
		t.Fatalf("route header: expected no magic-prefix value, got %q", got)
	}
}
