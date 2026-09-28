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

package caddyconfig

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// TestHandleLoadRejectsMalformedPayloads verifies that malformed documents
// are refused with a non-success APIError before any running configuration
// is touched. None of these cases may reach caddy.Load, so they must not
// mutate process state regardless of what (if anything) is currently running.
func TestHandleLoadRejectsMalformedPayloads(t *testing.T) {
	var al adminLoad

	for _, tc := range []struct {
		name        string
		method      string
		contentType string
		body        string
		wantStatus  int
		wantErr     string
	}{
		{
			name:        "empty body",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        "",
			wantStatus:  http.StatusBadRequest,
			wantErr:     "request body is empty",
		},
		{
			name:        "whitespace only",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        "   \n\t ",
			wantStatus:  http.StatusBadRequest,
			wantErr:     "request body is empty",
		},
		{
			name:        "empty Caddyfile body",
			method:      http.MethodPost,
			contentType: "text/caddyfile",
			body:        "",
			wantStatus:  http.StatusBadRequest,
			wantErr:     "request body is empty",
		},
		{
			name:        "null document",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        "null",
			wantStatus:  http.StatusBadRequest,
			wantErr:     "configuration must be a JSON object, got null",
		},
		{
			name:        "truncated JSON",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        `{"apps":`,
			wantStatus:  http.StatusBadRequest,
			wantErr:     "unexpected end of JSON input",
		},
		{
			name:        "trailing data",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        `{"apps":{}}GARBAGE`,
			wantStatus:  http.StatusBadRequest,
			wantErr:     "after top-level value",
		},
		{
			name:        "non-object array",
			method:      http.MethodPost,
			contentType: "application/json",
			body:        `[1,2,3]`,
			wantStatus:  http.StatusBadRequest,
			wantErr:     "configuration must be a JSON object",
		},
		{
			name:        "wrong method",
			method:      http.MethodGet,
			contentType: "application/json",
			body:        `{}`,
			wantStatus:  http.StatusMethodNotAllowed,
			wantErr:     "method not allowed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/load", strings.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}
			rec := httptest.NewRecorder()

			err := al.handleLoad(rec, req)
			if err == nil {
				t.Fatalf("expected an error, got nil; status=%d", rec.Code)
			}
			apiErr, ok := err.(caddy.APIError)
			if !ok {
				t.Fatalf("error is not an APIError: %T %v", err, err)
			}
			if apiErr.HTTPStatus != tc.wantStatus {
				t.Fatalf("status: got %d, want %d", apiErr.HTTPStatus, tc.wantStatus)
			}
			if !strings.Contains(apiErr.Error(), tc.wantErr) {
				t.Fatalf("error: got %q, want it to contain %q", apiErr.Error(), tc.wantErr)
			}
		})
	}
}
