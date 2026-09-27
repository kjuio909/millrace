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

import "testing"

func TestValidateConfigJSON(t *testing.T) {
	for i, tc := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name: "minimal object",
			body: `{}`,
		},
		{
			name: "typical config",
			body: `{"admin": {"listen": "localhost:2999"}, "apps": {"http": {"servers": {}}}}`,
		},
		{
			name: "duplicate keys are syntactically valid",
			body: `{"a": 1, "a": 2}`,
		},
		{
			name:    "empty body",
			body:    ``,
			wantErr: true,
		},
		{
			name:    "whitespace only",
			body:    "   \n\t",
			wantErr: true,
		},
		{
			name:    "truncated object",
			body:    `{"admin": {"listen":`,
			wantErr: true,
		},
		{
			name:    "truncated string",
			body:    `{"admin": "oops`,
			wantErr: true,
		},
		{
			name:    "data after complete object",
			body:    "{}\nGARBAGE",
			wantErr: true,
		},
		{
			name:    "second value after object",
			body:    `{}{}`,
			wantErr: true,
		},
		{
			name:    "null",
			body:    `null`,
			wantErr: true,
		},
		{
			name:    "array",
			body:    `[]`,
			wantErr: true,
		},
		{
			name:    "string",
			body:    `"config"`,
			wantErr: true,
		},
		{
			name:    "number",
			body:    `42`,
			wantErr: true,
		},
		{
			name:    "boolean",
			body:    `true`,
			wantErr: true,
		},
		// Semantic validation is intentionally left to the load path;
		// only JSON syntax and the top-level object shape matter here.
		{
			name: "unknown fields accepted",
			body: `{"not_a_real_field": true}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateConfigJSON([]byte(tc.body))
			if tc.wantErr && err == nil {
				t.Errorf("test %d (%s): expected error, got nil", i, tc.name)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("test %d (%s): expected no error, got: %v", i, tc.name, err)
			}
		})
	}
}
