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

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// TestMain isolates the in-process `caddy run` harness started by the
// caddytest tester from the developer's machine: this package's configs
// persist to a temporary autosave path rather than the real per-user
// file. (The cross-process subprocess tests set their own isolated
// HOME/XDG roots for the binaries they launch.)
func TestMain(m *testing.M) {
	origAutosavePath := caddy.ConfigAutosavePath
	caddy.ConfigAutosavePath = filepath.Join(os.TempDir(), "caddy-integration-autosave.json")
	// discard any copy a previous test process left behind so the harness
	// starts from its declared initial configuration
	_ = os.Remove(caddy.ConfigAutosavePath)
	defer func() {
		_ = os.Remove(caddy.ConfigAutosavePath)
		caddy.ConfigAutosavePath = origAutosavePath
	}()
	os.Exit(m.Run())
}
