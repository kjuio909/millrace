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

package caddy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain isolates on-disk configuration persistence from the
// developer's machine: tests run Load() against a temporary autosave
// path and leave the real autosave file untouched.
func TestMain(m *testing.M) {
	origAutosavePath := ConfigAutosavePath
	ConfigAutosavePath = filepath.Join(os.TempDir(), "caddy-test-autosave.json")
	_ = os.Remove(ConfigAutosavePath)
	defer func() {
		_ = os.Remove(ConfigAutosavePath)
		ConfigAutosavePath = origAutosavePath
	}()
	os.Exit(m.Run())
}
