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

func TestConfigPersistDisabled(t *testing.T) {
	for i, tc := range []struct {
		name string
		json string
		want bool
	}{
		{
			name: "no admin config",
			json: `{"apps":{}}`,
			want: false,
		},
		{
			name: "admin without config settings",
			json: `{"admin":{"listen":"localhost:2019"}}`,
			want: false,
		},
		{
			name: "persist explicitly true",
			json: `{"admin":{"config":{"persist":true}}}`,
			want: false,
		},
		{
			name: "persist explicitly false",
			json: `{"admin":{"config":{"persist":false}}}`,
			want: true,
		},
		{
			name: "malformed json is treated as default (enabled)",
			json: `{"admin":`,
			want: false,
		},
	} {
		if got := configPersistDisabled([]byte(tc.json)); got != tc.want {
			t.Errorf("test %d (%s): got %v, want %v", i, tc.name, got, tc.want)
		}
	}
}

func TestRestoreAutosavedConfig(t *testing.T) {
	startup := []byte(`{"admin":{"listen":"localhost:2019"},"apps":{"http":{}}}`)
	saved := []byte(`{"admin":{"listen":"localhost:2019"},"apps":{"http":{"servers":{}}}}`)

	t.Run("no autosave file uses startup config", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "autosave.json")
		withAutosavePath(t, path, func() {
			got, ok := RestoreAutosavedConfig(startup)
			if ok {
				t.Fatalf("expected no restore, got %s", got)
			}
			if string(got) != string(startup) {
				t.Fatalf("expected startup config, got %s", got)
			}
		})
	})

	t.Run("different autosave restores last version", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "autosave.json")
		if err := os.WriteFile(path, saved, 0o600); err != nil {
			t.Fatal(err)
		}
		withAutosavePath(t, path, func() {
			got, ok := RestoreAutosavedConfig(startup)
			if !ok {
				t.Fatal("expected restore to happen")
			}
			if string(got) != string(saved) {
				t.Fatalf("expected restored saved config, got %s", got)
			}
		})
	})

	t.Run("identical autosave is a no-op", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "autosave.json")
		if err := os.WriteFile(path, startup, 0o600); err != nil {
			t.Fatal(err)
		}
		withAutosavePath(t, path, func() {
			if _, ok := RestoreAutosavedConfig(startup); ok {
				t.Fatal("identical config must not be reported as restored")
			}
		})
	})

	t.Run("persist disabled never restores", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "autosave.json")
		if err := os.WriteFile(path, saved, 0o600); err != nil {
			t.Fatal(err)
		}
		off := []byte(`{"admin":{"config":{"persist":false}}}`)
		withAutosavePath(t, path, func() {
			got, ok := RestoreAutosavedConfig(off)
			if ok {
				t.Fatalf("persist-off startup must not restore, got %s", got)
			}
			if string(got) != string(off) {
				t.Fatalf("expected startup config, got %s", got)
			}
		})
	})

	t.Run("null and empty startup documents never restore", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "autosave.json")
		if err := os.WriteFile(path, saved, 0o600); err != nil {
			t.Fatal(err)
		}
		withAutosavePath(t, path, func() {
			for _, startupDoc := range [][]byte{nil, []byte(""), []byte("  \n"), []byte("null"), []byte(`"string"`), []byte(`{"apps":`)} {
				if _, ok := RestoreAutosavedConfig(startupDoc); ok {
					t.Errorf("startup document %q must not restore the autosave", startupDoc)
				}
			}
		})
	})
}

func TestWriteConfigAutosaveIsAtomicAndComplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "autosave.json")
	withAutosavePath(t, path, func() {
		payload := []byte(`{"version":"one"}`)
		if err := writeConfigAutosave(payload); err != nil {
			t.Fatalf("first write: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(payload) {
			t.Fatalf("got %q, want %q", got, payload)
		}

		// a replacement must never leave a partial document behind
		payload2 := []byte(`{"version":"two"}`)
		if err := writeConfigAutosave(payload2); err != nil {
			t.Fatalf("second write: %v", err)
		}
		got, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(payload2) {
			t.Fatalf("got %q, want %q", got, payload2)
		}

		// no stray temporary files remain next to the autosave
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) == ".tmp" {
				t.Fatalf("temporary autosave file left behind: %s", entry.Name())
			}
		}
	})
}

// withAutosavePath temporarily points the autosave path at path for the
// duration of fn.
func withAutosavePath(t *testing.T, path string, fn func()) {
	t.Helper()
	orig := ConfigAutosavePath
	ConfigAutosavePath = path
	t.Cleanup(func() { ConfigAutosavePath = orig })
	fn()
}

// TestLoadPersistenceBoundary proves the persisted document follows the
// exact same boundary as the running configuration: a successful load
// replaces it, a failed load leaves the last successful version untouched,
// and a successful load with persistence disabled removes it.
func TestLoadPersistenceBoundary(t *testing.T) {
	modulesMu.RLock()
	_, registered := modules["foo"]
	modulesMu.RUnlock()
	if !registered {
		RegisterModule(fooModule{})
	}

	path := filepath.Join(t.TempDir(), "autosave.json")
	withAutosavePath(t, path, func() {
		cfgA := []byte(`{"apps":{"foo":{"strField":"A"}}}`)
		cfgB := []byte(`{"apps":{"foo":{"strField":"B"}}}`)
		cfgOff := []byte(`{"admin":{"config":{"persist":false}},"apps":{"foo":{"strField":"off"}}}`)
		badCfg := []byte(`{"apps":{"does_not_exist":{}}}`)

		readAutosave := func() []byte {
			t.Helper()
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading autosave: %v", err)
			}
			return b
		}

		// a successful load persists its version
		if err := Load(cfgA, true); err != nil {
			t.Fatalf("loading A: %v", err)
		}
		strippedA := RemoveMetaFields(cfgA)
		if got := readAutosave(); string(got) != string(strippedA) {
			t.Fatalf("autosave after A: got %s, want %s", got, strippedA)
		}

		// a failed load must not overwrite the last successful version
		if err := Load(badCfg, true); err == nil {
			t.Fatal("loading the bad config unexpectedly succeeded")
		}
		if got := readAutosave(); string(got) != string(strippedA) {
			t.Fatalf("autosave after failed load: got %s, want %s", got, strippedA)
		}

		// the next successful load replaces it
		if err := Load(cfgB, true); err != nil {
			t.Fatalf("loading B: %v", err)
		}
		strippedB := RemoveMetaFields(cfgB)
		if got := readAutosave(); string(got) != string(strippedB) {
			t.Fatalf("autosave after B: got %s, want %s", got, strippedB)
		}

		// a successful load with persistence disabled removes it
		if err := Load(cfgOff, true); err != nil {
			t.Fatalf("loading persist-off config: %v", err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("autosave was not removed after persistence was disabled (stat err: %v)", err)
		}
	})
}
