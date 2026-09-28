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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.uber.org/zap"
)

// writeConfigAutosave atomically replaces the autosave file with
// cfgJSON: it writes to a sibling temporary file, flushes it to
// stable storage, and renames it into place. A crash at any point
// therefore leaves either the previous complete autosave document or
// the new complete one - never a truncated/half-written document - so
// the persisted version can never describe a configuration that did
// not load.
func writeConfigAutosave(cfgJSON []byte) error {
	dir := filepath.Dir(ConfigAutosavePath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating autosave directory %s: %v", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".autosave*.tmp")
	if err != nil {
		return fmt.Errorf("creating temporary autosave file: %v", err)
	}
	tmpName := tmp.Name()
	// on every non-rename outcome the temporary file is discarded
	abort := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(cfgJSON); err != nil {
		_ = tmp.Close()
		abort()
		return fmt.Errorf("writing temporary autosave file: %v", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		abort()
		return fmt.Errorf("flushing temporary autosave file to disk: %v", err)
	}
	if err := tmp.Close(); err != nil {
		abort()
		return fmt.Errorf("closing temporary autosave file: %v", err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		abort()
		return fmt.Errorf("setting permissions on temporary autosave file: %v", err)
	}
	if err := os.Rename(tmpName, ConfigAutosavePath); err != nil {
		abort()
		return fmt.Errorf("replacing autosave file %s: %v", ConfigAutosavePath, err)
	}

	return nil
}

// configPersistDisabled reports whether cfgJSON explicitly turns config
// persistence off via admin.config.persist = false. A missing field means
// persistence is enabled (the default).
func configPersistDisabled(cfgJSON []byte) bool {
	var probe struct {
		Admin *struct {
			Config *struct {
				Persist *bool `json:"persist"`
			} `json:"config"`
		} `json:"admin"`
	}
	if err := json.Unmarshal(cfgJSON, &probe); err != nil {
		return false
	}
	return probe.Admin != nil &&
		probe.Admin.Config != nil &&
		probe.Admin.Config.Persist != nil &&
		!*probe.Admin.Config.Persist
}

// RestoreAutosavedConfig decides what a process starting with startupJSON
// should run. Configurations pushed through the admin API are persisted to
// ConfigAutosavePath once they have successfully started; if such a
// document exists, is different from the startup configuration, and the
// startup configuration does not explicitly disable persistence, the
// persisted document is returned with ok=true so the process resumes the
// last running version rather than the (older) startup file.
//
// A startup configuration with persistence disabled always returns
// startupJSON: an online load made under such a configuration is never
// persisted and a restart must return to that round's startup file.
// A missing or unreadable autosave, an empty startup document, or an
// identical autosave likewise leaves startupJSON untouched.
func RestoreAutosavedConfig(startupJSON []byte) (cfg []byte, ok bool) {
	// an empty document is "no configuration" and never resumes anything
	if len(bytes.TrimSpace(startupJSON)) == 0 {
		return startupJSON, false
	}

	// only an explicit JSON object can be a startup configuration; a null
	// or any other document never silently swaps in the autosaved version
	var startupDoc any
	if err := json.Unmarshal(startupJSON, &startupDoc); err != nil {
		return startupJSON, false
	}
	if _, isObject := startupDoc.(map[string]any); !isObject {
		return startupJSON, false
	}

	saved, err := os.ReadFile(ConfigAutosavePath)
	if errors.Is(err, fs.ErrNotExist) {
		return startupJSON, false
	}
	if err != nil {
		Log().Warn("unable to read autosaved config; using startup configuration instead",
			zap.String("autosave_file", ConfigAutosavePath),
			zap.Error(err))
		return startupJSON, false
	}
	if configPersistDisabled(startupJSON) {
		return startupJSON, false
	}
	if bytes.Equal(bytes.TrimSpace(saved), bytes.TrimSpace(startupJSON)) {
		return startupJSON, false
	}

	Log().Info("restoring autosaved configuration from last successful load",
		zap.String("autosave_file", ConfigAutosavePath))

	return saved, true
}
