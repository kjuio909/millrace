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

//go:build unix && !solaris

package caddy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// freeTCPPort briefly binds a port to discover a free address.
func freeTCPPort(t *testing.T) string {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("discovering free port: %v", err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	return addr
}

// TestSharedListenerOverlapAndRelease verifies that two listeners acquired
// for the same address within a process overlap (graceful reload), that the
// address stays bound while any handle is open, and that it is fully released
// once every handle is closed so a fresh process can take it.
func TestSharedListenerOverlapAndRelease(t *testing.T) {
	addr := freeTCPPort(t)
	na, err := ParseNetworkAddress(addr)
	if err != nil {
		t.Fatalf("parsing address: %v", err)
	}

	ctx := context.Background()
	cfg := net.ListenConfig{}

	h1, err := na.Listen(ctx, 0, cfg)
	if err != nil {
		t.Fatalf("first listen: %v", err)
	}
	l1 := h1.(net.Listener)

	// a raw listener must not be able to grab the address while it is held
	if _, err := net.Listen("tcp", addr); err == nil {
		t.Fatal("raw listener unexpectedly bound address already held by caddy")
	}

	// a second in-process acquisition must overlap the first (reload support)
	h2, err := na.Listen(ctx, 0, cfg)
	if err != nil {
		t.Fatalf("second (overlapping) listen: %v", err)
	}
	l2 := h2.(net.Listener)

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	srv1, srv2 := &http.Server{Handler: handler}, &http.Server{Handler: handler}
	go func() { _ = srv1.Serve(l1) }()
	go func() { _ = srv2.Serve(l2) }()
	time.Sleep(100 * time.Millisecond)

	if err := httpGetRetry(addr); err != nil {
		t.Fatalf("request through shared listeners: %v", err)
	}

	// stop the "old" server and drop its handle; the "new" one must keep serving
	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := srv1.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("stopping old server: %v", err)
	}
	if err := l1.Close(); err != nil {
		t.Fatalf("closing old listener handle: %v", err)
	}
	if _, err := net.Listen("tcp", addr); err == nil {
		t.Fatal("address released while the new config still holds it")
	}
	if err := httpGetRetry(addr); err != nil {
		t.Fatalf("request through remaining listener: %v", err)
	}

	if err := srv2.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("stopping new server: %v", err)
	}
	if err := l2.Close(); err != nil {
		t.Fatalf("closing new listener handle: %v", err)
	}

	// once all references are gone the address must be re-bindable
	var l3 net.Listener
	for retry := 0; retry < 40; retry++ {
		l3, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		if retry == 39 {
			t.Fatalf("address not released after all handles closed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = l3.Close()
}

// TestListenerNoCrossProcessReuse ensures that an address held by caddy cannot
// be bound by a separate process even when that process requests SO_REUSEPORT:
// an overlapping start must surface as a bind failure rather than silently
// splitting traffic. (Before this fix, Unix listeners set SO_REUSEPORT, which
// let a second process bind the same address.)
func TestListenerNoCrossProcessReuse(t *testing.T) {
	if os.Getenv("CADDY_LISTEN_CONFLICT_CHILD") == "1" {
		// child: attempt a SO_REUSEPORT bind to the address the parent holds
		lc := net.ListenConfig{
			Control: func(_, _ string, rc syscall.RawConn) error {
				var serr error
				if err := rc.Control(func(fd uintptr) {
					serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
				}); err != nil {
					return err
				}
				return serr
			},
		}
		ln, err := lc.Listen(context.Background(), "tcp", os.Getenv("CADDY_LISTEN_CONFLICT_ADDR"))
		if err == nil {
			_ = ln.Close()
			os.Exit(0) // unexpected: a second process grabbed the address
		}
		os.Exit(3) // expected: bind conflict
	}

	addr := freeTCPPort(t)
	na, err := ParseNetworkAddress(addr)
	if err != nil {
		t.Fatalf("parsing address: %v", err)
	}
	h, err := na.Listen(context.Background(), 0, net.ListenConfig{})
	if err != nil {
		t.Fatalf("holding listener: %v", err)
	}
	defer func() { _ = h.(net.Listener).Close() }()

	cmd := exec.Command(os.Args[0], "-test.run", "TestListenerNoCrossProcessReuse")
	cmd.Env = append(os.Environ(),
		"CADDY_LISTEN_CONFLICT_CHILD=1",
		"CADDY_LISTEN_CONFLICT_ADDR="+addr,
	)
	err = cmd.Run()
	if err == nil {
		t.Fatal("second process unexpectedly bound an address already held by caddy")
	}
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 3 {
		t.Fatalf("child failed for an unexpected reason (want exit code 3): %v", err)
	}
}

func httpGetRetry(addr string) error {
	var lastErr error
	for i := 0; i < 20; i++ {
		resp, err := http.Get("http://" + addr)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return lastErr
}
