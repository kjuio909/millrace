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

package caddyhttp

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestDrainControllerFenceStopsAccepting verifies the core guarantee of the
// configuration-switch fence: after beginDrain + waitFence return, the old
// server provably no longer accepts a connection, independently of goroutine
// scheduling, while the server object stays usable for a second (idempotent)
// drain.
func TestDrainControllerFenceStopsAccepting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	drain := newDrainController()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "ok")
		}),
	}
	srv.RegisterOnShutdown(drain.onServerShutdown)

	serveFinished := drain.trackServe()
	go func() {
		defer serveFinished()
		_ = srv.Serve(ln)
	}()

	// before the drain the server accepts
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial before drain: %v", err)
	}
	conn.Close()

	done := drain.beginDrain(srv, time.Second, nil)
	drain.waitFence(nil)

	// the fence is a deterministic signal: accepting must already have stopped,
	// not merely "be about to stop". The listener must reject a new connection
	// promptly (either refused or accepted-then-closed by shutdown); it must
	// never hand one to the old server.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", ln.Addr().String(), 250*time.Millisecond)
		if derr != nil {
			break // listener is down: expected
		}
		// a connection could theoretically be accepted right at the boundary;
		// the old server must not answer a new request after the fence, so an
		// HTTP exchange must not succeed
		c.SetDeadline(time.Now().Add(500 * time.Millisecond))
		_, werr := c.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
		buf := make([]byte, 16)
		n, _ := io.ReadFull(c, buf)
		c.Close()
		if werr == nil && n == len(buf) {
			t.Fatalf("old server answered a new request after the drain fence: %q", buf)
		}
		break
	}

	// idempotent: a second drain neither blocks forever nor panics
	drain.waitFence(nil)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("background shutdown did not complete once no connections were active")
	}
}

// TestDrainControllerFenceKeepsInFlight verifies that reaching the admission
// fence does not interrupt a response already in flight: the handler stays
// alive after waitFence returns and is allowed to finish within the grace
// period.
func TestDrainControllerFenceKeepsInFlight(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	release := make(chan struct{})
	handlerEntered := make(chan struct{})

	drain := newDrainController()
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(handlerEntered)
			w.WriteHeader(http.StatusOK)
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			// emulate a long streamed response that only finishes when released
			<-release
		}),
	}
	srv.RegisterOnShutdown(drain.onServerShutdown)

	serveFinished := drain.trackServe()
	go func() {
		defer serveFinished()
		_ = srv.Serve(ln)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	buf := make([]byte, 1024)
	if _, err := readSome(conn, buf); err != nil {
		t.Fatalf("read status: %v", err)
	}
	<-handlerEntered

	// fence reached while the response is still in flight
	done := drain.beginDrain(srv, 5*time.Second, nil)
	drain.waitFence(nil)

	// the handler must still be blocked (not cut short by the fence)
	select {
	case <-done:
		t.Fatal("background drain completed while an in-flight response was still open")
	case <-time.After(200 * time.Millisecond):
	}

	// releasing the in-flight response lets the drain finish
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("in-flight drain did not complete after the response ended")
	}
}

func readSome(conn net.Conn, buf []byte) (int, error) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	total := 0
	for total == 0 {
		n, err := conn.Read(buf[total:])
		total += n
		if total > 0 {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
