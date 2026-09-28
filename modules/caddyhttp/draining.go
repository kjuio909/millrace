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
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// drainFenceTimeout bounds how long a configuration switch waits for an old
// server to reach the point at which it provably no longer admits new work.
// Closing the listeners (the strongest guarantee) is synchronous inside
// http.Server.Shutdown and is not subject to this timeout; the timeout only
// guards the bookkeeping performed afterwards, so a wedged server cannot make
// POST /load hang forever.
const drainFenceTimeout = 5 * time.Second

// drainController makes the instant an old HTTP server stops admitting new
// connections and requests deterministic across a configuration switch.
//
// http.Server.Shutdown performs the right actions, but Caddy historically
// waited merely for the shutdown goroutine to be scheduled - which could
// happen before Shutdown had set its shutdown flag or closed a single
// listener. This controller turns that into an explicit fence:
//
//   - http.Server.Shutdown sets its shutdown flag and then synchronously
//     closes its listeners, which makes every Serve loop return. The
//     controller waits for those Serve loops to actually finish, so once the
//     fence is reached the old server provably cannot accept another
//     connection; every new connection to the reused socket reaches the new
//     server. The shutdown flag is already set by then too, so an HTTP/1
//     keep-alive connection serves at most the response already in flight -
//     the net/http server checks the flag synchronously before processing any
//     further request, including one already buffered. A connection accepted
//     just before the fence and still doing its TLS handshake or reading its
//     first request reaches the same flag and is refused (the client then
//     transparently reconnects to the new server), never answered with the
//     old configuration.
//   - Shutdown broadcasts HTTP/2 GOAWAY (the standard library registers this
//     on the same shutdown that closes the listeners), after which the client
//     places new streams on a fresh connection to the new server.
//   - responses already in flight keep being served by the old server in the
//     background until they complete or the grace period expires; the fence
//     never waits for or cuts them short.
type drainController struct {
	once sync.Once

	mu sync.Mutex

	// serves is closed once each tracked Serve loop has returned after its
	// listener was shut down; that is the proof that accepting has stopped.
	serves []<-chan struct{}

	// hooksDone is closed from the server OnShutdown hook. Shutdown invokes
	// these hooks (the standard library's HTTP/2 GOAWAY broadcast is one of
	// them) once the listeners are already closed, so reaching it means the
	// graceful shutdown is under way.
	hooksOnce sync.Once
	hooksDone chan struct{}

	shutdownDone   chan struct{}
	shutdownDoneMu sync.Mutex
}

func newDrainController() *drainController {
	return &drainController{
		hooksDone: make(chan struct{}),
	}
}

// trackServe registers a Serve loop and returns a function to call when that
// loop has returned. It lets the fence wait for accepting to stop without
// instrumenting every Accept call.
func (d *drainController) trackServe() func() {
	finished := make(chan struct{})
	d.mu.Lock()
	d.serves = append(d.serves, finished)
	d.mu.Unlock()
	return func() { close(finished) }
}

// onServerShutdown is the http.Server OnShutdown callback. Shutdown invokes
// it after it has synchronously closed every listener. Half-open connections
// (accepted but not yet reading a request) are intentionally not touched
// here: http.Server.Shutdown closes them from its own connection bookkeeping,
// and closing one externally after it raced into an Active state could abort
// a request that had just started. Such connections cannot answer with the
// old config anyway, since the server checks its shutdown flag synchronously
// before dispatching each freshly read request.
func (d *drainController) onServerShutdown() {
	d.hooksOnce.Do(func() { close(d.hooksDone) })
}

// beginDrain starts the graceful shutdown and returns a channel closed when it
// fully completes. It is idempotent. gracePeriod bounds how long responses
// already in flight are allowed to finish in the background; a non-positive
// value waits indefinitely. The context is owned by the drain itself rather
// than the caller, because Stop returns as soon as the admission fence is
// reached while in-flight responses keep draining afterwards.
func (d *drainController) beginDrain(server *http.Server, gracePeriod time.Duration, logger *zap.Logger) <-chan struct{} {
	d.once.Do(func() {
		d.shutdownDoneMu.Lock()
		d.shutdownDone = make(chan struct{})
		d.shutdownDoneMu.Unlock()

		go func() {
			defer close(d.shutdownDone)

			ctx, cancel := context.WithCancel(context.Background())
			if gracePeriod > 0 {
				ctx, cancel = context.WithTimeoutCause(ctx, gracePeriod,
					fmt.Errorf("server graceful shutdown %ds timeout", int(gracePeriod.Seconds())))
			}
			defer cancel()

			if err := server.Shutdown(ctx); err != nil {
				if cause := context.Cause(ctx); cause != nil && err == context.DeadlineExceeded {
					err = cause
				}
				if logger != nil {
					logger.Error("server shutdown", zap.Error(err))
				}
			}
		}()
	})

	d.shutdownDoneMu.Lock()
	done := d.shutdownDone
	d.shutdownDoneMu.Unlock()
	return done
}

// waitFence blocks until the old server provably stopped accepting new
// connections and disabled further keep-alive requests, or the timeout
// elapses. It never waits for responses already in flight.
func (d *drainController) waitFence(logger *zap.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), drainFenceTimeout)
	defer cancel()

	d.mu.Lock()
	serves := append([]<-chan struct{}(nil), d.serves...)
	d.mu.Unlock()

	for _, finished := range serves {
		select {
		case <-finished:
		case <-ctx.Done():
			if logger != nil {
				logger.Error("timed out waiting for old server to stop accepting",
					zap.Duration("timeout", drainFenceTimeout))
			}
			// accepting should stop synchronously once Shutdown closes the
			// listener; proceed rather than stall the whole config switch
			return
		}
	}

	// every Serve loop has returned (listeners provably closed); wait for the
	// OnShutdown hooks (which broadcast HTTP/2 GOAWAY) to run too
	select {
	case <-d.hooksDone:
	case <-ctx.Done():
		if logger != nil {
			logger.Error("timed out waiting for old server shutdown hooks",
				zap.Duration("timeout", drainFenceTimeout))
		}
	}
}
