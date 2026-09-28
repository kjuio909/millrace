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

//go:build !unix || solaris

package caddy

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"sync"
)

func listenReusable(ctx context.Context, lnKey string, network, address string, config net.ListenConfig) (any, error) {
	var socketFile *os.File

	fd := slices.Contains([]string{"fd", "fdgram"}, network)
	if fd {
		socketFd, err := strconv.ParseUint(address, 0, strconv.IntSize)
		if err != nil {
			return nil, fmt.Errorf("invalid file descriptor: %v", err)
		}

		func() {
			socketFilesMu.Lock()
			defer socketFilesMu.Unlock()

			socketFdWide := uintptr(socketFd)
			var ok bool

			socketFile, ok = socketFiles[socketFdWide]

			if !ok {
				socketFile = os.NewFile(socketFdWide, lnKey)
				if socketFile != nil {
					socketFiles[socketFdWide] = socketFile
				}
			}
		}()

		if socketFile == nil {
			return nil, fmt.Errorf("invalid socket file descriptor: %d", socketFd)
		}
	}

	datagram := slices.Contains([]string{"udp", "udp4", "udp6", "unixgram", "fdgram"}, network)
	if datagram {
		sharedPc, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
			var (
				pc  net.PacketConn
				err error
			)
			if fd {
				pc, err = net.FilePacketConn(socketFile)
			} else {
				pc, err = config.ListenPacket(ctx, network, address)
			}
			if err != nil {
				return nil, err
			}
			return &sharedPacketConn{PacketConn: pc, key: lnKey}, nil
		})
		if err != nil {
			return nil, err
		}
		return &fakeClosePacketConn{sharedPacketConn: sharedPc.(*sharedPacketConn)}, nil
	}

	sharedLn, _, err := listenerPool.LoadOrNew(lnKey, func() (Destructor, error) {
		var (
			ln  net.Listener
			err error
		)
		if fd {
			ln, err = net.FileListener(socketFile)
		} else {
			ln, err = config.Listen(ctx, network, address)
		}
		if err != nil {
			return nil, err
		}
		return &sharedListener{Listener: ln, key: lnKey}, nil
	})
	if err != nil {
		return nil, err
	}

	return &fakeCloseListener{sharedListener: sharedLn.(*sharedListener), keepAliveConfig: config.KeepAliveConfig}, nil
}

// socketFiles is a fd -> *os.File map used to make a FileListener/FilePacketConn from a file descriptor.
var socketFiles = map[uintptr]*os.File{}

// socketFilesMu synchronizes socketFiles insertions
var socketFilesMu sync.Mutex
