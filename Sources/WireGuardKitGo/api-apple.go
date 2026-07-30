/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdlib.h>
// #include <stdint.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
// static void callCarrierState(void *func, void *ctx, int32_t up)
// {
// 	((void(*)(void *, int32_t))func)(ctx, up);
// }
// static void callHandshakeState(void *func, void *ctx, int32_t up)
// {
// 	((void(*)(void *, int32_t))func)(ctx, up);
// }
import "C"

import (
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	// The device has no C-facing handshake event, so we tap its own log stream
	// (every Verbosef line, level 0, funnels through here) for the two moments
	// the UDP-only reconnection reaction needs. Done before the loggerFunc guard
	// so it fires even when the host set no logger.
	if l == 0 {
		classifyHandshake(msg)
	}
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(msg))
}

// classifyHandshake turns wireguard-go's own timer log lines into a liveness
// push for the host. The strings are stable for the pinned device version:
//   - "Received handshake response" (receive.go) is exactly timersHandshakeComplete
//     for the initiator — the path is alive again → up.
//   - "giving up" (timers.go, after RekeyAttemptTime) is WG's own verdict that the
//     handshake will not complete — the session is dead → down. It respects the
//     tx gate for free: with no outbound traffic WG never initiates, so it never
//     gives up on an idle tunnel.
//
// TestHandshakeLogStringsPresent guards these against a device bump.
func classifyHandshake(msg string) {
	switch {
	case strings.Contains(msg, "Received handshake response"):
		notifyHandshakeState(true)
	case strings.Contains(msg, "giving up"):
		notifyHandshakeState(false)
	}
}

// handshakeStateFn, when set by the bridge (wgSetHandshakeStateFn), is the host's
// liveness push for the UDP-only case (no carrier). Mirrors carrierStateFn;
// guarded by handshakeStateMu because the bridge clears it on tunnel teardown
// while device timer goroutines may still be logging.
var (
	handshakeStateMu sync.Mutex
	handshakeStateFn func(up bool)
)

func setHandshakeStateFn(fn func(up bool)) {
	handshakeStateMu.Lock()
	handshakeStateFn = fn
	handshakeStateMu.Unlock()
}

// notifyHandshakeState calls the host callback with handshakeStateMu released.
// The callback only queues onto the host's runloop (never blocks), so firing it
// from inside a device timer log call cannot deadlock against a device lock.
func notifyHandshakeState(up bool) {
	handshakeStateMu.Lock()
	fn := handshakeStateFn
	handshakeStateMu.Unlock()
	if fn != nil {
		fn(up)
	}
}

type tunnelHandle struct {
	*device.Device
	*device.Logger
	bind *fallbackBind // the UDP/wss carrier bind, for wgGetCarrierMode
}

var tunnelHandles = make(map[int32]tunnelHandle)

func init() {
	signals := make(chan os.Signal)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

// wgSetCarrierStateFn installs the host callback the wss carrier notifies when
// it loses or regains reachability (up=0/1). WG has no transport-down event of
// its own, so this is what lets the host emit RECONNECTING mid-session. Pass a
// null fn to unregister — the host MUST do so before tearing the tunnel down,
// since carrier goroutines can fire right up until wgTurnOff returns.
//
//export wgSetCarrierStateFn
func wgSetCarrierStateFn(context, fn uintptr) {
	if fn == 0 {
		setCarrierStateFn(nil)
		return
	}
	ctxPtr := unsafe.Pointer(context)
	fnPtr := unsafe.Pointer(fn)
	setCarrierStateFn(func(up bool) {
		var v C.int32_t
		if up {
			v = 1
		}
		C.callCarrierState(fnPtr, ctxPtr, v)
	})
}

//export wgSetHandshakeStateFn
func wgSetHandshakeStateFn(context, fn uintptr) {
	if fn == 0 {
		setHandshakeStateFn(nil)
		return
	}
	ctxPtr := unsafe.Pointer(context)
	fnPtr := unsafe.Pointer(fn)
	setHandshakeStateFn(func(up bool) {
		var v C.int32_t
		if up {
			v = 1
		}
		C.callHandshakeState(fnPtr, ctxPtr, v)
	})
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	logger.Verbosef("Attaching to interface")
	// Carry the optional wss relay URL out-of-band in the settings string and
	// strip it before IpcSet (wireguard-go rejects unknown UAPI keys). An empty
	// URL yields the stock UDP-only bind.
	relayURL, cleaned := SplitRelayEndpoint(C.GoString(settings))
	carrierLogf = logger.Verbosef // route carrier lifecycle diagnostics to the WG log
	bind := NewFallbackBind(relayURL)
	dev := device.NewDevice(tun, bind, logger)

	err = dev.IpcSet(cleaned)
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	dev.Up()
	logger.Verbosef("Device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		unix.Close(dupTunFd)
		return -1
	}
	fb, _ := bind.(*fallbackBind) // always succeeds; kept for wgGetCarrierMode
	tunnelHandles[i] = tunnelHandle{dev, logger, fb}
	return i
}

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	delete(tunnelHandles, tunnelHandle)
	dev.Close()
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return 0
	}
	err := dev.IpcSet(C.GoString(settings))
	if err != nil {
		dev.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	device, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}
	settings, err := device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgGetCarrierMode
func wgGetCarrierMode(tunnelHandle int32) int32 {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok || handle.bind == nil {
		return -1 // no such tunnel / UDP-only build
	}
	return handle.bind.Mode() // 0 UDP, 1 TCP, 2 probe (on TCP data-plane)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := dev.BindUpdate()
			if err == nil {
				dev.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			dev.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		dev.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.DisableSomeRoamingForBrokenMobileSemantics()
}

//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

func main() {}
