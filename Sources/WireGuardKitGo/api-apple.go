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
// static void callCarrierTarget(void *func, void *ctx, const char *addr)
// {
// 	((void(*)(void *, const char *))func)(ctx, addr);
// }
import "C"

import (
	"encoding/hex"
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
	// The device has no C-facing handshake event, so we tap its own log stream for
	// the moments the UDP-only reconnection reaction needs. Both levels are read:
	// the handshake timers log at Verbosef (0) while the send failures log at
	// Errorf (1). Done before the loggerFunc guard so it fires even when the host
	// set no logger.
	classifyHandshake(msg)
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(msg))
}

// How often a failed send may be reported to the host. The report itself is made by the
// bind, which holds the error (conn_fallback.go: Send), but the pacing lives here next to
// the other half of the pair: resetSendFailurePacing() is called the moment a round trip
// lands, so the next outage is reported without waiting this out.
//
// Paced because send failures arrive as fast as the peer tries to transmit - dozens a
// second once the interface is gone - and every down report spends one unit of the host's
// retry budget (WGClientImpl::m_reconnectCountDown). Unpaced, that budget is gone in a
// couple of seconds and a brief WiFi drop tears the session down. The quantum is the one
// every other reporter uses (RekeyTimeout; carrierRetryInterval in conn_fallback.go,
// RetryInterval in wgtimers.h), so one report means one retry attempt.
const sendFailureReportInterval = 5 * time.Second

var (
	sendFailureMu     sync.Mutex
	lastSendFailureAt time.Time
)

func sendFailureReportDue() bool {
	sendFailureMu.Lock()
	defer sendFailureMu.Unlock()
	now := time.Now()
	if !lastSendFailureAt.IsZero() && now.Sub(lastSendFailureAt) < sendFailureReportInterval {
		return false
	}
	lastSendFailureAt = now
	return true
}

func resetSendFailurePacing() {
	sendFailureMu.Lock()
	lastSendFailureAt = time.Time{}
	sendFailureMu.Unlock()
}

// classifyHandshake reads the ONE thing the host still needs from the device's own log:
// WG's verdict that the handshake will not complete ("giving up", timers.go, after
// RekeyAttemptTime). That one is a decision of the device's timers, not a packet, so
// there is nothing below this layer to report it.
//
// Everything else the host used to learn by matching log lines - a handshake response, an
// initiation, a keepalive, a send that never left the machine - is now reported by the
// bind, from the packet and the error themselves (conn_fallback.go: noteLiveness, Send).
// Matching strings for those was a guess at a wording that a device bump could change
// silently, and for the response it was also a race: the device writes that line BEFORE
// timersHandshakeComplete() moves the stamp the host then checks.
//
// It respects the tx gate for free: with no outbound traffic WG never initiates, so it
// never gives up on an idle tunnel.
func classifyHandshake(msg string) {
	if strings.Contains(msg, "giving up") {
		notifyHandshakeState(handshakeDown)
	}
}

// handshakeStateFn, when set by the bridge (wgSetHandshakeStateFn), is the host's
// liveness push for the UDP-only case (no carrier). Mirrors carrierStateFn;
// guarded by handshakeStateMu because the bridge clears it on tunnel teardown
// while device timer goroutines may still be logging.
//
// The three values the push carries. They cross into C as the int32 of
// wgSetHandshakeStateFn, and both ends tolerate the other being older: a host that only
// knows up/down reads handshakeHint as a plain "up", and a bridge that only knows up/down
// sends handshakeProven, which is how an "up" used to be treated.
const (
	handshakeDown   int32 = 0 // the session is dead (WG gave up, or a send never left)
	handshakeProven int32 = 1 // a full round trip landed: report it
	handshakeHint   int32 = 2 // something arrived; whether it proves anything is the host's call
	// A send that never left this machine, which is a verdict about the PATH and not
	// about the session: no route, no address, the interface gone. Distinct from
	// handshakeDown because the host does different things with them - down is one failed
	// attempt out of three, this one is the pause - and because only the bind can tell
	// them apart: by the time the error is a log line, the errno is gone. On 2026-11-17 a
	// 314 ms WiFi blip was reported "available" again before the interface had an address;
	// the sends that followed failed with ENETUNREACH, each spent one of three attempts,
	// and 19 s later the session was torn down and the user tunnel demoted over a network
	// that had never actually come back.
	handshakeNoPath int32 = 3
)

var (
	handshakeStateMu sync.Mutex
	handshakeStateFn func(state int32)
)

func setHandshakeStateFn(fn func(state int32)) {
	handshakeStateMu.Lock()
	handshakeStateFn = fn
	handshakeStateMu.Unlock()
}

// notifyHandshakeState calls the host callback with handshakeStateMu released.
// The callback only queues onto the host's runloop (never blocks), so firing it
// from inside a device timer log call cannot deadlock against a device lock.
func notifyHandshakeState(state int32) {
	handshakeStateMu.Lock()
	fn := handshakeStateFn
	handshakeStateMu.Unlock()
	if fn != nil {
		fn(state)
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
	setHandshakeStateFn(func(state int32) {
		C.callHandshakeState(fnPtr, ctxPtr, C.int32_t(state))
	})
}

// wgSetCarrierTargetFn installs the host callback the carrier calls with the address it
// is about to dial, BEFORE it dials it, so the host can keep the relay's own packets out
// of the tunnel (in a full tunnel they have to be pinned to the physical gateway, and the
// pin can only name an address somebody has chosen). The callback runs on the dialling
// goroutine and the dial waits for it. Pass a null fn to unregister - the host MUST do so
// before tearing the tunnel down.
//
//export wgSetCarrierTargetFn
func wgSetCarrierTargetFn(context, fn uintptr) {
	if fn == 0 {
		setCarrierTargetFn(nil)
		return
	}
	ctxPtr := unsafe.Pointer(context)
	fnPtr := unsafe.Pointer(fn)
	setCarrierTargetFn(func(addr string) {
		C.callCarrierTarget(fnPtr, ctxPtr, cstring(addr))
	})
}

// peerKeysFromUAPI pulls the peers' public keys out of the UAPI configuration the host
// hands wgTurnOn, so the bridge can address a peer directly (device.LookupPeer) instead
// of going through the device's own timers. One key per "public_key=" line, hex.
func peerKeysFromUAPI(settings string) []device.NoisePublicKey {
	const prefix = "public_key="
	var keys []device.NoisePublicKey
	for _, line := range strings.Split(settings, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimSpace(line[len(prefix):]))
		if err != nil || len(raw) != device.NoisePublicKeySize {
			continue
		}
		var key device.NoisePublicKey
		copy(key[:], raw)
		keys = append(keys, key)
	}
	return keys
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
	relayURL, relayToken, cleaned := SplitRelayEndpoint(C.GoString(settings))
	carrierLogf = logger.Verbosef // route carrier lifecycle diagnostics to the WG log
	bind := NewFallbackBind(relayURL, relayToken)
	dev := device.NewDevice(tun, bind, logger)

	err = dev.IpcSet(cleaned)
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	// What a UDP probe rides: a handshake initiation, on demand, from the peer itself -
	// the one packet the server answers at once (see fallbackBind.probeHandshake). Set
	// after IpcSet, which is what creates the peers LookupPeer resolves, and before
	// dev.Up(), which opens the bind and starts the monitor that reads it.
	//
	// isRetry is true on purpose: a non-retry initiation resets the device's
	// handshake-attempt counter, and with it WG's own "giving up" verdict - the host's
	// only down report on the UDP-only path.
	if fb, ok := bind.(*fallbackBind); ok {
		keys := peerKeysFromUAPI(cleaned)
		fb.SetProbeHandshake(func() {
			for _, key := range keys {
				if peer := dev.LookupPeer(key); peer != nil {
					if perr := peer.SendHandshakeInitiation(true); perr != nil {
						logger.Verbosef("probe: handshake initiation failed: %v", perr)
					}
				}
			}
		})
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

//export wgArmUDPProbe
func wgArmUDPProbe(tunnelHandle int32) {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok || handle.bind == nil {
		return
	}
	handle.bind.ArmProbe()
}

//export wgKickHandshake
func wgKickHandshake(tunnelHandle int32) {
	handle, ok := tunnelHandles[tunnelHandle]
	if !ok || handle.bind == nil {
		return
	}
	handle.bind.KickHandshake()
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
