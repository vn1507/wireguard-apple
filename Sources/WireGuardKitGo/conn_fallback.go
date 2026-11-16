/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 Alkira. All Rights Reserved.
 *
 * In-process UDP/TCP fallback transport for wireguard-go.
 *
 * WireGuard is natively UDP-only. When UDP to the server is blocked, this
 * conn.Bind transparently tunnels the very same WG datagrams over a WebSocket
 * (wss/443) carrier to a relay, then back into the normal WG pipeline on the
 * server. The WG crypto and handshake bytes are unchanged — only the carrier
 * differs — so the tunnel interface and peer config stay identical and there is
 * no interface restart on a native<->fallback switch.
 *
 * This device.NewDevice(tun, bind, logger)
 * takes the Bind as a constructor parameter, so no fork of wireguard-go is
 * needed. The default UDP path is delegated to conn.NewStdNetBind(); the TCP
 * path is a single wss connection whose binary frames each carry one WG
 * datagram (WebSocket framing replaces an explicit length prefix).
 *
 * NOTE: this file is duplicated verbatim in the wireguard-apple bridge
 * (Sources/WireGuardKitGo/conn_fallback.go); keep the two byte-identical.
 */

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/websocket"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

// The non-standard UAPI lines the C++ side emits to carry the relay through
// wgTurnOn's settings string: its URL and the token that authenticates us to it.
// wireguard-go's IpcSet rejects unknown keys, so the bridge must strip both
// before IpcSet and hand them to NewFallbackBind.
const (
	relayEndpointKey = "relay_endpoint="
	relayTokenKey    = "relay_token="
)

// SplitRelayEndpoint removes the relay lines from a UAPI settings string and
// returns the last relay URL and token found plus the cleaned settings, safe to
// pass to device.IpcSet. An empty URL means no relay was configured.
func SplitRelayEndpoint(settings string) (relayURL, relayToken, cleaned string) {
	lines := strings.Split(settings, "\n")
	kept := lines[:0]
	for _, line := range lines {
		if strings.HasPrefix(line, relayEndpointKey) {
			relayURL = strings.TrimSpace(line[len(relayEndpointKey):])
			continue
		}
		if strings.HasPrefix(line, relayTokenKey) {
			relayToken = strings.TrimSpace(line[len(relayTokenKey):])
			continue
		}
		kept = append(kept, line)
	}
	return relayURL, relayToken, strings.Join(kept, "\n")
}

// Carrier modes for fallbackBind.mode (accessed atomically).
const (
	carrierUDP   int32 = iota
	carrierTCP         // all traffic over the wss carrier
	carrierProbe       // TCP data-plane stays up while UDP is re-probed in parallel
)

// How long the bind tolerates UDP silence after Open before falling back to
// TCP, and how often it re-probes UDP once on the TCP carrier. UDP is always
// the preferred carrier — TCP is a fallback only (TCP-over-TCP degrades under
// loss), so we keep trying to climb back to UDP.
const (
	// How long inbound silence has to last, while we are sending, before the path we are
	// on is declared not to be carrying us. It is WireGuard's own number: KeepaliveTimeout
	// after receiving our traffic the peer owes us a passive keepalive, and one
	// RekeyTimeout later the device gives up on the session and re-initiates ("Retrying
	// handshake because we stopped hearing back after 15 seconds", device/timers.go). So
	// this is the moment the protocol itself calls the path dead, and switching exactly
	// then puts the initiation WireGuard is about to send on the new carrier.
	//
	// It MUST stay below the host's PathSilenceTimeout (wgtimers.h), the moment the host
	// REPORTS a loss and arms the service's one-minute teardown: the layer that can fix
	// the problem has to act before the layer that can only complain about it. The other
	// way round on 2026-11-13, the host reported Reconnecting at 15 s while the carrier
	// only began looking for a way out at 25 s.
	udpSilenceTimeout = device.KeepaliveTimeout + device.RekeyTimeout
	udpReprobeEvery   = 30 * time.Second
	udpReprobeWindow  = 5 * time.Second
	// The same rule for the relay, which until now had no liveness of its own at all: a
	// wss carrier whose far end goes away without closing the socket - a NAT timeout, a
	// front end pulled out of service, a black-holed path - never errors, because the
	// reader blocks and the writes land in the kernel buffer. Nothing redialled it. That
	// is the hole the 22:09:57-22:10:15 silence of 2026-11-13 fell through.
	relaySilenceTimeout = udpSilenceTimeout

	// One write to the relay socket may not hold the device's sender for longer than
	// this. Without a deadline a stalled connection (a full window, a path that stopped
	// acknowledging) blocks the WireGuard send path for as long as the OS retransmits.
	relayWriteTimeout = device.RekeyTimeout

	// How long an armed probe waits for its initiation to ride before giving up. The
	// probe forces one itself, and the device rate-limits initiations to one per
	// RekeyTimeout (device/send.go), so a slot still empty after that plus one window is
	// a probe nothing is going to ride - and while the mode sits at carrierProbe the
	// periodic re-probe does not run at all.
	probeArmWindow = device.RekeyTimeout + udpReprobeWindow

	// How long the FIRST probe of a relay spell waits. The block that drove us here is
	// usually somebody's network, not ours - a captive hotspot, a conference wifi, a
	// firewall between two offices - and the thing that ends it is just as abrupt: the
	// laptop moves, the rule is lifted, the user reconnects. There is no reason the
	// first look should cost a full udpReprobeEvery, and that one interval was the
	// largest single part of a 51 s recovery measured on 2026-11-12. Later probes keep
	// the longer spacing, because by then the block has proven to be a lasting one.
	udpReprobeFirst = 10 * time.Second

	// Until the first inbound UDP packet of this session, the same verdict is made
	// on a much shorter window: this is the initial "is UDP usable at all" probe,
	// and it has to finish inside the host's connect timeout (wgtimers.h,
	// ConnectHandshakeTimeout = 15s) or the connect fails before the carrier is
	// ever dialed. Handshake initiations go out every RekeyTimeout (5s), so
	// switching at 8s still leaves a try to land over the carrier. Once UDP has
	// answered once, the longer window rules: a live tunnel must not flap.
	udpConnectSilenceTimeout = 8 * time.Second
)

// carrierDialTimeout bounds one wss dial. It matters most to the monitor, which
// dials the relay to find out whether it could carry anything before giving up on
// UDP: an unbounded dial into a blackhole blocks on an unanswered SYN for as long
// as the OS keeps retransmitting it - about 75 s - and the liveness watch blocks
// with it.
const carrierDialTimeout = 10 * time.Second

// carrierRetryInterval is how long a failed carrier waits before the next redial
// attempt — the analog of the ovpn3 core's reconnect interval, which is what
// paces the RECONNECTING events the host counts (OVPNClientImpl::stateEvent).
//
// It is load-bearing twice over. Without it, dialWS is on the per-packet Send
// path, so a down carrier would attempt a full TCP+TLS+WS handshake for every
// outbound WireGuard packet — a dial storm that also serialises Send behind a
// blocking dial, since dialWS holds mu. And because each real attempt is
// reported exactly once, this interval is also what makes the host's retry
// budget (WGClientImpl::m_reconnectCountDown vs m_maxReconnectAttempts) count
// attempts rather than packets.
//
// Anchored to WireGuard's own handshake-retry cadence rather than a copied
// literal: it IS device.RekeyTimeout (5s), the same value the host's shared
// reconnect quantum uses (wg::timers::RetryInterval in wgtimers.h, mirrored by
// kCarrierRetryInterval on Windows and carrierRetryInterval in wg-carrier), so
// the retry budget counts at one rate on every path.
const carrierRetryInterval = device.RekeyTimeout

// carrierLogf, when set by the bridge (wgTurnOn) to the device's Verbosef,
// receives carrier lifecycle diagnostics (dial, UDP<->TCP switch, dial errors).
// nil keeps the carrier silent. Intentionally NOT per-packet — that would spam
// the log with every transport datagram in TCP mode.
var carrierLogf func(string, ...interface{})

func clog(format string, args ...interface{}) {
	if carrierLogf != nil {
		carrierLogf(format, args...)
	}
}

// carrierStateFn, when set by the bridge (wgSetCarrierStateFn), is notified when
// the wss carrier gains or loses reachability. WG is connectionless and has no
// "transport died" event of its own, so on the TCP carrier this is the one place
// that knows: it lets the host surface a mid-session loss the way OpenVPN's
// TRANSPORT_ERROR does. Guarded by carrierStateMu because the bridge clears it
// on tunnel teardown while carrier goroutines may still be firing.
var (
	carrierStateMu sync.Mutex
	carrierStateFn func(up bool)
)

func setCarrierStateFn(fn func(up bool)) {
	carrierStateMu.Lock()
	carrierStateFn = fn
	carrierStateMu.Unlock()
}

// carrierTargetFn, when set by the bridge (wgSetCarrierTargetFn), is told which address
// the carrier is about to dial, before it dials it. The host needs that to keep the
// relay's own packets out of the tunnel: in a full tunnel they have to be pinned to the
// physical gateway, and a pin can only name an address somebody has chosen. The
// exclusions installed at bring-up name the relay as the profile spelled it then, which
// a redial onto another front end, a re-fetched profile and a relay host with several
// addresses all leave behind - and a dial that goes into the tunnel it exists to replace
// cannot come back. Same answer OpenVPN's updateGateway hands the service: what the
// transport picked, reported by the layer that picked it.
var carrierTargetFn func(addr string)

func setCarrierTargetFn(fn func(addr string)) {
	carrierStateMu.Lock()
	carrierTargetFn = fn
	carrierStateMu.Unlock()
}

// notifyCarrierTarget calls that callback with carrierStateMu released - it crosses into
// C++ and must not run under a bind lock. It is called on the dialling path, so the host
// does its route surgery while the dial waits.
func notifyCarrierTarget(addr string) {
	if addr == "" {
		return
	}
	carrierStateMu.Lock()
	fn := carrierTargetFn
	carrierStateMu.Unlock()
	if fn != nil {
		fn(addr)
	}
}

// notifyCarrierState calls the host callback with carrierStateMu released: it
// crosses into C++ and must not run while a bind lock is held.
func notifyCarrierState(up bool) {
	carrierStateMu.Lock()
	fn := carrierStateFn
	carrierStateMu.Unlock()
	if fn != nil {
		fn(up)
	}
}

// fallbackBind implements conn.Bind. It embeds the stock UDP bind and adds one
// wss carrier to a relay. Send() routes per the current mode; Receive() pulls
// from whichever carrier delivered a packet (the UDP fns from the inner bind
// plus one appended fn draining the wss reader).
type fallbackBind struct {
	inner      conn.Bind // conn.NewStdNetBind(): the native UDP path
	relayURL   string    // the relay URL as the server wrote it; empty disables the TCP carrier
	relayToken string    // presented as "Authorization: Bearer"; never logged

	mode int32 // carrierUDP | carrierTCP (atomic)

	// lastUDPRecvNano is the wall-clock time of the most recent inbound UDP
	// packet (atomic). Stale-ness past udpSilenceTimeout triggers fallback.
	lastUDPRecvNano int64

	// lastUDPSendNano is the wall-clock time of the most recent outbound UDP
	// packet (atomic). The monitor only counts inbound silence as a dead path
	// when we have actually sent over UDP since the last inbound packet
	// (lastUDPSendNano > lastUDPRecvNano), mirroring the C++ watchdog's
	// txAdvanced gate: an idle tunnel with no traffic and no PersistentKeepalive
	// legitimately goes quiet and must not flap onto the TCP carrier.
	lastUDPSendNano int64

	// lastUDPProvenNano is lastUDPRecvNano without the inbound packets that say
	// nothing about OUR direction (atomic). Today that is the handshake initiation:
	// a peer initiates only while it has NOT heard from us, and repeats every
	// RekeyTimeout for as long as that lasts, so counting one as liveness keeps the
	// silence rule below fresh exactly when the path is dead outbound. Measured on
	// 2026-11-10: with our egress to :51820 firewalled off and the server re-initiating
	// every 5 s, the switch to the relay took 4 min 7 s instead of the intended 26 s.
	//
	// Separate from lastUDPRecvNano rather than replacing it, because the two answer
	// different questions and both answers are right: "is the UDP path carrying this
	// session" (here) and "has the peer come back onto UDP at all" (there, which is
	// what the re-probe reads - see the carrierTCP branch of monitor).
	lastUDPProvenNano int64

	// lastProbeSendNano is when the current probe last put a packet on UDP, 0 if it has
	// not managed to yet (atomic). The probe is only as good as the packet it rides, and
	// it has no packets of its own: it duplicates whatever WireGuard happens to send. So
	// this, not a wall-clock window, is what the probe is measured against - it is the
	// moment a reply became possible at all.
	//
	// Distinct from lastUDPSendNano because that one deliberately skips keepalives (see
	// noteUDPSend): nothing answers a keepalive, so it cannot arm the silence detector.
	// For a probe a keepalive is enough, and on an idle tunnel it is all there is - the
	// server authenticates it, adopts the source it arrived from (device/receive.go:
	// SetEndpointFromPacket) and its own next packet comes back over UDP. That is the
	// round trip the probe is waiting for, and it is why an idle tunnel can prove UDP
	// at all.
	lastProbeSendNano int64

	// probeHandshake asks the device to send a handshake initiation to the peer. That is
	// the packet - and the only packet - a probe is worth riding: the server answers an
	// initiation at once, so the answer lands inside the probe's window, where a
	// keepalive is answered by nothing at all and leaves the verdict to the peer's own
	// next packet up to a keepalive interval away. nil when the host did not wire it up,
	// and the probe then waits for an initiation the device sends on its own.
	//
	// It has to come from the device: the packet must be a REAL one, built with the keys.
	// Plain field, no lock - set once, between device.NewDevice() and dev.Up(), so it is
	// in place before Open() starts the monitor that reads it.
	probeHandshake func()

	// lastTCPRecvNano / lastTCPSendNano are the relay's own liveness clocks (atomic),
	// the mirror of the two UDP ones above and read the same way: only a carrier we are
	// actively sending real packets on may be declared dead, which is what keeps an idle
	// tunnel from being flapped. The send stamp skips keepalives for the reason
	// noteUDPSend gives. Until these existed the relay had no liveness at all.
	lastTCPRecvNano int64
	lastTCPSendNano int64

	// probeArmedNano is when the current probe was armed (atomic), which is what bounds
	// the wait for something to ride it: while the mode sits at carrierProbe the periodic
	// re-probe does not run, so a probe nobody rides used to be able to stop the climb
	// back to UDP for the rest of the session.
	probeArmedNano int64

	// lastPushNano / lastPushState pace the liveness push to the host (atomic): what was
	// last said, and when. A change is always worth saying at once; a repetition waits
	// out one RekeyTimeout, because the push crosses into C++ and real data would
	// otherwise push on every packet.
	lastPushNano  int64
	lastPushState int32

	// everRecvUDP is 1 once any inbound UDP packet has arrived this session
	// (atomic). Until then the tunnel has never been up over UDP, which is what
	// tells the initial probe apart from a mid-session drop.
	everRecvUDP int32

	// everOpened is set by the first Open and never cleared, which is what tells a
	// brand-new session from a re-open of this one. wireguard-go calls Open again on
	// every BindUpdate - a socket bump, and a resume from sleep - and what it must NOT
	// do then is forget what this session already learned about the path. Guarded by mu.
	everOpened bool

	// carrierUp is 1 while the wss carrier last dialed successfully, 0 once a dial
	// failed (atomic). The up edge gates reporting so recovery is reported once,
	// not per surviving packet.
	carrierUp int32

	// lastDialFail is when the most recent dial attempt failed, and lastDialErr
	// what it failed with. Together they pace retries to one per
	// carrierRetryInterval: until it elapses, dialWS hands back lastDialErr
	// without touching the network. Guarded by mu (written and read only inside
	// dialWS), unlike the atomics above.
	lastDialFail time.Time
	lastDialErr  error

	// canonEP is the peer endpoint parsed from the WG config. TCP-delivered
	// packets are reported as coming from it so WG's roaming logic does not
	// re-home the peer onto the (meaningless) relay socket address.
	canonEP atomic.Value // conn.Endpoint

	// canonEPText is that same endpoint as the WG config spelled it. The relay is
	// told where to forward with it (X-Alkira-Target), and it must match the
	// manager-signed "tgt" claim in the token character for character - which is
	// why it is the config's own text and not a re-rendered address.
	canonEPText atomic.Value // string

	mu      sync.Mutex
	ws      *websocket.Conn
	recvCh  chan []byte
	closeCh chan struct{}
	closed  bool
}

// NewFallbackBind returns a conn.Bind that tunnels WG over UDP, falling back to
// a wss carrier at relayURL when UDP is blocked. An empty relayURL yields the
// stock UDP-only behavior (no carrier ever created).
func NewFallbackBind(relayURL, relayToken string) conn.Bind {
	return &fallbackBind{
		inner:      conn.NewStdNetBind(),
		relayURL:   relayURL,
		relayToken: relayToken,
	}
}

// SetProbeHandshake hands the bind the way to make the device initiate a handshake.
// Called once after the device is built and before it is brought up - see probeHandshake.
func (b *fallbackBind) SetProbeHandshake(initiate func()) {
	b.probeHandshake = initiate
}

// ArmProbe arms a probe that only a handshake initiation may ride, if the bind is on
// the relay at all. The host calls it (wgArmUDPProbe) at the moment its own watchdog
// gives up on the relay and reports Reconnecting: a carrier that has stopped answering
// has nothing left to lose, WireGuard is already sending a fresh initiation every
// RekeyTimeout, and this costs one packet to put the next one on UDP instead - where,
// if UDP is open, the answer comes back inside the probe's own window.
//
// A no-op anywhere else: on UDP there is nothing to probe, and if a probe is already
// under way the CAS simply fails and leaves it alone.
// ArmProbe starts a probe of the direct path, if the bind is on the relay at all: the
// next handshake initiation goes out over UDP instead of the relay, and whether its
// answer arrives there is the whole verdict. The host calls it (wgArmUDPProbe) when its
// own watchdog gives up on the relay - a carrier that has stopped answering has nothing
// left to lose, and the direct path is then the most worth re-testing.
//
// A no-op anywhere else: on UDP there is nothing to probe, and a probe already under way
// is left alone (the CAS fails). Throttled, because the host reports a silent relay once
// per RetryInterval and the device initiates on the same cadence - arming on every report
// would hand every initiation to UDP and leave the relay, which may be the one path that
// still works, nothing to recover with.
func (b *fallbackBind) ArmProbe() {
	if time.Since(time.Unix(0, atomic.LoadInt64(&b.probeArmedNano))) < udpReprobeFirst {
		return
	}
	if !atomic.CompareAndSwapInt32(&b.mode, carrierTCP, carrierProbe) {
		return
	}
	atomic.StoreInt64(&b.lastProbeSendNano, 0)
	atomic.StoreInt64(&b.probeArmedNano, time.Now().UnixNano())
	clog("CARRIER probing UDP with the next handshake (the relay has gone quiet)")
	if initiate := b.probeHandshake; initiate != nil {
		go initiate()
	}
}

// Mode returns the carrier the bind is currently sending on (carrierUDP,
// carrierTCP, or carrierProbe), read atomically. The host app queries it through
// the bridge (wgGetCarrierMode) to report the live transport — e.g. the relay's
// TCP port instead of the bypassed UDP endpoint while on the wss carrier.
func (b *fallbackBind) Mode() int32 {
	return atomic.LoadInt32(&b.mode)
}

// Open delegates to the inner UDP bind, wraps its receive fns to track UDP
// liveness, and appends one fn that drains wss frames. A monitor goroutine
// drives the UDP<->TCP switch.
func (b *fallbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	innerFns, actualPort, err := b.inner.Open(port)
	if err != nil {
		return nil, 0, err
	}

	b.mu.Lock()
	b.closed = false
	b.recvCh = make(chan []byte, 128)
	b.closeCh = make(chan struct{})
	// Clear any pacing left by a previous session so this one's first dial is
	// attempted immediately rather than replaying a stale failure.
	b.lastDialFail = time.Time{}
	b.lastDialErr = nil
	firstOpen := !b.everOpened
	b.everOpened = true
	b.mu.Unlock()
	if firstOpen {
		// Only a new session starts out on UDP knowing nothing. A re-open keeps both:
		// wireguard-go calls Open again on a socket bump and on resume from sleep, and
		// resetting here threw away the one thing this session had established - that UDP
		// is blocked on this network. The carrier went back to UDP, the host published it,
		// and the monitor spent the short initial window rediscovering the block before
		// switching back to TCP: a visible transport flip and several dead seconds after
		// every wake. Climbing back to UDP is the re-probe's job (udpReprobeEvery), which
		// does it without diverting traffic onto a path that may not carry it.
		atomic.StoreInt32(&b.mode, carrierUDP)
		atomic.StoreInt32(&b.everRecvUDP, 0)
		// Seed send strictly before recv so a fresh session never trips the monitor
		// until we have actually sent something over UDP this session.
		now := time.Now().UnixNano()
		atomic.StoreInt64(&b.lastUDPRecvNano, now)
		atomic.StoreInt64(&b.lastUDPProvenNano, now)
		atomic.StoreInt64(&b.lastUDPSendNano, 0)
	}
	// The liveness clocks deliberately survive a re-open, for the same reason the
	// mode does. A fresh recv stamp is indistinguishable from an arrived packet, and
	// both branches of the monitor read it as one: carrierProbe takes
	// lastUDPRecvNano > probeSince as "UDP recovered" and switches the whole tunnel
	// back onto a path nothing has come from, while carrierUDP restarts the silence
	// countdown from zero. Open() runs on every BindUpdate - the C++ watchdog bumps
	// the socket at PathSilenceTimeout, and again on every wake - so stamping here
	// published UDP one second after a wake with UDP firewalled off, and postponed
	// the real verdict by a full udpSilenceTimeout per kick.
	// Start "up" so the first failed dial registers as a genuine down edge.
	atomic.StoreInt32(&b.carrierUp, 1)

	fns := make([]conn.ReceiveFunc, 0, len(innerFns)+1)
	for _, fn := range innerFns {
		inner := fn
		fns = append(fns, func(buf []byte) (int, conn.Endpoint, error) {
			n, ep, ferr := inner(buf)
			if ferr == nil {
				b.noteUDPRecv(buf[:n])
			}
			return n, ep, ferr
		})
	}

	if b.relayURL != "" {
		fns = append(fns, b.receiveTCP)
		go b.monitor()
	}

	return fns, actualPort, nil
}

// receiveTCP blocks until a wss frame arrives, the bind closes, or the carrier
// drops. Delivered packets are attributed to the canonical peer endpoint.
func (b *fallbackBind) receiveTCP(buf []byte) (int, conn.Endpoint, error) {
	b.mu.Lock()
	recvCh, closeCh := b.recvCh, b.closeCh
	b.mu.Unlock()
	if recvCh == nil {
		return 0, nil, net.ErrClosed
	}

	select {
	case frame, ok := <-recvCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(buf, frame)
		// What the relay just delivered says two things, and both have a reader: the
		// relay is carrying inbound traffic (its own liveness clock, read by the monitor)
		// and, if the packet answers one of ours, the session is alive in our direction -
		// which is the liveness report the host used to get by matching log lines.
		if shape := wgShape(frame); shape != shapeUnknown {
			atomic.StoreInt64(&b.lastTCPRecvNano, time.Now().UnixNano())
			b.noteLiveness(shape)
		}
		ep, _ := b.canonEP.Load().(conn.Endpoint)
		if ep == nil {
			// No endpoint parsed yet; drop rather than hand WG a nil ep.
			return 0, nil, net.ErrClosed
		}
		return n, ep, nil
	case <-closeCh:
		return 0, nil, net.ErrClosed
	}
}

// WireGuard datagram shapes, as far as they can be told apart without the keys: the
// type word and the length are the whole of it. Everything in this file that reasons
// about a packet - what a probe may ride, what counts as liveness, what re-homes the
// peer onto the carrier it arrived on - reasons about one of these.
const (
	shapeUnknown    int32 = iota // not a WireGuard datagram at all
	shapeInitiation              // a handshake initiation: the peer has not heard from us
	shapeKeepalive               // an empty transport packet: nothing ever answers one
	shapeExchange                // a response, a cookie reply, or real data
)

// wgShape classifies one datagram by type and length. It is deliberately strict: a read
// off the UDP socket is not necessarily a WireGuard packet at all - inner() reports any
// datagram the kernel had, and the device drops a good share of them without a word -
// and on 2026-11-10 one such silent arrival was taken for liveness and moved the whole
// tunnel onto a path where not a single handshake of ours was being answered.
func wgShape(pkt []byte) int32 {
	const (
		messageInitiation  = 1
		messageResponse    = 2
		messageCookieReply = 3
		messageTransport   = 4

		sizeInitiation   = 148
		sizeResponse     = 92
		sizeCookieReply  = 64
		sizeMinTransport = 32
	)

	if len(pkt) < sizeMinTransport {
		return shapeUnknown
	}
	switch pkt[0] {
	case messageInitiation:
		if len(pkt) == sizeInitiation {
			return shapeInitiation
		}
	case messageResponse:
		if len(pkt) == sizeResponse {
			return shapeExchange
		}
	case messageCookieReply:
		if len(pkt) == sizeCookieReply {
			return shapeExchange
		}
	case messageTransport:
		// A keepalive is exactly the minimum - a 16-byte transport header plus a
		// 16-byte Poly1305 tag and no payload; the smallest real data packet is 48.
		if len(pkt) == sizeMinTransport {
			return shapeKeepalive
		}
		return shapeExchange
	}
	return shapeUnknown
}

// noteUDPSend records an outbound UDP packet for the liveness monitor, but only
// for packets that warrant a reply. WireGuard keepalives are one-way (the peer
// never answers them), so counting our own keepalive as "we are using the path"
// would let an otherwise idle tunnel — whose sole egress is its keepalives —
// falsely trip the UDP->TCP switch. This makes the client robust whether or not
// the server is configured to send keepalives back: handshakes and real data
// still arm the detector, so a genuinely blocked path (we keep sending, nothing
// comes back) is still caught.
func (b *fallbackBind) noteUDPSend(buf []byte) {
	if wgShape(buf) == shapeKeepalive {
		return
	}
	atomic.StoreInt64(&b.lastUDPSendNano, time.Now().UnixNano())
}

// noteUDPRecv stamps the inbound clocks for the liveness monitor. Both of them, because
// an arriving UDP packet answers two different questions and the honest answers differ.
//
// "Has the peer come back onto UDP at all" - lastUDPRecvNano, any packet. While the
// session rides the relay the server sends to the endpoint it last heard from, so UDP
// traffic arriving at all means it has adopted our UDP source again (device/receive.go:
// SetEndpointFromPacket), and it only does that on receiving a packet of ours. Any
// inbound packet is therefore a completed round trip in that state - initiation included.
//
// "Is UDP carrying this session" - lastUDPProvenNano, which skips the handshake
// initiation. On an established path an initiation is evidence AGAINST us: the peer
// starts over only while it has not heard from us, and keeps doing so every RekeyTimeout.
func (b *fallbackBind) noteUDPRecv(pkt []byte) {
	shape := wgShape(pkt)
	b.noteLiveness(shape)
	switch shape {
	case shapeUnknown:
		// Not a WireGuard datagram, so not evidence of anything. The switch back to UDP
		// is a real decision made on these stamps, and on 2026-11-10 one arrival that
		// never reached the device moved the whole tunnel onto a dead path.
		return
	case shapeInitiation:
		// Shaped right, so the peer is there and reachable TOWARDS us - but it is not
		// evidence that we are reachable: the peer starts over only while it has NOT
		// heard from us, and repeats every RekeyTimeout for as long as that lasts.
		atomic.StoreInt64(&b.lastUDPRecvNano, time.Now().UnixNano())
		atomic.StoreInt32(&b.everRecvUDP, 1)
		return
	}

	// A response, a cookie reply or transport data: all three were sent BY the peer TO
	// us, which is what both clocks are about.
	now := time.Now().UnixNano()
	atomic.StoreInt64(&b.lastUDPRecvNano, now)
	atomic.StoreInt32(&b.everRecvUDP, 1)
	atomic.StoreInt64(&b.lastUDPProvenNano, now)
}

// noteLiveness tells the host what an inbound packet says about the SESSION, whichever
// carrier it arrived on. This is where that report belongs: the packet is here, with its
// type and length, and the alternative - matching the device's own log lines in
// classifyHandshake - was both a guess at a wording and a race the comments there had to
// document, since the line for a handshake response is written BEFORE the stamp the host
// then checks.
//
//   - a response, a cookie reply or transport data answers something of ours, so our own
//     direction works: handshakeProven, the report that lifts the host out of
//     Reconnecting on its own.
//   - an initiation or a keepalive proves only that the peer is there. An initiation is
//     evidence AGAINST us (the peer repeats it precisely while it has not heard from us),
//     and a keepalive may be a persistent one, which owes nothing to a packet of ours.
//     Both go up as handshakeHint, and what to do with them stays the host's call.
func (b *fallbackBind) noteLiveness(shape int32) {
	state := handshakeHint
	switch shape {
	case shapeUnknown:
		return
	case shapeExchange:
		state = handshakeProven
	}

	now := time.Now().UnixNano()
	if state == atomic.LoadInt32(&b.lastPushState) &&
		now-atomic.LoadInt64(&b.lastPushNano) < int64(device.RekeyTimeout) {
		return // the same thing we said a moment ago; the host has it
	}
	atomic.StoreInt32(&b.lastPushState, state)
	atomic.StoreInt64(&b.lastPushNano, now)
	if state == handshakeProven {
		// A round trip landed, so the next send failure is news again.
		resetSendFailurePacing()
	}
	notifyHandshakeState(state)
}

// Send routes the packet over the carrier selected by the current mode.
func (b *fallbackBind) Send(buf []byte, ep conn.Endpoint) error {
	switch atomic.LoadInt32(&b.mode) {
	case carrierTCP:
		return b.sendTCP(buf)
	case carrierProbe:
		// The probe is ONE packet, it goes over UDP ALONE, and it is a handshake
		// initiation or nothing.
		//
		// Alone, because the server sees two copies of one packet and drops the second by
		// the replay filter BEFORE the endpoint is adopted (device/receive.go:
		// ValidateCounter at 415, SetEndpointFromPacket at 419), so whichever copy arrives
		// second might as well not have been sent - and when that is the UDP one, a warm
		// relay against a cold direct path, the server never learns we are reachable on
		// UDP. Measured on 2026-11-10: five probes in a row reported no answer over a path
		// that was open the whole time.
		//
		// An initiation, because it is the only packet the server answers by itself, and a
		// probe is worth exactly as much as its answer. Riding a keepalive instead left the
		// verdict to the peer's own next packet - a keepalive interval away, and only if
		// our own relay traffic had not moved the peer's endpoint back meanwhile - and the
		// rules that had to be invented for that are gone with it.
		//
		// The CAS is what makes it one: the stamp is zeroed when the probe arms, so the
		// first initiation after that takes the slot and everything else goes to the relay.
		if wgShape(buf) != shapeInitiation {
			return b.sendTCP(buf)
		}
		if atomic.CompareAndSwapInt64(&b.lastProbeSendNano, 0, time.Now().UnixNano()) {
			b.noteUDPSend(buf)
			if err := b.inner.Send(buf, ep); err != nil {
				// Deliberately not returned: this packet is the probe, and a probe that
				// could not leave is just a failed probe - the window expires and we stay
				// on the relay. Handing the error up would turn it into wireguard-go's
				// "Failed to send", which is a liveness verdict about a session that is
				// perfectly healthy on the relay.
				clog("CARRIER probe could not leave on UDP: %v", err)
			}
			return nil
		}
		return b.sendTCP(buf)
	default: // carrierUDP
		b.noteUDPSend(buf)
		err := b.inner.Send(buf, ep)
		if err != nil && sendFailureReportDue() {
			// The datagram never reached the wire: the interface it would have left by is
			// gone (WiFi off reads as "can't assign requested address"). Reported from
			// here, where the error is, instead of being read back out of the device's log
			// line about it. Paced, because a peer with traffic to send produces dozens a
			// second and every report spends a unit of the host's retry budget.
			clog("CARRIER udp send failed: %v", err)
			notifyHandshakeState(handshakeDown)
		}
		return err
	}
}

// sendTCP lazily (re)establishes the wss carrier and writes one binary frame.
func (b *fallbackBind) sendTCP(buf []byte) error {
	ws, err := b.ensureWS()
	if err != nil {
		clog("CARRIER sendTCP ensureWS err: %v", err)
		return err
	}
	// A write that cannot complete must not hold the device's sender - see
	// relayWriteTimeout. A deadline error is not fatal to the write, so it is logged and
	// the send goes ahead: a connection that cannot take a deadline can still carry.
	if derr := ws.SetWriteDeadline(time.Now().Add(relayWriteTimeout)); derr != nil {
		clog("CARRIER sendTCP deadline err: %v", derr)
	}
	if err := websocket.Message.Send(ws, buf); err != nil {
		clog("CARRIER sendTCP write err: %v", err)
		// This connection is finished either way - a timed-out write leaves it poisoned -
		// so drop it here instead of waiting for the reader to notice, and let the next
		// packet dial a fresh one (paced by carrierRetryInterval).
		b.dropWS()
		return err
	}
	// Same keepalive exception noteUDPSend makes, for the same reason: nothing answers a
	// keepalive, so our own cannot be what declares the relay dead.
	if wgShape(buf) != shapeKeepalive {
		atomic.StoreInt64(&b.lastTCPSendNano, time.Now().UnixNano())
	}
	return nil
}

// dropWS closes the current wss connection and forgets it, so the next packet dials a
// fresh one. Closing is also what unblocks readLoop, which is otherwise parked in a read
// that a half-open connection will never complete.
func (b *fallbackBind) dropWS() {
	b.mu.Lock()
	ws := b.ws
	b.ws = nil
	b.mu.Unlock()
	if ws != nil {
		ws.Close()
	}
}

// parseRelay turns the configured relay into what the WebSocket dialer needs: the
// URL to dial and the same-origin http(s) Origin the handshake requires.
//
// The URL is the server's, dialed as written - its host, port and path are the
// relay's own business, and so is the destination it forwards to (the relay reads
// that from the token). The only thing rewritten is the scheme, because a
// WebSocket dial is spelled ws/wss where the profile says http/https; it is the
// same wire protocol either way.
func parseRelay(relayURL string) (dialURL, origin string, err error) {
	u, perr := url.Parse(relayURL)
	if perr != nil {
		return "", "", perr
	}
	if u.Host == "" {
		return "", "", fmt.Errorf("relay without a host: %q", relayURL)
	}

	scheme := "https"
	switch u.Scheme {
	case "ws", "http":
		u.Scheme, scheme = "ws", "http"
	default:
		u.Scheme = "wss"
	}
	origin = scheme + "://" + u.Host
	return u.String(), origin, nil
}

// ensureWS returns the live wss connection, dialing (and starting the reader
// goroutine) on first use or after a drop. Caller-agnostic to mode. The Send
// path is the natural place the carrier re-dials, so no separate retry loop is
// needed; dialWS paces the attempts and each real one is reported to the host as
// exactly one retry.
func (b *fallbackBind) ensureWS() (*websocket.Conn, error) {
	ws, attempted, err := b.dialWS()
	// A closed bind is teardown, not a transport failure: stay quiet so stop()
	// never looks like a mid-session drop to the host.
	if err != nil && errors.Is(err, net.ErrClosed) {
		return nil, err
	}
	// Reported here, outside dialWS's b.mu: the host callback crosses into C++
	// and must never run under a bind lock. Only real attempts are reported —
	// suppressed ones would put the host back to counting packets.
	if attempted {
		b.reportCarrier(err == nil)
	}
	return ws, err
}

// reportCarrier notifies the host of the outcome of one carrier dial attempt.
// Callers must invoke it once per real attempt and never for a suppressed one:
// dialWS already paces attempts to carrierRetryInterval, so no throttle is
// needed here and one "down" is one RECONNECTING for the host to count.
// Recovery (up) is still edge-gated, since a live carrier returns its cached
// conn without dialing and the surviving attempts would otherwise re-report it.
func (b *fallbackBind) reportCarrier(up bool) {
	if up {
		if atomic.SwapInt32(&b.carrierUp, 1) == 0 {
			clog("CARRIER reachability -> up")
			notifyCarrierState(true)
		}
		return
	}

	atomic.StoreInt32(&b.carrierUp, 0)
	clog("CARRIER reachability -> down")
	notifyCarrierState(false)
}

// dialWS returns the cached wss conn, dialling one if needed. Holds b.mu. The
// bool reports whether this call made a real dial attempt: false means the conn
// was already up, the bind is closing, or the attempt was suppressed by
// carrierRetryInterval — none of which the host should count as a retry.
func (b *fallbackBind) dialWS() (*websocket.Conn, bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, false, net.ErrClosed
	}
	if b.ws != nil {
		return b.ws, false, nil
	}

	// Pace the retries: until carrierRetryInterval has elapsed since the last
	// failure, replay that failure instead of dialing. attempted=false keeps the
	// suppressed calls out of the host's retry count, so the budget counts
	// attempts and not packets.
	if b.lastDialErr != nil && time.Since(b.lastDialFail) < carrierRetryInterval {
		return nil, false, b.lastDialErr
	}

	// From here on every exit is a real attempt: record its outcome so the next
	// caller is paced against this one.
	fail := func(err error) (*websocket.Conn, bool, error) {
		b.lastDialFail = time.Now()
		b.lastDialErr = err
		return nil, true, err
	}

	dialURL, origin, err := parseRelay(b.relayURL)
	if err != nil {
		return fail(err)
	}

	cfg, err := websocket.NewConfig(dialURL, origin)
	if err != nil {
		return fail(err)
	}
	cfg.Dialer = &net.Dialer{Timeout: carrierDialTimeout}
	// Where to forward, and the manager's attestation of it. The relay takes the
	// destination from the header and only accepts it when the token's "tgt" claim
	// says the same, so the two always travel together.
	if target, _ := b.canonEPText.Load().(string); target != "" {
		cfg.Header.Set("X-Alkira-Target", target)
	}
	if b.relayToken != "" {
		cfg.Header.Set("Authorization", "Bearer "+b.relayToken)
	}

	// Resolve here rather than leaving it to the dialer, because the host has to be told
	// which address this dial is about to use and the dialer never says. IPv4 only, like
	// the rest of the client. On a relay the manager spells as an address - which is what
	// it does today - this is the address itself and costs nothing.
	if host := cfg.Location.Hostname(); host != "" {
		addr := host
		if net.ParseIP(host) == nil {
			// Bounded by the same budget as the dial itself: a resolver that does not
			// answer must not hold the sender that got here any longer than a dial would.
			ctx, cancel := context.WithTimeout(context.Background(), carrierDialTimeout)
			ips, lerr := net.DefaultResolver.LookupIP(ctx, "ip4", host)
			cancel()
			if lerr != nil || len(ips) == 0 {
				clog("CARRIER dial: cannot resolve %s: %v", host, lerr)
				return fail(fmt.Errorf("resolve relay %q: %w", host, lerr))
			}
			addr = ips[0].String()
			// Dial the address we just named to the host, not the name again - a second
			// lookup could pick another one, and then the pin covers the wrong address.
			// The certificate is still verified against the name.
			port := cfg.Location.Port()
			if port == "" {
				port = "443"
				if cfg.Location.Scheme == "ws" {
					port = "80"
				}
			}
			cfg.Location.Host = net.JoinHostPort(addr, port)
			cfg.TlsConfig = &tls.Config{ServerName: host}
			dialURL = cfg.Location.String()
		}
		// Before the dial, so the host's exclusion is in place when the packets leave.
		notifyCarrierTarget(addr)
	}

	// The token is deliberately absent from the log line: it is a credential.
	target, _ := b.canonEPText.Load().(string)
	clog("CARRIER dialing %s (target %s)", dialURL, target)
	ws, err := websocket.DialConfig(cfg)
	if err != nil {
		clog("CARRIER dial err: %v", err)
		return fail(err)
	}
	clog("CARRIER dial OK")
	b.lastDialErr = nil
	b.ws = ws
	go b.readLoop(ws)
	return ws, true, nil
}

// readLoop drains binary frames from one wss connection into recvCh until the
// connection drops or the bind closes, then clears the cached conn so the next
// send redials.
func (b *fallbackBind) readLoop(ws *websocket.Conn) {
	b.mu.Lock()
	recvCh, closeCh := b.recvCh, b.closeCh
	b.mu.Unlock()

	for {
		var data []byte
		if err := websocket.Message.Receive(ws, &data); err != nil {
			// Mostly the relay hanging up, sometimes our own dropWS. Either way the
			// socket is gone and the next packet redials; unlogged, that redial reads
			// as a dial out of nowhere, which is how a relay-side close spent a whole
			// session invisible.
			clog("CARRIER relay read ended: %v", err)
			break
		}
		if len(data) == 0 {
			continue
		}
		select {
		case recvCh <- data:
		case <-closeCh:
			ws.Close()
			return
		}
	}

	b.mu.Lock()
	if b.ws == ws {
		b.ws = nil
	}
	b.mu.Unlock()
	ws.Close()
}

// monitor drives the carrier switch. It prefers UDP and only falls back when
// UDP has been silent past udpSilenceTimeout, periodically re-probing UDP so a
// recovered network climbs back off the TCP fallback.
func (b *fallbackBind) monitor() {
	b.mu.Lock()
	closeCh := b.closeCh
	b.mu.Unlock()

	const tickEvery = time.Second
	// A gap between ticks far larger than tickEvery means this goroutine was not
	// running — system sleep/suspend (or a severe scheduling stall). The
	// WireGuardKitGo runtime's boottime patch makes the clock advance across
	// sleep so WG's own protocol timers expire correctly, but it also means the
	// silence we "observe" on the first post-wake tick is time we never actually
	// watched the path, not evidence UDP is dead. Re-baseline the liveness clock
	// on such a tick instead of switching, giving UDP a fresh udpSilenceTimeout
	// to prove itself after wake.
	const wakeResyncGap = 3 * time.Second

	ticker := time.NewTicker(tickEvery)
	defer ticker.Stop()

	var tcpSince time.Time
	// How long THIS relay spell waits before its next probe: short for the first look
	// after the switch, udpReprobeEvery for every one after it. A local, because the
	// schedule belongs to the spell and the spell belongs to this loop.
	nextProbeIn := udpReprobeFirst
	prevTick := time.Now()
	for {
		select {
		case <-closeCh:
			return
		case now := <-ticker.C:
			if now.Sub(prevTick) > wakeResyncGap {
				// Suspended since the last tick: the accumulated silence is not
				// ours to trust. Reset the UDP baseline (send strictly before
				// recv, mirroring Open) and skip this tick's verdict so a real
				// post-wake block is still caught one udpSilenceTimeout later.
				atomic.StoreInt64(&b.lastUDPSendNano, 0)
				atomic.StoreInt64(&b.lastUDPRecvNano, now.UnixNano())
				atomic.StoreInt64(&b.lastUDPProvenNano, now.UnixNano())
				// The probe's own evidence has to go with that baseline, because the
				// recv stamp above is a fiction - nothing arrived, we simply refuse to
				// count time we never watched - and the probe cannot tell that fiction
				// from a real packet: it asks whether a recv landed after its send, and
				// a send from BEFORE the sleep is satisfied by a stamp written after it.
				// That is how a wake with UDP firewalled off announced "udp recovered"
				// one tick later and moved the whole tunnel back onto a path where every
				// send then failed with EADDRNOTAVAIL. Clearing it makes the post-wake
				// probe prove UDP on a packet it sent after the wake, or not at all.
				atomic.StoreInt64(&b.lastProbeSendNano, 0)
				tcpSince = now
				atomic.StoreInt64(&b.lastTCPRecvNano, now.UnixNano())
				atomic.StoreInt64(&b.lastTCPSendNano, 0)
				// A wake is also the one moment the network may have changed entirely
				// underneath us, so look at UDP again on the short interval rather than
				// carrying on with whatever this relay spell had got to.
				nextProbeIn = udpReprobeFirst
				prevTick = now
				continue
			}
			prevTick = now

			switch atomic.LoadInt32(&b.mode) {
			case carrierUDP:
				// The PROVEN clock here, not the plain recv one: on a path we are already
				// using,
				// inbound that cannot have been caused by us is not a sign of life. See
				// noteUDPRecv and lastUDPProvenNano.
				lastUDP := time.Unix(0, atomic.LoadInt64(&b.lastUDPProvenNano))
				lastSend := time.Unix(0, atomic.LoadInt64(&b.lastUDPSendNano))
				// Only a path we are actively using can be declared dead: require
				// an outbound UDP packet since the last inbound one (lastSend >
				// lastUDP). This mirrors the C++ watchdog's txAdvanced gate — an
				// idle tunnel sends nothing, so it never trips this even past
				// udpSilenceTimeout, while a real block (we keep sending handshake
				// initiations, nothing comes back) does.
				silence := udpSilenceTimeout
				if atomic.LoadInt32(&b.everRecvUDP) == 0 {
					silence = udpConnectSilenceTimeout
				}
				if lastSend.After(lastUDP) && now.Sub(lastUDP) > silence {
					// Silence says UDP is not carrying us. It does not say the relay
					// would, so prove that before giving up the path we have. With no
					// network at all - WiFi switched off - every UDP send fails with
					// EADDRNOTAVAIL and the silence accumulates exactly as it does under
					// a filtered path; switching on it published TCP, dialled into the
					// void for as long as the outage lasted, and then brought the session
					// back up on the relay instead of the direct path that had just
					// become available again. A dial is also the only honest test, since
					// it covers a relay that is down, unreachable or refusing the token
					// and not merely a missing route.
					ws, attempted, derr := b.dialWS()
					// Dialling is time we knowingly spent not watching the path, not a
					// suspend: leaving it to look like one would re-baseline the UDP
					// clock below and erase the very verdict we are acting on.
					prevTick = time.Now()
					if derr != nil || ws == nil {
						if attempted {
							clog("CARRIER keeping UDP (udp silent %v, relay unreachable: %v)",
								now.Sub(lastUDP).Truncate(time.Millisecond), derr)
						}
						continue
					}
					// The dial can take seconds, and UDP may have answered during them -
					// then there is nothing left to fall back from.
					if time.Unix(0, atomic.LoadInt64(&b.lastUDPProvenNano)).After(lastUDP) {
						clog("CARRIER keeping UDP (recovered while dialling the relay)")
						continue
					}
					atomic.StoreInt32(&b.mode, carrierTCP)
					// No probe has ridden anything yet, and the branches below read this
					// stamp as exactly that. Left standing, a send from before the switch
					// would pair up with the server's next stragglers - it keeps our UDP
					// endpoint until our first relay packet makes it migrate - and bounce
					// the tunnel straight back onto the path we just left. Same "send
					// strictly before recv" ordering Open uses, for the same reason.
					atomic.StoreInt64(&b.lastProbeSendNano, 0)
					atomic.StoreInt64(&b.lastUDPSendNano, 0)
					tcpSince = now
					nextProbeIn = udpReprobeFirst
					// The spell starts with a clean slate on the relay side as well:
					// lastTCPRecvNano is what tells a silent peer from a blocked UDP
					// path, and a stamp left over from the last spell would answer for
					// this one.
					atomic.StoreInt64(&b.lastTCPRecvNano, now.UnixNano())
					atomic.StoreInt64(&b.lastTCPSendNano, 0)
					clog("CARRIER switch UDP->TCP (udp silent %v)", now.Sub(lastUDP).Truncate(time.Millisecond))
					// The dial above was a real attempt and it succeeded: record it so
					// carrierUp stays honest and a later drop still reports one down edge.
					b.reportCarrier(true)
					// The host reads the live mode (wgGetCarrierMode) to report which
					// port the tunnel is on, and it only distinguishes UDP (0) from the
					// relay (carrierTCP/carrierProbe, both > 0). So notify exactly on
					// the transitions that cross that boundary - this one and the
					// recovery below - and stay quiet for the TCP<->Probe churn, which
					// changes nothing the host can see. The carrier is up either way:
					// "up" here means "the transport changed, re-read it", and the host
					// treats a repeated up on a live connection as exactly that.
					// reportCarrier() also fires on the very first wss dial; a duplicate
					// is harmless, and this is the only notification a later switch
					// gets, since a cached conn makes no dial attempt at all.
					notifyCarrierState(true)
				}
			case carrierTCP:
				// The relay's own liveness, which it never had before: the mirror of the
				// UDP rule above, gated the same way. Only a carrier we are actively
				// sending real packets on may be called dead, so an idle tunnel is never
				// touched - and dropping the connection is the whole remedy, because the
				// next packet dials a fresh one, possibly onto another front end. A wss
				// whose far end goes away without closing the socket errors nowhere: the
				// reader blocks, the writes land in the kernel buffer, and on 2026-11-13
				// eighteen seconds of that silence (22:09:57-22:10:15) produced nothing
				// but the host reporting Reconnecting.
				relayRecv := time.Unix(0, atomic.LoadInt64(&b.lastTCPRecvNano))
				relaySend := time.Unix(0, atomic.LoadInt64(&b.lastTCPSendNano))
				if relaySend.After(relayRecv) && now.Sub(relayRecv) > relaySilenceTimeout {
					clog("CARRIER relay silent %v; dropping the connection and redialling",
						now.Sub(relayRecv).Truncate(time.Millisecond))
					b.dropWS()
					// The clocks belonged to the socket we have just thrown away.
					atomic.StoreInt64(&b.lastTCPRecvNano, now.UnixNano())
					atomic.StoreInt64(&b.lastTCPSendNano, 0)
					// A relay that stopped carrying us is also the moment the direct path
					// is most worth re-testing, so bring the next probe forward.
					tcpSince = now
					nextProbeIn = udpReprobeFirst
					continue
				}
				// Periodically re-probe UDP, non-destructively: arm a probe, which puts
				// exactly ONE packet on UDP (see Send) and leaves the rest of the traffic
				// on the relay, and ask the device for the one packet worth riding it.
				if now.Sub(tcpSince) > nextProbeIn {
					atomic.StoreInt32(&b.mode, carrierProbe)
					atomic.StoreInt64(&b.lastProbeSendNano, 0)
					atomic.StoreInt64(&b.probeArmedNano, now.UnixNano())
					clog("CARRIER probing UDP (%v on the relay)",
						now.Sub(tcpSince).Truncate(time.Second))
					// In a goroutine because it reaches into the device's send path, which
					// comes back into Send() on this same bind; the monitor must not be
					// the one blocked there.
					if initiate := b.probeHandshake; initiate != nil {
						go initiate()
					}
				}
			case carrierProbe:
				// The probe is one handshake initiation on UDP and the answer to it, so
				// there is one thing to wait for and one window to wait in. Until the
				// initiation has left there is nothing to measure at all: the device
				// rate-limits them to one per RekeyTimeout (device/send.go), so the one
				// this probe asked for may be a few seconds out.
				probeSentNano := atomic.LoadInt64(&b.lastProbeSendNano)
				if probeSentNano == 0 {
					// Nothing rode it. This wait used to be unbounded, and while the mode
					// sits at carrierProbe the periodic re-probe above does not run - so a
					// probe nobody rode could stop the climb back to UDP for the rest of
					// the session.
					armed := time.Unix(0, atomic.LoadInt64(&b.probeArmedNano))
					if now.Sub(armed) > probeArmWindow {
						atomic.StoreInt32(&b.mode, carrierTCP)
						tcpSince = now
						nextProbeIn = udpReprobeFirst
						clog("CARRIER nothing rode the probe within %v; back to the relay",
							probeArmWindow)
					}
					break // armed, with nothing to ride yet
				}
				probeSent := time.Unix(0, probeSentNano)
				// The PROVEN clock, not lastUDPRecvNano: what answers an initiation is a
				// handshake response, and that is a packet one-way traffic cannot produce.
				// An inbound initiation on UDP would land on the other clock and prove
				// nothing - the peer may still hold the UDP endpoint it had before the
				// relay and be initiating into a path that carries nothing of ours.
				lastProven := time.Unix(0, atomic.LoadInt64(&b.lastUDPProvenNano))
				switch {
				case lastProven.After(probeSent):
					atomic.StoreInt32(&b.mode, carrierUDP)
					clog("CARRIER switch TCP->UDP (the probe was answered)")
					// Back across the UDP/relay boundary - see the UDP->TCP switch above.
					// Nothing else reports this direction: the recovery is a plain mode
					// store, with no dial and so no reportCarrier().
					notifyCarrierState(true)
				case now.Sub(probeSent) > udpReprobeWindow:
					// One round trip is all this verdict needs, and all of it. The rules
					// that used to hang off this branch - a late arrival still counting, a
					// window the peer sat out in silence, our own relay traffic taking the
					// probe's endpoint adoption back - existed only because the probe rode
					// a keepalive, which nothing answers.
					atomic.StoreInt32(&b.mode, carrierTCP)
					tcpSince = now
					nextProbeIn = udpReprobeEvery
					clog("CARRIER probe unanswered on UDP within %v; staying on the relay",
						udpReprobeWindow)
				}
			}
		}
	}
}

// ParseEndpoint delegates to the inner UDP bind (the WG config Endpoint stays
// the real server IP:port) and caches the result as the canonical endpoint for
// TCP-delivered packets.
func (b *fallbackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ep, err := b.inner.ParseEndpoint(s)
	if err == nil && ep != nil {
		b.canonEP.Store(ep)
		b.canonEPText.Store(s)
	}
	return ep, err
}

// SetMark applies to the UDP path only; the wss carrier rides the OS default.
func (b *fallbackBind) SetMark(mark uint32) error {
	return b.inner.SetMark(mark)
}

// Close tears down the wss carrier and the inner UDP bind.
func (b *fallbackBind) Close() error {
	b.mu.Lock()
	if !b.closed {
		b.closed = true
		if b.closeCh != nil {
			close(b.closeCh)
		}
		if b.ws != nil {
			b.ws.Close()
			b.ws = nil
		}
	}
	b.mu.Unlock()
	return b.inner.Close()
}
