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
	udpSilenceTimeout = 25 * time.Second
	udpReprobeEvery   = 30 * time.Second
	udpReprobeWindow  = 5 * time.Second

	// Until the first inbound UDP packet of this session, the same verdict is made
	// on a much shorter window: this is the initial "is UDP usable at all" probe,
	// and it has to finish inside the host's connect timeout (wgtimers.h,
	// ConnectHandshakeTimeout = 15s) or the connect fails before the carrier is
	// ever dialed. Handshake initiations go out every RekeyTimeout (5s), so
	// switching at 8s still leaves a try to land over the carrier. Once UDP has
	// answered once, the longer window rules: a live tunnel must not flap.
	udpConnectSilenceTimeout = 8 * time.Second
)

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

	// everRecvUDP is 1 once any inbound UDP packet has arrived this session
	// (atomic). Until then the tunnel has never been up over UDP, which is what
	// tells the initial probe apart from a mid-session drop.
	everRecvUDP int32

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
	b.mu.Unlock()
	atomic.StoreInt32(&b.mode, carrierUDP)
	atomic.StoreInt64(&b.lastUDPRecvNano, time.Now().UnixNano())
	// Nothing has come back over UDP in THIS session yet, so the monitor judges the
	// path on the short initial window until something does.
	atomic.StoreInt32(&b.everRecvUDP, 0)
	// Seed send strictly before recv so a fresh session never trips the monitor
	// until we have actually sent something over UDP this session.
	atomic.StoreInt64(&b.lastUDPSendNano, 0)
	// Start "up" so the first failed dial registers as a genuine down edge.
	atomic.StoreInt32(&b.carrierUp, 1)

	fns := make([]conn.ReceiveFunc, 0, len(innerFns)+1)
	for _, fn := range innerFns {
		inner := fn
		fns = append(fns, func(buf []byte) (int, conn.Endpoint, error) {
			n, ep, ferr := inner(buf)
			if ferr == nil {
				atomic.StoreInt64(&b.lastUDPRecvNano, time.Now().UnixNano())
				atomic.StoreInt32(&b.everRecvUDP, 1)
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

// noteUDPSend records an outbound UDP packet for the liveness monitor, but only
// for packets that warrant a reply. WireGuard keepalives are one-way (the peer
// never answers them), so counting our own keepalive as "we are using the path"
// would let an otherwise idle tunnel — whose sole egress is its keepalives —
// falsely trip the UDP->TCP switch. This makes the client robust whether or not
// the server is configured to send keepalives back: handshakes and real data
// still arm the detector, so a genuinely blocked path (we keep sending, nothing
// comes back) is still caught.
func (b *fallbackBind) noteUDPSend(buf []byte) {
	// A keepalive is a transport-data message (type 4, so buf[0]==4 in the
	// little-endian type word) with an empty payload: 16-byte transport header +
	// 16-byte Poly1305 tag = 32 bytes exactly. The smallest real data packet is
	// 48 bytes and handshakes are 148/92/64, so length alone disambiguates.
	const messageTransport = 4
	const keepaliveSize = 32
	if len(buf) == keepaliveSize && buf[0] == messageTransport {
		return
	}
	atomic.StoreInt64(&b.lastUDPSendNano, time.Now().UnixNano())
}

// Send routes the packet over the carrier selected by the current mode.
func (b *fallbackBind) Send(buf []byte, ep conn.Endpoint) error {
	switch atomic.LoadInt32(&b.mode) {
	case carrierTCP:
		return b.sendTCP(buf)
	case carrierProbe:
		// Keep the real data flowing over TCP while speculatively re-probing
		// UDP: a copy also goes out over UDP so that, if UDP has recovered, its
		// replies refresh lastUDPRecvNano and monitor climbs back to the UDP
		// carrier — WITHOUT ever blackholing live traffic into a still-blocked
		// UDP path (which stalls the tunneled TCP for seconds every re-probe).
		b.noteUDPSend(buf)
		_ = b.inner.Send(buf, ep)
		return b.sendTCP(buf)
	default: // carrierUDP
		b.noteUDPSend(buf)
		return b.inner.Send(buf, ep)
	}
}

// sendTCP lazily (re)establishes the wss carrier and writes one binary frame.
func (b *fallbackBind) sendTCP(buf []byte) error {
	ws, err := b.ensureWS()
	if err != nil {
		clog("CARRIER sendTCP ensureWS err: %v", err)
		return err
	}
	if err := websocket.Message.Send(ws, buf); err != nil {
		clog("CARRIER sendTCP write err: %v", err)
		return err
	}
	return nil
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
	// Where to forward, and the manager's attestation of it. The relay takes the
	// destination from the header and only accepts it when the token's "tgt" claim
	// says the same, so the two always travel together.
	if target, _ := b.canonEPText.Load().(string); target != "" {
		cfg.Header.Set("X-Alkira-Target", target)
	}
	if b.relayToken != "" {
		cfg.Header.Set("Authorization", "Bearer "+b.relayToken)
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

	var tcpSince, probeSince time.Time
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
				prevTick = now
				continue
			}
			prevTick = now

			mode := atomic.LoadInt32(&b.mode)

			lastUDP := time.Unix(0, atomic.LoadInt64(&b.lastUDPRecvNano))
			switch mode {
			case carrierUDP:
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
					atomic.StoreInt32(&b.mode, carrierTCP)
					tcpSince = now
					clog("CARRIER switch UDP->TCP (udp silent %v)", now.Sub(lastUDP).Truncate(time.Millisecond))
				}
			case carrierTCP:
				// Periodically re-probe UDP, but non-destructively: enter the
				// dual-send probe rather than diverting real data onto the
				// (still-blocked) UDP path.
				if now.Sub(tcpSince) > udpReprobeEvery {
					atomic.StoreInt32(&b.mode, carrierProbe)
					probeSince = now
				}
			case carrierProbe:
				switch {
				case lastUDP.After(probeSince):
					// A UDP reply landed during the probe → UDP is back.
					atomic.StoreInt32(&b.mode, carrierUDP)
					clog("CARRIER switch TCP->UDP (udp recovered)")
				case now.Sub(probeSince) > udpReprobeWindow:
					// UDP still dead; fall back to plain TCP until the next probe.
					atomic.StoreInt32(&b.mode, carrierTCP)
					tcpSince = now
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
