/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);

/* Notified when the wss carrier loses (up=0) or regains (up=1) reachability;
 * only transitions are reported. Called from wireguard-go goroutines. Pass a
 * NULL fn to unregister, which the host must do before wgTurnOff. */
typedef void(*carrier_state_fn_t)(void *context, int32_t up);
extern void wgSetCarrierStateFn(void *context, carrier_state_fn_t fn);

/* UDP-only liveness push: wireguard-go sniffs its own handshake log and reports
 * WG's handshake-complete (up=1) / gave-up-after-RekeyAttemptTime (up=0). Same
 * contract as carrier_state_fn_t (foreign goroutine, NULL to unregister before
 * wgTurnOff); it is what makes the no-carrier path event-driven. */
typedef void(*handshake_state_fn_t)(void *context, int32_t up);
extern void wgSetHandshakeStateFn(void *context, handshake_state_fn_t fn);
extern int wgTurnOn(const char *settings, int32_t tun_fd);
extern void wgTurnOff(int handle);
extern int64_t wgSetConfig(int handle, const char *settings);
extern char *wgGetConfig(int handle);
extern int32_t wgGetCarrierMode(int handle);
extern void wgBumpSockets(int handle);
extern void wgKickHandshake(int handle);
/* Arms a UDP probe that only a handshake initiation may ride, and only while the
 * session is on the wss carrier. Called when the host's own watchdog gives up on
 * the relay: WireGuard is re-initiating every RekeyTimeout anyway, and this puts the
 * next initiation on UDP, where an open path answers inside the probe's window. */
extern void wgArmUDPProbe(int handle);
/* Installs the callback the carrier calls with the address it is about to dial, BEFORE it
 * dials it, so a full tunnel can pin that address to the physical gateway first - the
 * exclusions installed at bring-up name the relay as the profile spelled it then, which a
 * redial onto another front end or a re-fetched profile leaves behind. The callback runs
 * on a Go goroutine and the dial waits for it; pass NULL to unregister before teardown. */
typedef void(*carrier_target_fn_t)(void *context, const char *addr);
extern void wgSetCarrierTargetFn(void *context, carrier_target_fn_t fn);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern const char *wgVersion();

#endif
