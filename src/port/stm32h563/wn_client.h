/* wn_client.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfIP TCP/IP stack.
 *
 * wolfIP is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfIP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 *
 * wolfNano TLS 1.3 client demo over wolfIP. The active profile (PSK X25519 /
 * PSK P-256 / PQC hybrid / cert / cert+ML-DSA) is chosen at build time via
 * -DWN_PROFILE_<name>; this one app drives whichever connect entry point fits.
 */
#ifndef WN_CLIENT_H
#define WN_CLIENT_H

#include <stdint.h>
#include "wolfip.h"

typedef void (*wn_debug_cb)(const char *s);

/* Connect to server_ip:port, run the wolfNano handshake for the compiled
 * profile, do one application-data echo round trip, and close. Prints progress,
 * the handshake cycle/ms timing, and the echo via dbg. Returns 0 on success. */
int wn_client_run(struct wolfIP *stack, uint32_t server_ip, uint16_t port,
                  wn_debug_cb dbg);

#endif /* WN_CLIENT_H */
