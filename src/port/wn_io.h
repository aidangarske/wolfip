/* wn_io.h
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
 * wolfIP <-> wolfNano glue.
 *
 * Unlike wolfSSL's non-blocking SetIO callbacks (wolfssl_io.c), wolfNano's
 * wn_Connect_* / wn_Send / wn_Recv run the handshake SYNCHRONOUSLY: they call
 * ioSend/ioRecv expecting them to make forward progress like blocking POSIX
 * send()/recv(). wolfIP is a single-threaded poll-driven stack, so these shims
 * must pump wolfIP_poll() themselves until bytes move (or a timeout elapses).
 */
#ifndef WN_IO_H
#define WN_IO_H

#include "wolfip.h"
#include "wolfnano.h"   /* wn_IoSend / wn_IoRecv / byte / word32 */

/* Per-connection context handed to wolfNano as ioCtx. */
struct wn_io_desc {
    struct wolfIP *stack;
    int            fd;
};

/* Overall blocking timeout for a single send/recv pump loop (ms of real time,
 * measured via the DWT cycle counter). Generous: a LAN TLS 1.3 handshake is
 * well under a second, but allow for TCP retransmits. */
#ifndef WN_IO_TIMEOUT_MS
#define WN_IO_TIMEOUT_MS 10000u
#endif

/* wn_IoSend: write all len bytes (pumping the stack), return len, or <0. */
int wn_io_send(void* ctx, const byte* buf, word32 len);

/* wn_IoRecv: return as soon as >=1 byte is available (POSIX recv semantics),
 * or <=0 on close/error/timeout. Pumps the stack while waiting. */
int wn_io_recv(void* ctx, byte* buf, word32 len);

/* --- timing: DWT cycle counter (Cortex-M33 core peripheral) --------------- */

/* Core clock in Hz; the H563 port boots at reset-default HSI. Override with
 * -DWN_CORE_HZ=<hz> if you configure a PLL. */
#ifndef WN_CORE_HZ
#define WN_CORE_HZ 64000000u
#endif

/* Enable DWT->CYCCNT. Call once at startup before wn_now_ms()/wn_dwt_cycles(). */
void     wn_dwt_init(void);

/* Monotonic 64-bit cycle count (accumulated; immune to 32-bit CYCCNT wrap as
 * long as it is sampled at least once per ~2^32 cycles, which the poll loops do). */
uint64_t wn_dwt_cycles(void);

/* Monotonic milliseconds derived from the cycle counter (for wolfIP_poll). */
uint64_t wn_now_ms(void);

#endif /* WN_IO_H */
