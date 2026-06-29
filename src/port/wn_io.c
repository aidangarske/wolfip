/* wn_io.c
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
 * wolfIP <-> wolfNano synchronous I/O shim (see wn_io.h).
 */
#include "wn_io.h"

/* --- DWT cycle counter (ARMv7-M / ARMv8-M debug block) -------------------- */
#define WN_DEMCR    (*(volatile uint32_t *)0xE000EDFCu) /* bit24 TRCENA       */
#define WN_DWT_CTRL (*(volatile uint32_t *)0xE0001000u) /* bit0  CYCCNTENA    */
#define WN_DWT_CYC  (*(volatile uint32_t *)0xE0001004u) /* free-running count */
#define WN_DEMCR_TRCENA     (1u << 24)
#define WN_DWT_CTRL_CYCCNT  (1u << 0)

static uint64_t s_acc_cyc;   /* accumulated 64-bit cycle count */
static uint32_t s_last_cyc;  /* last raw CYCCNT sample */

void wn_dwt_init(void)
{
    WN_DEMCR    |= WN_DEMCR_TRCENA;
    WN_DWT_CYC   = 0u;
    WN_DWT_CTRL |= WN_DWT_CTRL_CYCCNT;
    s_last_cyc   = WN_DWT_CYC;
    s_acc_cyc    = 0u;
}

uint64_t wn_dwt_cycles(void)
{
    uint32_t c = WN_DWT_CYC;
    s_acc_cyc += (uint32_t)(c - s_last_cyc); /* unsigned wrap-safe delta */
    s_last_cyc = c;
    return s_acc_cyc;
}

uint64_t wn_now_ms(void)
{
    return wn_dwt_cycles() / (uint64_t)(WN_CORE_HZ / 1000u);
}

/* --- transport callbacks -------------------------------------------------- */

/* wolfIP returns -WOLFIP_EAGAIN or -1 when no progress is possible right now;
 * 0 or any other negative means the connection is closed/reset. */
static int wn_would_block(int r)
{
    return (r == -WOLFIP_EAGAIN) || (r == -1);
}

int wn_io_send(void* ctx, const byte* buf, word32 len)
{
    struct wn_io_desc* d = (struct wn_io_desc*)ctx;
    word32   sent  = 0;
    uint64_t start = wn_now_ms();

    if (d == NULL || d->stack == NULL)
        return -1;

    while (sent < len) {
        int r;
        (void)wolfIP_poll(d->stack, wn_now_ms());
        r = wolfIP_sock_send(d->stack, d->fd, buf + sent, len - sent, 0);
        if (r > 0) {
            sent += (word32)r;
            start = wn_now_ms();    /* progress: reset the watchdog */
            continue;
        }
        if (wn_would_block(r)) {
            if (wn_now_ms() - start > WN_IO_TIMEOUT_MS)
                return -1;          /* stalled */
            continue;
        }
        return r;                   /* closed / error */
    }

    /* Nudge the stack so the queued segment goes out promptly. */
    (void)wolfIP_poll(d->stack, wn_now_ms());
    return (int)len;
}

int wn_io_recv(void* ctx, byte* buf, word32 len)
{
    struct wn_io_desc* d = (struct wn_io_desc*)ctx;
    uint64_t start = wn_now_ms();

    if (d == NULL || d->stack == NULL)
        return -1;

    for (;;) {
        int r;
        (void)wolfIP_poll(d->stack, wn_now_ms());
        r = wolfIP_sock_recv(d->stack, d->fd, buf, len, 0);
        if (r > 0)
            return r;               /* up-to-len bytes, like POSIX recv() */
        if (wn_would_block(r)) {
            if (wn_now_ms() - start > WN_IO_TIMEOUT_MS)
                return -1;          /* stalled */
            continue;
        }
        return (r == 0) ? -1 : r;   /* closed / error */
    }
}
