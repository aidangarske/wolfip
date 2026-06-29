/* wn_client.c
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
 * wolfNano TLS 1.3 client demo over wolfIP (see wn_client.h).
 */
#include "wn_client.h"
#include "wn_io.h"

#include "wn_connect.h"             /* wolfNano: wn_Connect_* / wn_Session API */
#include <string.h>

#if defined(WN_PROFILE_CERT) || defined(WN_PROFILE_CERT_MLDSA)
#include "wn_certs.h"               /* pinned trust anchor (server cert DER) */
#endif

/* Scratch buffer wolfNano uses for record framing. PSK paths need ~8 KB; the
 * cert paths need ~13 KB (wn_connect.h), so size for the largest profile. */
#ifndef WN_SCRATCH_SZ
#define WN_SCRATCH_SZ 16384
#endif

/* wolfSSL's example server (-s) PSK for identity "Client_identity":
 * 01 23 45 67 89 ab cd ef, repeated to 32 bytes. */
static const byte g_psk[32] = {
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
    0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};
static const char g_identity[] = "Client_identity";
static const byte g_msg[]      = "hello from wolfNano over wolfIP\n";

/* wolfNano's Hash-DRBG seed source (CUSTOM_RAND_GENERATE_SEED == wn_seed).
 * Wired to the STM32H5 hardware TRNG via custom_rand_gen_block() in main.c. */
extern int custom_rand_gen_block(unsigned char* output, unsigned int sz);
int wn_seed(unsigned char* output, unsigned int sz)
{
    return custom_rand_gen_block(output, sz);
}

/* --- tiny formatting helpers (dbg only takes strings) --------------------- */
static void dbg_u32(wn_debug_cb dbg, const char *label, uint32_t v)
{
    char b[12];
    int i = (int)sizeof(b);
    b[--i] = '\0';
    if (v == 0) {
        b[--i] = '0';
    } else {
        while (v && i > 0) { b[--i] = (char)('0' + (v % 10u)); v /= 10u; }
    }
    if (dbg) { dbg(label); dbg(&b[i]); }
}

int wn_client_run(struct wolfIP *stack, uint32_t server_ip, uint16_t port,
                  wn_debug_cb dbg)
{
    struct wn_io_desc io;
    struct wolfIP_sockaddr_in addr;
    WC_RNG rng;
    wn_Session sess;
    static byte scratch[WN_SCRATCH_SZ];
    byte in[256];
    word32 got = 0;
    uint64_t c0, c1;
    uint64_t start;
    int fd, rc;
    int have_rng = 0;

#define DBG(s) do { if (dbg) dbg(s); } while (0)

    fd = wolfIP_sock_socket(stack, AF_INET, IPSTACK_SOCK_STREAM, 0);
    if (fd < 0) { DBG("  wn: socket() failed\n"); return -1; }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = ee16(port);
    addr.sin_addr.s_addr = ee32(server_ip);

    /* Non-blocking TCP connect: pump the stack until the 3-way handshake
     * completes (wolfIP_sock_connect returns -WOLFIP_EAGAIN while in progress). */
    DBG("  wn: TCP connect...\n");
    rc = wolfIP_sock_connect(stack, fd, (struct wolfIP_sockaddr *)&addr,
                             sizeof(addr));
    start = wn_now_ms();
    while (rc == -WOLFIP_EAGAIN) {
        (void)wolfIP_poll(stack, wn_now_ms());
        rc = wolfIP_sock_connect(stack, fd, (struct wolfIP_sockaddr *)&addr,
                                 sizeof(addr));
        if (wn_now_ms() - start > WN_IO_TIMEOUT_MS) { rc = -1; break; }
    }
    if (rc < 0) {
        DBG("  wn: TCP connect FAILED\n");
        wolfIP_sock_close(stack, fd);
        return -1;
    }
    DBG("  wn: TCP connected\n");

    io.stack = stack;
    io.fd    = fd;

    if (wc_InitRng(&rng) != 0) {
        DBG("  wn: wc_InitRng FAILED\n");
        goto out;
    }
    have_rng = 1;

    DBG("  wn: TLS 1.3 handshake...\n");
    c0 = wn_dwt_cycles();
#if defined(WN_PROFILE_CERT) || defined(WN_PROFILE_CERT_MLDSA)
    /* Cert auth: pin the server's self-signed cert (DER) as the trust anchor.
     * The server's leaf must verify against it and CertificateVerify must check
     * with the leaf key. (Anchor-only: pin the exact expected leaf.) */
    (void)g_psk; (void)g_identity;
#if defined(WN_PROFILE_CERT_MLDSA)
    rc = wn_Connect_Cert_ex(&sess, &rng, wn_io_send, wn_io_recv, &io,
                            wn_anchor_mldsa, wn_anchor_mldsa_len,
                            scratch, (word32)sizeof(scratch));
#else
    rc = wn_Connect_Cert_ex(&sess, &rng, wn_io_send, wn_io_recv, &io,
                            wn_anchor_ecdsa, wn_anchor_ecdsa_len,
                            scratch, (word32)sizeof(scratch));
#endif
    c1 = wn_dwt_cycles();
#else
    /* PSK + ECDHE (X25519, P-256, or X25519MLKEM768 hybrid per profile). */
    rc = wn_Connect_Psk_ex(&sess, &rng, wn_io_send, wn_io_recv, &io,
                           g_psk, (word32)sizeof(g_psk), g_identity,
                           scratch, (word32)sizeof(scratch));
    c1 = wn_dwt_cycles();
#endif
    if (rc != 0) {
        DBG("  wn: handshake FAILED: ");
        DBG(wn_ErrorToString(rc));
        DBG("\n");
        goto out;
    }
    dbg_u32(dbg, "  wn: handshake OK, cycles=", (uint32_t)(c1 - c0));
    dbg_u32(dbg, " (~", (uint32_t)((c1 - c0) / (uint64_t)(WN_CORE_HZ / 1000u)));
    DBG(" ms)\n");

    rc = wn_Send(&sess, g_msg, (word32)(sizeof(g_msg) - 1));
    if (rc == 0)
        rc = wn_Recv(&sess, in, (word32)(sizeof(in) - 1), &got);
    if (rc == 0) {
        in[got] = '\0';
        DBG("  wn: echo: ");
        DBG((const char *)in);
        if (got == 0 || in[got - 1] != '\n') DBG("\n");
        DBG("  wn: PASS\n");
    } else {
        DBG("  wn: app-data FAILED: ");
        DBG(wn_ErrorToString(rc));
        DBG("\n");
    }
    wn_Close(&sess);

out:
    if (have_rng) wc_FreeRng(&rng);
    wolfIP_sock_close(stack, fd);
    return rc;

#undef DBG
}
