/* user_settings.h  (wolfNano build for the STM32H563 wolfIP port)
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
 * Selects one of wolfNano's public configs/ starter profiles (the SAME headers
 * a customer ships), then layers the STM32H563 bare-metal additions: route
 * wolfSSL's RNG to the on-chip TRNG already implemented in main.c.
 *
 * Profile is chosen by the Makefile via -DWN_PROFILE_<name>. Default = the
 * smallest PSK + ECDHE X25519 build (configs/user_settings_minimal.h).
 */
#ifndef WN_PORT_USER_SETTINGS_H
#define WN_PORT_USER_SETTINGS_H

#if   defined(WN_PROFILE_PSK_P256)
    #include "user_settings_psk_p256.h"
#elif defined(WN_PROFILE_PQC)
    #include "user_settings_pqc.h"
#elif defined(WN_PROFILE_CERT)
    #include "user_settings_cert.h"
#elif defined(WN_PROFILE_CERT_MLDSA)
    #include "user_settings_cert_mldsa.h"
#else /* WN_PROFILE_PSK_X25519 (default) */
    #include "user_settings_minimal.h"
#endif

/* --- STM32H563 bare-metal additions over the wolfNano config -------------- */

/* RNG: the wolfNano config already enables the Hash-DRBG and points its seed
 * source at CUSTOM_RAND_GENERATE_SEED == wn_seed (see wolfnano_config.h). The
 * host build provides wn_seed via tests/wn_host_seed.c; this port provides it in
 * wn_client.c, wired to the STM32H5 hardware TRNG (custom_rand_gen_block in
 * main.c). Nothing to (re)define here — declare the symbol for completeness. */
#ifdef __cplusplus
extern "C" {
#endif
int wn_seed(unsigned char* output, unsigned int sz);
#ifdef __cplusplus
}
#endif

#endif /* WN_PORT_USER_SETTINGS_H */
