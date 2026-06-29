/* wn_netcfg.h — demo network overrides for the wolfNano-over-wolfIP examples.
 *
 * Force-included (gcc -include wn_netcfg.h) ahead of config.h so the board uses a
 * static IP on the Raspberry Pi's LAN and skips DHCP. Adjust to your network.
 */
#ifndef WN_NETCFG_H
#define WN_NETCFG_H

#define WOLFIP_ENABLE_DHCP 0          /* deterministic static IP (no DHCP wait) */
#define WOLFIP_IP      "10.0.4.222"   /* board address (free on the Pi's subnet) */
#define WOLFIP_NETMASK "255.255.255.0"
#define WOLFIP_GW      "10.0.4.1"

#endif /* WN_NETCFG_H */
