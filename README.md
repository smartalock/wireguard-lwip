# WireGuard Implementation for lwIP

This project is a C implementation of the [WireGuard&reg;](https://www.wireguard.com/) protocol intended to be used with the [lwIP IP stack](https://www.nongnu.org/lwip/)

# Motivation

There is a desire to use secure communication in smaller embedded devices to communicate with off-premises devices; WireGuard&reg; seems perfect for this task due to its small code base and secure nature

This project tackles the problem of using WireGuard&reg; on embedded systems in that it is:
- malloc-free so fits into a fixed RAM size
- written entirely in C
- has low memory requirements in terms of stack size, flash storage and RAM
- compatible with the popular lwIP IP stack

# Code Layout

The code is split into four main portions

- wireguard.c contains the bulk of the WireGuard&reg; protocol code and is not specific to any particular IP stack
- wireguardif.c contains the lwIP integration code and makes a netif network interface and handles periodic tasks such as keepalive/expiration timers
- wireguard-platform.h contains the definition of the four functions to be implemented per platform (a sample implementation is given in wireguard-platform.sample)
- crypto code (see below)

## Crypto Code

The supplied cryptographic routines are written entirely in C and are not optimised for any particular platform. These work and use little memory but will probably be slow on your platform.

You will want to swap out the supplied versions for optimised C or assembly versions or those available through the O/S or crypto libraries on your platform. Simply edit the crypto.h header file to point at the routines you want to use.

The crypto routines supplied are:
- BLAKE2S - adapted from the implementation in the RFC itself at https://tools.ietf.org/html/rfc7693
- CHACHA20 - adapted from code at https://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/ref/chacha.c
- HCHACHA20 - implemented from scratch following description here https://tools.ietf.org/id/draft-arciszewski-xchacha-02.html
- POLY1305 - taken from https://github.com/floodyberry/poly1305-donna
- CHACHA20POLY1305 - implemented from scratch following description here https://tools.ietf.org/html/rfc7539
- AEAD_XChaCha20_Poly1305 - implemented from scratch following description here https://tools.ietf.org/id/draft-arciszewski-xchacha-02.html
- X25519 - taken from STROBE project at https://sourceforge.net/p/strobe, in addition there is a version optimised for Cortex-M0 processors which requires very little stack taken from https://munacl.cryptojedi.org/curve25519-cortexm0.shtml

# Integrating into your platform

You will need to implement a platform file that provides four functions (see wireguard-platform.h):
- wireguard_sys_now() - a monotonic counter used for calculating time differences - e.g. sys_now() from lwIP
- wireguard_tai64n_now() - a tai64n timestamp function returning the current timestamp. There are workarounds if your platform doesn't have access to a realtime clock or accurate time such as using a 32-bit boot counter + 64 bit uptime offset
- wireguard_is_under_load() - an indication of whether the system is currently under load and should generate cookie reply messages
- wireguard_random_bytes() - a good random number generator that is able to generate random data suitable to be used as crypto keys. The example uses rand() which on POSIX systems is *not* a good choice, it is intended that you use the hardware peripheral on your platform to generate random data

# Handshake Replay Protection Across Restarts

WireGuard protects against replayed handshake initiations using the TAI64N timestamp inside each initiation (section 5.1 of the whitepaper). There are two sides to this:

- **Timestamps you send** - wireguard_tai64n_now() must keep increasing across restarts, otherwise the other end of the tunnel will silently ignore your handshakes after a reboot. See the boot counter example in example/wireguard-platform.c if you don't have an accurate clock.
- **Timestamps you receive** - the greatest timestamp received from each peer is only kept in RAM. Unless you persist it, an attacker who captured an old handshake initiation can replay it once after each restart, which will cause the device to send traffic to the attacker's address until a new handshake completes or the peer is reset.

To persist the received timestamp:
- set wireguardif_peer.remote_initiation_accepted to a callback before adding the peer - it is called each time a handshake initiation from that peer is accepted (typically every 2 minutes while traffic is flowing), call wireguardif_peer_greatest_timestamp() and save the result into non-volatile memory against this peer to be used at re-initialisation
- the callback runs in the lwIP thread (tcpip context) after the handshake response has been sent - don't block here, copy the value and defer any flash write or other storage to a separate task, otherwise the network stack will stall while it completes
- wireguardif_peer_greatest_timestamp() can also be used to read the value at any other time, e.g. to save peer's timestamp before a controlled shutdown

Alternatively, if your device and its peers have accurate real time clocks (Linux peers use real time) you can avoid persisting anything by setting greatest_timestamp to the current TAI64N time minus an allowable amount for clock skew when adding the peer.

# lwIP Code Example
(note error checking omitted)

    #include "lwip/ip.h"
    #include "wireguardif.h"

    static struct netif wg_netif_struct = {0};
    static struct netif *wg_netif = NULL;
    static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;

    static const char *peer_public_key = "cDfetaDFWnbxts2Pbz4vFYreikPEEVhTlV/sniIEBjo=";

    // Provided by your application - non-volatile storage for a peer's greatest handshake timestamp, keyed by the peer's public key
    void load_peer_timestamp(const char *public_key, uint8_t *timestamp);
    void save_peer_timestamp(const char *public_key, const uint8_t *timestamp);

    // Called by the WireGuard interface each time a handshake initiation from a peer is accepted - can save remote timestamp to prevent replays
    static void wireguard_initiation_accepted(struct netif *netif, u8_t peer_index) {
    	uint8_t timestamp[WIREGUARDIF_TIMESTAMP_LEN];
    	if (peer_index == wireguard_peer_index) {
    		if (wireguardif_peer_greatest_timestamp(netif, peer_index, timestamp, sizeof(timestamp)) == ERR_OK) {
    			// Remember for next reboot - save_peer_timestamp() must not block, e.g. it copies the value and signals your own task to write it to flash
    			save_peer_timestamp(peer_public_key, timestamp);
    		}
    	}
    }

    static void wireguard_setup() {
    	struct wireguardif_init_data wg = {0};
    	struct wireguardif_peer peer;
    	ip4_addr_t ipaddr, netmask, gateway;

    	IP4_ADDR(&ipaddr, 192, 168, 40, 10);
    	IP4_ADDR(&netmask, 255, 255, 255, 0);
    	IP4_ADDR(&gateway, 192, 168, 40, 1);

    	// Setup the WireGuard device structure
    	wg.private_key = "8BU1giso23adjCk93dnpLJnK788bRAtpZxs8d+Jo+Vg=";
    	wg.listen_port = 51820;
    	wg.bind_netif = NULL;

    	// Register the new WireGuard network interface with lwIP
    	wg_netif = netif_add(&wg_netif_struct, &ipaddr, &netmask, &gateway, &wg, &wireguardif_init, &ip_input);

    	// Mark the interface as administratively up, link up flag is set automatically when peer connects
    	netif_set_up(wg_netif);

    	// Initialise the first WireGuard peer structure
    	wireguardif_peer_init(&peer);
    	peer.public_key = peer_public_key;
    	peer.preshared_key = NULL;
    	// Allow all IPs through tunnel
    	IP_ADDR4(&peer.allowed_ip, 0, 0, 0, 0);
    	IP_ADDR4(&peer.allowed_mask, 0, 0, 0, 0);

    	// Optional: Restore the greatest handshake timestamp previously received from this peer (leave as all zero if none saved)
    	load_peer_timestamp(peer_public_key, peer.greatest_timestamp);
    	// Optional: Get notified each time the peer's handshake is accepted so the new timestamp can be saved
    	peer.remote_initiation_accepted = wireguard_initiation_accepted;

    	// If we know the endpoint's address can add here
    	IP_ADDR4(&peer.endpoint_ip, 10, 0, 0, 12);
    	peer.endport_port = 12345;

    	// Register the new WireGuard peer with the network interface
    	wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);

    	if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
    		// Start outbound connection to peer
    		wireguardif_connect(wg_netif, wireguard_peer_index);
    	}
    }


# More Information

WireGuard&reg; was created and developed by Jason A. Donenfeld. "WireGuard" and the "WireGuard" logo are registered trademarks of Jason A. Donenfeld. See https://www.wireguard.com/ for more information

This project is not approved, sponsored or affiliated with WireGuard or with the community.

- The whitepaper https://www.wireguard.com/papers/wireguard.pdf
- The Wikipedia page https://en.wikipedia.org/wiki/WireGuard 

# License

The code is copyrighted under BSD 3 clause Copyright (c) 2021 Daniel Hope (www.floorsense.nz)

See LICENSE for details

# Contact

Daniel Hope at Smartalock
