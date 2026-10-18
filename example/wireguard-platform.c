#include "wireguard-platform.h"

#include <stdlib.h>
#include "crypto.h"
#include "lwip/sys.h"

// This file contains a sample Wireguard platform integration.
// ** It should not be used in production systems verbatim as
// ** - it is unlikely to function (handshakes will fail due to remote-end replay protection)
// ** - will probably generate insecure crypto keys unless your rand() implementation is backed by hardware crypto peripheral

// DO NOT USE THIS FUNCTION - IMPLEMENT A BETTER RANDOM BYTE GENERATOR IN YOUR IMPLEMENTATION
void wireguard_random_bytes(void *bytes, size_t size) {
	int x;
	uint8_t *out = (uint8_t *)bytes;
	for (x=0; x < size; x++) {
		out[x] = rand() % 0x100;
	}
}

uint32_t wireguard_sys_now() {
	// Default to the LwIP system time
	return sys_now();
}

// CHANGE THIS TO GET THE ACTUAL UNIX TIMESTMP IN MILLIS - HANDSHAKES WILL FAIL IF THIS DOESN'T INCREASE EACH TIME CALLED
void wireguard_tai64n_now(uint8_t *output) {
	// See https://cr.yp.to/libtai/tai64.html
	// 64 bit seconds from 1970 = 8 bytes
	// 32 bit nano seconds from current second

	uint64_t millis = sys_now(); // <--- this will cause handshakes to fail

	// Split into seconds offset + nanos
	uint64_t seconds = 0x400000000000000aULL + (millis / 1000);
	uint32_t nanos = (millis % 1000) * 1000;
	U64TO8_BIG(output + 0, seconds);
	U32TO8_BIG(output + 8, nanos);

	// As an alternative to generating a real tai64n timestamp on systems without realtime or semi-accurate clocks
	// implementers could consider a system such as below where the system records a monotonic increasing boot counter
	// recording the number of times powered on along with a 64-bit uptime counter
	// uint32_t boot_count = current_boot_counter();
	// uint64_t uptime = uptime_millis();
	// U32TO8_BIG(output + 0, boot_count);
	// U64TO8_BIG(output + 4, uptime);	
}

bool wireguard_is_under_load() {
	return false;
}

