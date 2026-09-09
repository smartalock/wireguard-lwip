#include "wireguard-platform.h"

#include <stdlib.h>
#include <sys/time.h>
#include "crypto.h"
#include "lwip/sys.h"

// This file contains a sample Wireguard platform integration

// DO NOT USE THIS FUNCTION - IMPLEMENT A BETTER RANDOM BYTE GENERATOR IN YOUR IMPLEMENTATION
void wireguard_random_bytes(void *bytes, size_t size) {
	int x;
	uint8_t *out = (uint8_t *)bytes;
	for (x=0; x < size; x++) {
		out[x] = rand() % 0xFF;
	}
}

uint32_t wireguard_sys_now() {
	// Default to the LwIP system time
	return sys_now();
}

void wireguard_tai64n_now(uint8_t *output) {
	// See https://cr.yp.to/libtai/tai64.html
	// 64 bit seconds from 1970 = 8 bytes
	// 32 bit nano seconds from current second

	// Must be wall-clock time, not sys_now() uptime: handshakes are rejected
	// unless this strictly increases from the last value a peer saw from us,
	// and uptime resets near zero on every reboot while a still-running peer
	// keeps its old high-water mark - silently breaking reconnection after a
	// restart until uptime climbs back past it. gettimeofday() needs your
	// libc's time-of-day to actually be set (e.g. via SNTP) to be correct;
	// until then this is no worse than the uptime it replaces.
	struct timeval tv;
	gettimeofday(&tv, NULL);

	// Split into seconds offset + nanos
	uint64_t seconds = 0x400000000000000aULL + (uint64_t)tv.tv_sec;
	uint32_t nanos = (uint32_t)tv.tv_usec * 1000;
	U64TO8_BIG(output + 0, seconds);
	U32TO8_BIG(output + 8, nanos);
}

bool wireguard_is_under_load() {
	return false;
}

