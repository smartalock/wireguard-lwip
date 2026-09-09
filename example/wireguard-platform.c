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

// wireguard_tai64n_now() below uses gettimeofday(), which only returns a
// meaningful value if *your* platform actually has a wall-clock time source
// wired up (an RTC, SNTP, etc.) - on a target with none, it silently returns
// something useless (typically the epoch, or uptime from an arbitrary
// start), and you get exactly the "handshakes fail after every reboot" bug
// this comment exists to prevent, just one layer further hidden than the
// uptime bug it replaces. Whether that's actually true varies per target, so
// it can't be checked at compile time - this define is you asserting it
// rather than the build silently assuming it. Define
// WIREGUARD_PLATFORM_TIME_IS_WALL_CLOCK once you've confirmed
// gettimeofday() (or whatever you replace it with below) returns real
// wall-clock time on your platform.
#ifndef WIREGUARD_PLATFORM_TIME_IS_WALL_CLOCK
#error "wireguard_tai64n_now() needs real wall-clock time, not uptime - see the comment above it. Define WIREGUARD_PLATFORM_TIME_IS_WALL_CLOCK once your gettimeofday() (or platform equivalent) is confirmed correct."
#endif

void wireguard_tai64n_now(uint8_t *output) {
	// See https://cr.yp.to/libtai/tai64.html
	// 64 bit seconds from 1970 = 8 bytes
	// 32 bit nano seconds from current second

	// Must be wall-clock time, not sys_now() uptime: handshakes are rejected
	// unless this strictly increases from the last value a peer saw from us,
	// and uptime resets near zero on every reboot while a still-running peer
	// keeps its old high-water mark - silently breaking reconnection after a
	// restart until uptime climbs back past it. See the
	// WIREGUARD_PLATFORM_TIME_IS_WALL_CLOCK check above.
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

