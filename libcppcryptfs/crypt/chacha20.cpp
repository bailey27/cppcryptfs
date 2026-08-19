/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2026 fzxx (github.com/fzxx)

cppcryptfs is based on the design of gocryptfs (github.com/rfjakob/gocryptfs)

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to deal in the above Software without the above permission notice
and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include "stdafx.h"

#include <cstring>
#include <cstdint>

#include "chacha20.h"


/* ChaCha20 quarter-round: mixes four 32-bit state words (a, b, c, d). */
static void chacha20_quarter_round(uint32_t s[16], int a, int b, int c, int d)
{
	s[a] += s[b]; s[d] ^= s[a]; s[d] = (s[d] << 16) | (s[d] >> 16);
	s[c] += s[d]; s[b] ^= s[c]; s[b] = (s[b] << 12) | (s[b] >> 20);
	s[a] += s[b]; s[d] ^= s[a]; s[d] = (s[d] << 8)  | (s[d] >> 24);
	s[c] += s[d]; s[b] ^= s[c]; s[b] = (s[b] << 7)  | (s[b] >> 25);
}

static void wipe_words(uint32_t *p, int n)
{
	volatile uint32_t *v = p;
	while (n--)
		*v++ = 0;
}

void hchacha20(const unsigned char key[32], const unsigned char nonce[16], unsigned char out[32])
{
	/* "expand 32-byte k" constant */
	static const uint32_t constant[4] = {
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	};

	uint32_t state[16];

	state[0] = constant[0];
	state[1] = constant[1];
	state[2] = constant[2];
	state[3] = constant[3];

	// gocryptfs (golang.org/x/crypto/chacha20) loads the key and nonce as
	// little-endian uint32 words. Read them explicitly little-endian here so
	// the derived subkey matches regardless of the host's byte order.
	for (int i = 0; i < 8; i++)
		state[4 + i] = (uint32_t)key[4*i] | ((uint32_t)key[4*i+1] << 8) |
			((uint32_t)key[4*i+2] << 16) | ((uint32_t)key[4*i+3] << 24);

	for (int i = 0; i < 4; i++)
		state[12 + i] = (uint32_t)nonce[4*i] | ((uint32_t)nonce[4*i+1] << 8) |
			((uint32_t)nonce[4*i+2] << 16) | ((uint32_t)nonce[4*i+3] << 24);

	uint32_t working[16];
	memcpy(working, state, sizeof(working));

	for (int round = 0; round < 10; round++) {
		/* column rounds */
		chacha20_quarter_round(working, 0, 4, 8, 12);
		chacha20_quarter_round(working, 1, 5, 9, 13);
		chacha20_quarter_round(working, 2, 6, 10, 14);
		chacha20_quarter_round(working, 3, 7, 11, 15);
		/* diagonal rounds */
		chacha20_quarter_round(working, 0, 5, 10, 15);
		chacha20_quarter_round(working, 1, 6, 11, 12);
		chacha20_quarter_round(working, 2, 7, 8, 13);
		chacha20_quarter_round(working, 3, 4, 9, 14);
	}

	/* HChaCha20 outputs words 0-3 and 12-15 of the permuted state directly,
	 * without adding the initial state (unlike ChaCha20). */
	uint32_t out_words[8];
	for (int i = 0; i < 4; i++)
		out_words[i] = working[i];
	for (int i = 0; i < 4; i++)
		out_words[4 + i] = working[12 + i];

	memcpy(out, out_words, 32);

	wipe_words(state, 16);
	wipe_words(working, 16);
	wipe_words(out_words, 8);
}
