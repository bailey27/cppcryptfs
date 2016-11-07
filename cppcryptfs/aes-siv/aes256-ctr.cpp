#include "stdafx.h"
#include "aes256-ctr.h"
#include <string.h>

void aes256_ctr_increment_nonce(uint8_t *nonce)
{
	for (int i = 15; i >= 0; i--)
	{
		if (nonce[i] < 0xff)
		{
			nonce[i]++;
			break;
		}
		else
			nonce[i] = 0x00;
	}
}

void aes256_ctr(AES *ctx, uint8_t *input, const size_t input_len, const uint8_t *iv)
{
	uint8_t nonce[16], buf[16];
	memcpy(nonce, iv, sizeof(nonce));

	size_t count = 0;
	while (count + 16 <= input_len)
	{
		memcpy(buf, nonce, sizeof(nonce));
		ctx->encrypt(buf, buf);
		aes256_xor(&input[count], buf, sizeof(buf));

		aes256_ctr_increment_nonce(nonce);
		count += 16;
	}

	size_t rem = input_len - count;
	if (rem > 0)
	{
		ctx->encrypt(nonce, nonce);
		aes256_xor(&input[count], nonce, rem);
	}
}