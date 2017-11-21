#include "stdafx.h"
#include "aes256-cmac.h"
#include "aes256-common.h"
#include <string.h>

void aes256_cmac_generate_subkeys(AES *ctx, uint8_t *k1, uint8_t *k2)
{
	uint8_t buf[16];
	size_t bufsize = sizeof(buf);
	memcpy(buf, aes256_zero_block, bufsize);

	// Encrypt the zero string.
	ctx->encrypt(buf, buf);

	memcpy(k1, buf, bufsize);
	aes256_bitshift_left(k1, bufsize);

	if (buf[0] >> 7 != 0)
		aes256_xor(k1, aes256_cmac_Rb, bufsize);

	memcpy(k2, k1, bufsize);
	aes256_bitshift_left(k2, bufsize);

	if (k1[0] >> 7 != 0)
		aes256_xor(k2, aes256_cmac_Rb, bufsize);
}

void aes256_cmac(AES *ctx, const uint8_t *plaintext, const size_t plaintext_len, uint8_t *mac)
{
	uint8_t buf[16], k1[16], k2[16];
	aes256_cmac_generate_subkeys(ctx, k1, k2);

	memcpy(mac, aes256_zero_block, sizeof(aes256_zero_block));
	size_t count = 0;
	while (count + 16 < plaintext_len)
	{
		memcpy(buf, &plaintext[count], 16);
		aes256_xor(mac, buf, 16);
		ctx->encrypt(mac, mac);
		count += 16;
	}

	size_t last_block_len = plaintext_len - count;
	memcpy(buf, &plaintext[count], last_block_len);
	if (last_block_len == 16)
	{
		// The last block is a complete block.
		aes256_xor(buf, k1, 16);
	}
	else
	{
		// The last block is an incomplete block.
		buf[last_block_len] = aes256_iso_pad;
		for (size_t i = last_block_len + 1; i < 16; i++)
			buf[i] = 0x00;
		aes256_xor(buf, k2, 16);
	}
	aes256_xor(mac, buf, 16);
	ctx->encrypt(mac, mac);
}
