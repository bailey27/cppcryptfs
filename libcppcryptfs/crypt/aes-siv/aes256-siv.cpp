#include "stdafx.h"
#include "aes256-siv.h"
#include "aes256-cmac.h"
#include "aes256-ctr.h"
#include <stdlib.h>
#include <string.h>

#include "crypt/siv.h"

const uint8_t aes256_siv_one_block[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

void aes256_siv_dbl(uint8_t *block)
{
	bool need_xor = (block[0] >> 7 == 1);
	aes256_bitshift_left(block, 16);
	if (need_xor)
		aes256_xor(block, aes256_cmac_Rb, 16);
}

void aes256_siv_s2v(AES *ctx, const uint8_t *header_data,
	const size_t *header_sizes, const uint8_t header_sizes_len,
	const uint8_t *plaintext, const size_t plaintext_len, uint8_t *mac)
{
	uint8_t headers = (plaintext_len == 0 ? header_sizes_len - 1 : header_sizes_len);

	size_t header_loc = 0;
	uint8_t buf[16];
	aes256_cmac(ctx, aes256_zero_block, 16, mac);
	for (uint8_t h = 0; h < headers; h++)
	{
		aes256_siv_dbl(mac);
		size_t header_size = header_sizes[h];
		aes256_cmac(ctx, &header_data[header_loc], header_size, buf);
		aes256_xor(mac, buf, 16);
		header_loc += header_size;
	}

	const uint8_t *last_part = plaintext;
	size_t last_part_len = plaintext_len;

	if (last_part_len >= 16)
	{
		uint8_t *last_part_mod = (uint8_t*)malloc(last_part_len);

		memcpy(last_part_mod, last_part, last_part_len);
		aes256_xor(&last_part_mod[last_part_len - 16], mac, 16);
		aes256_cmac(ctx, last_part_mod, last_part_len, mac);

		free(last_part_mod);
	}
	else
	{
		aes256_siv_dbl(mac);
		memcpy(buf, last_part, last_part_len);
		buf[last_part_len] = aes256_iso_pad;
		for (size_t i = last_part_len + 1; i < 16; i++)
			buf[i] = 0x00;
		aes256_xor(buf, mac, 16);
		aes256_cmac(ctx, buf, 16, mac);
	}
}

bool aes256_encrypt_siv(const SivContext *siv_context, const uint8_t *header_data,
	const size_t *header_sizes, const uint8_t header_sizes_len,
	uint8_t *plaintext, const size_t plaintext_len, uint8_t *siv)
{
	if (header_sizes_len > 126)
		return false;

	AES ctx;
	//ctx.set_key(key, 32);
	ctx.set_keys(siv_context->GetEncryptKeyLow(), siv_context->GetDecryptKeyLow());

	aes256_siv_s2v(&ctx, header_data, header_sizes, header_sizes_len, plaintext, plaintext_len, siv);

	uint8_t iv[16];
	memcpy(iv, siv, sizeof(iv));

	// Clear the 31st and 63rd bits in the IV.
	iv[8] &= 0x7f;
	iv[12] &= 0x7f;

	//ctx.set_key(&key[32], 32);
	ctx.set_keys(siv_context->GetEncryptKeyHigh(), siv_context->GetDecryptKeyHigh());
	aes256_ctr(&ctx, plaintext, plaintext_len, iv);

	return true;
}

bool aes256_decrypt_siv(const SivContext *siv_context, const uint8_t *header_data,
	const size_t *header_sizes, const uint8_t header_sizes_len,
	uint8_t *ciphertext, const size_t ciphertext_len, const uint8_t *siv)
{
	if (header_sizes_len > 126)
		return false;

	AES ctx;
	//ctx.set_key(&key[32], 32);
	ctx.set_keys(siv_context->GetEncryptKeyHigh(), siv_context->GetDecryptKeyHigh());

	uint8_t iv[16];
	memcpy(iv, siv, sizeof(iv));

	// Clear the 31st and 63rd bits in the IV.
	iv[8] &= 0x7f;
	iv[12] &= 0x7f;

	aes256_ctr(&ctx, ciphertext, ciphertext_len, iv);

	//ctx.set_key(key, 32);
	ctx.set_keys(siv_context->GetEncryptKeyLow(), siv_context->GetDecryptKeyLow());
	uint8_t mac[16];
	aes256_siv_s2v(&ctx, header_data, header_sizes, header_sizes_len, ciphertext, ciphertext_len, mac);

	return (memcmp(siv, mac, 16) == 0);
}
