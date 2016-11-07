#include "stdafx.h"
#include "aes256-common.h"

void aes256_xor(uint8_t *buf, const uint8_t *xorval, const size_t len)
{
	for (size_t i = 0; i < len; i++)
		buf[i] ^= xorval[i];
}

void aes256_bitshift_left(uint8_t *buf, const size_t len)
{
	for (size_t i = 0; i < len - 1; ++i)
	{
		buf[i] = (buf[i] << 1) | ((buf[i + 1] >> 7) & 1);
	}
	buf[len - 1] = buf[len - 1] << 1;
}
