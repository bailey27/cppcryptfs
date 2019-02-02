#ifndef AES256_CTR_H
#define AES256_CTR_H

#include "aes256-common.h"

extern "C"
{
	void aes256_ctr(AES *, uint8_t *plaintext, const size_t plaintext_len, const uint8_t *iv);
}

#endif // AES256_CTR_H