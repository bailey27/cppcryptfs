#ifndef AES256_CMAC_H
#define AES256_CMAC_H

#include <stdlib.h>

#include "aes256-common.h"

extern "C"
{
	void aes256_cmac(AES *, const uint8_t *plaintext, const size_t plaintext_len, uint8_t *mac);
}

#endif // AES256_CMAC_H