#ifndef AES256_SIV_H
#define AES256_SIV_H

#include "aes256-common.h"

extern "C"
{
	bool aes256_encrypt_siv(const uint8_t *key, const uint8_t *header_data,
		const size_t *header_sizes, const uint8_t header_sizes_len,
		uint8_t *plaintext, const size_t plaintext_len, uint8_t *siv);

	bool aes256_decrypt_siv(const uint8_t *key, const uint8_t *header_data,
		const size_t *header_sizes, const uint8_t header_sizes_len,
		uint8_t *ciphertext, const size_t ciphertext_len, const uint8_t *siv);
}

#endif // AES256_SIV_H
