#pragma once

#include "cryptconfig.h"
#include "cryptcontext.h"



#define GetMasterKey() (con->GetConfig()->GetKey())

void *get_crypt_context(int ivlen, int mode);

void free_crypt_context(void *context);

int encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *aad,
	int aad_len, const unsigned char *key, const unsigned char *iv, 
	unsigned char *ciphertext, unsigned char *tag, void *context);

int decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
	int aad_len, unsigned char *tag, const unsigned char *key, const unsigned char *iv, 
	unsigned char *plaintext, void *context);

bool sha256(const std::string& str, BYTE *sum);  // sum is a 32-byte buffer