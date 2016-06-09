/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016 - Bailey Brown (github.com/bailey27/cppcryptfs)

cppcryptfs is based on the design of gocryptfs (github.com/rfjakob/gocryptfs)

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/


#include "stdafx.h"

#include <openssl/evp.h>

#include "cryptdefs.h"

#include <string>


static void
handleErrors()
{
	throw (-1);
}



void *get_crypt_context(int ivlen, int mode)
{
	EVP_CIPHER_CTX *ctx = NULL;

	try {
		/* Create and initialise the context */
		if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

		const EVP_CIPHER *cipher = NULL;

		switch (mode) {
	
		case AES_MODE_CBC:
			cipher = EVP_aes_256_cbc();
			break;
		case AES_MODE_GCM:
			cipher = EVP_aes_256_gcm();
			break;
		default:
			handleErrors();
			break;
		}

		/* Initialise the encryption operation. */
		if (1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
			handleErrors();

		if (mode == AES_MODE_GCM && ivlen != 12) {
			/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
			if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivlen, NULL))
				handleErrors();
		}

	} catch (int) {
		if (ctx)
			EVP_CIPHER_CTX_free(ctx);
		ctx = NULL;
	}

	return (void*)ctx;
}

void free_crypt_context(void *context)
{
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)context;

	/* Clean up */
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
}


int encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *aad,
	int aad_len, const unsigned char *key, const unsigned char *iv, 
	unsigned char *ciphertext, unsigned char *tag, void *context)
{
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)context;

	if (!ctx)
		return -1;

	int len;

	int ciphertext_len;

	try {

		
		if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

		/* Provide any AAD data. This can be called zero or more times as
		* required
		*/
		if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
			handleErrors();

		/* Provide the message to be encrypted, and obtain the encrypted output.
		* EVP_EncryptUpdate can be called multiple times if necessary
		*/
		if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			handleErrors();
		ciphertext_len = len;

		/* Finalise the encryption. Normally ciphertext bytes may be written at
		* this stage, but this does not occur in GCM mode
		*/
		if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
		ciphertext_len += len;

		/* Get the tag */
		if (tag) {
			if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
				handleErrors();
		}

	} catch (int) {
		ciphertext_len = -1;
	}

	return ciphertext_len;
}

int decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
	int aad_len, unsigned char *tag, const unsigned char *key, const unsigned char *iv, 
	unsigned char *plaintext, void *context)
{
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX*)context;

	if (!ctx)
		return -1;

	int len;
	int plaintext_len;
	int ret;

	

	try {

		
		/* Initialise Key and IV */
		if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

		/* Provide any AAD data. This can be called zero or more times as
		* required
		*/
		if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
			handleErrors();

		/* Provide the message to be decrypted, and obtain the plaintext output.
		* EVP_DecryptUpdate can be called multiple times if necessary
		*/
		if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			handleErrors();
		plaintext_len = len;

		/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
		if (tag) {
			if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
				handleErrors();
		}

		/* Finalise the decryption. A positive return value indicates success,
		* anything else is a failure - the plaintext is not trustworthy.
		*/
		ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	}
	catch (int) {
		ret = -1;
	}

	

	if (ret > 0)
	{
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else
	{
		/* Verify failed */
		return -1;
	}
}

bool sha256(const std::string& str, BYTE *sum)
{
	EVP_MD_CTX *mdctx = NULL;
	bool ret = true;

	try {

		if (EVP_MD_size(EVP_sha256()) != 32)
			handleErrors();

		if ((mdctx = EVP_MD_CTX_create()) == NULL)
			handleErrors();

		if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
			handleErrors();

		if (1 != EVP_DigestUpdate(mdctx, &str[0], str.size()))
			handleErrors();

		unsigned int len;
		if (1 != EVP_DigestFinal_ex(mdctx, sum, &len))
			handleErrors();

		if (len != 32)
			handleErrors();

	} catch (...) {
		ret = false;
	}

	if (mdctx)
		EVP_MD_CTX_destroy(mdctx);

	return ret;

}
