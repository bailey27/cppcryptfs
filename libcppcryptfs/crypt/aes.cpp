/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2022 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include "AES.h"


#ifdef USE_AES_NI
#ifdef __cplusplus
extern "C" {
#endif

	unsigned int OPENSSL_ia32cap_P[];

#define HAVE_AES_NI   (OPENSSL_ia32cap_P[1]&(1<<(57-32)))

	int aesni_set_encrypt_key(const unsigned char *userKey, int bits,
		AES_KEY *key);
	int aesni_set_decrypt_key(const unsigned char *userKey, int bits,
		AES_KEY *key);

	void aesni_encrypt(const unsigned char *in, unsigned char *out,
		const AES_KEY *key);
	void aesni_decrypt(const unsigned char *in, unsigned char *out,
		const AES_KEY *key);
#ifdef __cplusplus
};
#endif
#endif // USE_AES_NI


bool AES::use_aes_ni()
{
#ifdef USE_AES_NI
	if (HAVE_AES_NI)
		return true;
#endif
	return false;
}

void AES::initialize_keys(const unsigned char *key, int keylen /* in bits */, 
				AES_KEY *encrypt_key, AES_KEY *decrypt_key)
{
#ifdef USE_AES_NI
	if (AES::use_aes_ni()) {
		aesni_set_encrypt_key(key, keylen, encrypt_key);
		aesni_set_decrypt_key(key, keylen, decrypt_key);
	} else
#endif
	{
		AES_set_encrypt_key(key, keylen, encrypt_key);
		AES_set_decrypt_key(key, keylen, decrypt_key);
	}
}

AES::AES()
{
	m_key_encrypt = NULL;
	m_key_decrypt = NULL;
	m_use_aes_ni = use_aes_ni();
}

AES::~AES()
{
	// don't delete keys
}

void AES::set_keys(const AES_KEY *key_encrypt, const AES_KEY *key_decrypt) 
{ 
	m_key_encrypt = key_encrypt; 
	m_key_decrypt = key_decrypt; 
}

// encrypt single AES block (16 bytes)
void AES::encrypt(const unsigned char* plain, unsigned char *cipher) const
{ 
#ifdef USE_AES_NI
	if (m_use_aes_ni) {
		aesni_encrypt(plain, cipher, m_key_encrypt);
	} else
#endif
	{
		AES_encrypt(plain, cipher, m_key_encrypt);
	}
}

// decrypt single AES block (16 bytes)
void AES::decrypt(const unsigned char *cipher, unsigned char *plain) const
{ 
#ifdef USE_AES_NI
	if (m_use_aes_ni) {
		aesni_decrypt(cipher, plain, m_key_decrypt);
	} else
#endif
	{
		AES_decrypt(cipher, plain, m_key_decrypt);
	}
}

