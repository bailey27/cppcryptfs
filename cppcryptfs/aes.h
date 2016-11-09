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

#pragma once

#include "openssl/aes.h"

#define USE_AES_NI 1

#ifdef USE_AES_NI
#ifdef __cplusplus
extern "C" {
#endif
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

// this class is used by aes-siv

class AES
{
public:

	static bool use_aes_ni();

	void set_keys(const AES_KEY *key_encrypt, const AES_KEY *key_decrypt);

	// encrypt single AES block (16 bytes)
	void encrypt(const unsigned char* plain, unsigned char *cipher);

	// decrypt single AES block (16 bytes)
	void decrypt(const unsigned char *cipher, unsigned char *plain);
  
	AES();

	virtual ~AES();

 private:
	 const AES_KEY *m_key_encrypt;
	 const AES_KEY *m_key_decrypt;
	 bool m_use_aes_ni;
};


