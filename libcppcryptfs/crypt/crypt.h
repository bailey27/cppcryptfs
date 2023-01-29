/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2023 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include "config/cryptconfig.h"
#include "context/cryptcontext.h"


class SivContext;

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;

shared_ptr<EVP_CIPHER_CTX> get_crypt_context(int ivlen, int mode);

int encrypt(const unsigned char *plaintext, int plaintext_len, unsigned char *aad,
	int aad_len, const unsigned char *key, const unsigned char *iv, 
	unsigned char *ciphertext, unsigned char *tag, EVP_CIPHER_CTX* ctx);

int decrypt(const unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
	int aad_len, unsigned char *tag, const unsigned char *key, const unsigned char *iv, 
	unsigned char *plaintext, EVP_CIPHER_CTX* ctx);

int encrypt_siv(const unsigned char *plaintext, int plaintext_len, unsigned char *aad,
	int aad_len, const unsigned char *iv,
	unsigned char *ciphertext, unsigned char *siv, const SivContext *context);

int decrypt_siv(const unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
	int aad_len, const unsigned char *siv, const unsigned char *iv,
	unsigned char *plaintext, const SivContext *context);

bool sha256(const string& str, BYTE *sum);  // sum is a 32-byte buffer

bool sha256(const BYTE *data, int datalen, BYTE *sum); // sum is a 32-byte buffer

bool sha512(const BYTE *data, int datalen, BYTE *sum); // sum is a 64-byte buffer

bool encrypt_string_gcm(const wstring& str, const BYTE *key, string& base64_out);

bool decrypt_string_gcm(const string& base64_in, const BYTE *key, wstring& str);

bool hkdfDerive(const BYTE *masterKey, int masterKeyLen, BYTE *newKey, int newKeyLen, const char *info);

extern const char *hkdfInfoEMENames;
extern const char *hkdfInfoGCMContent;
extern const char *hkdfInfoSIVContent;