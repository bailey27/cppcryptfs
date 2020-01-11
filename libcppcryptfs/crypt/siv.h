/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2020 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include "util/LockZeroBuffer.h"
#include "openssl/aes.h"

#define SIV_KEY_ENCRYPT_LOW_INDEX  0
#define SIV_KEY_DECRYPT_LOW_INDEX  1
#define SIV_KEY_ENCRYPT_HIGH_INDEX 2
#define SIV_KEY_DECRYPT_HIGH_INDEX 3

class SivContext {

public:

	bool SetKey(const unsigned char *key, int keylen, bool hkdf); // keylen must be 32
																  // disallow copying
	SivContext(SivContext const&) = delete;
	void operator=(SivContext const&) = delete;
	SivContext();
	virtual ~SivContext();

	const AES_KEY *GetEncryptKeyLow() const { return m_pKeys ? &m_pKeys->m_buf[SIV_KEY_ENCRYPT_LOW_INDEX] : NULL; };
	const AES_KEY *GetDecryptKeyLow() const { return m_pKeys ? &m_pKeys->m_buf[SIV_KEY_DECRYPT_LOW_INDEX] : NULL; };
	const AES_KEY *GetEncryptKeyHigh() const { return m_pKeys ? &m_pKeys->m_buf[SIV_KEY_ENCRYPT_HIGH_INDEX] : NULL; };
	const AES_KEY *GetDecryptKeyHigh() const { return m_pKeys ? &m_pKeys->m_buf[SIV_KEY_DECRYPT_HIGH_INDEX] : NULL; };
	
private:
	LockZeroBuffer<AES_KEY> *m_pKeys;
};