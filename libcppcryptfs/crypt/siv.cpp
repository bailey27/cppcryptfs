
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

#include "stdafx.h"
#include "crypt.h"

#include "siv.h"
#include "aes.h"

SivContext::SivContext()
{
	m_pKeys = NULL;
}

SivContext::~SivContext()
{
	if (m_pKeys)
		delete m_pKeys;
}

bool SivContext::SetKey(const unsigned char *key, int keylen, bool hkdf, CryptConfig *pConfig)
{
	if (keylen != 32)
		return false;

	if (!pConfig)
		throw std::exception("SivContext::SetKey where is my config?");

	if (!m_pKeys)
		m_pKeys = new LockZeroBuffer<AES_KEY>(4, true, nullptr);

	pConfig->m_keybuf_manager.RegisterBuf(m_pKeys);

	LockZeroBuffer<BYTE> key64(64, true, nullptr);

	if (hkdf) {
		if (!hkdfDerive(key, keylen, key64.m_buf, key64.m_len, hkdfInfoSIVContent))
			return false;
	} else {
		if (!sha512(key, 32, key64.m_buf))
			return false;
	}

	AES::initialize_keys(key64.m_buf, 256, &m_pKeys->m_buf[SIV_KEY_ENCRYPT_LOW_INDEX], 
										&m_pKeys->m_buf[SIV_KEY_DECRYPT_LOW_INDEX]);

	AES::initialize_keys(key64.m_buf + 32 , 256, &m_pKeys->m_buf[SIV_KEY_ENCRYPT_HIGH_INDEX], 
											&m_pKeys->m_buf[SIV_KEY_DECRYPT_HIGH_INDEX]);

	return true;
}