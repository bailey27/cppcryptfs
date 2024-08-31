/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2024 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include <windows.h>

#include <util/util.h>

#include "cryptdefs.h"

#include "openssl/aes.h"

#include "aes.h"

#include "util/LockZeroBuffer.h"


class CryptConfig;

// we do EME only on individual path components (file/directory names)
// a stack buffer of 384 bytes should handle all cases without
// dynamic allocation being necessary
typedef TempBuffer<BYTE, 384> EmeBuffer_t;

class EmeCryptContext {
public:
	
private:

	LockZeroBuffer<AES_KEY> *m_pKeyBuf;
	LockZeroBuffer<BYTE> *m_pLTableBuf;
public:
	AES m_aes_ctx;
	LPBYTE *m_LTable;

	EmeCryptContext();

	// disallow copying
	EmeCryptContext(EmeCryptContext const&) = delete;
	void operator=(EmeCryptContext const&) = delete;

	virtual ~EmeCryptContext();

	void tabulateL(int m, CryptConfig *pConfig);


	bool init(const BYTE *key, bool hkdf, CryptConfig *pConfig);
	
};


bool EmeTransform(const EmeCryptContext *eme_context, 
	const BYTE *T, const BYTE *P, int len, bool direction, EmeBuffer_t& buffer);

