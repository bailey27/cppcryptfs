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

#include <windows.h>

#include "cryptdefs.h"

#include "openssl/aes.h"

#include "LockZeroBuffer.h"

class lCacheContainer;

struct struct_EmeCryptContext {
	const BYTE *key;
	lCacheContainer *lc;
};

typedef struct struct_EmeCryptContext EmeCryptContext;

class lCacheContainer {
private:
	void tabulateL(const EmeCryptContext *eme_context, int m);
public:

	const AES_KEY *get_encryption_key() { return pEncKeyBuf ? pEncKeyBuf->m_buf : NULL; }
	const AES_KEY *get_decryption_key() { return pDecKeyBuf ? pDecKeyBuf->m_buf : NULL; }

	LockZeroBuffer<AES_KEY> *pEncKeyBuf;
	LockZeroBuffer<AES_KEY> *pDecKeyBuf;
	LockZeroBuffer<BYTE> *pLTableBuf;
	LPBYTE *LTable;

	void init(EmeCryptContext *eme_context);
	lCacheContainer();
	virtual ~lCacheContainer();
};


BYTE* EmeTransform(const EmeCryptContext *eme_context, const BYTE *T, const BYTE *P, int len, bool direction);

