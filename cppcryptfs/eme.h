/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2017 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include "aes.h"

#include "LockZeroBuffer.h"




class EmeCryptContext {
public:
	
	AES m_aes_ctx;

	EmeCryptContext();
	virtual ~EmeCryptContext();

private:
	const BYTE *m_key;
	LockZeroBuffer<AES_KEY> *m_pKeyBuf;
	LockZeroBuffer<BYTE> *m_pLTableBuf;

	void tabulateL(int m);
public:

	LPBYTE *m_LTable;

	void init(const BYTE *key);
};


BYTE* EmeTransform(const EmeCryptContext *eme_context, 
	const BYTE *T, const BYTE *P, int len, bool direction);

