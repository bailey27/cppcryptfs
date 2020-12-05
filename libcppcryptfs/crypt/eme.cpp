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


/* 
	This code was translated into C++ by Bailey Brown from
	eme.go from the project EME for Go (github.com/rfjakob/eme).

	Below is the comment header from emo.go 
*/

// EME (ECB-Mix-ECB) is a wide-block encryption mode presented in the 2003 paper
// "A Parallelizable Enciphering Mode" by Halevi and Rogaway.
// This is an implementation of EME in Go.

#include "stdafx.h"
#include <windows.h>

#include "util/util.h"
#include "eme.h"
#include "crypt.h"
#include "config/cryptconfig.h"
#include "openssl/aes.h"

#include "aes.h"



static const bool DirectionEncrypt = true;
static const bool DirectionDecrypt = false;

static void panic(const WCHAR *mes)
{
	throw(-1);
}
	

	// multByTwo - GF multiplication as specified in the EME-32 draft
static void multByTwo(BYTE *out, const BYTE *in, int len) {
	if (len != 16) {
		panic(L"len must be 16");
	}
	BYTE tmp[16];

	tmp[0] = 2 * in[0];
	if (in[15] >= 128) {
		tmp[0] = tmp[0] ^ 135;
	}
	 for (int j = 1; j < 16; j++) {
		 tmp[j] = 2 * in[j];
			 if (in[j - 1] >= 128) {
				 tmp[j] += 1;
			 }
	 }

	 for (int i = 0; i < 16; i++)
		 out[i] = tmp[i];
}

static void xorBlocks(BYTE* out,  const BYTE* in1,  const BYTE* in2, int len) {

	for (int i = 0; i < len; i++) {
		out[i] = in1[i] ^ in2[i];
	}
}

static void AesEncrypt(BYTE* dst, const BYTE* src, int len, const EmeCryptContext *eme_context)
{
	int numBlocks = len / 16;

	for (int i = 0; i < numBlocks; i++) {
		eme_context->m_aes_ctx.encrypt(src + i * 16, dst + i * 16);
	}
}

static void AesDecrypt(BYTE* dst, const BYTE* src, int len, const EmeCryptContext *eme_context)
{
	int numBlocks = len / 16;

	for (int i = 0; i < numBlocks; i++) {
		eme_context->m_aes_ctx.decrypt(src + i * 16, dst + i * 16);
	}
}

// aesTransform - encrypt or decrypt (according to "direction") using block
// cipher "bc" (typically AES)
static void aesTransform(BYTE* dst, const BYTE* src, bool direction, int len, const EmeCryptContext *eme_context) {
	if (direction == DirectionEncrypt) {
		AesEncrypt(dst, src, len, eme_context);
		return;
	}
	else if (direction == DirectionDecrypt) {
		AesDecrypt(dst, src, len, eme_context);
		return;
	}
	else {
		panic(L"unknown direction");
	}
}

EmeCryptContext::EmeCryptContext()
{ 
	
	m_LTable = NULL;

	m_pKeyBuf = NULL;

	m_pLTableBuf = NULL;
}

EmeCryptContext::~EmeCryptContext()
{
	if (m_LTable) 
		delete[] m_LTable;

	if (m_pLTableBuf)
		delete m_pLTableBuf;

	if (m_pKeyBuf)
		delete m_pKeyBuf;
}

// tabulateL - calculate L_i for messages up to a length of m cipher blocks
void EmeCryptContext::tabulateL(int m, CryptConfig *pConfig){

	/* set L0 = 2*AESenc(K; 0) */
	BYTE eZero[16];
	memset(eZero, 0, sizeof(eZero));

	LockZeroBuffer<BYTE> Li(16, true);

	AesEncrypt(Li.m_buf, eZero, 16, this);

	m_LTable = new LPBYTE[m];

	// Allocate pool once and slice into m pieces in the loop

	m_pLTableBuf = new LockZeroBuffer<BYTE>(m * 16, true);

	pConfig->m_keybuf_manager.RegisterBuf(m_pLTableBuf);

	BYTE *pool = m_pLTableBuf->m_buf;

	for (int i = 0; i < m; i++) {
		multByTwo(Li.m_buf, Li.m_buf, 16);
		m_LTable[i] = pool + i * 16;
		memcpy(m_LTable[i], Li.m_buf, 16);
	}
	
}





bool EmeCryptContext::init(const BYTE *key, bool hkdf, CryptConfig *pConfig)
{
	const BYTE *emeKey = key;

	if (!pConfig)
		throw std::exception("EMeCryptContext init: where is my config?");

	LockZeroBuffer<BYTE> hkdfKey(MASTER_KEY_LEN, false);

	if (hkdf) {
		if (!hkdfKey.IsLocked())
			return false;
		if (!hkdfDerive(key, MASTER_KEY_LEN, hkdfKey.m_buf, hkdfKey.m_len, hkdfInfoEMENames))
			return false;

		emeKey = hkdfKey.m_buf;
	}

	m_pKeyBuf = new LockZeroBuffer<AES_KEY>(2, true);

	pConfig->m_keybuf_manager.RegisterBuf(m_pKeyBuf);

	AES::initialize_keys(emeKey, 256, &m_pKeyBuf->m_buf[0], &m_pKeyBuf->m_buf[1]);

	m_aes_ctx.set_keys(&m_pKeyBuf->m_buf[0], &m_pKeyBuf->m_buf[1]);

	tabulateL(16 * 8, pConfig);

	return true;

}



// Transform - EME-encrypt or EME-decrypt, according to "direction"
// (defined in the constants directionEncrypt and directionDecrypt).
// The data in "P" is en- or decrypted with the block ciper "bc" under tweak "T".
// The result is returned in a freshly allocated slice.
bool EmeTransform(const EmeCryptContext *eme_context, const BYTE *T, const BYTE *P, int len, bool direction, 
				  TempBuffer<BYTE, 512>& buffer)  {

	BYTE *C = NULL;

	bool error = false;

	try {
		if (len % 16 != 0) {
			panic(L"Data length is not a multiple of 16");
		}
		int m = len / 16;
		if (m == 0 || m > 16 * 8) {
			panic(L"EME operates on 1-128 block-cipher blocks");
		}

		C = buffer.get(len+1); // +1 so caller can add a null terminator if necessary without any trouble

		BYTE **LTable = eme_context->m_LTable;

		BYTE PPj[16];

		for (int j = 0; j < m; j++) {
			BYTE Pj[16];
			memcpy(Pj, P + j * 16, 16);
			/* PPj = 2**(j-1)*L xor Pj */
			xorBlocks(PPj, Pj, LTable[j], 16);
			/* PPPj = AESenc(K; PPj) */
			aesTransform(C + j * 16, PPj, direction, 16, eme_context);
		}

		/* MP =(xorSum PPPj) xor T */
		BYTE MP[16];
		xorBlocks(MP, C, T, 16);
		for (int j = 1; j < m; j++) {
			xorBlocks(MP, MP, C + j * 16, 16);
		}

		/* MC = AESenc(K; MP) */
		BYTE MC[16];
		aesTransform(MC, MP, direction, 16, eme_context);

		/* M = MP xor MC */
		BYTE M[16];
		xorBlocks(M, MP, MC, 16);
		BYTE CCCj[16];
		for (int j = 1; j < m; j++) {
			multByTwo(M, M, 16);
			/* CCCj = 2**(j-1)*M xor PPPj */
			xorBlocks(CCCj, C + j * 16, M, 16);
			memcpy(C + j * 16, CCCj, 16);
		}

		/* CCC1 = (xorSum CCCj) xor T xor MC */

		BYTE CCC1[16];
		xorBlocks(CCC1, MC, T, 16);
		for (int j = 1; j < m; j++) {
			xorBlocks(CCC1, CCC1, C + j * 16, 16);
		}

		memcpy(C, CCC1, 16);

		for (int j = 0; j < m; j++) {
			/* CCj = AES-enc(K; CCCj) */
			BYTE dst[16];

			aesTransform(dst, C + j * 16, direction, 16, eme_context);

			/* Cj = 2**(j-1)*L xor CCj */
			xorBlocks(C + j * 16, dst, LTable[j], 16);
		}
	} catch (...) {
		error = true;
	}

	if (!error) {
		return true;
	} else {		
		return false;
	}
}
