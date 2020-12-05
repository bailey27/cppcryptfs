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

#include "config/cryptconfig.h"
#include "crypt/cryptdefs.h"
#include "util/util.h"
#include "crypt/crypt.h"
#include "cryptio.h"



int
read_block(CryptContext *con, HANDLE hfile, BYTE *inputbuf, int bytesinbuf, int *bytes_consumed, const unsigned char *fileid, unsigned long long block, unsigned char *ptbuf, openssl_crypt_context_t openssl_crypt_context)
{
	static_assert(BLOCK_IV_LEN == BLOCK_SIV_LEN, "BLOCK_IV_LEN != BLOCK_SIV_LEN.");
	static_assert(BLOCK_SIV_LEN == BLOCK_TAG_LEN, "BLOCK_SIV_LEN != BLOCK_TAG_LEN.");

	long long offset = FILE_HEADER_LEN + block*CIPHER_BS;

	OVERLAPPED ov;

	if (hfile != INVALID_HANDLE_VALUE) {
		SetOverlapped(&ov, offset);
	}

	unsigned long long be_block = MakeBigEndian(block);

	unsigned char auth_data[sizeof(be_block) + FILE_ID_LEN];

	memcpy(auth_data, &be_block, sizeof(be_block));

	memcpy(auth_data + sizeof(be_block), fileid, FILE_ID_LEN);

	unsigned char buf[CIPHER_BS];

	DWORD nread = 0;

	if (hfile == INVALID_HANDLE_VALUE && inputbuf) {
		int to_consume = min(CIPHER_BS, bytesinbuf);
		if (bytes_consumed != NULL)
			*bytes_consumed = to_consume;
		nread = to_consume;
	} else {
		if (!ReadFile(hfile, buf, sizeof(buf), &nread, &ov)) {
			DWORD error = GetLastError();
			if (error == ERROR_HANDLE_EOF) {
				return 0;
			} else {
				return -1;
			}
		}
	}

	if (nread == 0)
		return 0;

	if (nread <= CIPHER_BLOCK_OVERHEAD) {
		SetLastError(ERROR_INVALID_DATA);
		return -1;
	}

	int ptlen;
	
	if (con->GetConfig()->m_AESSIV) {
		ptlen = decrypt_siv((inputbuf ? inputbuf : buf) + BLOCK_IV_LEN + BLOCK_SIV_LEN, nread - BLOCK_IV_LEN - BLOCK_SIV_LEN, auth_data, sizeof(auth_data), 
			(inputbuf ? inputbuf : buf) + BLOCK_IV_LEN, (inputbuf ? inputbuf : buf), ptbuf, &con->m_siv);	
	} else {
		ptlen = decrypt((inputbuf ? inputbuf : buf) + BLOCK_IV_LEN, nread - BLOCK_IV_LEN - BLOCK_TAG_LEN, auth_data, sizeof(auth_data),
			(inputbuf ? inputbuf : buf) + nread - BLOCK_TAG_LEN, con->GetConfig()->GetGcmContentKey(), (inputbuf ? inputbuf : buf), ptbuf, openssl_crypt_context);
	}

	if (ptlen < 0) {  // return all zeros for un-authenticated blocks (might exist if file was resized without writing)

		// if we read all zeros, then it is (probably) really from a hole in the file

		if (is_all_zeros(inputbuf ? inputbuf : buf, nread)) {
			memset(ptbuf, 0, nread - (BLOCK_IV_LEN + BLOCK_TAG_LEN));
			return nread - (BLOCK_IV_LEN + BLOCK_TAG_LEN);
		} else {
			// if there are any non-zero bytes, then there is definitely corrupted data, so return an error
			SetLastError(ERROR_DATA_CHECKSUM_ERROR);
			return -1;
		}
	
	}

	return ptlen;
}

int
write_block(CryptContext *con, unsigned char *cipher_buf, HANDLE hfile, const unsigned char *fileid, unsigned long long block, const unsigned char *ptbuf, int ptlen, openssl_crypt_context_t openssl_crypt_context, const unsigned char *iv)
{


	long long offset = FILE_HEADER_LEN + block*CIPHER_BS;

	if (!iv)
		return -1;

	OVERLAPPED ov;

	if (hfile != INVALID_HANDLE_VALUE) {
		SetOverlapped(&ov, offset);
	}

	unsigned long long be_block = MakeBigEndian(block);

	unsigned char auth_data[sizeof(be_block) + FILE_ID_LEN];

	memcpy(auth_data, &be_block, sizeof(be_block));

	memcpy(auth_data + sizeof(be_block), fileid, FILE_ID_LEN);

	unsigned char tag[BLOCK_TAG_LEN];

	if (!con->GetConfig()->m_reverse) {
		memcpy(cipher_buf, iv, BLOCK_IV_LEN);
	} else {
		const unsigned char* block0iv = iv;

		// On a 128-bit big-endian machine, this would be the low-order 64 bits
		// hence the name block0IVlow
		unsigned long long block0IVlow; 

		static_assert(BLOCK_SIV_LEN == 16, "BLOCK_SIV_LEN != 16.");
		static_assert(sizeof(block0IVlow) == 8, "sizeof(block0IVlow) != 8.");
		memcpy(&block0IVlow, block0iv + 8, sizeof(block0IVlow));

		block0IVlow = MakeBigEndianNative(block0IVlow);

		block0IVlow += block;

		block0IVlow = MakeBigEndian(block0IVlow);

		memcpy(cipher_buf, block0iv, 8);
		memcpy(cipher_buf + 8, &block0IVlow, sizeof(block0IVlow));
		
		
	}

	bool siv = con->GetConfig()->m_AESSIV;

	int ctlen;

	if (siv) {
		ctlen = encrypt_siv(ptbuf, ptlen, auth_data, sizeof(auth_data), 
			cipher_buf, cipher_buf + BLOCK_IV_LEN + BLOCK_SIV_LEN, cipher_buf + BLOCK_IV_LEN, &con->m_siv);
	} else {
		ctlen = encrypt(ptbuf, ptlen, auth_data, sizeof(auth_data), con->GetConfig()->GetGcmContentKey(),
			cipher_buf, cipher_buf + BLOCK_IV_LEN, tag, openssl_crypt_context);
	}

	if (ctlen < 0 || ctlen > PLAIN_BS)
		return -1;

	if (!siv)
		memcpy(cipher_buf + BLOCK_IV_LEN + ctlen, tag, sizeof(tag));

	if (!con->GetConfig()->m_reverse && hfile != INVALID_HANDLE_VALUE) {

		DWORD nWritten = 0;

		if (!WriteFile(hfile, cipher_buf, BLOCK_IV_LEN + ctlen + sizeof(tag), &nWritten, &ov)) {
			return -1;
		}
		
		if (nWritten == BLOCK_IV_LEN + ctlen + sizeof(tag)) {
			return ptlen;
		} else {
			return -1;
		}
	} else {
		return BLOCK_IV_LEN + ctlen + sizeof(tag);
	}
}
