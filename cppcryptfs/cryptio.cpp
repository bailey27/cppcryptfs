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

#include "stdafx.h"

#include "cryptconfig.h"
#include "cryptdefs.h"
#include "util.h"
#include "crypt.h"
#include "cryptio.h"



int
read_block(CryptContext *con, HANDLE hfile, const unsigned char *fileid, unsigned long long block, unsigned char *ptbuf, void *openssl_crypt_context)
{
	long long offset = FILE_HEADER_LEN + block*CIPHER_BS;

	LARGE_INTEGER l;

	l.QuadPart = offset;

	if (!SetFilePointerEx(hfile, l, NULL, FILE_BEGIN)) {
		return -1;
	}

	unsigned long long be_block = MakeBigEndian(block);

	unsigned char auth_data[sizeof(be_block) + FILE_ID_LEN];

	memcpy(auth_data, &be_block, sizeof(be_block));

	memcpy(auth_data + sizeof(be_block), fileid, FILE_ID_LEN);

	unsigned char buf[CIPHER_BS];

	DWORD nread = 0;

	if (!ReadFile(hfile, buf, sizeof(buf), &nread, NULL)) {
		DWORD error = GetLastError();
		return -1;
	}

	if (nread == 0)
		return 0;

	int ptlen;
	
	if (con->GetConfig()->m_AESSIV) {
		ptlen = decrypt_siv(buf + BLOCK_IV_LEN * 2, nread - BLOCK_IV_LEN * 2, auth_data, sizeof(auth_data), 
			buf + BLOCK_IV_LEN, con->GetConfig()->GetKey(), buf, ptbuf);	
	} else {
		ptlen = decrypt(buf + BLOCK_IV_LEN, nread - BLOCK_IV_LEN - BLOCK_TAG_LEN, auth_data, sizeof(auth_data),
			buf + nread - BLOCK_TAG_LEN, con->GetConfig()->GetKey(), buf, ptbuf, openssl_crypt_context);
	}

	if (ptlen < 0) {  // return all zeros for un-authenticated blocks (might exist if file was resized without writing)

		memset(ptbuf, 0, nread - (BLOCK_IV_LEN + BLOCK_TAG_LEN));

		return nread - (BLOCK_IV_LEN + BLOCK_TAG_LEN);
	
	}

	return ptlen;
}

int
write_block(CryptContext *con, HANDLE hfile, const unsigned char *fileid, unsigned long long block, const unsigned char *ptbuf, int ptlen, void *openssl_crypt_context)
{

	long long offset = FILE_HEADER_LEN + block*CIPHER_BS;

	LARGE_INTEGER l;

	l.QuadPart = offset;

	if (!SetFilePointerEx(hfile, l, NULL, FILE_BEGIN)) {
		return -1;
	}


	unsigned long long be_block = MakeBigEndian(block);

	unsigned char auth_data[sizeof(be_block) + FILE_ID_LEN];

	memcpy(auth_data, &be_block, sizeof(be_block));

	memcpy(auth_data + sizeof(be_block), fileid, FILE_ID_LEN);

	unsigned char buf[CIPHER_BS];

	unsigned char tag[BLOCK_TAG_LEN];

	if (!get_random_bytes(con, buf, BLOCK_IV_LEN))
		return -1;

	int ctlen = encrypt(ptbuf, ptlen, auth_data, sizeof(auth_data), con->GetConfig()->GetKey(), buf, buf + BLOCK_IV_LEN, tag, openssl_crypt_context);

	if (ctlen < 0 || ctlen > PLAIN_BS)
		return -1;

	memcpy(buf + BLOCK_IV_LEN + ctlen, tag, sizeof(tag));

	DWORD nWritten = 0;

	if (!WriteFile(hfile, buf, BLOCK_IV_LEN + ctlen + sizeof(tag), &nWritten, NULL)) {
		return -1;
	}

	if (nWritten == BLOCK_IV_LEN + ctlen + sizeof(tag)) {
		return ptlen;
	} else {
		return -1;
	}
}
