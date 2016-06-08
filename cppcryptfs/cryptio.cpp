#include "stdafx.h"

#include "cryptconfig.h"
#include "cryptdefs.h"
#include "util.h"
#include "crypt.h"
#include "cryptio.h"



int
read_block(CryptContext *con, HANDLE hfile, const unsigned char *fileid, unsigned long long block, unsigned char *ptbuf, void *crypt_context)
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
		
	/*
	int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
	int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv, int ivlen,
	unsigned char *plaintext, int mode)
	*/


	int ptlen = decrypt(buf + BLOCK_IV_LEN, nread - BLOCK_IV_LEN - BLOCK_TAG_LEN, auth_data, sizeof(auth_data), 
		buf + nread - BLOCK_TAG_LEN, con->GetConfig()->GetKey(), buf, ptbuf, crypt_context);

	if (ptlen < 0) {  // return all zeros for un-authenticated blocks (might exist if file was resized without writing)

		memset(ptbuf, 0, nread - (BLOCK_IV_LEN + BLOCK_TAG_LEN));

		return nread - (BLOCK_IV_LEN + BLOCK_TAG_LEN);
	
	}

	return ptlen;
}

int
write_block(CryptContext *con, HANDLE hfile, const unsigned char *fileid, unsigned long long block, const unsigned char *ptbuf, int ptlen, void *crypt_context)
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


	/*
	int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
	int aad_len, unsigned char *key, unsigned char *iv, int ivlen,
	unsigned char *ciphertext, unsigned char *tag, int mode)
	*/

	unsigned char tag[BLOCK_TAG_LEN];

	if (!get_random_bytes(buf, BLOCK_IV_LEN))
		return -1;

	int ctlen = encrypt(ptbuf, ptlen, auth_data, sizeof(auth_data), con->GetConfig()->GetKey(), buf, buf + BLOCK_IV_LEN, tag, crypt_context);

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
