#include "stdafx.h"
#include "cryptdefs.h"
#include "cryptio.h"
#include "cryptfile.h"
#include "fileutil.h"
#include "util.h"
#include "crypt.h"

CryptFile::CryptFile()
{
	m_handle = INVALID_HANDLE_VALUE;
	m_version = 0;
	m_is_empty = false;
	m_con = NULL;
	memset(m_fileid, 0, sizeof(m_fileid));
}

BOOL
CryptFile::Associate(CryptContext *con, HANDLE hfile)
{
	m_handle = hfile;

	m_con = con;

	LARGE_INTEGER l;

	if (!GetFileSizeEx(hfile, &l)) {
		DbgPrint(L"ASSOCIATE: failed to get size of file\n");
		return FALSE;
	}

	if (l.QuadPart == 0) {
		m_version = CRYPT_VERSION;
		m_is_empty = true;
		return TRUE;
	} else if (l.QuadPart < FILE_HEADER_LEN) {
		DbgPrint(L"ASSOCIATE: missing file header\n");
		return FALSE;
	}

	l.QuadPart = 0;

	if (!SetFilePointerEx(hfile, l, NULL, FILE_BEGIN)) {
		DbgPrint(L"ASSOCIATE: failed to seek\n");
		return FALSE;
	}

	// read header in one go to reduce number of reads
	unsigned char header[18];

	DWORD nread;

	if (!ReadFile(hfile, header, sizeof(header), &nread, NULL)) {
		DbgPrint(L"ASSOCIATE: failed to read header\n");
		return FALSE;
	}

	if (nread != sizeof(header)) {
		DbgPrint(L"ASSOCIATE: too few bytes read when reading header\n");
		return FALSE;
	}

	memcpy(&m_version, header, sizeof(m_version));

	m_version = MakeBigEndianNative(m_version);

	if (m_version != CRYPT_VERSION) {
		DbgPrint(L"ASSOCIATE: file version mismatch\n");
		return FALSE;
	}

	memcpy(m_fileid, header + sizeof(m_version), sizeof(m_fileid));

	static BYTE zerobytes[16] = { 0 };

	if (!memcmp(m_fileid, zerobytes, sizeof(m_fileid))) {
		DbgPrint(L"ASSOCIATE: fileid is all zeroes\n");
		return FALSE;
	}

	return TRUE;
}


CryptFile::~CryptFile()
{
	// do not close handle
}

BOOL CryptFile::Read(unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset)
{



	if (!pNread || !buf)
		return FALSE;

	*pNread = 0;

	LONGLONG bytesleft = buflen;

	unsigned char *p = buf;

	void *context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

	if (!context)
		return FALSE;

	BOOL bRet = TRUE;

	try {

		while (bytesleft > 0) {

			LONGLONG blockno = offset / PLAIN_BS;
			int blockoff = (int)(offset % PLAIN_BS);

			int advance;

			if (blockoff == 0 && bytesleft >= PLAIN_BS) {

				advance = read_block(m_con, m_handle, m_fileid, blockno, p, context);

				if (advance < 0)
					throw(-1);

				if (advance < 1)
					break;

			}
			else {

				unsigned char blockbuf[PLAIN_BS];

				int blockbytes = read_block(m_con, m_handle, m_fileid, blockno, blockbuf, context);

				if (blockbytes < 0)
					throw(-1);

				if (blockbytes < 1)
					break;

				int blockcpy = (int)min(bytesleft, blockbytes - blockoff);

				if (blockcpy < 1)
					break;

				memcpy(p, blockbuf + blockoff, blockcpy);

				advance = blockcpy;
			}

			p += advance;
			offset += advance;
			bytesleft -= advance;
			*pNread += advance;
		}
	} catch (...) {
		bRet = FALSE;
	}

	if (context)
		free_crypt_context(context);

	return bRet;
}


// write version and fileid to empty file before writing to it

BOOL CryptFile::WriteVersionAndFileId()
{
	LARGE_INTEGER l;
	l.QuadPart = 0;

	if (!SetFilePointerEx(m_handle, l, NULL, FILE_BEGIN))
		return FALSE;

	if (!get_random_bytes(m_fileid, FILE_ID_LEN))
		return FALSE;

	m_version = CRYPT_VERSION;

	unsigned short version = MakeBigEndian(m_version);

	DWORD nWritten = 0;

	if (!WriteFile(m_handle, &version, sizeof(version), &nWritten, NULL)) {
		return FALSE;
	}

	if (nWritten != sizeof(version))
		return FALSE;

	if (!WriteFile(m_handle, m_fileid, FILE_ID_LEN, &nWritten, NULL)) {
		return FALSE;
	}

	return nWritten == FILE_ID_LEN;
}


BOOL CryptFile::Write(const unsigned char *buf, DWORD buflen, LPDWORD pNwritten, LONGLONG offset, BOOL bWriteToEndOfFile)
{

	BOOL bRet = TRUE;

	if (bWriteToEndOfFile) {
		LARGE_INTEGER l;
		if (!GetFileSizeEx(m_handle, &l)) 
			return FALSE;
		if (!adjust_file_size_down(l))
			return FALSE;
		offset = l.QuadPart;
	}

	if (!pNwritten || !buf)
		return FALSE;

	if (buflen < 1)
		return TRUE;

	if (m_is_empty) {
		if (!WriteVersionAndFileId())
			return FALSE;

		m_is_empty = false;
	}

	*pNwritten = 0;

	LONGLONG bytesleft = buflen;

	const unsigned char *p = buf;

	void *context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

	if (!context)
		return FALSE;

	try {

		while (bytesleft > 0) {

			LONGLONG blockno = offset / PLAIN_BS;
			int blockoff = (int)(offset % PLAIN_BS);

			int advance;

			if (blockoff == 0 && bytesleft >= PLAIN_BS) { // overwriting whole blocks

				advance = write_block(m_con, m_handle, m_fileid, blockno, p, PLAIN_BS, context);

				if (advance != PLAIN_BS)
					throw(-1);

			}
			else { // else read-modify-write 

				unsigned char blockbuf[PLAIN_BS];

				memset(blockbuf, 0, sizeof(blockbuf));

				int blockbytes = read_block(m_con, m_handle, m_fileid, blockno, blockbuf, context);

				if (blockbytes < 0) {
					bRet = FALSE;
					break;
				}

				int blockcpy = (int)min(bytesleft, PLAIN_BS - blockoff);

				if (blockcpy < 1)
					break;

				memcpy(blockbuf + blockoff, p, blockcpy);

				int blockwrite = max(blockoff + blockcpy, blockbytes);

				int nWritten = write_block(m_con, m_handle, m_fileid, blockno, blockbuf, blockwrite, context);

				advance = blockcpy;

				if (nWritten != blockwrite)
					throw(-1);

			}

			p += advance;
			offset += advance;
			bytesleft -= advance;
			*pNwritten += advance;

		}
	} catch (...) {
		bRet = FALSE;
	}

	*pNwritten = min(*pNwritten, buflen);

	if (context)
		free_crypt_context(context);

	return bRet;
	
}

BOOL
CryptFile::LockFile(LONGLONG ByteOffset, LONGLONG Length)
{
	long long start_block = ByteOffset / PLAIN_BS;

	long long end_block = (ByteOffset + Length + PLAIN_BS - 1) / PLAIN_BS;

	long long start_offset = CIPHER_FILE_OVERHEAD + start_block*CIPHER_BS;

	long long end_offset = CIPHER_FILE_OVERHEAD + end_block*CIPHER_BS;

	long long length = end_offset - start_offset;

	
	LARGE_INTEGER off, len;

	off.QuadPart = start_offset;

	len.QuadPart = length;

	return ::LockFile(m_handle, off.LowPart, off.HighPart, len.LowPart, len.HighPart);
}

BOOL
CryptFile::UnlockFile(LONGLONG ByteOffset, LONGLONG Length)
{
	long long start_block = ByteOffset / PLAIN_BS;

	long long end_block = (ByteOffset + Length + PLAIN_BS - 1) / PLAIN_BS;

	long long start_offset = CIPHER_FILE_OVERHEAD + start_block*CIPHER_BS;

	long long end_offset = CIPHER_FILE_OVERHEAD + end_block*CIPHER_BS;

	long long length = end_offset - start_offset;


	LARGE_INTEGER off, len;

	off.QuadPart = start_offset;

	len.QuadPart = length;

	return ::UnlockFile(m_handle, off.LowPart, off.HighPart, len.LowPart, len.HighPart);
}

BOOL
CryptFile::SetEndOfFile(LONGLONG offset)
{

	LARGE_INTEGER fileSize;


	if (m_handle == NULL || m_handle == INVALID_HANDLE_VALUE)
		return FALSE;

	if (!GetFileSizeEx(m_handle, &fileSize)) {
		return FALSE;
	}

	if (m_is_empty && offset != 0) {
		if (!WriteVersionAndFileId())
			return FALSE;

		m_is_empty = false;
	}

	LARGE_INTEGER size_down = fileSize;

	if (!adjust_file_size_down(size_down)) {
		return FALSE;
	}

	LARGE_INTEGER up_off;
	up_off.QuadPart = offset;
	
	if (!adjust_file_size_up(up_off))
		return FALSE;

	long long last_block = offset / PLAIN_BS;

	int last_off = (int)(offset % PLAIN_BS);
	
	if (offset >= size_down.QuadPart || last_off == 0) { // not really sure what to do about growing files
		DbgPrint(L"setting end of file at %d\n", (int)up_off.QuadPart);
		if (!SetFilePointerEx(m_handle, up_off, NULL, FILE_BEGIN))
			return FALSE;

		return ::SetEndOfFile(m_handle);
	}

	
	// need to re-write truncated last block

	unsigned char buf[PLAIN_BS];

	void *context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

	if (!context)
		return FALSE;

	int nread = read_block(m_con, m_handle, m_fileid, last_block, buf, context);

	if (nread < 0) {
		free_crypt_context(context);
		return FALSE;
	}

	if (nread < 1) { // shouldn't happen
		free_crypt_context(context);
		if (!SetFilePointerEx(m_handle, up_off, NULL, FILE_BEGIN)) {
			return FALSE;
		}
		return ::SetEndOfFile(m_handle);
	}

	int nwritten = write_block(m_con, m_handle, m_fileid, last_block, buf, last_off, context);

	free_crypt_context(context);

	if (nwritten != last_off)
		return FALSE;

	if (!SetFilePointerEx(m_handle, up_off, NULL, FILE_BEGIN))
		return FALSE;

	return ::SetEndOfFile(m_handle);

}
