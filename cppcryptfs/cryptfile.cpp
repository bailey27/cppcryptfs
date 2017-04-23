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

#include "stdafx.h"
#include "cryptdefs.h"
#include "cryptio.h"
#include "cryptfile.h"
#include "cryptfilename.h"
#include "fileutil.h"
#include "util.h"
#include "crypt.h"

CryptFile *CryptFile::NewInstance(CryptContext *con)
{
	if (con->GetConfig()->m_reverse)
		return new CryptFileReverse;
	else
		return new CryptFileForward;
}

CryptFile::CryptFile()
{
	m_handle = INVALID_HANDLE_VALUE;
	m_is_empty = false;
	m_con = NULL;
	m_real_file_size = (long long)-1;
	memset(&m_header, 0, sizeof(m_header));
}


CryptFile::~CryptFile()
{
	// don't close m_handle
}

CryptFileForward::CryptFileForward()
{
	
}

CryptFileForward::~CryptFileForward()
{

}

BOOL
CryptFileForward::Associate(CryptContext *con, HANDLE hfile, LPCWSTR inputPath)
{

	static_assert(sizeof(m_header) == FILE_HEADER_LEN, "sizeof(m_header) != FILE_HEADER_LEN");

	m_handle = hfile;

	m_con = con;

	LARGE_INTEGER l;

	if (!GetFileSizeEx(hfile, &l)) {
		DbgPrint(L"ASSOCIATE: failed to get size of file\n");
		return FALSE;
	}

	m_real_file_size = l.QuadPart;

	if (l.QuadPart == 0) {
		m_header.version = CRYPT_VERSION;
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


	DWORD nread;

	if (!ReadFile(hfile, &m_header, sizeof(m_header), &nread, NULL)) {
		DbgPrint(L"ASSOCIATE: failed to read header\n");
		return FALSE;
	}

	if (nread != FILE_HEADER_LEN) {
		DbgPrint(L"ASSOCIATE: wrong number of bytes read when reading file header\n");
		return FALSE;
	}

	m_header.version = MakeBigEndianNative(m_header.version);

	if (m_header.version != CRYPT_VERSION) {
		DbgPrint(L"ASSOCIATE: file version mismatch\n");
		return FALSE;
	}

	static BYTE zerobytes[FILE_ID_LEN] = { 0 };

	if (!memcmp(m_header.fileid, zerobytes, sizeof(m_header.fileid))) {
		DbgPrint(L"ASSOCIATE: fileid is all zeroes\n");
		return FALSE;
	}


	return TRUE;
}


BOOL CryptFileForward::Read(unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset)
{


	if (m_real_file_size == (long long)-1)
		return FALSE;

	if (!pNread || !buf)
		return FALSE;

	*pNread = 0;

	if (buflen == 0) {
		return TRUE;
	}

	LONGLONG bytesleft = buflen;

	unsigned char *p = buf;

	void *context;

	if (!m_con->GetConfig()->m_AESSIV) {
		context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

		if (!context)
			return FALSE;
	} else {
		context = NULL;
	}

	BOOL bRet = TRUE;

	BYTE *inputbuf = NULL;
	int bytesinbuf = 0;
	int inputbuflen = 0;
	int inputbufpos = 0;

	int blocks_spanned = (int)(((offset + buflen - 1) / PLAIN_BS) - (offset / PLAIN_BS)) + 1;

	try {

		if (blocks_spanned > 1 && m_con->m_bufferblocks > 1) {
			inputbuflen = min(m_con->m_bufferblocks, blocks_spanned)*CIPHER_BS;
			inputbuf = new BYTE[inputbuflen];

			long long blockoff = FILE_HEADER_LEN + (offset / PLAIN_BS)*CIPHER_BS;

			LARGE_INTEGER l;

			l.QuadPart = blockoff;

			if (!SetFilePointerEx(m_handle, l, NULL, FILE_BEGIN)) {
				 throw(-1);
			}
			
		}

		while (bytesleft > 0) {

			LONGLONG blockno = offset / PLAIN_BS;
			int blockoff = (int)(offset % PLAIN_BS);

			int advance;

			if (inputbuf && bytesinbuf < 1) {
				DWORD nRead = 0;
				DWORD blocksleft =  (DWORD)(((offset + bytesleft - 1) / PLAIN_BS) - (offset / PLAIN_BS)) + 1;
				DWORD readlen = min((DWORD)inputbuflen, blocksleft*CIPHER_BS);
				if (!ReadFile(m_handle, inputbuf, readlen, &nRead, NULL)) {
					throw(-1);
				}
				bytesinbuf = nRead;
				inputbufpos = 0;
			}

			if (blockoff == 0 && bytesleft >= PLAIN_BS) {

				if (inputbuf) {
					int consumed = 0;
					advance = read_block(m_con, INVALID_HANDLE_VALUE, inputbuf + inputbufpos, bytesinbuf, &consumed, m_header.fileid, blockno, p, context);
					inputbufpos += consumed;
					bytesinbuf -= consumed;
				} else {
					advance = read_block(m_con, m_handle, NULL, 0, NULL, m_header.fileid, blockno, p, context);
				}

				if (advance < 0)
					throw(-1);

				if (advance < 1)
					break;

			} else {

				unsigned char blockbuf[PLAIN_BS];

				int blockbytes = 0;

				if (inputbuf) {
					int consumed = 0;
					blockbytes = read_block(m_con, INVALID_HANDLE_VALUE, inputbuf + inputbufpos, bytesinbuf, &consumed, m_header.fileid, blockno, blockbuf, context);
					inputbufpos += consumed;
					bytesinbuf -= consumed;
				} else {
					blockbytes = read_block(m_con, m_handle, NULL, 0, NULL, m_header.fileid, blockno, blockbuf, context);
				}

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

	if (inputbuf)
		delete[] inputbuf;

	return bRet;
}

BOOL CryptFileForward::FlushOutput(LONGLONG& beginblock, BYTE *outputbuf, int& outputbytes)
{
	long long outputoffset = FILE_HEADER_LEN + beginblock*CIPHER_BS;

	LARGE_INTEGER l;

	l.QuadPart = outputoffset;

	if (!SetFilePointerEx(m_handle, l, NULL, FILE_BEGIN)) {
		return FALSE;
	}

	DWORD outputwritten;

	if (!WriteFile(m_handle, outputbuf, outputbytes, &outputwritten, NULL)) {
		return FALSE;
	}

	if (outputwritten != outputbytes) {
		return FALSE;
	}

	outputbytes = 0;
	beginblock = 0;

	return TRUE;
}

// write version and fileid to empty file before writing to it

BOOL CryptFileForward::WriteVersionAndFileId()
{
	if (m_real_file_size == (long long)-1)
		return FALSE;

	LARGE_INTEGER l;
	l.QuadPart = 0;

	if (!SetFilePointerEx(m_handle, l, NULL, FILE_BEGIN))
		return FALSE;

	if (!get_random_bytes(m_con, m_header.fileid, FILE_ID_LEN))
		return FALSE;

	unsigned short version = CRYPT_VERSION;

	m_header.version = MakeBigEndian(version);

	DWORD nWritten = 0;

	if (!WriteFile(m_handle, &m_header, sizeof(m_header), &nWritten, NULL)) {
		m_header.version = CRYPT_VERSION;
		return FALSE;
	}

	m_header.version = CRYPT_VERSION;

	m_real_file_size = FILE_HEADER_LEN;

	m_is_empty = false;

	return nWritten == FILE_HEADER_LEN;
}


BOOL CryptFileForward::Write(const unsigned char *buf, DWORD buflen, LPDWORD pNwritten, LONGLONG offset, BOOL bWriteToEndOfFile, BOOL bPagingIo)
{
	
	if (m_real_file_size == (long long)-1)
		return FALSE;

	if (!pNwritten || !buf)
		return FALSE;

	*pNwritten = 0;

	if (buflen < 1)
		return TRUE;

	BOOL bRet = TRUE;

	if (bWriteToEndOfFile) {
		LARGE_INTEGER l;
		l.QuadPart = m_real_file_size;
		if (!adjust_file_offset_down(l))
			return FALSE;
		offset = l.QuadPart;
	} else {
		if (bPagingIo) {
			LARGE_INTEGER l;
			l.QuadPart = m_real_file_size;
			if (!adjust_file_offset_down(l))
				return FALSE;

			if (offset >= l.QuadPart)
			{
				DbgPrint(L"CryptFile paging io past end of file, return\n");
				*pNwritten = 0;
				return true;
			}

			if ((offset + buflen) > l.QuadPart)
			{
				DbgPrint(L"CryptFile addjusting write length due to paging io\n");
				buflen = (DWORD)(l.QuadPart - offset);
			}
		}
	}

	if (m_is_empty) {
		if (!WriteVersionAndFileId())
			return FALSE;	
	} else {
		LARGE_INTEGER size_down;
		size_down.QuadPart = m_real_file_size;
		adjust_file_offset_down(size_down);
		// if creating a hole, call this->SetEndOfFile() to deal with last block if necessary
		if (offset > size_down.QuadPart && (size_down.QuadPart % PLAIN_BS)) {
			DbgPrint(L"Calling SetEndOfFile %llu to deal with hole\n", offset);
			SetEndOfFile(offset, FALSE);
		}
	}

	LONGLONG bytesleft = buflen;

	const unsigned char *p = buf;

	void *context;
	
	if (!m_con->GetConfig()->m_AESSIV) {
		context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

		if (!context)
			return FALSE;
	} else {
		context = NULL;
	}

	BYTE *outputbuf = NULL;
	int outputbytes = 0;
	int outputbuflen = 0;
	LONGLONG beginblock;

	int blocks_spanned = (int)(((offset + buflen - 1) / PLAIN_BS) - (offset / PLAIN_BS)) + 1;

	try {

		if (blocks_spanned > 1 && m_con->m_bufferblocks > 1) {
			outputbuflen = min(m_con->m_bufferblocks, blocks_spanned)*CIPHER_BS;
			outputbuf = new BYTE[outputbuflen];
		}

		BYTE cipher_buf[CIPHER_BS];

		while (bytesleft > 0) {

			LONGLONG blockno = offset / PLAIN_BS;
			int blockoff = (int)(offset % PLAIN_BS);

			int advance;

			if (outputbuf && outputbytes == outputbuflen) {
				if (!FlushOutput(beginblock, outputbuf, outputbytes))
					throw(-1);
			}

			if (blockoff == 0 && bytesleft >= PLAIN_BS) { // overwriting whole blocks

				if (outputbuf) {
					if (outputbytes == 0)
						beginblock = blockno;

					advance = write_block(m_con, outputbuf + outputbytes, INVALID_HANDLE_VALUE, m_header.fileid, blockno, p, PLAIN_BS, context);
					
					if (advance == CIPHER_BS) {
						advance = PLAIN_BS;
					} else {
						throw(-1);
					}
					outputbytes += CIPHER_BS;
				} else {
					advance = write_block(m_con, cipher_buf, m_handle, m_header.fileid, blockno, p, PLAIN_BS, context);

					if (advance != PLAIN_BS)
						throw(-1);
				} 
	


			} else { // else read-modify-write 

				if (outputbuf && outputbytes > 0) {
					if (!FlushOutput(beginblock, outputbuf, outputbytes))
						throw(-1);
				}

				unsigned char blockbuf[PLAIN_BS];

				memset(blockbuf, 0, sizeof(blockbuf));

				int blockbytes = read_block(m_con, m_handle, NULL, 0, NULL, m_header.fileid, blockno, blockbuf, context);

				if (blockbytes < 0) {
					bRet = FALSE;
					break;
				}

				int blockcpy = (int)min(bytesleft, PLAIN_BS - blockoff);

				if (blockcpy < 1)
					break;

				memcpy(blockbuf + blockoff, p, blockcpy);

				int blockwrite = max(blockoff + blockcpy, blockbytes);

				int nWritten = write_block(m_con, cipher_buf, m_handle, m_header.fileid, blockno, blockbuf, blockwrite, context);

				advance = blockcpy;

				if (nWritten != blockwrite)
					throw(-1);

			}

			p += advance;
			offset += advance;
			bytesleft -= advance;
			*pNwritten += advance;

		}

		if (outputbuf && outputbytes > 0) {
			if (!FlushOutput(beginblock, outputbuf, outputbytes))
				throw(-1);
		}

	} catch (...) {
		bRet = FALSE;
	}

	*pNwritten = min(*pNwritten, buflen);

	if (outputbuf)
		delete[] outputbuf;

	if (context)
		free_crypt_context(context);

	return bRet;
	
}

BOOL
CryptFileForward::LockFile(LONGLONG ByteOffset, LONGLONG Length)
{
	if (m_real_file_size == (long long)-1)
		return FALSE;

	long long start_block = ByteOffset / PLAIN_BS;

	long long end_block = (ByteOffset + Length - 1) / PLAIN_BS;

	long long start_offset = CIPHER_FILE_OVERHEAD + start_block*CIPHER_BS;

	long long end_offset = CIPHER_FILE_OVERHEAD + end_block*CIPHER_BS;

	long long length = end_offset - start_offset;

	
	LARGE_INTEGER off, len;

	off.QuadPart = start_offset;

	len.QuadPart = length;

	return ::LockFile(m_handle, off.LowPart, off.HighPart, len.LowPart, len.HighPart);
}

BOOL
CryptFileForward::UnlockFile(LONGLONG ByteOffset, LONGLONG Length)
{
	if (m_real_file_size == (long long)-1)
		return FALSE;

	long long start_block = ByteOffset / PLAIN_BS;

	long long end_block = (ByteOffset + Length - 1) / PLAIN_BS;

	long long start_offset = CIPHER_FILE_OVERHEAD + start_block*CIPHER_BS;

	long long end_offset = CIPHER_FILE_OVERHEAD + end_block*CIPHER_BS;

	long long length = end_offset - start_offset;


	LARGE_INTEGER off, len;

	off.QuadPart = start_offset;

	len.QuadPart = length;

	return ::UnlockFile(m_handle, off.LowPart, off.HighPart, len.LowPart, len.HighPart);
}





// re-writes last block of necessary to account for file growing or shrinking
// if bSet is TRUE (the default), actually calls SetEndOfFile()
BOOL
CryptFileForward::SetEndOfFile(LONGLONG offset, BOOL bSet)
{

	if (m_real_file_size == (long long)-1)
		return FALSE;

	if (m_handle == NULL || m_handle == INVALID_HANDLE_VALUE)
		return FALSE;

	if (m_is_empty && offset != 0) {
		if (!WriteVersionAndFileId())
			return FALSE;
	}

	LARGE_INTEGER size_down;

	size_down.QuadPart = m_real_file_size;

	if (!adjust_file_offset_down(size_down)) {
		return FALSE;
	}

	LARGE_INTEGER up_off;

	if (bSet) {
		up_off.QuadPart = offset;
		if (!adjust_file_offset_up_truncate_zero(up_off))
			return FALSE;
	}

	long long last_block;
	int to_write;

	bool growing = false;

	if (offset < size_down.QuadPart) {
		last_block = offset / PLAIN_BS;
		to_write = (int)(offset % PLAIN_BS);
	} else if (offset > size_down.QuadPart) {
		last_block = size_down.QuadPart / PLAIN_BS;
		to_write = size_down.QuadPart % PLAIN_BS ? (int)min(PLAIN_BS, offset - size_down.QuadPart) : 0;
		growing = true;
	} else {
		to_write = 0;
	}

	if (to_write == 0) { 
		if (bSet) {
			DbgPrint(L"setting end of file at %d\n", (int)up_off.QuadPart);
			if (!SetFilePointerEx(m_handle, up_off, NULL, FILE_BEGIN))
				return FALSE;
			return ::SetEndOfFile(m_handle);
		} else {
			return TRUE;
		}
	}

	// need to re-write truncated or expanded last block

	unsigned char buf[PLAIN_BS];

	memset(buf, 0, sizeof(buf));

	void *context;

	if (!m_con->GetConfig()->m_AESSIV) {
		context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

		if (!context)
			return FALSE;
	} else {
		context = NULL;
	}

	int nread = read_block(m_con, m_handle, NULL, 0, NULL, m_header.fileid, last_block, buf, context);

	if (nread < 0) {
		free_crypt_context(context);
		return FALSE;
	}

	if (nread < 1) { // shouldn't happen
		free_crypt_context(context);

		if (bSet) {
			if (!SetFilePointerEx(m_handle, up_off, NULL, FILE_BEGIN)) {
				return FALSE;
			}
			return ::SetEndOfFile(m_handle);
		} else {
			return TRUE;
		}
	}

	// if growing the file, then we're appending to_write zero bytes to the last block
	if (growing)
		to_write = min(to_write + nread, PLAIN_BS);

	BYTE cipher_buf[CIPHER_BS];

	int nwritten = write_block(m_con, cipher_buf, m_handle, m_header.fileid, last_block, buf, to_write, context);

	free_crypt_context(context);

	if (nwritten != to_write)
		return FALSE;

	if (bSet) {
		if (!SetFilePointerEx(m_handle, up_off, NULL, FILE_BEGIN))
			return FALSE;

		return ::SetEndOfFile(m_handle);
	} else {
		return TRUE;
	}

}

CryptFileReverse::CryptFileReverse()
{
	memset(m_block0iv, 0, sizeof(m_block0iv));
}

CryptFileReverse::~CryptFileReverse()
{
	// do not close m_handle
}


BOOL CryptFileReverse::Associate(CryptContext *con, HANDLE hfile, LPCWSTR inputPath)
{
	m_handle = hfile;

	m_con = con;

	LARGE_INTEGER l;

	if (inputPath == NULL) {
		DbgPrint(L"ASSOCIATE: failed because inputPath is NULL\n");
		return FALSE;
	}

	if (!GetFileSizeEx(hfile, &l)) {
		DbgPrint(L"ASSOCIATE: failed to get size of file\n");
		return FALSE;
	}

	m_real_file_size = l.QuadPart;

	if (l.QuadPart == 0) {
		m_header.version = CRYPT_VERSION;
		m_is_empty = true;
		return TRUE;
	} 

	// Here MakeBigEndianNative() is used to ensure that the version
	// stored in the header is in big-endian format
	// (it byte-swaps on a little-endian machine and
	// does nothing on a big-endian machine).
	//
	// This is so we don't have to byte-swap it when reading
	// from the virtual part of the file (the header).
	m_header.version = MakeBigEndianNative((unsigned short)m_con->GetConfig()->m_Version);


	if (!derive_path_iv(m_con, inputPath, m_header.fileid, TYPE_FILEID))
		return FALSE;
	
	if (!derive_path_iv(m_con, inputPath, m_block0iv, TYPE_BLOCK0IV))
		return FALSE;

	return TRUE;
}

BOOL CryptFileReverse::Read(unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset)
{
	if (m_real_file_size == (long long)-1)
		return FALSE;

	if (!pNread || !buf)
		return FALSE;

	*pNread = 0;

	if (m_is_empty) {
		return TRUE;
	}

	LONGLONG bytesleft = buflen;

	unsigned char *p = buf;

	void *context;

	if (!m_con->GetConfig()->m_AESSIV) {
		context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

		if (!context)
			return FALSE;
	} else {
		context = NULL;
	}

	BOOL bRet = TRUE;

	try {

		if (offset < sizeof(m_header)) {
			long long copylen = min(sizeof(m_header) - offset, min(bytesleft, sizeof(m_header)));
			memcpy(p, (BYTE*)&m_header + offset, copylen);
			bytesleft -= copylen;
			offset += copylen;
			p += copylen;
			*pNread += (int)copylen;
		} 

		while (bytesleft > 0) {	

			LONGLONG blockno = (offset - sizeof(m_header)) / CIPHER_BS;

			int blockoff = (int)((offset - sizeof(m_header)) % CIPHER_BS);

			LARGE_INTEGER l;

			l.QuadPart = blockno * PLAIN_BS;

			if (!SetFilePointerEx(m_handle, l, NULL, FILE_BEGIN)) {
				bRet = FALSE;
				break;
			}	

			int advance;

			BYTE plain_buf[PLAIN_BS];

			if (blockoff == 0 && bytesleft >= CIPHER_BS) {
				DWORD nRead = 0;
				if (!ReadFile(m_handle, plain_buf, sizeof(plain_buf), &nRead, NULL)) {
					bRet = FALSE;
					break;
				}

				if (nRead == 0) {
					bRet = TRUE;
					break;
				}
				// advance = read_block(m_con, m_handle, m_header.fileid, blockno, p, context);
				advance = write_block(m_con, p, INVALID_HANDLE_VALUE, m_header.fileid, blockno, plain_buf, (int)nRead, context, m_block0iv);

				if (advance < 0)
					throw(-1);

				if (advance < 1)
					break;

			} else {

				unsigned char blockbuf[CIPHER_BS];
				DWORD nRead = 0;
				if (!ReadFile(m_handle, plain_buf, sizeof(plain_buf), &nRead, NULL)) {
					bRet = FALSE;
					break;
				}

				if (nRead == 0) {
					bRet = TRUE;
					break;
				}

				//int blockbytes = read_block(m_con, m_handle, m_header.fileid, blockno, blockbuf, context);
				int blockbytes = write_block(m_con, blockbuf, INVALID_HANDLE_VALUE, m_header.fileid, blockno, plain_buf, (int)nRead, context, m_block0iv);

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
