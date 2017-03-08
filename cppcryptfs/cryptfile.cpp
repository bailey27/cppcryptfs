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
	m_con = NULL;
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

	m_handle = hfile;

	m_con = con;

	if (!m_con->m_file_id_manager.getencfilename(m_handle, m_path))
		return FALSE;

	return TRUE;
}


BOOL CryptFileForward::Read(unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset)
{

	unsigned char fileid[FILE_ID_LEN];
	bool is_empty;
	LONGLONG real_file_size;

	if (!m_con->m_file_id_manager.get(m_path.c_str(), fileid, is_empty, real_file_size)) {
		return FALSE;
	}

	if (!pNread || !buf)
		return FALSE;

	*pNread = 0;

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

	try {

		if (buflen > 2*PLAIN_BS && m_con->m_bufferblocks > 1) {
			inputbuflen = min((DWORD)m_con->m_bufferblocks*CIPHER_BS, (buflen + PLAIN_BS - 1) / PLAIN_BS*CIPHER_BS);
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
				if (!ReadFile(m_handle, inputbuf, inputbuflen, &nRead, NULL)) {
					throw(-1);
				}
				bytesinbuf = nRead;
				inputbufpos = 0;
			}

			if (blockoff == 0 && bytesleft >= PLAIN_BS) {

				if (inputbuf) {
					int consumed = 0;
					advance = read_block(m_con, INVALID_HANDLE_VALUE, inputbuf + inputbufpos, bytesinbuf, &consumed, fileid, blockno, p, context);
					inputbufpos += consumed;
					bytesinbuf -= consumed;
				} else {
					advance = read_block(m_con, m_handle, NULL, 0, NULL, fileid, blockno, p, context);
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
					blockbytes = read_block(m_con, INVALID_HANDLE_VALUE, inputbuf + inputbufpos, bytesinbuf, &consumed, fileid, blockno, p, context);
					inputbufpos += consumed;
					bytesinbuf -= consumed;
				} else {
					blockbytes = read_block(m_con, m_handle, NULL, 0, NULL, fileid, blockno, blockbuf, context);
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


static void // throws on error 
flushoutput(LONGLONG& beginblock, HANDLE handle, BYTE *outputbuf, int& outputbytes)
{
	long long outputoffset = FILE_HEADER_LEN + beginblock*CIPHER_BS;

	LARGE_INTEGER l;

	l.QuadPart = outputoffset;

	if (!SetFilePointerEx(handle, l, NULL, FILE_BEGIN)) {
		throw(-1);
	}

	DWORD outputwritten;

	if (!WriteFile(handle, outputbuf, outputbytes, &outputwritten, NULL)) {
		throw(-1);
	}
	if (outputwritten != outputbytes) {
		throw(-1);
	}

	outputbytes = 0;
	beginblock = 0;
}

BOOL CryptFileForward::Write(const unsigned char *buf, DWORD buflen, LPDWORD pNwritten, LONGLONG offset, BOOL bWriteToEndOfFile, BOOL bPagingIo)
{
	unsigned char fileid[FILE_ID_LEN];
	bool is_empty;
	LONGLONG real_file_size;

	if (!m_con->m_file_id_manager.get(m_path.c_str(), fileid, is_empty, real_file_size)) {
		return FALSE;
	}

	BOOL bRet = TRUE;

	if (bWriteToEndOfFile) {
		LARGE_INTEGER l;
		l.QuadPart = real_file_size;
		if (!adjust_file_offset_down(l))
			return FALSE;
		offset = l.QuadPart;
	} else {
		if (bPagingIo) {
			LARGE_INTEGER l;
			l.QuadPart = real_file_size;
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

	if (!pNwritten || !buf)
		return FALSE;

	if (buflen < 1)
		return TRUE;

	if (is_empty) {
		if (!m_con->m_file_id_manager.writeheader(m_con, m_path.c_str(), m_handle, fileid)) {
			return FALSE;
		}
	} else {
		LARGE_INTEGER size_down;
		size_down.QuadPart = real_file_size;
		adjust_file_offset_down(size_down);
		// if creating a hole, call this->SetEndOfFile() to deal with last block if necessary
		if (offset > size_down.QuadPart && (size_down.QuadPart % PLAIN_BS)) {
			SetEndOfFile(offset, FALSE);
		}
	}

	*pNwritten = 0;

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

	try {

		if (buflen > PLAIN_BS*2 && m_con->m_bufferblocks > 1) {
			outputbuflen = min((DWORD)m_con->m_bufferblocks*CIPHER_BS, ((buflen + PLAIN_BS - 1) / PLAIN_BS)*CIPHER_BS);
			outputbuf = new BYTE[outputbuflen];
		}

		BYTE cipher_buf[CIPHER_BS];

		while (bytesleft > 0) {

			LONGLONG blockno = offset / PLAIN_BS;
			int blockoff = (int)(offset % PLAIN_BS);

			int advance;

			if (outputbuf && outputbytes == outputbuflen) {
				flushoutput(beginblock, m_handle, outputbuf, outputbytes);
			}

			if (blockoff == 0 && bytesleft >= PLAIN_BS) { // overwriting whole blocks

				if (outputbuf) {
					if (outputbytes == 0)
						beginblock = blockno;

					advance = write_block(m_con, outputbuf + outputbytes, INVALID_HANDLE_VALUE, fileid, blockno, p, PLAIN_BS, context);
					
					if (advance == CIPHER_BS) {
						advance = PLAIN_BS;
					} else {
						throw(-1);
					}
					outputbytes += CIPHER_BS;
				} else {
					advance = write_block(m_con, cipher_buf, m_handle, fileid, blockno, p, PLAIN_BS, context);

					if (advance != PLAIN_BS)
						throw(-1);
				} 
	


			} else { // else read-modify-write 

				if (outputbuf && outputbytes > 0) {
					flushoutput(beginblock, m_handle, outputbuf, outputbytes);
				}

				unsigned char blockbuf[PLAIN_BS];

				memset(blockbuf, 0, sizeof(blockbuf));

				int blockbytes = read_block(m_con, m_handle, NULL, 0, NULL, fileid, blockno, blockbuf, context);

				if (blockbytes < 0) {
					bRet = FALSE;
					break;
				}

				int blockcpy = (int)min(bytesleft, PLAIN_BS - blockoff);

				if (blockcpy < 1)
					break;

				memcpy(blockbuf + blockoff, p, blockcpy);

				int blockwrite = max(blockoff + blockcpy, blockbytes);

				int nWritten = write_block(m_con, cipher_buf, m_handle, fileid, blockno, blockbuf, blockwrite, context);

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
			flushoutput(beginblock, m_handle, outputbuf, outputbytes);
		}

	} catch (...) {
		bRet = FALSE;
	}

	*pNwritten = min(*pNwritten, buflen);

	if (outputbuf)
		delete[] outputbuf;

	if (context)
		free_crypt_context(context);

	if (!m_con->m_file_id_manager.update_file_size(m_path.c_str(), offset + *pNwritten, false)) {
		return FALSE;
	}

	return bRet;
	
}

BOOL
CryptFileForward::LockFile(LONGLONG ByteOffset, LONGLONG Length)
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
CryptFileForward::UnlockFile(LONGLONG ByteOffset, LONGLONG Length)
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





// re-writes last block of necessary to account for file growing or shrinking
// if bSet is TRUE (the default), actually calls SetEndOfFile()
BOOL
CryptFileForward::SetEndOfFile(LONGLONG offset, BOOL bSet)
{


	if (m_handle == NULL || m_handle == INVALID_HANDLE_VALUE)
		return FALSE;

	unsigned char fileid[FILE_ID_LEN];
	bool is_empty;
	LONGLONG real_file_size;

	if (!m_con->m_file_id_manager.get(m_path.c_str(), fileid, is_empty, real_file_size)) {
		return FALSE;
	}

	if (is_empty && offset != 0) {
		if (!m_con->m_file_id_manager.writeheader(m_con, m_path.c_str(), m_handle, fileid))
			return FALSE;
	}

	LARGE_INTEGER size_down;
	
	size_down.QuadPart = real_file_size;

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

	if (offset < size_down.QuadPart) {
		last_block = offset / PLAIN_BS;
		to_write = (int)(offset % PLAIN_BS);
	} else if (offset > size_down.QuadPart) {
		last_block = size_down.QuadPart / PLAIN_BS;
		to_write = size_down.QuadPart % PLAIN_BS ? (int)min(PLAIN_BS, offset - size_down.QuadPart) : 0;
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

	int nread = read_block(m_con, m_handle, NULL, 0, NULL, fileid, last_block, buf, context);

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
	
	BYTE cipher_buf[CIPHER_BS];

	int nwritten = write_block(m_con, cipher_buf, m_handle, fileid, last_block, buf, to_write, context);

	free_crypt_context(context);

	if (nwritten != to_write)
		return FALSE;

	if (bSet) {
		if (!SetFilePointerEx(m_handle, up_off, NULL, FILE_BEGIN))
			return FALSE;
		if (!m_con->m_file_id_manager.update_file_size(m_path.c_str(), offset, true)) {
			return FALSE;
		}
		return ::SetEndOfFile(m_handle);
	} else {
		return TRUE;
	}

}

CryptFileReverse::CryptFileReverse()
{
	memset(&m_header, 0, sizeof(m_header));
	m_real_file_size = -1;
	m_is_empty = true;
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
