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
#include "crypt/cryptdefs.h"
#include "filename/cryptfilename.h"
#include "util/fileutil.h"
#include "util/util.h"
#include "crypt/crypt.h"
#include "cryptio.h"
#include "cryptfile.h"
#include "iobufferpool.h"

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
	m_pkdc = nullptr;
	m_real_file_size = (long long)-1;
	memset(&m_header, 0, sizeof(m_header));	
}


CryptFile::~CryptFile()
{
	// don't close 

	if (m_pkdc)
		delete m_pkdc;
}

void CryptFile::GetKeys()
{
	if (!m_pkdc) {
		assert(m_con);
		if (!m_con)
			throw(std::exception("CryptFile::GetKeys() called with null context"));
		m_pkdc = new KeyDecryptor(&m_con->GetConfig()->m_keybuf_manager);
	}
}

CryptFileForward::CryptFileForward()
{
	m_bExclusiveLock = false;
	m_openfile = nullptr;
}

CryptFileForward::~CryptFileForward()
{
	Unlock();
}

BOOL
CryptFileForward::Associate(CryptContext *con, HANDLE hfile, LPCWSTR inputPath, bool bForWrite)
{
	m_openfile = con->m_openfiles.GetOpenFile(inputPath);

	if (!m_openfile) {
		assert(false);
		return FALSE;
	}

	m_bExclusiveLock = bForWrite;

	// the destructor does the unlocking
	Lock();

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

	OVERLAPPED ov;
	SetOverlapped(&ov, l.QuadPart);

	DWORD nread;

	if (!ReadFile(hfile, &m_header, sizeof(m_header), &nread, &ov)) {
		DWORD error = GetLastError();
		DbgPrint(L"ASSOCIATE: failed to read header, error = %d\n", error);
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

	shared_ptr<EVP_CIPHER_CTX> context;
	GetKeys();
	if (!m_con->GetConfig()->m_AESSIV) {
		context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

		if (!context)
			return FALSE;
	} 

	BOOL bRet = TRUE;

	IoBuffer *iobuf = NULL;
	BYTE *inputbuf = NULL;
	int bytesinbuf = 0;
	int inputbuflen = 0;
	int inputbufpos = 0;

	int blocks_spanned = (int)(((offset + buflen - 1) / PLAIN_BS) - (offset / PLAIN_BS)) + 1;

	OVERLAPPED ov;
	memset(&ov, 0, sizeof(ov));

	try {

		if (blocks_spanned > 1 && m_con->m_bufferblocks > 1) {
			inputbuflen = min(m_con->m_bufferblocks, blocks_spanned)*CIPHER_BS;
			iobuf = IoBufferPool::getInstance().GetIoBuffer(inputbuflen, 0);
			if (iobuf == NULL) {
				SetLastError(ERROR_OUTOFMEMORY);
				throw(-1);
			}
			inputbuf = iobuf->m_pBuf;

			long long blockoff = FILE_HEADER_LEN + (offset / PLAIN_BS)*CIPHER_BS;

			SetOverlapped(&ov, blockoff);
		}

		while (bytesleft > 0) {

			LONGLONG blockno = offset / PLAIN_BS;
			int blockoff = (int)(offset % PLAIN_BS);

			int advance;

			if (inputbuf && bytesinbuf < 1) {
				DWORD nRead = 0;
				DWORD blocksleft =  (DWORD)(((offset + bytesleft - 1) / PLAIN_BS) - (offset / PLAIN_BS)) + 1;
				DWORD readlen = min((DWORD)inputbuflen, blocksleft*CIPHER_BS);
				if (!ReadFile(m_handle, inputbuf, readlen, &nRead, &ov)) {
					auto LastErr = ::GetLastError();
					if (LastErr != ERROR_HANDLE_EOF)
						throw(-1);
				}
				
				IncOverlapped(&ov, nRead);

				bytesinbuf = nRead;
				inputbufpos = 0;
			}

			if (blockoff == 0 && bytesleft >= PLAIN_BS) {

				if (inputbuf) {
					int consumed = 0;
					advance = read_block(m_con, INVALID_HANDLE_VALUE, inputbuf + inputbufpos, bytesinbuf, &consumed, m_header.fileid, blockno, p, context.get());
					inputbufpos += consumed;
					bytesinbuf -= consumed;
				} else {
					advance = read_block(m_con, m_handle, NULL, 0, NULL, m_header.fileid, blockno, p, context.get());
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
					blockbytes = read_block(m_con, INVALID_HANDLE_VALUE, inputbuf + inputbufpos, bytesinbuf, &consumed, m_header.fileid, blockno, blockbuf, context.get());
					inputbufpos += consumed;
					bytesinbuf -= consumed;
				} else {
					blockbytes = read_block(m_con, m_handle, NULL, 0, NULL, m_header.fileid, blockno, blockbuf, context.get());
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

	if (iobuf)
		IoBufferPool::getInstance().ReleaseIoBuffer(iobuf);

	return bRet;
}

BOOL CryptFileForward::FlushOutput(LONGLONG& beginblock, BYTE *outputbuf, int& outputbytes)
{
	long long outputoffset = FILE_HEADER_LEN + beginblock*CIPHER_BS;

	GoShared();

	OVERLAPPED ov;
	SetOverlapped(&ov, outputoffset);

	DWORD outputwritten;	

	if (!WriteFile(m_handle, outputbuf, outputbytes, &outputwritten, &ov)) {
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

	OVERLAPPED ov;
	memset(&ov, 0, sizeof(ov));

	if (!get_random_bytes(m_con, m_header.fileid, FILE_ID_LEN))
		return FALSE;

	unsigned short version = CRYPT_VERSION;

	m_header.version = MakeBigEndian(version);

	DWORD nWritten = 0;

	if (!WriteFile(m_handle, &m_header, sizeof(m_header), &nWritten, &ov)) {
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

	shared_ptr<EVP_CIPHER_CTX> context;
	GetKeys();
	if (!m_con->GetConfig()->m_AESSIV) {
		context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

		if (!context)
			return FALSE;
	} 

	IoBuffer *iobuf = NULL;
	BYTE *outputbuf = NULL;
	int outputbytes = 0;
	int outputbuflen = 0;
	LONGLONG beginblock;

	int blocks_spanned = (int)(((offset + buflen - 1) / PLAIN_BS) - (offset / PLAIN_BS)) + 1;

	BYTE* ivbufptr = nullptr;
	BYTE* ivbufbase = nullptr;

	BYTE ivbuf[4096];

	bool ivsonstack = static_cast<size_t>(blocks_spanned) * BLOCK_IV_LEN <= sizeof(ivbuf);

	try {

		if (blocks_spanned > 1 && m_con->m_bufferblocks > 1) {
			outputbuflen = min(m_con->m_bufferblocks, blocks_spanned)*CIPHER_BS;
			iobuf = IoBufferPool::getInstance().GetIoBuffer(outputbuflen, ivsonstack ? 0 : static_cast<size_t>(blocks_spanned) * BLOCK_IV_LEN);
			if (iobuf == NULL) {
				::SetLastError(ERROR_OUTOFMEMORY);
				throw(-1);
			}
			outputbuf = iobuf->m_pBuf;
			if (ivsonstack)
				ivbufptr = ivbufbase = ivbuf;
			else
				ivbufptr = ivbufbase = iobuf->m_pIvBuf;
		} else {
			if (ivsonstack) {
				ivbufptr = ivbufbase = ivbuf;
			} else {
				iobuf = IoBufferPool::getInstance().GetIoBuffer(0, static_cast<size_t>(blocks_spanned) * BLOCK_IV_LEN);
				if (iobuf == NULL) {
					::SetLastError(ERROR_OUTOFMEMORY);
					throw(-1);
				}
				ivbufptr = ivbufbase = iobuf->m_pIvBuf;
			}
		}

		if (!get_random_bytes(m_con, ivbufptr, blocks_spanned * BLOCK_IV_LEN)) {
			throw(-1);
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

				GoShared();

				if (outputbuf) {
					if (outputbytes == 0)
						beginblock = blockno;

					advance = write_block(m_con, outputbuf + outputbytes, INVALID_HANDLE_VALUE, m_header.fileid, blockno, p, PLAIN_BS, context.get(), ivbufptr);
					ivbufptr += BLOCK_IV_LEN;
					
					if (advance == CIPHER_BS) {
						advance = PLAIN_BS;
					} else {
						throw(-1);
					}
					outputbytes += CIPHER_BS;
				} else {
					advance = write_block(m_con, cipher_buf, m_handle, m_header.fileid, blockno, p, PLAIN_BS, context.get(), ivbufptr);
					ivbufptr += BLOCK_IV_LEN;

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

				// we need exclusive access
				GoExclusive();

				int blockbytes = read_block(m_con, m_handle, NULL, 0, NULL, m_header.fileid, blockno, blockbuf, context.get());

				if (blockbytes < 0) {
					bRet = FALSE;
					break;
				}

				int blockcpy = (int)min(bytesleft, PLAIN_BS - blockoff);

				if (blockcpy < 1)
					break;

				memcpy(blockbuf + blockoff, p, blockcpy);

				int blockwrite = max(blockoff + blockcpy, blockbytes);

				int nWritten = write_block(m_con, cipher_buf, m_handle, m_header.fileid, blockno, blockbuf, blockwrite, context.get(), ivbufptr);
				ivbufptr += BLOCK_IV_LEN;

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

	if (iobuf)
		IoBufferPool::getInstance().ReleaseIoBuffer(iobuf);	

	// we didn't use all ivs or went past the end of our ivs which is bad
	if (ivbufptr != ivbufbase + static_cast<size_t>(blocks_spanned) * BLOCK_IV_LEN) {
		assert(false);
		::SetLastError(ERROR_BAD_LENGTH);
		bRet = FALSE;
	}

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
			return SetEndOfFileInternal(up_off);
		} else {
			return TRUE;
		}
	}

	// need to re-write truncated or expanded last block

	unsigned char buf[PLAIN_BS];

	memset(buf, 0, sizeof(buf));

	shared_ptr<EVP_CIPHER_CTX> context;
	GetKeys();
	if (!m_con->GetConfig()->m_AESSIV) {
		context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

		if (!context)
			return FALSE;
	} 

	int nread = read_block(m_con, m_handle, NULL, 0, NULL, m_header.fileid, last_block, buf, context.get());

	if (nread < 0) {	
		return FALSE;
	}

	if (nread < 1) { // shouldn't happen		
		if (bSet) {
			return SetEndOfFileInternal(up_off);
		} else {
			return TRUE;
		}
	}

	// if growing the file, then we're appending to_write zero bytes to the last block
	if (growing)
		to_write = min(to_write + nread, PLAIN_BS);

	BYTE cipher_buf[CIPHER_BS];

	BYTE iv[BLOCK_IV_LEN];

	if (!get_random_bytes(m_con, iv, BLOCK_IV_LEN)) {		
		return FALSE;
	}

	int nwritten = write_block(m_con, cipher_buf, m_handle, m_header.fileid, last_block, buf, to_write, context.get(), iv);	

	if (nwritten != to_write)
		return FALSE;

	if (bSet) {
		return SetEndOfFileInternal(up_off);
	} else {
		return TRUE;
	}

}

BOOL CryptFileForward::SetEndOfFileInternal(LARGE_INTEGER& off)
{
#if 0 
	// now handled by per-file (not per-handle) shared mutex
	// below is the old comment

	// the calls to set the file pointer and then the end of file
	// need to be made atomic (serialized)
	lock_guard<mutex> lock(m_con->m_file_pointer_mutex);
#endif

	if (!SetFilePointerEx(m_handle, off, NULL, FILE_BEGIN))
		return FALSE;

	return ::SetEndOfFile(m_handle);
}

CryptFileReverse::CryptFileReverse()
{
	memset(m_block0iv, 0, sizeof(m_block0iv));
}

CryptFileReverse::~CryptFileReverse()
{
	// do not close m_handle
}


BOOL CryptFileReverse::Associate(CryptContext *con, HANDLE hfile, LPCWSTR inputPath, bool /* unused*/)
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

	shared_ptr<EVP_CIPHER_CTX> context;
	GetKeys();
	if (!m_con->GetConfig()->m_AESSIV) {
		context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

		if (!context)
			return FALSE;
	} 

	BOOL bRet = TRUE;

	try {

		if (offset < sizeof(m_header)) {
			long long copylen = min(sizeof(m_header) - offset, min(bytesleft, sizeof(m_header)));
			memcpy(p, (BYTE*)&m_header + offset, static_cast<size_t>(copylen));
			bytesleft -= copylen;
			offset += copylen;
			p += copylen;
			*pNread += (int)copylen;
		} 

		while (bytesleft > 0) {	

			LONGLONG blockno = (offset - sizeof(m_header)) / CIPHER_BS;

			int blockoff = (int)((offset - sizeof(m_header)) % CIPHER_BS);

			OVERLAPPED ov;
			SetOverlapped(&ov, blockno * PLAIN_BS);

			int advance;

			BYTE plain_buf[PLAIN_BS];

			if (blockoff == 0 && bytesleft >= CIPHER_BS) {
				DWORD nRead = 0;
				if (!ReadFile(m_handle, plain_buf, sizeof(plain_buf), &nRead, &ov)) {
					auto LastErr = ::GetLastError();
					if (LastErr == ERROR_HANDLE_EOF) {
						bRet = TRUE;
					} else {
						bRet = FALSE;
					}
					break;
				}

				if (nRead == 0) {
					bRet = TRUE;
					break;
				}
			
				// advance = read_block(m_con, m_handle, m_header.fileid, blockno, p, context);
				advance = write_block(m_con, p, INVALID_HANDLE_VALUE, m_header.fileid, blockno, plain_buf, (int)nRead, context.get(), m_block0iv);

				if (advance < 0)
					throw(-1);

				if (advance < 1)
					break;

			} else {

				unsigned char blockbuf[CIPHER_BS];
				DWORD nRead = 0;
				if (!ReadFile(m_handle, plain_buf, sizeof(plain_buf), &nRead, &ov)) {
					auto LastErr = ::GetLastError();
					if (LastErr == ERROR_HANDLE_EOF) {
						bRet = TRUE;
					} else {
						bRet = FALSE;
					}
					break;
				}

				if (nRead == 0) {
					bRet = TRUE;
					break;
				}

				//int blockbytes = read_block(m_con, m_handle, m_header.fileid, blockno, blockbuf, context);
				int blockbytes = write_block(m_con, blockbuf, INVALID_HANDLE_VALUE, m_header.fileid, blockno, plain_buf, (int)nRead, context.get(), m_block0iv);

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

	return bRet;
}
