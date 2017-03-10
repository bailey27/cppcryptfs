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

#include <string>

class CryptContext;

typedef struct struct_FileHeader {
	unsigned short version;
	unsigned char fileid[FILE_ID_LEN];
} FileHeader;

class CryptFile {
public:

	FileHeader m_header;
	LONGLONG m_real_file_size;
	bool m_is_empty;	

	HANDLE m_handle;

	std::wstring m_path;

	CryptContext *m_con;

	static CryptFile *NewInstance(CryptContext *con);

	virtual BOOL Associate(CryptContext *con, HANDLE hfile, LPCWSTR ptPath) = 0;

	virtual BOOL Read(unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset) = 0;

	virtual BOOL Write(const unsigned char *buf, DWORD buflen, LPDWORD pNwritten, LONGLONG offset, BOOL bWriteToEndOfFile, BOOL bPagingIo) = 0;

	virtual BOOL SetEndOfFile(LONGLONG offset, BOOL bSet = TRUE) = 0;

	virtual BOOL LockFile(LONGLONG ByteOffset, LONGLONG Length) = 0;

	virtual BOOL UnlockFile(LONGLONG ByteOffset, LONGLONG Length) = 0;

	BOOL NotImplemented() { SetLastError(ERROR_ACCESS_DENIED); return FALSE; };

	CryptFile();
	virtual ~CryptFile();

};

class CryptFileForward:  public CryptFile
{

public:


	virtual BOOL Associate(CryptContext *con, HANDLE hfile, LPCWSTR ptPath);

	virtual BOOL Read(unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset);

	virtual BOOL Write(const unsigned char *buf, DWORD buflen, LPDWORD pNwritten, LONGLONG offset, BOOL bWriteToEndOfFile, BOOL bPagingIo);

	virtual BOOL SetEndOfFile(LONGLONG offset, BOOL bSet = TRUE);

	virtual BOOL LockFile(LONGLONG ByteOffset, LONGLONG Length);

	virtual BOOL UnlockFile(LONGLONG ByteOffset, LONGLONG Length);

	CryptFileForward();

	~CryptFileForward();

protected:
	BOOL FlushOutput(LONGLONG& beginblock, BYTE *outputbuf, int& outputbytes); 
	BOOL WriteVersionAndFileId();


};

class CryptFileReverse:  public CryptFile
{
private:
	BYTE m_block0iv[BLOCK_SIV_LEN];
public:


	virtual BOOL Associate(CryptContext *con, HANDLE hfile, LPCWSTR ptPath);

	virtual BOOL Read(unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset);

	virtual BOOL Write(const unsigned char *buf, DWORD buflen, LPDWORD pNwritten, LONGLONG offset, BOOL bWriteToEndOfFile, BOOL bPagingIo)
	{
		return NotImplemented();
	};

	virtual BOOL SetEndOfFile(LONGLONG offset, BOOL bSet = TRUE) { return NotImplemented(); };

	virtual BOOL LockFile(LONGLONG ByteOffset, LONGLONG Length) { return NotImplemented(); };

	virtual BOOL UnlockFile(LONGLONG ByteOffset, LONGLONG Length) { return NotImplemented(); };

	CryptFileReverse();

	~CryptFileReverse();

};


