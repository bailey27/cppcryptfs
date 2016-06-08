#pragma once

#include <windows.h>
class CryptContext;

class CryptFile
{
public:
	HANDLE m_handle;

	unsigned char m_fileid[16];

	unsigned short m_version;

	bool m_is_empty;

	CryptContext *m_con;

	BOOL Associate(CryptContext *con, HANDLE hfile);

	BOOL Read(unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset);

	BOOL Write(const unsigned char *buf, DWORD buflen, LPDWORD pNwritten, LONGLONG offset, BOOL bWriteToEndOfFile);

	BOOL SetEndOfFile(LONGLONG offset);

	BOOL LockFile(LONGLONG ByteOffset, LONGLONG Length);

	BOOL UnlockFile(LONGLONG ByteOffset, LONGLONG Length);

	CryptFile();

	~CryptFile();

protected:
	BOOL WriteVersionAndFileId();
};

