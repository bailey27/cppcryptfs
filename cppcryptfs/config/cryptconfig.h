/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2018 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include <vector>

#include "util/LockZeroBuffer.h"

#define MAX_CONFIG_FILE_SIZE (16*1024*1024) // 16MB

#define DEFAULT_VOLUME_SERIAL_NUMBER 0xb2a1d417

class CryptContext;

class CryptConfig
{
public:
	int m_N;
	int m_R;
	int m_P;

	bool m_PlaintextNames;
private:
	LockZeroBuffer<unsigned char> *m_pKeyBuf;
	LockZeroBuffer<BYTE> *m_pGcmContentKey;
	bool m_DirIV;
public:
	bool DirIV() { return m_DirIV; };
	bool m_EMENames;
	bool m_GCMIV128;
	bool m_LongNames;
	bool m_AESSIV;
	bool m_Raw64;
	bool m_HKDF;

	bool m_reverse;

	int m_Version;
	std::wstring m_VolumeName;

	std::vector<unsigned char> m_encrypted_key_salt;
	std::vector<unsigned char> m_encrypted_key;


	std::wstring m_basedir;  // the real root of the fs

	DWORD m_serial; // windows volume serial number - derived from root diriv or from hash of root dir

	std::wstring m_mountpoint;

	const unsigned char *GetMasterKey() { return m_pKeyBuf ? m_pKeyBuf->m_buf : NULL; }
	int GetMasterKeyLength() { return m_pKeyBuf ? m_pKeyBuf->m_len : 0; }
	const WCHAR *GetMountPoint() { return m_mountpoint.c_str(); }
	const WCHAR *GetBaseDir() { return m_basedir.c_str(); }
	bool CryptConfig::InitGCMContentKey(const BYTE *key, bool hkdf);

	const BYTE *GetGcmContentKey() { return m_HKDF ? m_pGcmContentKey->m_buf : GetMasterKey(); };

	CryptConfig();
	bool read(std::wstring& mes, const WCHAR *config_file_path = NULL, bool reverse = false);
	bool decrypt_key(LPCTSTR password);

	bool create(const WCHAR *path, const WCHAR *specified_config_path, const WCHAR *password, bool eme, bool plaintext, bool longfilenames, 
					bool siv, bool reverse, const WCHAR *volume_name, std::wstring& error_mes);

	bool check_config(std::wstring& mes);

	bool write_volume_name();

	bool init_serial(CryptContext *con);

	WCHAR get_base_drive_letter();

	virtual ~CryptConfig();
};



