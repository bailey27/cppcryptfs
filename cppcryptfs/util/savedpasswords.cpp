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

#include "stdafx.h"
#include <Wincrypt.h>
#include "cppcryptfs.h"
#include "savedpasswords.h"
#include "util.h"
#include "LockZeroBuffer.h"

#include <list>

int SavedPasswords::ClearSavedPasswords(BOOL bDelete)
{

	int count = 0;
	
	LPCWSTR reg_path = theApp.m_pszRegistryKey;

	HKEY hk_pws;

	LSTATUS status = RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\cppcryptfs\\cppcryptfs\\" SAVED_PASSWORDS_SECTION, 0, KEY_ALL_ACCESS, &hk_pws);

	if (status == ERROR_FILE_NOT_FOUND)
		return count;
	else if (status != ERROR_SUCCESS)
		return -1;

	WCHAR hash[256];

	DWORD index = 0;

	DWORD hash_len = sizeof(hash) / sizeof(hash[0]) - 1;

	DWORD type;

	list<wstring> hashes;

	hash_len = sizeof(hash) / sizeof(hash[0]);

	while ((status = RegEnumValue(hk_pws, index, hash, &hash_len, NULL, &type, NULL, NULL)) == ERROR_SUCCESS) {
		index++;
		hash_len = sizeof(hash) / sizeof(hash[0]);
		if (type != REG_BINARY)
			continue;
		hashes.push_back(hash);
	}

	if (status != ERROR_NO_MORE_ITEMS) {
		RegCloseKey(hk_pws);
		return -1;
	}

	if (bDelete) {

		for (auto it : hashes) {
			status = RegDeleteValue(hk_pws, it.c_str());
			if (status != ERROR_SUCCESS) {
				RegCloseKey(hk_pws);
				return -1;
			}
			count++;
		}
	} else {
		count = (int)hashes.size();
	}

	RegCloseKey(hk_pws);

	return count;
}

BOOL SavedPasswords::SavePassword(LPCWSTR path, LPCWSTR password)
{
	wstring hash;

	if (!GetPathHash(path, hash)) {
		return FALSE;
	}

	LockZeroBuffer<WCHAR> *pBuf = NULL;


	DWORD len = (DWORD)wcslen(password);

	if (len < 1)
		return FALSE;

	if (len < MIN_SAVED_PASSWORD_LEN) {
		pBuf = new LockZeroBuffer<WCHAR>(MIN_SAVED_PASSWORD_LEN, true);
		wcscpy_s(pBuf->m_buf, MIN_SAVED_PASSWORD_LEN, password);
		password = pBuf->m_buf;
		len = MIN_SAVED_PASSWORD_LEN;
	} else {
		len += 1;
	}

	DATA_BLOB pw_blob;
	DATA_BLOB enc_pw_blob;
	DATA_BLOB optional_entropy;

	const char *entropy = OPTIONAL_ENTROPY;
	optional_entropy.cbData = (DWORD)strlen(entropy);
	optional_entropy.pbData = (BYTE*)entropy;

	pw_blob.cbData = len*sizeof(WCHAR);
	pw_blob.pbData = (BYTE*)password;

	bool bResult = CryptProtectData(&pw_blob, NULL, &optional_entropy, NULL, NULL, 0, &enc_pw_blob);
	
	if (pBuf)
		delete pBuf;
		

	if (!bResult)
		return FALSE;

	BOOL bRet = theApp.WriteProfileBinary(SAVED_PASSWORDS_SECTION, hash.c_str(), enc_pw_blob.pbData, enc_pw_blob.cbData);

	LocalFree(enc_pw_blob.pbData);

	return bRet;
}

BOOL SavedPasswords::RetrievePassword(LPCWSTR path, LPWSTR password_buf, DWORD password_buf_len)
{
	wstring hash;

	if (!GetPathHash(path, hash))
		return FALSE;

	BYTE *p = NULL;
	UINT len = 0;
	if (!theApp.GetProfileBinary(SAVED_PASSWORDS_SECTION, hash.c_str(), &p, &len))
		return FALSE;

	DATA_BLOB pw_blob;
	DATA_BLOB enc_pw_blob;

	DATA_BLOB optional_entropy;
	const char *entropy = OPTIONAL_ENTROPY;
	optional_entropy.cbData = (DWORD)strlen(entropy);
	optional_entropy.pbData = (BYTE*)entropy;

	enc_pw_blob.cbData = len;
	enc_pw_blob.pbData = p;

	BOOL bResult = CryptUnprotectData(&enc_pw_blob, NULL, &optional_entropy, NULL, NULL, 0, &pw_blob);

	if (!bResult) {
		delete[] p;
		return FALSE;
	}

	wcscpy_s(password_buf, password_buf_len, (WCHAR*)pw_blob.pbData);

	SecureZeroMemory(pw_blob.pbData, pw_blob.cbData);

	LocalFree(pw_blob.pbData);

	delete[] p;

	return TRUE;
}

int SavedPasswords::GetSavedPasswordsCount()
{
	return 0;
}

SavedPasswords::SavedPasswords()
{

}

SavedPasswords::~SavedPasswords()
{

}
