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

#include <string>

#include "cryptconfig.h"
#include "cryptcontext.h"
#include "cryptfilename.h"
#include "fileutil.h"
#include "pad16.h"



static const char longname_prefix[] = LONGNAME_PREFIX_A;
static const WCHAR longname_prefixW[] = LONGNAME_PREFIX_W;
static const WCHAR longname_suffix[] = LONGNAME_SUFFIX_W;


bool is_long_name(const WCHAR *filename)
{
	std::wstring path = filename;

	size_t last_slash = path.find_last_of('\\');
	if (last_slash != std::wstring::npos) {
		filename = &path[last_slash + 1];
	} 
	return !wcsncmp(filename, longname_prefixW, sizeof(longname_prefixW) / sizeof(longname_prefixW) - 1);
}

bool is_long_name_file(const WCHAR *filename)
{
	return wcslen(filename) > (LONGNAME_PREFIX_LEN + LONGNAME_SUFFIX_LEN) && !wcsncmp(filename, LONGNAME_PREFIX_W, LONGNAME_PREFIX_LEN) && !wcscmp(filename + wcslen(filename) - LONGNAME_SUFFIX_LEN, LONGNAME_SUFFIX_W);
}


const char * // returns base64-encoded, encrypted filename
encrypt_filename(CryptContext *con, const unsigned char *dir_iv, const WCHAR *filename, std::string& storage, void *context, std::string *actual_encrypted)
{
	std::string utf8_str;

	const char *rs = NULL;

	if (con->GetConfig()->m_PlaintextNames) {
		if (!unicode_to_utf8(filename, storage))
			return NULL;
		return &storage[0];
	}
	
	if (!unicode_to_utf8(filename, utf8_str))
		return NULL;
	

	if (con->GetConfig()->m_EMENames) {

		int paddedLen = 0;
		BYTE *padded = pad16((BYTE*)&utf8_str[0], (int)utf8_str.size(), paddedLen);

		if (!padded)
			return NULL;

		BYTE *ct = EmeTransform(&con->m_eme, (BYTE*)dir_iv, padded, paddedLen, true);

		free(padded);

		if (!ct) {
			return NULL;
		}

		rs = base64_encode(ct, paddedLen, storage);

		delete[] ct;



	} else {

		if (!context)
			return NULL;

		unsigned char ctbuf[4096];

		int ctlen = encrypt((const unsigned char *)&(utf8_str[0]), (int)strlen(&(utf8_str[0])), NULL, 0, con->GetConfig()->GetKey(), dir_iv, ctbuf, NULL, context);

		if (ctlen < 1)
			return NULL;

		
		rs = base64_encode(ctbuf, ctlen, storage);
		
		
	}

	if (con->GetConfig()->m_LongNames && storage.size() > 255) {
		if (actual_encrypted)
			*actual_encrypted = storage;
		BYTE sum[32];
		sha256(storage, sum);
		std::string base64_sum;
		if (!base64_encode(sum, sizeof(sum), base64_sum))
			return NULL;
		storage = longname_prefix;
		storage += base64_sum;
		rs = &storage[0];
	}

	return rs;
}

const WCHAR * // returns base64-encoded, encrypted filename
encrypt_filename(CryptContext *con, const unsigned char *dir_iv, const WCHAR *filename, std::wstring& storage, void *context, std::string *actual_encrypted)
{
	if (con->GetConfig()->m_PlaintextNames) {
		storage = filename;
		return &storage[0];
	}

	std::string utf8;
	if (!encrypt_filename(con, dir_iv, filename, utf8, context, actual_encrypted))
		return NULL;

	return utf8_to_unicode(&(utf8[0]), storage);
}

const WCHAR * // returns UNICODE plaintext filename
decrypt_filename(CryptContext *con, const WCHAR *path, const char *filename, std::wstring& storage)
{
	if (con->GetConfig()->m_PlaintextNames) {
		if (!utf8_to_unicode(filename, storage)) {
			return NULL;
		}
		return &storage[0];
	}

	BYTE dir_iv[DIR_IV_LEN];

	if (!get_dir_iv(con, path, dir_iv))
		return NULL;

	unsigned char ptbuf[4096];

	if (strlen(filename) > sizeof(ptbuf) / 2)
		return NULL;

	std::vector<unsigned char> ctstorage;

	char longname_buf[4096];

	if (!strncmp(filename, longname_prefix, sizeof(longname_prefix)-1)) {
		std::wstring fullpath = path;
		if (fullpath[fullpath.size() - 1] != '\\')
			fullpath.push_back('\\');
		std::wstring wfilename;
		if (!utf8_to_unicode(filename, wfilename))
			return NULL;
		fullpath += wfilename;
		fullpath += longname_suffix;

		HANDLE hFile = CreateFile(&fullpath[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == INVALID_HANDLE_VALUE)
			return NULL;

		DWORD nRead;

		if (!ReadFile(hFile, longname_buf, sizeof(longname_buf), &nRead, NULL)) {
			CloseHandle(hFile);
			return NULL;
		}

		CloseHandle(hFile);

		if (nRead < 1)
			return NULL;

		longname_buf[nRead] = '\0';

		filename = longname_buf;
	}

	if (!base64_decode(filename, ctstorage))
		return NULL;

	if (con->GetConfig()->m_EMENames) {

		BYTE *pt = EmeTransform(&con->m_eme, (BYTE*)dir_iv, &ctstorage[0], (int)ctstorage.size(), false);

		if (!pt)
			return NULL;

		int origLen = unPad16(pt, (int)ctstorage.size());

		if (origLen < 0) {
			delete[] pt;
			return NULL;
		}


		pt[origLen] = '\0';

		const WCHAR *ws = utf8_to_unicode((const char *)pt, storage);

		delete[] pt;

		return ws;

	} else {

		void *context = get_crypt_context(DIR_IV_LEN, AES_MODE_CBC);
		if (!context)
			return NULL;

		int ptlen = decrypt(&(ctstorage[0]), (int)ctstorage.size(), NULL, 0, NULL, con->GetConfig()->GetKey(), dir_iv, ptbuf, context);

		free_crypt_context(context);

		if (ptlen < 1)
			return NULL;

		if (ptlen > sizeof(ptbuf) - 1)
			return NULL;

		ptbuf[ptlen] = '\0';

		return utf8_to_unicode((const char *)ptbuf, storage);
	}
}

const WCHAR * // returns UNICODE plaintext filename
decrypt_filename(CryptContext *con, const WCHAR *path, const WCHAR *filename, std::wstring& storage)
{
	if (con->GetConfig()->m_PlaintextNames) {
		storage = filename;
		return &storage[0];
	}

	std::string utf8;
	const char *fname;
	fname = unicode_to_utf8(filename, utf8);
	if (!fname)
		return NULL;

	return decrypt_filename(con, path, fname, storage);
}

const WCHAR * // get encrypted path
encrypt_path(CryptContext *con, const WCHAR *path, std::wstring& storage, std::string *actual_encrypted)
{

	const TCHAR *rval = NULL;

	CryptConfig *config = con->GetConfig();

	void *context = NULL;


	try {
		if (wcslen(path) >= 2 && (path[0] == config->GetDriveLetter() || path[0] == tolower(config->GetDriveLetter())) && path[1] == ':') {
			path += 2;
		}

		storage += config->GetBaseDir();

		if (*path && path[0] == '\\') {
			storage.push_back('\\');
			path++;
		}

		const TCHAR *p = path;


		unsigned char dir_iv[DIR_IV_LEN];

		
		if (!get_dir_iv(con, &(storage[0]), dir_iv))
			throw(-1);
		

		if (!con->GetConfig()->m_EMENames) {
			context = get_crypt_context(DIR_IV_LEN, AES_MODE_CBC);
			if (!context)
				throw(-1);
		}

		while (*p) {

			std::wstring s;

			while (*p && *p != '\\') {
				s.push_back(*p++);
			}

			std::wstring uni_crypt_elem;
			if (actual_encrypted)
				actual_encrypted->clear();
			if (!encrypt_filename(con, dir_iv, &(s[0]), uni_crypt_elem, context, actual_encrypted))
				throw(-1);

			storage.append(uni_crypt_elem);

			if (*p) {
				storage.push_back(*p++); // append slash
	
				if (!get_dir_iv(con, &(storage[0]), dir_iv))
					throw(-1);
				
			}

		}

		rval = &(storage[0]);

	} catch (...) {

		rval = NULL;
	}

	if (context) {
		free_crypt_context(context);
	}
	
	return rval;

}

bool write_encrypted_long_name(const WCHAR *filePath, const std::string& enc_data)
{
	if (enc_data.size() < 1)
		return false;

	if (!PathFileExists(filePath))
		return true;

	std::wstring path = filePath;

	if (path[path.size() - 1] == '\\')
		path.erase(path.size() - 1);

	path += longname_suffix;

	if (PathFileExists(&path[0]))
		return true;

	HANDLE hFile = CreateFile(&path[0], GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		CloseHandle(hFile);
		return true;
	}

	DWORD nWritten = 0;

	if (!WriteFile(hFile, &enc_data[0], (DWORD)enc_data.size(), &nWritten, NULL)) {
		CloseHandle(hFile);
		return false;
	}

	CloseHandle(hFile);

	return nWritten == enc_data.size();

}

