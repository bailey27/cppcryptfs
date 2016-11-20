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


#include "cryptdefs.h"
#include "crypt.h"
#include "cryptconfig.h"
#include "cryptcontext.h"
#include "cryptfilename.h"
#include "fileutil.h"
#include "pad16.h"




static const WCHAR longname_prefix[] = LONGNAME_PREFIX_W;
static const WCHAR longname_suffix[] = LONGNAME_SUFFIX_W;


bool is_long_name(const WCHAR *filename)
{
	std::wstring path = filename;

	size_t last_slash = path.find_last_of('\\');
	if (last_slash != std::wstring::npos) {
		filename = &path[last_slash + 1];
	} 
	return !wcsncmp(filename, longname_prefix, sizeof(longname_prefix) / sizeof(longname_prefix[0]) - 1);
}

bool is_long_name_file(const WCHAR *filename)
{
	size_t len = wcslen(filename);

	return len > (LONGNAME_PREFIX_LEN + LONGNAME_SUFFIX_LEN) && !wcsncmp(filename, LONGNAME_PREFIX_W, LONGNAME_PREFIX_LEN) && !wcscmp(filename + len - LONGNAME_SUFFIX_LEN, LONGNAME_SUFFIX_W);
}

bool 
derive_path_iv(CryptContext *con, const WCHAR *path, unsigned char *iv, const char *type)
{

	DbgPrint(L"derive_path_iv input = %s\n", path);

	std::wstring wpath;

	const WCHAR *pathstr = path;

	if (*pathstr == '\\' || *pathstr == '/')
		pathstr++;

	wpath = pathstr;

	if (wpath.length() > 0) {
		if (wpath[wpath.length() - 1] == '\\' || wpath[wpath.length()] - 1 == '/')
			wpath.erase(wpath.length() - 1);
	}

	int i;
	int len = (int)wpath.length();
	for (i = 0; i < len; i++) {
		if (wpath[i] == '\\')
			wpath[i] = '/';
	}

	std::string utf8path;

	if (!unicode_to_utf8(&wpath[0], utf8path))
		return false;

	bool bRet = true;

	BYTE *pbuf = NULL;

	try {
		int typelen = (int)strlen(type);
		int bufsize = (int)(utf8path.length() + 1 + typelen);
		pbuf = new BYTE[bufsize];
		memcpy(pbuf, &utf8path[0], utf8path.length() + 1);
		memcpy(pbuf + utf8path.length() + 1, type, typelen);
		BYTE hash[SHA256_LEN];
		if (!sha256(pbuf, bufsize, hash))
			throw(-1);

		memcpy(iv, hash, DIR_IV_LEN);  // all iv's are 16 bytes (DIR_IV_LEN)

	} catch (...) {
		bRet = false;
	}

	if (pbuf)
		delete[] pbuf;

	return bRet;
}


const WCHAR * // returns base64-encoded, encrypted filename
encrypt_filename(const CryptContext *con, const unsigned char *dir_iv, const WCHAR *filename, std::wstring& storage, std::string *actual_encrypted)
{
	std::string utf8_str;

	const WCHAR *rs = NULL;

	if (con->GetConfig()->m_PlaintextNames) {
		storage = filename;
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

		// CBC names no longer supported

		return NULL;
		
		
	}

	if (con->GetConfig()->m_LongNames && storage.size() > MAX_FILENAME_LEN) {
		std::string utf8;
		if (!unicode_to_utf8(&storage[0], utf8))
			return NULL;
		if (actual_encrypted) {
			*actual_encrypted = utf8;
		}
		BYTE sum[32];
		if (!sha256(utf8, sum))
			return NULL;
		std::wstring base64_sum;
		if (!base64_encode(sum, sizeof(sum), base64_sum))
			return NULL;
		storage = longname_prefix;
		storage += base64_sum;
		rs = &storage[0];
	}

	return rs;
}



const WCHAR * // returns UNICODE plaintext filename
decrypt_filename(CryptContext *con, const BYTE *dir_iv, const WCHAR *path, const WCHAR *filename, std::wstring& storage)
{
	if (con->GetConfig()->m_PlaintextNames) {
		storage = filename;
		return &storage[0];
	}

	std::vector<unsigned char> ctstorage;

	char longname_buf[4096];

	std::wstring longname_storage;

	if (!wcsncmp(filename, longname_prefix, sizeof(longname_prefix)/sizeof(longname_prefix[0])-1)) {
		if (con->GetConfig()->m_reverse) {
			if (decrypt_reverse_longname(con, filename, path, dir_iv, storage))
				return &storage[0];
			else
				return false;
		} else {
			std::wstring fullpath = path;
			if (fullpath[fullpath.size() - 1] != '\\')
				fullpath.push_back('\\');

			fullpath += filename;
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

			if (!utf8_to_unicode(longname_buf, longname_storage))
				return NULL;

			filename = &longname_storage[0];
		}
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
		// CBC names no longer supported
		return NULL;
	}
}

static const WCHAR *
extract_lfn_base64_hash(const WCHAR *lfn, std::wstring& storage)
{
	storage.clear();

	storage.reserve(50);

	const WCHAR *p = lfn + sizeof(LONGNAME_PREFIX_W) / sizeof(WCHAR) - 1;

	while (*p && *p != '.')
		storage.push_back(*p++);

	return &storage[0];
}	


const WCHAR *
decrypt_reverse_longname(CryptContext *con, LPCWSTR filename, LPCWSTR plain_path, const BYTE *dir_iv, std::wstring& decrypted_name)
{
	HANDLE hFind = INVALID_HANDLE_VALUE;
	bool found = false;

	try {
		
		std::wstring storage = plain_path;

		std::wstring base64_hash;
		if (!extract_lfn_base64_hash(filename /* &s[0] */, base64_hash))
			throw(-1);
		std::wstring lfn_path;
		if (con->m_lfn_cache.lookup(&base64_hash[0], lfn_path)) {
			const WCHAR *ps = wcsrchr(&lfn_path[0], '\\');
			decrypted_name = ps ? ps + 1 : &lfn_path[0];
			found = true;
		} else {
			// go through all the files in the dir
			// if the name is long enough to be a long file name (> 176 chars in utf8)
			// then encrypt it and see if it matches the one we're looking for

			// store any we generate in the lfn cache for later use

			WIN32_FIND_DATA fdata;
			std::wstring findspec = storage;
			findspec += L"*";
			hFind = FindFirstFile(&findspec[0], &fdata);
			if (hFind == INVALID_HANDLE_VALUE)
				throw(-1);
			do {
				std::string utf8name;

				if (!unicode_to_utf8(fdata.cFileName, utf8name))
					throw(-1);

				if (utf8name.length() <= SHORT_NAME_MAX)
					continue;

				std::wstring find_enc;

				if (!encrypt_filename(con, dir_iv, fdata.cFileName, find_enc, NULL))
					throw(-1);

				std::wstring find_base64_hash;
				extract_lfn_base64_hash(&find_enc[0], find_base64_hash);
				con->m_lfn_cache.store(&find_base64_hash[0], &(storage + fdata.cFileName)[0]);
				if (find_base64_hash == base64_hash) {
					decrypted_name /* uni_plain_elem */ = fdata.cFileName;
					found = true;
					break;
				}
			} while (FindNextFile(hFind, &fdata));

			FindClose(hFind);
			hFind = NULL;

		}
	} catch (...) {
		found = false;
	}

	if (hFind && hFind != INVALID_HANDLE_VALUE)
		FindClose(hFind);

	if (found)
		return &decrypted_name[0];
	else
		return NULL;

}

const WCHAR * // get decrypted path (used only in reverse mode)
decrypt_path(CryptContext *con, const WCHAR *path, std::wstring& storage)
{
	const WCHAR *rval = NULL;

	HANDLE hFind = NULL;

	CryptConfig *config = con->GetConfig();

	bool done = false;

	try {

		if (!config->m_reverse)
			throw(-1);

		storage = config->GetBaseDir();

		if (config->m_PlaintextNames || (path[0] == '\\' && path[1] == '\0')) {

			storage += path;

		} else {

			// we can short-circuit the process in the case where the final file or dir is a long file name
			// and it is found in the long file name (lfn) cache

			const WCHAR *last_elem = wcsrchr(path, '\\');

			if (last_elem) {
				last_elem++;
				if (is_long_name(last_elem)) {
					std::wstring base64_hash;
					if (!extract_lfn_base64_hash(&last_elem[0], base64_hash)) {
						throw(-1);
					}
					std::wstring lfn_path;
					if (con->m_lfn_cache.lookup(&base64_hash[0], storage)) {
						done = true;
					}
				}
			}

	

			if (!done) {

				std::wstring diriv_path = L"";

				if (*path && path[0] == '\\') {
					storage.push_back('\\');
					path++;
				}

				const TCHAR *p = path;


				unsigned char dir_iv[DIR_IV_LEN];


				if (!derive_path_iv(con, &diriv_path[0], dir_iv, TYPE_DIRIV))
					throw(-1);

				if (!con->GetConfig()->m_EMENames) {
					// CBC names no longer supported
					throw(-1);
				}

				std::wstring s;

				std::wstring uni_plain_elem;

				while (*p) {

					s.clear();

					uni_plain_elem.clear();

					while (*p && *p != '\\') {
						diriv_path.push_back(*p);
						s.push_back(*p++);
					}

					if (!is_long_name(&s[0])) {
						if (!decrypt_filename(con, dir_iv, &storage[0], &s[0], uni_plain_elem)) {
							throw(-1);
						}
					} else {
						if (!decrypt_reverse_longname(con, &s[0], &storage[0], dir_iv, uni_plain_elem))
							throw(-1);
					}

					storage.append(uni_plain_elem);

					if (*p) {
						diriv_path.push_back(*p);
						storage.push_back(*p++); // append slash

						if (!derive_path_iv(con, &diriv_path[0], dir_iv, TYPE_DIRIV))
							throw(-1);

					}

				}
			}
		}

		rval = &storage[0];

	} catch (...) {
		rval = NULL;
	}

	if (hFind && hFind != INVALID_HANDLE_VALUE)
		FindClose(hFind);

	return rval;
}


const WCHAR * // get encrypted path
encrypt_path(CryptContext *con, const WCHAR *path, std::wstring& storage, std::string *actual_encrypted)
{

	const WCHAR *rval = NULL;

	CryptConfig *config = con->GetConfig();


	try {
		
		storage = config->GetBaseDir();

		if (config->m_PlaintextNames || (path[0] == '\\' && path[1] == '\0')) {

			storage += path;

		} else {

			if (*path && path[0] == '\\') {
				storage.push_back('\\');
				path++;
			}

			const TCHAR *p = path;


			unsigned char dir_iv[DIR_IV_LEN];

			if (!get_dir_iv(con, &storage[0], dir_iv))
				throw(-1);


			if (!con->GetConfig()->m_EMENames) {
				// CBC names no longer supported
				throw(-1);
			}

			std::wstring s;

			std::wstring uni_crypt_elem;

			while (*p) {

				s.clear();

				uni_crypt_elem.clear();

				while (*p && *p != '\\') {
					s.push_back(*p++);
				}
	
				if (actual_encrypted)
					actual_encrypted->clear();

				if (!encrypt_filename(con, dir_iv, &s[0], uni_crypt_elem, actual_encrypted))
					throw(-1);

				storage.append(uni_crypt_elem);

				if (*p) {
					storage.push_back(*p++); // append slash

					if (!get_dir_iv(con, &storage[0], dir_iv))
						throw(-1);

				}

			}
		}

		rval = &storage[0];

	} catch (...) {

		rval = NULL;
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

