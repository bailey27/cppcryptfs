/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2019 Bailey Brown (github.com/bailey27/cppcryptfs)

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


#include "crypt/cryptdefs.h"
#include "crypt/crypt.h"
#include "config/cryptconfig.h"
#include "context/cryptcontext.h"
#include "cryptfilename.h"
#include "util/fileutil.h"
#include "util/pad16.h"

#ifdef _WIN32
#include <Shlwapi.h>
#endif




static const WCHAR longname_prefix[] = LONGNAME_PREFIX_W;
static const WCHAR longname_suffix[] = LONGNAME_SUFFIX_W;


bool is_long_name(const WCHAR *filename)
{
	wstring path = filename;

	size_t last_slash = path.find_last_of('\\');
	if (last_slash != wstring::npos) {
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

	DbgPrint(L"derive_path_iv path = %s, type = %S\n", path, type);

	wstring wpath;

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

	string utf8path;

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
encrypt_filename(const CryptContext *con, const unsigned char *dir_iv, const WCHAR *filename, wstring& storage, string *actual_encrypted)
{
	string utf8_str;

	const WCHAR *rs = NULL;

	if (con->GetConfig()->m_PlaintextNames) {
		storage = filename;
		return storage.c_str();
	}

	wstring file_without_stream;
	wstring stream;

	bool have_stream = get_file_stream(filename, &file_without_stream, &stream);

	if (!unicode_to_utf8(file_without_stream.c_str(), utf8_str))
		return NULL;
	
	if (con->GetConfig()->m_EMENames) {

		int paddedLen = 0;
		BYTE *padded = pad16((BYTE*)utf8_str.c_str(), (int)utf8_str.size(), paddedLen);

		if (!padded)
			return NULL;

		BYTE *ct = EmeTransform(&con->m_eme, (BYTE*)dir_iv, padded, paddedLen, true);

		free(padded);

		if (!ct) {
			return NULL;
		}

		rs = base64_encode(ct, paddedLen, storage, true, !con->GetConfig()->m_Raw64);

		delete[] ct;

	} else {
		// CBC names no longer supported
		return NULL;	
	}

	if (con->GetConfig()->m_LongNames && storage.length() > MAX_FILENAME_LEN) {
		string utf8;
		if (!unicode_to_utf8(storage.c_str(), utf8))
			return NULL;
		if (actual_encrypted) {
			*actual_encrypted = utf8;
		}
		BYTE sum[32];
		if (!sha256(utf8, sum))
			return NULL;
		wstring base64_sum;
		if (!base64_encode(sum, sizeof(sum), base64_sum, true, !con->GetConfig()->m_Raw64))
			return NULL;
		storage = longname_prefix;
		storage += base64_sum;

		rs = storage.c_str();
	}

	if (have_stream && rs) {
		wstring enc_stream;
		if (encrypt_stream_name(con, dir_iv, stream.c_str(), enc_stream)) {
			storage += enc_stream;
			rs = storage.c_str();
		} else {
			storage = L"";
			rs = NULL;
		}
		
	}

	return rs;
}



const WCHAR * // returns UNICODE plaintext filename
decrypt_filename(CryptContext *con, const BYTE *dir_iv, const WCHAR *path, const WCHAR *filename, wstring& storage)
{
	if (con->GetConfig()->m_PlaintextNames) {
		storage = filename;
		return &storage[0];
	}

	wstring file_without_stream;
	wstring stream;

	bool have_stream = get_file_stream(filename, &file_without_stream, &stream);

	vector<unsigned char> ctstorage;

	char longname_buf[4096];

	wstring longname_storage;

	if (!wcsncmp(file_without_stream.c_str(), longname_prefix, sizeof(longname_prefix)/sizeof(longname_prefix[0])-1)) {
		if (con->GetConfig()->m_reverse) {
			if (decrypt_reverse_longname(con, file_without_stream.c_str(), path, dir_iv, storage))
				return &storage[0];
			else
				return false;
		} else {
			wstring fullpath = path;
			if (fullpath[fullpath.size() - 1] != '\\')
				fullpath.push_back('\\');

			fullpath += file_without_stream.c_str();
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

			file_without_stream = &longname_storage[0];
		}
	}

	if (!base64_decode(file_without_stream.c_str(), ctstorage, true, !con->GetConfig()->m_Raw64))
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

		if (have_stream && ws) {
			wstring dec_stream;
			if (decrypt_stream_name(con, dir_iv, stream.c_str(), dec_stream)) {
				storage += dec_stream;
				ws = storage.c_str();
			} else {
				storage += L":"; // if failure use invalid empty stream name
				ws = storage.c_str();
			}
		}

		return ws;

	} else {
		// CBC names no longer supported
		return NULL;
	}
}

static const WCHAR *
extract_lfn_base64_hash(const WCHAR *lfn, wstring& storage)
{
	storage.clear();

	storage.reserve(50);

	const WCHAR *p = lfn + sizeof(LONGNAME_PREFIX_W) / sizeof(WCHAR) - 1;

	while (*p && *p != '.')
		storage.push_back(*p++);

	return &storage[0];
}	


const WCHAR *
decrypt_reverse_longname(CryptContext *con, LPCWSTR filename, LPCWSTR plain_path, const BYTE *dir_iv, wstring& decrypted_name)
{
	HANDLE hFind = INVALID_HANDLE_VALUE;
	bool found = false;

	try {
		
		wstring storage = plain_path;

		wstring base64_hash;
		if (!extract_lfn_base64_hash(filename /* &s[0] */, base64_hash))
			throw(-1);
		wstring lfn_path;
		if (con->m_lfn_cache.lookup(&base64_hash[0], &lfn_path, NULL)) {
			const WCHAR *ps = wcsrchr(&lfn_path[0], '\\');
			decrypted_name = ps ? ps + 1 : &lfn_path[0];
			found = true;
		} else {
			// go through all the files in the dir
			// if the name is long enough to be a long file name (> 176 chars in utf8)
			// then encrypt it and see if it matches the one we're looking for

			// store any we generate in the lfn cache for later use

			WIN32_FIND_DATA fdata;
			wstring findspec = storage;
			findspec += L"*";
			hFind = FindFirstFile(&findspec[0], &fdata);
			if (hFind == INVALID_HANDLE_VALUE)
				throw(-1);

			string utf8name;
			wstring find_enc;
			string actual_encrypted;
			wstring find_base64_hash;
			wstring find_path;

			do {

				if (!wcscmp(fdata.cFileName, L".") || !wcscmp(fdata.cFileName, L".."))
					continue;
				
				if (!unicode_to_utf8(fdata.cFileName, utf8name))
					throw(-1);

				if (utf8name.length() <= SHORT_NAME_MAX)
					continue;				

				if (!encrypt_filename(con, dir_iv, fdata.cFileName, find_enc, &actual_encrypted))
					throw(-1);
	
				extract_lfn_base64_hash(&find_enc[0], find_base64_hash);

				find_path = storage;
				find_path += fdata.cFileName;

				con->m_lfn_cache.store_if_not_there(&find_base64_hash[0], &find_path[0], &actual_encrypted[0]);

				if (find_base64_hash == base64_hash) {
					decrypted_name = fdata.cFileName;
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
decrypt_path(CryptContext *con, const WCHAR *path, wstring& storage)
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
					wstring base64_hash;
					if (!extract_lfn_base64_hash(&last_elem[0], base64_hash)) {
						throw(-1);
					}
					wstring lfn_path;
					if (con->m_lfn_cache.lookup(&base64_hash[0], &storage, NULL)) {
						done = true;
					}
				}
			}

	

			if (!done) {

				wstring diriv_path = L"";

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

				wstring s;

				wstring uni_plain_elem;

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
encrypt_path(CryptContext *con, const WCHAR *path, wstring& storage, string *actual_encrypted)
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

			wstring s;

			wstring uni_crypt_elem;

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

#ifdef _WIN32
bool write_encrypted_long_name(const WCHAR *filePath, const string& enc_data)
{
	if (enc_data.size() < 1)
		return false;

	if (!PathFileExists(filePath))
		return true;

	wstring path = filePath;

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

#endif // _WIN32

bool
rt_is_config_file(CryptContext *con, LPCWSTR FileName)
{
	if (!con->GetConfig()->m_reverse)
		return false;
	else
		return *FileName == '\\' && !lstrcmpi(FileName + 1, CONFIG_NAME);
}

bool
rt_is_reverse_config_file(CryptContext *con, LPCWSTR FileName)
{
	if (!con->GetConfig()->m_reverse)
		return false;
	else
		return *FileName == '\\' && !lstrcmpi(FileName + 1, REVERSE_CONFIG_NAME);
}

bool
rt_is_dir_iv_file(CryptContext *con, LPCWSTR FileName)
{
	CryptConfig *cfg = con->GetConfig();

	if (!cfg->m_reverse || cfg->m_PlaintextNames || !cfg->DirIV())
		return false;

	const WCHAR *last_slash = wcsrchr(FileName, '\\');

	const WCHAR *str = last_slash ? last_slash + 1 : FileName;

	return !lstrcmpi(str, DIR_IV_NAME);
}

bool 
rt_is_name_file(CryptContext *con, LPCWSTR FileName)
{
	CryptConfig *cfg = con->GetConfig();

	if (!cfg->m_reverse || cfg->m_PlaintextNames || !cfg->m_LongNames)
		return false;

	const WCHAR *last_slash = wcsrchr(FileName, '\\');

	const WCHAR *str = last_slash ? last_slash + 1 : FileName;

	return is_long_name_file(str);
}

bool
rt_is_virtual_file(CryptContext *con, LPCWSTR FileName)
{
	return rt_is_dir_iv_file(con, FileName) || rt_is_name_file(con, FileName);
}

const WCHAR *
remove_longname_suffix(const WCHAR *filepath, wstring& storage)
{
	storage = filepath;

	size_t len = storage.length() - (sizeof(LONGNAME_SUFFIX_W) / sizeof(WCHAR) - 1);

	storage = storage.substr(0, len);

	return &storage[0];
}

bool
get_actual_encrypted(CryptContext *con, LPCWSTR FileName, string& actual_encrypted)
{
	
	wstring encrypted_name;

	if (!get_bare_filename(FileName, encrypted_name))
		return false;

	wstring base64_hash;

	if (extract_lfn_base64_hash(&encrypted_name[0], base64_hash)) {
		if (con->m_lfn_cache.lookup(&base64_hash[0], NULL, &actual_encrypted)) {
			return true;
		}
	}

	wstring dirpath;
	wstring decrypted_name;

	BYTE dir_iv[DIR_IV_LEN];

	if (!get_file_directory(FileName, dirpath))
		return false;

	if (!derive_path_iv(con, &dirpath[0], dir_iv, TYPE_DIRIV))
		return false;

	//encrypted_name = encrypted_name.substr(0, encrypted_name.length() - sizeof(LONGNAME_SUFFIX_W) / sizeof(WCHAR) - 1);

	if (!decrypt_filename(con, dir_iv, &dirpath[0], &encrypted_name[0], decrypted_name))
		return false;

	if (!encrypt_filename(con, dir_iv, &decrypted_name[0], encrypted_name, &actual_encrypted))
		return false;

	return true;
}

bool
get_bare_filename(LPCWSTR filepath, wstring& filename)
{
	size_t len = wcslen(filepath);

	if (len < 1)
		return false;

	const WCHAR *lastslash = wcsrchr(filepath, '\\');

	if (!lastslash)
		return true;

	filename = filepath;

	filename = filename.substr(lastslash - filepath + 1);

	return true;
}

bool 
get_file_directory(LPCWSTR filepath, wstring& dirpath)
{
	size_t len = wcslen(filepath);

	if (len < 1)
		return false;

	const WCHAR *lastslash = wcsrchr(filepath, '\\');

	if (!lastslash)
		return false;

	if (lastslash == filepath) {
		dirpath = L"\\";
		return true;
	} 

	dirpath = filepath;

	dirpath = dirpath.substr(0, lastslash - filepath);

	return true;
}

const WCHAR * // returns base64-encoded, encrypted stream name.  input stream name is expected to start with colon
encrypt_stream_name(const CryptContext *con, const unsigned char *dir_iv, const WCHAR *stream, wstring& storage)
{

	if (!stream || stream[0] != ':')
		return NULL;

	wstring stream_without_type;
	wstring type;

	if (!remove_stream_type(stream, stream_without_type, type))
		return false;

	LPCWSTR rs;
	
	if (stream_without_type.length() > 1) {
		rs = encrypt_filename(con, dir_iv, stream_without_type.c_str() + 1, storage, NULL);
	} else {
		storage = L"";
		rs = storage.c_str();
	}

	if (!rs) 
		return NULL;

	if (is_long_name(rs))
		return NULL;

	storage = L":" + storage + type;

	return storage.c_str();
}

const WCHAR * // returns UNICODE plaintext stream name.  input stream name is expected to start with colon
decrypt_stream_name(CryptContext *con, const BYTE *dir_iv, const WCHAR *stream, wstring& storage)
{
	if (!stream || stream[0] != ':')
		return NULL;

	if (is_long_name(stream + 1))
		return NULL;

	wstring stream_without_type;
	wstring type;

	if (!remove_stream_type(stream, stream_without_type, type))
		return false;

	LPCWSTR rs;
		
	if (stream_without_type.length() > 1) {
		rs = decrypt_filename(con, dir_iv, NULL, stream_without_type.c_str() + 1, storage);
	} else {
		storage = L"";
		rs = storage.c_str();
	}

	if (!rs)
		return NULL;

	storage = L":" + storage + type;

	return storage.c_str();
}