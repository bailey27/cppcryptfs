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

#include "Shlwapi.h"

#include "cryptdefs.h"
#include "fileutil.h"
#include "cryptfilename.h"

#include <string>
#include <vector>

#include "dirivcache.h"

bool
adjust_file_offset_down(LARGE_INTEGER& l)
{
	long long offset = l.QuadPart;

	if (offset < 0)
		return false;

	if (offset == 0)
		return true;

	long long blocks = (offset - CIPHER_FILE_OVERHEAD + CIPHER_BS - 1) / CIPHER_BS;
	offset -= (blocks*CIPHER_BLOCK_OVERHEAD + CIPHER_FILE_OVERHEAD);
	if (offset < 0)
		return false;

	l.QuadPart = offset;

	return true;
}

bool
adjust_file_offset_up(LARGE_INTEGER& l)
{
	long long offset = l.QuadPart;

	if (offset < 0)
		return false;

	if (offset == 0)
		return true;

	long long blocks = (offset + PLAIN_BS - 1) / PLAIN_BS;
	offset += (blocks*CIPHER_BLOCK_OVERHEAD + CIPHER_FILE_OVERHEAD);
	
	l.QuadPart = offset;

	return true;
}

bool adjust_file_size_down(LARGE_INTEGER& l)
{
	return adjust_file_offset_down(l);
}

bool adjust_file_size_up(LARGE_INTEGER& l)
{
	return adjust_file_offset_up(l);
}

static bool
read_dir_iv(const TCHAR *path, unsigned char *diriv, FILETIME& LastWriteTime)
{

	HANDLE hfile = INVALID_HANDLE_VALUE;
	DWORD nRead = 0;

	try {
		std::wstring path_str;

		path_str.append(path);

		if (path_str[path_str.size() - 1] != '\\') {
			path_str.push_back('\\');
		}

		path_str.append(DIR_IV_NAME);

		hfile = CreateFile(&path_str[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (hfile == INVALID_HANDLE_VALUE) {
			throw(-1);
		}

		if (!ReadFile(hfile, diriv, DIR_IV_LEN, &nRead, NULL)) {
			throw(-1);
		}

		if (!GetFileTime(hfile, NULL, NULL, &LastWriteTime)) {
			throw(-1);
		}
	}
	catch (...) {
		nRead = 0;
	}

	if (hfile != INVALID_HANDLE_VALUE)
		CloseHandle(hfile);

	return nRead == DIR_IV_LEN;
}

bool
get_dir_iv(CryptContext *con, const WCHAR *path, unsigned char *diriv)
{

	if (con && !con->GetConfig()->DirIV()) {
		memset(diriv, 0, DIR_IV_LEN);
		return true;
	}

	bool bret = true;

	try {

		if (con && con->GetConfig()->m_reverse) {
			throw(-1);
		}

		if (!con->m_dir_iv_cache.lookup(path, diriv)) {
			FILETIME LastWritten;
			if (!read_dir_iv(path, diriv, LastWritten))
				throw(-1);
			if (!con->m_dir_iv_cache.store(path, diriv, LastWritten)) {
				throw(-1);
			}
		}
	} catch (...) {
		bret = false;
	}

	return bret;
}

static bool
convert_fdata(const CryptContext *con, const BYTE *dir_iv, const WCHAR *path, WIN32_FIND_DATAW& fdata, std::string *actual_encrypted)
{

	if (!wcscmp(fdata.cFileName, L".") || !wcscmp(fdata.cFileName, L".."))
		return true;

	bool isReverseConfig = con->GetConfig()->m_reverse && !wcscmp(fdata.cFileName, REVERSE_CONFIG_NAME);

	long long size = ((long long)fdata.nFileSizeHigh << 32) | fdata.nFileSizeLow;

	if (size > 0 && !(fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !isReverseConfig) {
		LARGE_INTEGER l;
		l.LowPart = fdata.nFileSizeLow;
		l.HighPart = fdata.nFileSizeHigh;
		if (con->GetConfig()->m_reverse) {
			if (!adjust_file_size_up(l))
				return false;
		} else {
			if (!adjust_file_size_down(l))
				return false;
		}
		fdata.nFileSizeHigh = l.HighPart;
		fdata.nFileSizeLow = l.LowPart;
	}

	

	if (wcscmp(fdata.cFileName, L".") && wcscmp(fdata.cFileName, L"..")) {
		std::wstring storage;
		const WCHAR *dname;
		
		if (isReverseConfig) {
			fdata.dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;
			dname = CONFIG_NAME;
		} else {
			if (con->GetConfig()->m_reverse) {
				dname = encrypt_filename(con, dir_iv, fdata.cFileName, storage, actual_encrypted);	
			} else {
				dname = decrypt_filename(con, dir_iv, path, fdata.cFileName, storage);
			}
		}

		if (!dname)
			return false;

		if (wcslen(dname) < MAX_PATH) {
			if (wcscpy_s(fdata.cFileName, MAX_PATH, dname))
				return false;
		}
		else {
			return false;
		}
	}

	// short name - not really needed
	fdata.cAlternateFileName[0] = '\0';

	return true;
}

static bool is_interesting_name(BOOL isRoot, const WIN32_FIND_DATAW& fdata, bool reverse)
{
	if (isRoot && (!wcscmp(fdata.cFileName, L".") || !wcscmp(fdata.cFileName, L".."))) {
		return false;
	} else if ((!reverse && !wcscmp(fdata.cFileName, CONFIG_NAME)) || !wcscmp(fdata.cFileName, DIR_IV_NAME)) {
		return false;
	} else if (is_long_name_file(fdata.cFileName)) {
		return false;
	} else {
		return true;
	}
}

DWORD
find_files(CryptContext *con, const WCHAR *pt_path, const WCHAR *path, PCryptFillFindData fillData, void * dokan_cb, void * dokan_ctx)
{
	DWORD ret = 0;
	HANDLE hfind = INVALID_HANDLE_VALUE;

	bool reverse = con->GetConfig()->m_reverse;

	bool plaintext_names = con->GetConfig()->m_PlaintextNames;

	try {

		std::wstring enc_path_search = path;

		WIN32_FIND_DATAW fdata, fdata_dot;

		if (enc_path_search[enc_path_search.size() - 1] != '\\')
			enc_path_search.push_back('\\');

		enc_path_search.push_back('*');

		hfind = FindFirstFile(&enc_path_search[0], &fdata);

		if (hfind == INVALID_HANDLE_VALUE)
			throw((int)GetLastError());

		BYTE dir_iv[DIR_IV_LEN];

		if (reverse) {
			if (!derive_path_iv(con, pt_path, dir_iv, TYPE_DIRIV)) {
				throw((int)ERROR_PATH_NOT_FOUND);
			}
		} else {
			if (!get_dir_iv(con, path, dir_iv)) {
				DWORD error = GetLastError();
				if (error == 0)
					error = ERROR_PATH_NOT_FOUND;
				throw((int)error);
			}
		}
	

		bool isRoot = !wcscmp(pt_path, L"\\");

		std::string actual_encrypted;

		do {
			if (reverse && !wcscmp(fdata.cFileName, L".")) {
				fdata_dot = fdata;
			}
			if (!is_interesting_name(isRoot, fdata, reverse))
				continue;
			if (!convert_fdata(con, dir_iv, path, fdata, &actual_encrypted))
				continue;
			fillData(&fdata, dokan_cb, dokan_ctx);
			if (reverse && !plaintext_names && is_long_name(fdata.cFileName)) {
				wcscat_s(fdata.cFileName, MAX_PATH, LONGNAME_SUFFIX_W);
				fdata.cAlternateFileName[0] = '\0';
				fdata.nFileSizeHigh = 0;
				fdata.nFileSizeLow = (DWORD)actual_encrypted.length();
				fillData(&fdata, dokan_cb, dokan_ctx);
			}
		} while (FindNextFile(hfind, &fdata));

		DWORD err = GetLastError();

		if (err != ERROR_NO_MORE_FILES)
			throw((int)err);

		if (reverse && !plaintext_names) {
			fdata_dot.cAlternateFileName[0] = '\0';
			wcscpy_s(fdata_dot.cFileName, MAX_PATH, DIR_IV_NAME);
			fdata_dot.nFileSizeHigh = 0;
			fdata_dot.nFileSizeLow = DIR_IV_LEN;
			fdata_dot.ftLastWriteTime = fdata_dot.ftCreationTime;
			fdata_dot.dwFileAttributes = FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY;
			fillData(&fdata_dot, dokan_cb, dokan_ctx);
		}

		ret = 0;

	} catch (int error) {
		ret = (DWORD)error;
	} catch (...) {
		ret = ERROR_OUTOFMEMORY;
	}

	if (hfind != INVALID_HANDLE_VALUE)
		FindClose(hfind);

	return ret;
}

DWORD
get_file_information(LPCWSTR FileName, HANDLE handle, LPBY_HANDLE_FILE_INFORMATION pInfo)
{
	BOOL opened = FALSE;

	DWORD dwRet = 0;

	try {


		LPCWSTR encpath = FileName;

		if (!encpath)
			throw((int)ERROR_OUTOFMEMORY);



		if (!handle || handle == INVALID_HANDLE_VALUE) {

			throw((int)ERROR_INVALID_PARAMETER);

		}


		if (!GetFileInformationByHandle(handle, pInfo)) {
			

			if (opened) {
				opened = FALSE;
				CloseHandle(handle);
			}

			// FileName is a root directory
			// in this case, FindFirstFile can't get directory information
			if (wcslen(FileName) == 1) {
				
				pInfo->dwFileAttributes = GetFileAttributes(encpath);

			} else {
				WIN32_FIND_DATAW find;
				ZeroMemory(&find, sizeof(WIN32_FIND_DATAW));
				HANDLE findHandle = FindFirstFile(encpath, &find);
				if (findHandle == INVALID_HANDLE_VALUE) {
					DWORD error = GetLastError();
					
					throw((int)error);
				}
				pInfo->dwFileAttributes = find.dwFileAttributes;
				pInfo->ftCreationTime = find.ftCreationTime;
				pInfo->ftLastAccessTime = find.ftLastAccessTime;
				pInfo->ftLastWriteTime = find.ftLastWriteTime;
				pInfo->nFileSizeHigh = find.nFileSizeHigh;
				pInfo->nFileSizeLow = find.nFileSizeLow;
				
				FindClose(findHandle);
			}
		} 

		if (!(pInfo->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {

			LARGE_INTEGER l;
			l.LowPart = pInfo->nFileSizeLow;
			l.HighPart = pInfo->nFileSizeHigh;

			if (!adjust_file_size_down(l))
				throw((int)ERROR_INVALID_PARAMETER);

			pInfo->nFileSizeLow = l.LowPart;
			pInfo->nFileSizeHigh = l.HighPart;
		}


	} catch (int err) {
		dwRet = (DWORD)err;
	} catch (...) {
		dwRet = ERROR_ACCESS_DENIED;
	}
	
	if (opened)
		CloseHandle(handle);

	if (dwRet)
		SetLastError(dwRet);

	return dwRet;
}

bool
create_dir_iv(CryptContext *con, LPCWSTR path)
{

	if (con && !con->GetConfig()->DirIV())
		return true;

	DWORD error = 0;
	HANDLE hfile = INVALID_HANDLE_VALUE;

	try {

		unsigned char diriv[DIR_IV_LEN];

		if (!get_random_bytes(con, diriv, DIR_IV_LEN))
			throw ((int)(GetLastError() ? GetLastError() : ERROR_OUTOFMEMORY));

		std::wstring path_str = path;

		LPCWSTR encpath = &path_str[0];

		if (!encpath)
			throw((int)ERROR_OUTOFMEMORY);

		if (path_str[path_str.size() - 1] != '\\') {
			path_str.push_back('\\');
		}

		path_str.append(DIR_IV_NAME);

		hfile = CreateFile(&path_str[0], GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL);

		if (hfile == INVALID_HANDLE_VALUE)
			throw((int)ERROR_ACCESS_DENIED);

		DWORD nWritten = 0;
		if (!WriteFile(hfile, diriv, DIR_IV_LEN, &nWritten, NULL)) {
			throw((int)GetLastError());
		}

		if (nWritten != DIR_IV_LEN) {
			throw((int)ERROR_OUTOFMEMORY);
		}

		FILETIME LastWriteTime;

		if (!GetFileTime(hfile, NULL, NULL, &LastWriteTime)) {
			throw((int)GetLastError());
		}

		CloseHandle(hfile);
		hfile = INVALID_HANDLE_VALUE;

		// assume somebody will want to use it soon
		if (con)
			con->m_dir_iv_cache.store(path, diriv, LastWriteTime);

		DWORD attr = GetFileAttributesW(&path_str[0]);
		if (attr != INVALID_FILE_ATTRIBUTES) {
			attr |= FILE_ATTRIBUTE_READONLY;
			SetFileAttributes(&path_str[0], attr);
		}

	} catch (int err) {
		error = (DWORD)err;
	} catch (...) {
		error = ERROR_OUTOFMEMORY;
	}

	if (hfile != INVALID_HANDLE_VALUE)
		CloseHandle(hfile);

	return error == 0;
}

bool
can_delete_directory(LPCWSTR path, BOOL bMustReallyBeEmpty)
{
	bool bret = true;

	WIN32_FIND_DATAW findData;

	HANDLE hFind = INVALID_HANDLE_VALUE;

	DWORD error = 0;

	try {

		std::wstring enc_path = path;

		const WCHAR *filePath = &enc_path[0];

		if (!filePath)
			throw((int)ERROR_FILE_NOT_FOUND);

		if (enc_path[enc_path.size() - 1] != '\\')
			enc_path.push_back('\\');

		enc_path.push_back('*');

		filePath = &enc_path[0];

		hFind = FindFirstFile(filePath, &findData);

		if (hFind == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			throw((int)error);
		}

		while (hFind != INVALID_HANDLE_VALUE) {
			if (wcscmp(findData.cFileName, L"..") != 0 &&
				wcscmp(findData.cFileName, L".") != 0 &&
				(bMustReallyBeEmpty || wcscmp(findData.cFileName, DIR_IV_NAME) != 0)) {
				throw((int)ERROR_DIR_NOT_EMPTY);
			}
			if (!FindNextFile(hFind, &findData)) {
				break;
			}
		}
		error = GetLastError();

		if (error != ERROR_NO_MORE_FILES) {
			throw((int)error);
		}

	} catch (int err) {
		SetLastError((DWORD)err);
		bret = false;
	} 

	error = GetLastError();

	if (hFind != INVALID_HANDLE_VALUE && hFind != NULL)
		FindClose(hFind);

	if (error && !bret)
		SetLastError(error);

	return bret;

}

bool can_delete_file(LPCWSTR path)
{
	return true;
}

bool
delete_directory(CryptContext *con, LPCWSTR path)
{
	bool bret = true;

	try {

		if (con->GetConfig()->DirIV()) {

			std::wstring diriv_file = path;

			if (diriv_file[diriv_file.size() - 1] != '\\')
				diriv_file.push_back('\\');

			diriv_file.append(DIR_IV_NAME);

			DWORD attr = GetFileAttributes(&diriv_file[0]);

			if (attr != INVALID_FILE_ATTRIBUTES) {

				if (attr & FILE_ATTRIBUTE_READONLY) {
					attr &= ~FILE_ATTRIBUTE_READONLY;
					if (!SetFileAttributes(&diriv_file[0], attr)) {
						throw((int)GetLastError());
					}
				}

				con->m_dir_iv_cache.remove(path);

				if (!DeleteFile(&diriv_file[0])) {
					throw((int)GetLastError());
				}
			}
			
		}

		if (!RemoveDirectory(path)) {
			throw((int)GetLastError());
		}

		if (!con->GetConfig()->m_PlaintextNames && con->GetConfig()->m_LongNames && is_long_name(path)) {
			std::wstring name_file = path;
			if (name_file[name_file.size()-1] == '\\') {
				name_file.erase(name_file.size() - 1);
			}
			name_file += LONGNAME_SUFFIX_W;

			if (PathFileExists(&name_file[0])) {
				if (!DeleteFile(&name_file[0])) {
					throw((int)GetLastError());
				}
			}
		}

	} catch (int err) {
		if (err)
			SetLastError((DWORD)err);
		bret = false;
	} catch (...) {
		bret = false;
	}

	return bret;
}

bool delete_file(const CryptContext *con, const WCHAR *filename)
{
	if (PathFileExists(filename)) {
		if (!DeleteFile(filename))
			return false;
	}

	if (!con->GetConfig()->m_PlaintextNames && con->GetConfig()->m_LongNames && is_long_name(filename)) {
	
		std::wstring path = filename;

		path += LONGNAME_SUFFIX_W;

		if (PathFileExists(&path[0])) {
			if (DeleteFile(&path[0]))
				return true;
			else
				return false;
		}

		return true;
	} else {
		return true;
	}

}


