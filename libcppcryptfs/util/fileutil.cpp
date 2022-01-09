/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2022 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#ifdef _WIN32
#include "Shlwapi.h"
#endif

#include "crypt/cryptdefs.h"
#include "util/fileutil.h"
#include "filename/cryptfilename.h"

#include <string>
#include <vector>

#include "filename/dirivcache.h"

#ifdef _WIN32
// derive attributes for virtual reverse-mode diriv file from 
// the attributes of its directory
static DWORD 
VirtualAttributesDirIv(DWORD attr)
{
	attr &= ~(FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NORMAL);
	attr |= FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE;
	return attr;
}

// derive attributes for virtual reverse-mode longname name file
// from the attributes of its related file or directory
static DWORD
VirtualAttributesNameFile(DWORD attr)
{
	bool bForDir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
	attr &= ~FILE_ATTRIBUTE_DIRECTORY;
	if (attr == 0)
		attr = bForDir ? FILE_ATTRIBUTE_ARCHIVE : FILE_ATTRIBUTE_NORMAL;
	return attr;
}

#endif // _WIN32

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

bool
adjust_file_offset_up_truncate_zero(LARGE_INTEGER& l)
{
	long long offset = l.QuadPart;

	if (offset < 0)
		return false;

	if (offset == 0) // truncate zero-length file to 0 bytes
		return true;

	long long blocks = (offset + PLAIN_BS - 1) / PLAIN_BS;
	offset += blocks*CIPHER_BLOCK_OVERHEAD + CIPHER_FILE_OVERHEAD;

	l.QuadPart = offset;

	return true;
}

#ifdef _WIN32
static bool
read_dir_iv(const TCHAR *path, unsigned char *diriv, FILETIME& LastWriteTime)
{

	HANDLE hfile = INVALID_HANDLE_VALUE;
	DWORD nRead = 0;

	bool caught_wstring = false;

	try {
		wstring path_str;

		path_str.append(path);

		if (path_str[path_str.size() - 1] != '\\') {
			path_str.push_back('\\');
		}

		path_str.append(DIR_IV_NAME);

		hfile = ::CreateFile(&path_str[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

		if (hfile == INVALID_HANDLE_VALUE) {
			auto lasterr =::GetLastError();
			throw(L"\terror opening diriv file " + path_str + L" lasterr = " + to_wstring(lasterr));
		}

		if (!::ReadFile(hfile, diriv, DIR_IV_LEN, &nRead, NULL)) {
			auto lasterr = ::GetLastError();
			throw(L"\terror reading diriv file " + path_str + L" lasterr = " + to_wstring(lasterr));
		}

		if (!::GetFileTime(hfile, NULL, NULL, &LastWriteTime)) {
			auto lasterr = ::GetLastError();
			throw(L"\terror getting filetime of diriv file " + path_str + L" lasterr = " + to_wstring(lasterr));			
		}
	} catch (const wstring& mes) {
		DbgPrint(L"\tget_diriv: %s\n", mes.c_str());
		nRead = 0;
		caught_wstring = true;
	} catch (...) {
		nRead = 0;		
	}

	if (hfile != INVALID_HANDLE_VALUE)
		::CloseHandle(hfile);

	if (!caught_wstring && nRead != DIR_IV_LEN) {
		DbgPrint(L"\tget_diriv read incorrect number of bytes from %s, read %u bytes instead of %u\n", path, nRead, DIR_IV_LEN);
	}

	return nRead == DIR_IV_LEN;
}

#endif // _WIN32

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
			throw(wstring(L"\tcalled for reverse fs"));
		}

		if (!con->m_dir_iv_cache.lookup(path, diriv)) {
			FILETIME LastWritten;
			if (!read_dir_iv(path, diriv, LastWritten))
				throw(wstring(L"read_dir_iv failed for") + path);
			if (!con->m_dir_iv_cache.store(path, diriv, LastWritten)) {
				throw(wstring(L"store_diriv failed for ") + path);
			}
		}
	} catch (const wstring& mes) {
		DbgPrint(L"\tget_diriv %s\n", mes.c_str());
		bret = false;
	} catch (...) {
		bret = false;
	}

	return bret;
}

static bool
convert_fdata(CryptContext *con, BOOL isRoot, const BYTE *dir_iv, const WCHAR *path, WIN32_FIND_DATAW& fdata, string *actual_encrypted, wstring&  storage)
{

	if (!wcscmp(fdata.cFileName, L".") || !wcscmp(fdata.cFileName, L".."))
		return true;

	bool isReverseConfig = isRoot && con->GetConfig()->m_reverse && !wcscmp(fdata.cFileName, REVERSE_CONFIG_NAME);

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
		storage.clear();
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

		// wcscpy_s throws a weird exception if src is too long so check the length before calling it
		if (wcslen(dname) >= std::size(fdata.cFileName)) {
			return false;
		}
		if (wcscpy_s(fdata.cFileName, dname)) {
			return false;
		}
	}

	// short name - not really needed
	fdata.cAlternateFileName[0] = '\0';

	return true;
}

static bool is_interesting_name(BOOL isRoot, const WIN32_FIND_DATAW& fdata, CryptContext *con)
{
	bool reverse = con->GetConfig()->m_reverse;
	bool plaintext = con->GetConfig()->m_PlaintextNames;
	bool isconfig = !lstrcmpi(fdata.cFileName, CONFIG_NAME);
	
	if (isRoot && (!wcscmp(fdata.cFileName, L".") || !wcscmp(fdata.cFileName, L".."))) {
		return false;
	} else if ((!reverse && isRoot && isconfig) || (!reverse && !plaintext && !lstrcmpi(fdata.cFileName, DIR_IV_NAME))) {
		return false;
	} else if (!plaintext && !reverse && is_long_name_file(fdata.cFileName)) {
		return false;
	} else if (isRoot && reverse && plaintext && isconfig) {
		return false;
	} else {
		return true;
	}
}

#ifdef _WIN32
DWORD
find_files(CryptContext *con, const WCHAR *pt_path, const WCHAR *path, PCryptFillFindData fillData, void * dokan_cb, void * dokan_ctx)
{
	DWORD ret = 0;
	HANDLE hfind = INVALID_HANDLE_VALUE;

	bool reverse = con->GetConfig()->m_reverse;

	bool plaintext_names = con->GetConfig()->m_PlaintextNames;

	KeyDecryptor kdc(plaintext_names ? nullptr : &con->GetConfig()->m_keybuf_manager);

	list<wstring> files; // used only if case-insensitive

	try {

		wstring enc_path_search = path;

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

		string actual_encrypted;

		wstring storage;

		storage.reserve(MAX_PATH);

		do {
			if (reverse && !wcscmp(fdata.cFileName, L".")) {
				fdata_dot = fdata;
			}
			if (!is_interesting_name(isRoot, fdata, con))
				continue;
			WIN32_FIND_DATAW fdata_orig = fdata;
			if (!convert_fdata(con, isRoot, dir_iv, path, fdata, &actual_encrypted, storage))
				continue;
			fillData(&fdata, &fdata_orig, dokan_cb, dokan_ctx);
			if (reverse && !plaintext_names && is_long_name(fdata.cFileName)) {
				wcscat_s(fdata.cFileName, MAX_PATH, LONGNAME_SUFFIX_W);
				fdata.dwFileAttributes = VirtualAttributesNameFile(fdata.dwFileAttributes);
				fdata.ftLastWriteTime = fdata.ftCreationTime;
				fdata.cAlternateFileName[0] = '\0';
				fdata.nFileSizeHigh = 0;
				fdata.nFileSizeLow = (DWORD)actual_encrypted.length();
				fdata_orig = fdata;
				fillData(&fdata, &fdata_orig, dokan_cb, dokan_ctx);
			}
			if (con->IsCaseInsensitive()) {
				files.push_back(fdata.cFileName);
			}
		} while (FindNextFile(hfind, &fdata));

		DWORD err = GetLastError();

		if (err != ERROR_NO_MORE_FILES)
			throw((int)err);

		if (reverse && !plaintext_names) {
			fdata_dot.cAlternateFileName[0] = '\0';
			wcscpy_s(fdata_dot.cFileName, DIR_IV_NAME);
			fdata_dot.nFileSizeHigh = 0;
			fdata_dot.nFileSizeLow = DIR_IV_LEN;
			fdata_dot.ftLastWriteTime = fdata_dot.ftCreationTime;
			fdata_dot.dwFileAttributes = VirtualAttributesDirIv(fdata_dot.dwFileAttributes);
			WIN32_FIND_DATAW fdata_orig = fdata_dot;
			fillData(&fdata_dot, &fdata_orig, dokan_cb, dokan_ctx);
		}

		ret = 0;

	} catch (int error) {
		ret = (DWORD)error;
	} catch (...) {
		ret = ERROR_OUTOFMEMORY;
	}

	if (hfind != INVALID_HANDLE_VALUE)
		FindClose(hfind);

	if (ret == 0 && con->IsCaseInsensitive())
		con->m_case_cache.store(pt_path, files);

	return ret;
}
#endif // _WIN32


bool
read_virtual_file(CryptContext *con, LPCWSTR FileName, unsigned char *buf, DWORD buflen, LPDWORD pNread, LONGLONG offset)
{
	if (rt_is_dir_iv_file(con, FileName)) {
		wstring dirpath;
		if (!get_file_directory(FileName, dirpath))
			return false;
		BYTE dir_iv[DIR_IV_LEN];
		if (!derive_path_iv(con, &dirpath[0], dir_iv, TYPE_DIRIV))
			return false;
		LONGLONG count = min(DIR_IV_LEN - offset, buflen);
		if (count <= 0) {
			*pNread = 0;
			return true;
		}
		memcpy(buf, dir_iv + offset, static_cast<size_t>(count));
		*pNread = (DWORD)count;
		return true;
	} else if (rt_is_name_file(con, FileName)) {
		string actual_encrypted;
		if (!get_actual_encrypted(con, FileName, actual_encrypted))
			return false;
		LONGLONG count = min(actual_encrypted.length() - offset, buflen);
		if (count <= 0) {
			*pNread = 0;
			return true;
		}
		memcpy(buf, &actual_encrypted[0], static_cast<size_t>(count));
		*pNread = (DWORD)count;
		return true;
	} else {
		return false;
	}
}


#ifdef _WIN32
DWORD
get_file_information(CryptContext *con, function<LPCWSTR()> getEncPath, LPCWSTR inputPath, HANDLE handle, LPBY_HANDLE_FILE_INFORMATION pInfo)
{
	BOOL opened = FALSE;

	DWORD dwRet = 0;

	bool is_config = rt_is_config_file(con, inputPath);

	bool is_dir_iv = rt_is_dir_iv_file(con, inputPath);

	bool is_virtual = rt_is_virtual_file(con, inputPath);

	bool is_name_file = rt_is_name_file(con, inputPath);

	try {	


		if (!handle || (handle == INVALID_HANDLE_VALUE && !is_virtual)) {

			throw((int)ERROR_INVALID_PARAMETER);

		}

		if (is_dir_iv) {
			wstring dirpath;
			if (!get_file_directory(getEncPath(), dirpath))
				throw((int)ERROR_ACCESS_DENIED);

			HANDLE hDir = CreateFile(&dirpath[0], FILE_READ_ATTRIBUTES, 
							FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
							NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
			if (hDir == INVALID_HANDLE_VALUE)
				throw((int)GetLastError());

			BOOL bResult = GetFileInformationByHandle(hDir, pInfo);

			if (!bResult) {
				DWORD lastErr = GetLastError();
				CloseHandle(hDir);
				throw((int)lastErr);
			}

			CloseHandle(hDir);

			pInfo->dwFileAttributes = VirtualAttributesDirIv(pInfo->dwFileAttributes);
			pInfo->ftLastWriteTime = pInfo->ftCreationTime;
			pInfo->nFileSizeHigh = 0;
			pInfo->nFileSizeLow = DIR_IV_LEN;
			pInfo->nNumberOfLinks = 1;

		} else if (is_name_file) {

			wstring enc_filename;

			remove_longname_suffix(inputPath, enc_filename);

			wstring decrypted_name;

			if (!decrypt_path(con, &enc_filename[0], decrypted_name))
				throw((int)ERROR_ACCESS_DENIED);

			HANDLE hFile = CreateFile(&decrypted_name[0], FILE_READ_ATTRIBUTES, 
							FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
							NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
			if (hFile == INVALID_HANDLE_VALUE)
				throw((int)GetLastError());

			BOOL bResult = GetFileInformationByHandle(hFile, pInfo);

			if (!bResult) {
				DWORD lastErr = GetLastError();
				CloseHandle(hFile);
				throw((int)lastErr);
			}

			CloseHandle(hFile);

			string actual_encrypted;

			if (!get_actual_encrypted(con, &enc_filename[0], actual_encrypted))
				throw((int)ERROR_ACCESS_DENIED);

			pInfo->dwFileAttributes = VirtualAttributesNameFile(pInfo->dwFileAttributes);
			pInfo->ftLastWriteTime = pInfo->ftCreationTime;
			pInfo->nFileSizeHigh = 0;
			pInfo->nFileSizeLow = (DWORD)actual_encrypted.length();
			pInfo->nNumberOfLinks = 1;

		}  else if (!GetFileInformationByHandle(handle, pInfo)) {
			

			if (opened) {
				opened = FALSE;
				CloseHandle(handle);
			}

			// FileName is a root directory
			// in this case, FindFirstFile can't get directory information
			if (wcslen(getEncPath()) == 1) {
				
				pInfo->dwFileAttributes = GetFileAttributes(getEncPath());

			} else {
				WIN32_FIND_DATAW find;
				ZeroMemory(&find, sizeof(WIN32_FIND_DATAW));
				HANDLE findHandle = FindFirstFile(getEncPath(), &find);
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

		if (!is_config && !is_virtual && !(pInfo->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {

			LARGE_INTEGER l;
			l.LowPart = pInfo->nFileSizeLow;
			l.HighPart = pInfo->nFileSizeHigh;

			if (con->GetConfig()->m_reverse) {
				if (!adjust_file_size_up(l))
					throw((int)ERROR_INVALID_PARAMETER);
			} else {
				if (!adjust_file_size_down(l))
					throw((int)ERROR_INVALID_PARAMETER);
			}

			pInfo->nFileSizeLow = l.LowPart;
			pInfo->nFileSizeHigh = l.HighPart;
	
		}

		if (is_config)
			pInfo->dwFileAttributes &= ~FILE_ATTRIBUTE_HIDDEN;


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
#endif // _WIN32


#ifdef _WIN32
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

		wstring path_str = path;

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

#endif // _WIN32

#ifdef _WIN32
bool
is_empty_directory(LPCWSTR path, BOOL bMustReallyBeEmpty, CryptContext *con)
{
	bool bret = true;

	WIN32_FIND_DATAW findData;

	HANDLE hFind = INVALID_HANDLE_VALUE;

	DWORD error = 0;

	try {

		wstring enc_path = path;

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

		vector<wstring> dummy;

		auto& deletable_files = con ? con->GetDeletableFiles() : dummy;

		auto can_be_deleted = [](const vector<wstring>& deletable_files, LPCWSTR fname) -> bool {
			auto count = deletable_files.size();
			for (size_t i = 0; i < count; i++) {
				if (lstrcmpi(deletable_files[i].c_str(), fname) == 0)
					return true;
			}
			return false;
		};

		while (hFind != INVALID_HANDLE_VALUE) {
			if (wcscmp(findData.cFileName, L"..") != 0 &&
				wcscmp(findData.cFileName, L".") != 0 &&
				(bMustReallyBeEmpty || !can_be_deleted(deletable_files, findData.cFileName))) {
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

bool
can_delete_directory(LPCWSTR path, BOOL bMustReallyBeEmpty, CryptContext *con)
{
	return is_empty_directory(path, bMustReallyBeEmpty, con);
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

		wstring path_with_slash = path;	

		if (path_with_slash[path_with_slash.size() - 1] != '\\')
			path_with_slash.push_back('\\');

		vector<wstring> dummy;

		auto& files_to_delete = con ? con->GetDeletableFiles() : dummy;

		wstring file_to_delete;

		for (size_t i = 0; i < files_to_delete.size(); i++) {

			file_to_delete = path_with_slash + files_to_delete[i];

			DWORD attr = GetFileAttributes(file_to_delete.c_str());

			if (attr != INVALID_FILE_ATTRIBUTES) {

				if (attr & FILE_ATTRIBUTE_READONLY) {
					attr &= ~FILE_ATTRIBUTE_READONLY;
					if (!SetFileAttributes(file_to_delete.c_str(), attr)) {
						throw((int)GetLastError());
					}
				}

				if (!DeleteFile(file_to_delete.c_str())) {
					throw((int)GetLastError());
				}
			}
		}

		if (con->GetConfig()->DirIV()) {
			con->m_dir_iv_cache.remove(path);
		}

		if (!RemoveDirectory(path)) {
			throw((int)GetLastError());
		}

		if (!con->GetConfig()->m_PlaintextNames && con->GetConfig()->m_LongNames && is_long_name(path)) {
			wstring name_file = path;
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

bool delete_file(const CryptContext *con, const WCHAR *filename, bool cleanup_longname_file_only)
{
	if (!cleanup_longname_file_only && PathFileExists(filename)) {
		if (!DeleteFile(filename))
			return false;
	}

	if (!con->GetConfig()->m_PlaintextNames && con->GetConfig()->m_LongNames && is_long_name(filename)) {
	
		wstring path = filename;

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
#endif // _WIN32


bool
get_dir_and_file_from_path(LPCWSTR path, wstring *dir, wstring *file)
{

	if (!wcscmp(path, L"\\")) {
		if (dir)
			*dir = L"\\";
		if (file)
			*file = L"";
		return true;
	}
	
	LPCWSTR pLastSlash = wcsrchr(path, '\\');

	if (!pLastSlash) {
		return false;
	}

	if (file) {
		*file = pLastSlash + 1;
	}

	if (dir) {
		if (pLastSlash != path) {
			*dir = path;
			dir->erase(pLastSlash - path);
		} else {
			*dir = L"\\";
		}
	}

	return true;
}


bool	  
get_file_stream(LPCWSTR filename, wstring *file, wstring *stream)
{

	LPCWSTR pStreamColon = wcschr(filename, ':');

	if (pStreamColon) { // have stream
		if (file) {
			*file = filename;
			file->erase(pStreamColon - filename);
		}
		if (stream)
			*stream = pStreamColon;
		return true;
	} else {
		if (file)
			*file = filename;
		if (stream)
			*stream = L"";
		return false;
	}
}

bool
remove_stream_type(LPCWSTR stream, wstring& stream_without_type, wstring& type)
{
	if (!stream || stream[0] != ':')
		return false;

	LPCWSTR pLastColon = wcsrchr(stream, ':');

	if (pLastColon == stream) {
		type = L"";
		stream_without_type = stream;
		return true;
	}

	stream_without_type = stream;

	stream_without_type.erase(pLastColon - stream);

	type = pLastColon;

	return true;
}

bool
convert_find_stream_data(CryptContext *con, LPCWSTR pt_path, LPCWSTR path, WIN32_FIND_STREAM_DATA& fdata)
{

	BYTE dir_iv[DIR_IV_LEN];

	bool plaintext_names = con->GetConfig()->m_PlaintextNames;

	bool reverse = con->GetConfig()->m_reverse;

	if (!plaintext_names && wcscmp(fdata.cStreamName, L"::$DATA")) {
		if (reverse) {
			wstring dirpath;
			if (!get_file_directory(pt_path, dirpath))
				return false;
			if (!derive_path_iv(con, dirpath.c_str(), dir_iv, TYPE_DIRIV))
				return false;

			wstring enc_stream;

			if (!encrypt_stream_name(con, dir_iv, fdata.cStreamName, enc_stream))
				return false;

			wcscpy_s(fdata.cStreamName, enc_stream.c_str());

		} else {
			wstring dirpath;
			if (!get_file_directory(path, dirpath))
				return false;
			if (!get_dir_iv(con, dirpath.c_str(), dir_iv))
				return false;

			wstring pt_stream;

			if (!decrypt_stream_name(con, dir_iv, fdata.cStreamName, pt_stream))
				return false;

			wcscpy_s(fdata.cStreamName, pt_stream.c_str());

		}

	}

	if (reverse) {
		if (!adjust_file_size_up(fdata.StreamSize))
			return false;
	} else {
		if (!adjust_file_size_down(fdata.StreamSize))
			return false;
	}

	return true;
}

#ifdef _WIN32
bool is_suitable_mountpoint(LPCWSTR path)
{
	if (!is_empty_directory(path, TRUE))
		return false;

	WCHAR rpath[4];

	rpath[0] = *path;
	rpath[1] = ':';
	rpath[2] = '\\';
	rpath[3] = '\0';

	WCHAR fsnamebuf[256];

	if (!GetVolumeInformationW(rpath, NULL,
		0, NULL, NULL,
		NULL, fsnamebuf, sizeof(fsnamebuf) / sizeof(fsnamebuf[0]) - 1)) {
		DWORD error = GetLastError();
		//DbgPrint(L"get fs name error = %u\n", error);
		return false;
	}

	return !lstrcmpi(fsnamebuf, L"NTFS");

}

bool is_mountpoint_a_dir(LPCWSTR mountpoint)
{
	if (!mountpoint)
		return false;

	return wcslen(mountpoint) > 2;
}

bool is_mountpoint_a_drive(LPCWSTR mountpoint)
{
	if (!mountpoint)
		return false;

	return !is_mountpoint_a_dir(mountpoint);
}

wstring prepare_basedir(const wchar_t *path)
{
	wstring basedir = path;

	// strip any trailing backslashes
	while (basedir.size() > 0 &&
		basedir[basedir.size() - 1] == '\\')
		basedir.erase(basedir.size() - 1);

	wstring holder = basedir;

	WCHAR drive[_MAX_DRIVE] = { 0 };
	WCHAR dir[_MAX_DIR];
	WCHAR fname[_MAX_FNAME];
	WCHAR ext[_MAX_EXT];

	const auto err = _wsplitpath_s(holder.c_str(), drive, dir, fname, ext);

	const bool unc = !err && wcslen(drive) == 0;

	// for UNC paths, need to eat all leading \ for them to work
	while (unc && holder.length() > 1 && holder[0] == '\\') {
		holder = holder.c_str() + 1;
	}

	basedir = !unc ?
		L"\\\\?\\" : L"\\\\?\\UNC\\"; // this prefix enables up to 32K long file paths on NTFS

	basedir += holder;

	return basedir;
}

#endif // __WIN32