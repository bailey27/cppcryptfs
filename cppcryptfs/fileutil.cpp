#include "stdafx.h"

#include "Shlwapi.h"

#include "cryptdefs.h"
#include "fileutil.h"
#include "cryptfilename.h"

#include <string>
#include <vector>

#include "dirivcache.h"

static DirIvCache dir_iv_cache;

bool
adjust_file_size_down(LARGE_INTEGER& l)
{
	long long size = l.QuadPart;

	if (size < 0)
		return false;

	if (size == 0)
		return true;

	long long blocks = (size - CIPHER_FILE_OVERHEAD + CIPHER_BS - 1) / CIPHER_BS;
	size -= (blocks*CIPHER_BLOCK_OVERHEAD + CIPHER_FILE_OVERHEAD);
	if (size < 1)
		return false;

	l.QuadPart = size;

	return true;
}

bool
adjust_file_size_up(LARGE_INTEGER& l)
{
	long long size = l.QuadPart;

	if (size < 0)
		return false;

	if (size == 0)
		return true;

	long long blocks = (size + PLAIN_BS - 1) / PLAIN_BS;
	size += (blocks*CIPHER_BLOCK_OVERHEAD + CIPHER_FILE_OVERHEAD);
	if (size < 1)
		return false;

	l.QuadPart = size;

	return true;
}

bool
adjust_write_offset_size_up(LARGE_INTEGER& l)
{
	long long size = l.QuadPart;

	if (size < 0)
		return false;

	if (size == 0)
		return true;

	long long blocks = (size + PLAIN_BS - 1) / PLAIN_BS;
	size += (blocks*CIPHER_BLOCK_OVERHEAD + CIPHER_FILE_OVERHEAD);
	if (size < 1)
		return false;

	l.QuadPart = size;

	return true;
}

static bool
read_dir_iv(const TCHAR *path, unsigned char *diriv)
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
	}
	catch (...) {
		nRead = 0;
	}

	if (hfile != INVALID_HANDLE_VALUE)
		CloseHandle(hfile);

	return nRead == DIR_IV_LEN;
}

bool
get_dir_iv(CryptContext *con, const TCHAR *path, unsigned char *diriv)
{

	if (con && !con->GetConfig()->DirIV()) {
		memset(diriv, 0, DIR_IV_LEN);
		return true;
	}

	bool bret = true;

	try {
		if (!dir_iv_cache.lookup(path, diriv)) {
			if (!read_dir_iv(path, diriv))
				throw(-1);
			if (!dir_iv_cache.store(path, diriv)) {
				throw(-1);
			}
		}
	} catch (...) {
		bret = false;
	}

	return bret;
}

static bool
convert_fdata(CryptContext *con, const WCHAR *path, WIN32_FIND_DATAW& fdata)
{

	if (!wcscmp(fdata.cFileName, L".") || !wcscmp(fdata.cFileName, L".."))
		return true;

	long long size = ((long long)fdata.nFileSizeHigh << 32) | fdata.nFileSizeLow;

	if (size > 0 && !(fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
		LARGE_INTEGER l;
		l.LowPart = fdata.nFileSizeLow;
		l.HighPart = fdata.nFileSizeHigh;
		if (!adjust_file_size_down(l))
			return false;
		fdata.nFileSizeHigh = l.HighPart;
		fdata.nFileSizeLow = l.LowPart;
	}

	std::wstring storage;
	const WCHAR *dname = decrypt_filename(con, path, fdata.cFileName, storage);

	if (!dname)
		return false;

	if (wcslen(dname) < MAX_PATH) {
		if (wcscpy_s(fdata.cFileName, MAX_PATH, dname))
			return false;
	} else {
		return false;
	}
#if 0 // GetShortPathNameW() seems to return a short name based on the encrypted name (how?)
	GetShortPathNameW(dname, fdata.cAlternateFileName, sizeof(fdata.cAlternateFileName) / sizeof(WCHAR));
#else
	fdata.cAlternateFileName[0] = '\0';
#endif
	return true;
}

DWORD
find_files(CryptContext *con, const WCHAR *pt_path, const WCHAR *path, std::vector<WIN32_FIND_DATAW>& files)
{
	DWORD ret = 0;
	HANDLE hfind = INVALID_HANDLE_VALUE;
	try {

		std::wstring enc_path = path;

		WIN32_FIND_DATAW fdata;		

		if (enc_path[enc_path.size()-1] != '\\')
			enc_path.push_back('\\');

		enc_path.push_back('*');

		hfind = FindFirstFile(&enc_path[0], &fdata);

		if (hfind == INVALID_HANDLE_VALUE)
			throw((int)GetLastError());

		if (wcscmp(fdata.cFileName, CONFIG_NAME) && wcscmp(fdata.cFileName, DIR_IV_NAME)) {

			if (!convert_fdata(con, path, fdata))
				throw((int)ERROR_PATH_NOT_FOUND);

			files.push_back(fdata);
		}

		bool isRoot = !wcscmp(pt_path, L"\\");

		while (FindNextFile(hfind, &fdata)) {
			if (isRoot && (!wcscmp(fdata.cFileName, L".") || !wcscmp(fdata.cFileName, L"..")))
				continue;
			if (!wcscmp(fdata.cFileName, CONFIG_NAME) || !wcscmp(fdata.cFileName, DIR_IV_NAME))
				continue;
			if (is_long_name_file(fdata.cFileName))
				continue;
			if (!convert_fdata(con, path, fdata))
				continue;
			files.push_back(fdata);
		}

		DWORD err = GetLastError();

		if (err != ERROR_NO_MORE_FILES)
			throw((int)err);

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
			

			// If CreateDirectory returned FILE_ALREADY_EXISTS and
			// it is called with FILE_OPEN_IF, that handle must be opened.
			handle = CreateFile(encpath, 0, FILE_SHARE_READ, NULL, OPEN_EXISTING,
				FILE_FLAG_BACKUP_SEMANTICS, NULL);
			if (handle == INVALID_HANDLE_VALUE) {
				DWORD error = GetLastError();
				
				throw((int)error);
			}
			opened = TRUE;
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

		LARGE_INTEGER l;
		l.LowPart = pInfo->nFileSizeLow;
		l.HighPart = pInfo->nFileSizeHigh;

		if (!adjust_file_size_down(l))
			throw((int)ERROR_INVALID_PARAMETER);

		pInfo->nFileSizeLow = l.LowPart;
		pInfo->nFileSizeHigh = l.HighPart;


	} catch (int err) {
		dwRet = (DWORD)err;
	} catch (...) {
		dwRet = ERROR_ACCESS_DENIED;
	}
	
	if (opened)
		CloseHandle(handle);

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

		if (!get_random_bytes(diriv, DIR_IV_LEN))
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

		if (nWritten != DIR_IV_LEN)
			throw((int)ERROR_OUTOFMEMORY);

		CloseHandle(hfile);
		hfile = INVALID_HANDLE_VALUE;

		// assume somebody will want to use it soon
		dir_iv_cache.store(path, diriv);

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

		std::wstring diriv_file = path;

		if (diriv_file[diriv_file.size() - 1] != '\\')
			diriv_file.push_back('\\');

		diriv_file.append(DIR_IV_NAME);

		if (PathFileExists(&diriv_file[0])) {
			DWORD attr = GetFileAttributes(&diriv_file[0]);
			if (attr != INVALID_FILE_ATTRIBUTES) {
				attr &= ~FILE_ATTRIBUTE_READONLY;
				if (!SetFileAttributes(&diriv_file[0], attr)) {
					throw((int)GetLastError());
				}
			} else {
				throw((int)GetLastError());
			}
			dir_iv_cache.remove(path);
			if (!DeleteFile(&diriv_file[0])) {
				throw((int)GetLastError());
			}
		}

		if (!RemoveDirectory(path)) {
			throw((int)GetLastError());
		}

		if (!con->GetConfig()->m_PlaintextNames && con->GetConfig()->m_LongNames) {
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
		std::wstring name_file;



	} catch (int err) {
		if (err)
			SetLastError((DWORD)err);
		bret = false;
	} catch (...) {
		bret = false;
	}

	return bret;
}

bool delete_file(CryptContext *con, const WCHAR *filename)
{
	if (PathFileExists(filename)) {
		if (!DeleteFile(filename))
			return false;
	}

	if (!con->GetConfig()->m_PlaintextNames && con->GetConfig()->m_LongNames) {
	
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


