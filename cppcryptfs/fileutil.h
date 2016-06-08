#pragma once

#include <windows.h>

#include <vector>

class CryptContext;

void DbgPrint(LPCWSTR format, ...);

bool
get_dir_iv(CryptContext *con, const WCHAR *path, unsigned char *dir_iv);

DWORD
find_files(CryptContext *con, const WCHAR *pt_path, const WCHAR *path, std::vector<WIN32_FIND_DATAW>& files);

DWORD
get_file_information(LPCWSTR FileName, HANDLE handle, LPBY_HANDLE_FILE_INFORMATION pInfo);

bool
create_dir_iv(CryptContext *con, LPCWSTR path); // path is unencrypted

bool
adjust_file_size_down(LARGE_INTEGER& l);

bool
adjust_file_size_up(LARGE_INTEGER& l);

bool
can_delete_directory(LPCWSTR path, BOOL bMustReallyBeEmpty = FALSE);

bool 
can_delete_file(LPCWSTR path);

bool
delete_directory(CryptContext *context, LPCWSTR path);

bool
delete_file(CryptContext *con, const WCHAR *filename);

