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

