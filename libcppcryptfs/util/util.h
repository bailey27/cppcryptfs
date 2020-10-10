/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2020 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include <string>
#include <vector>
#include <utility>

using namespace std;

class CryptContext;

void SetDbgVars(BOOL DebugMode, BOOL UseStdErr, BOOL UseLogFile, FILE* logfile);
void DbgPrint(LPCWSTR format, ...);

const char *
unicode_to_utf8(const WCHAR *unicode_str, char *buf, int buflen);

const char *
unicode_to_utf8(const WCHAR *unicode_str, string& storage);

const WCHAR *
utf8_to_unicode(const char *utf8_str, wstring& storage);

bool
base64_decode(const char *str, vector<unsigned char>& storage, bool urlTransform, bool padding);

bool
base64_decode(const WCHAR *str, vector<unsigned char>& storage, bool urlTransform, bool padding);

const char *
base64_encode(const BYTE *data, DWORD datalen, string& storage, bool urlTransform, bool padding);

const WCHAR *
base64_encode(const BYTE *data, DWORD datalen, wstring& storage, bool urlTransform, bool padding);


BOOL
IsBigEndianMachine();


template<typename T>
T swapBytesVal(T x);

template<typename T>
T MakeBigEndian(T n);

template<typename T>
T MakeBigEndianNative(T n);

bool read_password(WCHAR *pwbuf, int pwbuflen, const WCHAR *prompt = NULL);

bool
get_random_bytes(CryptContext *con, unsigned char *buf, DWORD len);

bool get_sys_random_bytes(unsigned char *buf, DWORD len);

DWORD getppid();

bool have_args();

bool OpenConsole(DWORD pid = 0);

void CloseConsole();

void ConsoleErrMesPipe(LPCWSTR err, HANDLE hPipe);

bool touppercase(LPCWSTR in, wstring& out);

int compare_names(CryptContext *con, LPCWSTR name1, LPCWSTR name2);

bool is_all_zeros(const BYTE *buf, size_t len);

BOOL GetPathHash(LPCWSTR path, wstring& hashstr);

void SetOverlapped(LPOVERLAPPED pOv, LONGLONG offset);

void IncOverlapped(LPOVERLAPPED pOv, DWORD increment);

const wchar_t* get_command_line_usage();