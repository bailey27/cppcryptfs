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

#include <stdio.h>
#include "util.h"
#include "cryptdefs.h"
#include <openssl/rand.h>

#include <wincrypt.h>

#include <iostream>

#include "randombytes.h"

template<typename T>
T swapBytesVal(T x)
{
	T y;
	char* px = (char*)&x;
	char* py = (char*)&y;
	for (int i = 0; i<sizeof(T); i++)
		py[i] = px[sizeof(T) - 1 - i];
	return y;
}

template<typename T>
T MakeBigEndian(T n)
{

	if (!IsBigEndianMachine()) {
		return swapBytesVal(n);
	} else {
		return n;
	}
}

template unsigned long long MakeBigEndian(unsigned long long);

template<typename T>
T MakeBigEndianNative(T n)
{
	return MakeBigEndian(n);
}

template unsigned short MakeBigEndianNative(unsigned short);

BOOL
IsBigEndianMachine()
{
	const unsigned int a = 1;

	const unsigned char *p = (const unsigned char *)&a;

	return !p[0];
}

const char *
unicode_to_utf8(const WCHAR *unicode_str, char *buf, int buflen)
{
	int len = WideCharToMultiByte(CP_UTF8, 0, unicode_str, -1, NULL, 0, NULL, NULL);

	if (len == 0)
		return NULL;

	// len includes space for null char
	if (len > buflen)
		return NULL;

	if (WideCharToMultiByte(CP_UTF8, 0, unicode_str, -1, buf, len, NULL, NULL) == 0) {
		return NULL;
	}

	return buf;
}

const char *
unicode_to_utf8(const WCHAR *unicode_str, std::string& storage)
{

	int len = WideCharToMultiByte(CP_UTF8, 0, unicode_str, -1, NULL, 0, NULL, NULL);

	if (len == 0)
		return NULL;

	// len includes space for null char
	char *p_utf8 = new char[len];

	if (!p_utf8)
		return NULL;

	if (WideCharToMultiByte(CP_UTF8, 0, unicode_str, -1, p_utf8, len, NULL, NULL) == 0) {
		delete[] p_utf8;
		return NULL;
	}

	storage = p_utf8;

	delete[] p_utf8;

	return &storage[0];
}

const char *
unicode_to_utf8_trivial(const WCHAR *unicode_str, std::string& storage)
{

	size_t len = wcslen(unicode_str);

	storage.clear();

	storage.reserve(len);

	size_t i;

	for (i = 0; i < len; i++)
		storage.push_back((char)(unicode_str[i]));

	return &storage[0];
}

const WCHAR *
utf8_to_unicode(const char *utf8_str, std::wstring& storage)
{
	int len = MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, NULL, 0);

	if (len == 0)
		return NULL;

	// len includes space for null char
	WCHAR *p_unicode = new WCHAR[len];

	if (!p_unicode)
		return NULL;

	if (MultiByteToWideChar(CP_UTF8, 0, utf8_str, -1, p_unicode, len) == 0) {
		delete[] p_unicode;
		return NULL;
	}

	storage = p_unicode;

	delete[] p_unicode;

	return &storage[0];
}


const WCHAR *
utf8_to_unicode_trivial(const char *utf8_str, std::wstring& storage)
{

	size_t len = strlen(utf8_str);

	storage.clear();

	storage.reserve(len);

	size_t i;

	for (i = 0; i < len; i++)
		storage.push_back(utf8_str[i]);

	return &storage[0];
}

bool
base64_decode(const char *str, std::vector<unsigned char>& storage, bool urlTransform)
{
	size_t str_len;

	if (!str || (str_len = strlen(str)) < 1)
		return false;

	// we almost always have urlTransform as true so it doens't hurt too much to unconditionally make a copy of the string
	char *p = _strdup(str);

	if (!p)
		return false;

	if (urlTransform) {	

		size_t i;
		for (i = 0; i < str_len; i++) {
			if (p[i] == '-')
				p[i] = '+';
			else if (p[i] == '_')
				p[i] = '/';
		}
	}

	DWORD len = (DWORD)str_len;

	try {
		storage.resize(len);
	} 
	catch (...) {
		free(p);
		return false;
	}

	BOOL bResult = CryptStringToBinaryA(p, 0, CRYPT_STRING_BASE64, &storage[0], &len, NULL, NULL);

	free(p);

	if (bResult) {
		storage.resize(len);
		return true;
	} else {
		return false;
	}
}


const char *
base64_encode(const BYTE *data, DWORD datalen, std::string& storage, bool urlTransform)
{
	if (!data || datalen < 1)
		return NULL;

	DWORD base64len = datalen*2;

	char *base64str = new char[base64len + 1];

	if (!base64str)
		return NULL;

	BOOL bResult = CryptBinaryToStringA(data, datalen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64str, &base64len);

	if (bResult) {

		if (urlTransform) {
			size_t len = strlen(base64str);
			size_t i;
			for (i = 0; i < len; i++) {
				if (base64str[i] == '+')
					base64str[i] = '-';
				else if (base64str[i] == '/')
					base64str[i] = '_';
			}
		}
		storage = base64str;
		delete[] base64str;
		return &storage[0];
	} else {
		delete[] base64str;
		return NULL;
	}
}

bool read_password(WCHAR *pwbuf, int pwbuflen, const WCHAR *prompt)
{
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);

	if (!hStdin)
		return false;

	std::wcout << (prompt ? prompt : L"Password: ");

	DWORD old_mode = 0;
	if (!GetConsoleMode(hStdin, &old_mode))
		return false;

	if (!SetConsoleMode(hStdin, old_mode & (~ENABLE_ECHO_INPUT)))
		return false;

	DWORD nRead = 0;

	ReadConsole(hStdin, pwbuf, pwbuflen - 1, &nRead, NULL);

	if (nRead >= 2 && pwbuf[nRead - 2] == L'\r' && pwbuf[nRead - 1] == L'\n')
		pwbuf[nRead - 2] = '\0';

	SetConsoleMode(hStdin, old_mode);

	std::wcout << L"\n";

	return true;
}


bool
get_sys_random_bytes(unsigned char *buf, DWORD len)
{
	
	HCRYPTPROV hProvider = NULL;

	if (!CryptAcquireContextW(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		return false;
	}

	if (!CryptGenRandom(hProvider, len, buf)) {
		CryptReleaseContext(hProvider, 0);
		return false;
	}

	CryptReleaseContext(hProvider, 0);

	return true;

}

static RandomBytes rand_bytes;

bool
get_random_bytes(unsigned char *buf, DWORD len)
{
	return rand_bytes.GetRandomBytes(buf, len);
}


