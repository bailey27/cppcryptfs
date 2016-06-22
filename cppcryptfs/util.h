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


const char *
unicode_to_utf8(const WCHAR *unicode_str, char *buf, int buflen);

const char *
unicode_to_utf8(const WCHAR *unicode_str, std::string& storage);

const char *
unicode_to_utf8_trivial(const WCHAR *unicode_str, std::string& storage);

const WCHAR *
utf8_to_unicode(const char *utf8_str, std::wstring& storage);

const WCHAR *
utf8_to_unicode_trivial(const char *utf8_str, std::wstring& storage);

bool
base64_decode(const char *str, std::vector<unsigned char>& storage, bool urlTransform = true);

const char *
base64_encode(const BYTE *data, DWORD datalen, std::string& storage, bool urlTransform = true);


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
get_random_bytes(unsigned char *buf, DWORD len);

bool get_sys_random_bytes(unsigned char *buf, DWORD len);
