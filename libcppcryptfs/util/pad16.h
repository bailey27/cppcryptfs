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

/*
This code was translated into C++ by Bailey Brown from
pad16.go from the project gocryptfs (github.com/rfjakob/gocryptfs).

Bellow is the comment header from pad16.go
*/

// pad16 - pad data to AES block size (=16 byte) using standard PKCS#7 padding
// https://tools.ietf.org/html/rfc5652#section-6.3

#pragma once

#include <windows.h>

template <size_t L>
bool pad16(const BYTE* orig, int len, int& newLen, TempBuffer<BYTE, L>& padded) {
	int oldLen = len;
	if (oldLen == 0) {
		return NULL;
	}
	int padLen = 16 - oldLen % 16;
	if (padLen == 0) {
		padLen = 16;
	}
	newLen = oldLen + padLen;
	BYTE* p = padded.get(newLen);
	if (!p)
		return false;
	memcpy(p, orig, len);
	BYTE padByte = (BYTE)(padLen);
	for (int i = oldLen; i < newLen; i++) {
		p[i] = padByte;
	}
	return true;
}

int unPad16(BYTE *padded, int len);