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

#include "stdafx.h"
#include <stdlib.h>

#include "pad16.h"

BYTE* pad16(const BYTE* orig, int len, int& newLen)  {
	int oldLen = len;
	if (oldLen == 0) {
		return NULL;
	}
	int padLen = 16 - oldLen % 16;
	if (padLen == 0) {
		padLen = 16;
	}
	newLen = oldLen + padLen;
	BYTE *padded = (BYTE*)malloc(newLen);
	if (!padded)
		return NULL;
	memcpy(padded, orig, len);
	BYTE padByte = (BYTE)(padLen);
	for (int i = oldLen; i < newLen; i++) {
		padded[i] = padByte;
	}
	return padded;
}

// unPad16 - remove padding
int unPad16(BYTE *padded, int len) {
	int oldLen = len;
	if (oldLen % 16 != 0) {
		return -1;
	}
		// The last byte is always a padding byte
	BYTE padByte = padded[oldLen - 1];
		// The padding byte's value is the padding length
	int padLen = (int)(padByte);
	// Padding must be at least 1 byte
	if (padLen <= 0) {
		return -1;
	}
	// Larger paddings make no sense
	if (padLen > 16) {
		return -1;
	}
		// All padding bytes must be identical
	for (int i = oldLen - padLen; i < oldLen; i++) {
		if (padded[i] != padByte) {
			return -1;
		}
	}
	int newLen = oldLen - padLen;
	// Padding an empty string makes no sense
	if (newLen == 0) {
		return -1;
	}
	return newLen;
}