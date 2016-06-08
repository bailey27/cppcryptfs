// pad16 - pad data to AES block size (=16 byte) using standard PKCS#7 padding
// https://tools.ietf.org/html/rfc5652#section-6.3

#include "stdafx.h"

#include <windows.h>

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