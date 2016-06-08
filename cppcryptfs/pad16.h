#pragma once

#include <windows.h>

BYTE* pad16(const BYTE* orig, int len, int& newLen);

int unPad16(BYTE *padded, int len);