#pragma once

//
//  types.h
//  cppcryptfs
//
//  Created by Bailey Brown on 12/8/16.
//  Copyright © 2016-2024 Bailey Brown. All rights reserved.
//

#ifndef wintypes_h
#define wintypes_h

#ifdef _WIN32
#include "stdafx.h"
#else

#define MAX_PATH 260

typedef wchar_t WCHAR;
typedef const WCHAR *LPCWSTR;

typedef unsigned char BYTE;
typedef BYTE *LPBYTE;

typedef unsigned int DWORD, *LPDWORD;
typedef int LONG;
typedef long long LONGLONG;

typedef union _LARGE_INTEGER {
	struct {
		DWORD LowPart;
		LONG  HighPart;
	};
	struct {
		DWORD LowPart;
		LONG  HighPart;
	} u;
	LONGLONG QuadPart;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _WIN32_FIND_DATAW {
	WCHAR cFileName[MAX_PATH];
} WIN32_FIND_DATAW;

typedef WIN32_FIND_DATAW WIN32_FIND_DATA;

typedef int BOOL;
typedef unsigned char byte;

#endif // _WIN32
#endif /* wintypes_h */
