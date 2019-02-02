//
//  types.h
//  cppcryptfs
//
//  Created by Bailey Brown on 12/8/16.
//  Copyright © 2016 Bailey Brown. All rights reserved.
//

#ifndef types_h
#define types_h

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

#endif /* types_h */
