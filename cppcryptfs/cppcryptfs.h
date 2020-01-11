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

// cppcryptfs.h : main header file for the PROJECT_NAME application
//

#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols

#include <unordered_map>
#include <string>
#include "crypt/cryptdefs.h"

using namespace std;

#define CPPCRYPTFS_COPYDATA_CMDLINE_OLD 0x574cd9d1

#define CPPCRYPTFS_COPYDATA_PIPE 0x574cd9d2

#define CPPCRYPTFS_COPYDATA_CMDLINE_MAXLEN (64*1024) // keep small because of VirtualLock()

#define CPPCRYPTFS_REG_PATH L"Software\\cppcryptfs\\cppcryptfs\\"

#define CPPCRYPTFS_FOLDERS_SECTION L"Folders"
#define CPPCRYPTFS_CONFIGPATHS_SECTION L"ConfigPaths"
#define CPPCRYPTFS_MOUNTPOINTS_SECTION L"MountPoints"

typedef struct struct_CopyDataCmdLine {
	HANDLE hPipe; // handle of named pipe to read command line from
} CopyDataCmdLine;

// CcppcryptfsApp:
// See cppcryptfs.cpp for the implementation of this class
//

class CcppcryptfsApp : public CWinApp
{
public:
	void SendCmdArgsToSelf(HANDLE hPipe);
public:
	CcppcryptfsApp();
#if 0
	unordered_map<wstring, wstring> m_mountedMountPoints; // used for tracking all mounted mountpoints (dirs and drive letters)
																		 // drive letters are stored with colon e.g drive M as L"M:"
#endif
	DWORD m_mountedLetters;        // used for tracking mounted (by cpppcryptfs) drive letters
// Overrides
public:
	virtual BOOL InitInstance() override;

	virtual BOOL WriteProfileInt(LPCWSTR section, LPCWSTR entry, INT val) override;
	virtual BOOL WriteProfileString(LPCWSTR section, LPCWSTR entry, LPCWSTR val) override;
	virtual BOOL WriteProfileBinary(LPCWSTR section, LPCWSTR entry, LPBYTE pData, UINT nBytes) override;

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CcppcryptfsApp theApp;