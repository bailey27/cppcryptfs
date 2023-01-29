/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2023 Bailey Brown (github.com/bailey27/cppcryptfs)

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


#include "pch.h"
#include "framework.h"
#include "commonutil.h"

#include<memory>

#pragma comment(lib, "version.lib") 

bool
GetProductVersionInfo(wstring& strProductName, wstring& strProductVersion,
	wstring& strLegalCopyright, HMODULE hMod)
{

	TCHAR fullPath[MAX_PATH + 1];
	*fullPath = L'\0';
	if (!GetModuleFileName(hMod, fullPath, MAX_PATH)) {
		return false;
	}
	DWORD dummy = 0;
	DWORD vSize = GetFileVersionInfoSize(fullPath, &dummy);
	if (vSize < 1) {
		return false;
	}

	auto pVersionResourceHandle = cppcryptfs::unique_rsc(malloc, free, vSize);

	void* pVersionResource = pVersionResourceHandle.get();

	if (pVersionResource == NULL)
	{
		return false;
	}

	if (!GetFileVersionInfo(fullPath, NULL, vSize, pVersionResource)) {
		return false;
	}

	// get the name and version strings
	LPVOID pvProductName = NULL;
	unsigned int iProductNameLen = 0;
	LPVOID pvProductVersion = NULL;
	unsigned int iProductVersionLen = 0;
	LPVOID pvLegalCopyright = NULL;
	unsigned int iLegalCopyrightLen = 0;

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	// Read the list of languages and code pages.
	unsigned int cbTranslate;
	if (!VerQueryValue(pVersionResource,
		TEXT("\\VarFileInfo\\Translation"),
		(LPVOID*)&lpTranslate,
		&cbTranslate)) {

		return false;
	}

	if (cbTranslate / sizeof(struct LANGANDCODEPAGE) < 1) {
		return false;
	}

	wstring lang;

	WCHAR buf[16];

	// use the first language/codepage;

	wsprintf(buf, L"%04x%04x", lpTranslate->wLanguage, lpTranslate->wCodePage);

	lang = buf;

	// replace "040904e4" with the language ID of your resources
	if (!VerQueryValue(pVersionResource, (L"\\StringFileInfo\\" + lang + L"\\ProductName").c_str(), &pvProductName, &iProductNameLen) ||
		!VerQueryValue(pVersionResource, (L"\\StringFileInfo\\" + lang + L"\\ProductVersion").c_str(), &pvProductVersion, &iProductVersionLen) ||
		!VerQueryValue(pVersionResource, (L"\\StringFileInfo\\" + lang + L"\\LegalCopyright").c_str(), &pvLegalCopyright, &iLegalCopyrightLen))
	{
		return false;
	}

	if (iProductNameLen < 1 || iProductVersionLen < 1 || iLegalCopyrightLen < 1) {
		return false;
	}

	strProductName = (LPCTSTR)pvProductName;
	strProductVersion = (LPCTSTR)pvProductVersion;
	strLegalCopyright = (LPCTSTR)pvLegalCopyright;

	return true;
}

wstring GetWindowsErrorString(DWORD dwLastErr)
{
	wstring mes;

	if (dwLastErr == 0) {
		mes += L"unknown windows error 0";
		return mes;
	}

	LPTSTR errorText = NULL;

	if (!::FormatMessageW(
		// use system message tables to retrieve error text
		FORMAT_MESSAGE_FROM_SYSTEM
		// allocate buffer on local heap for error text
		| FORMAT_MESSAGE_ALLOCATE_BUFFER
		// Important! will fail otherwise, since we're not 
		// (and CANNOT) pass insertion parameters
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
		dwLastErr,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&errorText,  // output 
		0, // minimum size for output buffer
		NULL)) {   // arguments - see note 

		mes += L"unable to get message for error " + to_wstring(dwLastErr);

		if (errorText) {
			LocalFree(errorText);
		}

		return mes;
	}

	if (errorText) {
		// ... do something with the string `errorText` - log it, display it to the user, etc.
		mes += errorText;
		// release memory allocated by FormatMessage()
		LocalFree(errorText);
		errorText = NULL;
	} else {
		mes += L"got null message for error " + to_wstring(dwLastErr);
	}

	return mes;
}

