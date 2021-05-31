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

#include "stdafx.h"
#include "uiutil.h"

#include <list>

#include "ui/MountMangerDialog.h"
#include "ui/cryptdefaults.h"
#include "ui/certutil.h"

#include "dokan/cryptdokan.h"

using namespace std;

bool mountmanager_continue_mounting()
{
	CMountMangerDialog mdlg;

	mdlg.DoModal();

	return mdlg.m_bOkPressed != 0;
}

bool DeleteAllRegisteryValues(LPCWSTR regPath, wstring& mes)
{
	mes.clear();

	HKEY hkey;
	LSTATUS status = ::RegOpenKeyEx(HKEY_CURRENT_USER, regPath, 0, KEY_ALL_ACCESS, &hkey);
	if (status != ERROR_SUCCESS) {
		if (status != ERROR_FILE_NOT_FOUND) {
			mes = L"unable to open history";
		}
		return false;
	}
	DWORD index = 0;
	DWORD type;
	WCHAR val[256];
	DWORD val_len = _countof(val);
	list<std::wstring> values;
	while ((status = ::RegEnumValue(hkey, index, val, &val_len, NULL, &type, NULL, NULL)) == ERROR_SUCCESS) {
		index++;
		val_len = _countof(val);
		values.push_back(val);
	}

	if (status != ERROR_NO_MORE_ITEMS) {
		::RegCloseKey(hkey);
		mes = L"error while deleting history";
		return false;
	}

	for (auto it : values) {
		status = RegDeleteValue(hkey, it.c_str());
		if (status != ERROR_SUCCESS) {
			::RegCloseKey(hkey);
			mes = L"error while deleting registry value";
			return false;
		}
	}

	::RegCloseKey(hkey);

	return true;
}

bool NeverSaveHistory()
{
	bool bNeverSaveHistory = AfxGetApp()->GetProfileIntW(L"Settings", L"NeverSaveHistory", NEVER_SAVE_HISTORY_DEFAULT) != 0;
	return bNeverSaveHistory;
}

wstring CheckOpenHandles(HWND hWnd, const wchar_t* mp, bool interactive, bool force)
{

	if (force)
		return L"";

	auto warn = AfxGetApp()->GetProfileInt(L"Settings", L"WarnIfInUseOnDismounting", WARN_IF_IN_USE_ON_DISMOUNT_DEFAULT);

	if (!warn) {
		return L"";
	}

	int open_handle_count = get_open_handle_count(mp);

	if (open_handle_count < 0) {
		return L"Unable to determine if any handles are open";
	}
	else if (open_handle_count > 0) {
		if (interactive) {
			auto res = ::MessageBox(hWnd, mp ? (wstring(mp) + L" is still in use.  Do you wish to continue dismounting?").c_str() :
				L"Filesystem(s) are still in use.  Do you wish to continue dismounting?",
				L"cppcryptfs", MB_YESNO | MB_ICONHAND);
			if (res == IDYES)
				return L"";
			else
				return L"operation cancelled by user";
		}
		else {
			return mp ? wstring(mp) + L" is still in use.  Use --force to force dismounting." :
				L"Filesystem(s) are still in use.  Use --force to force dismounting.";
		}
	}
	return L"";
}
