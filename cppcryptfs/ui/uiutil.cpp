#include "stdafx.h"
#include "uiutil.h"

#include <list>

#include "ui/MountMangerDialog.h"
#include "ui/cryptdefaults.h"
#include "ui/certutil.h"

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

