#include "stdafx.h"
#include "locutils.h"

CString LocUtils::GetStringFromResources(UINT nID) {
    CString str;
    static HINSTANCE hExe = GetModuleHandle(NULL);
    if (hExe == NULL || !str.LoadString(hExe, nID)) {
        return _T("Error: String not found");
    }
    return str;
}
