#include "stdafx.h"
#include "locutils.h"

CString LocUtils::GetStringFromResources(UINT nID) {
    CString str;
    if (!str.LoadString(AfxGetResourceHandle(), nID)) {
        return _T("Error: String not found");
    }
    return str;
}
