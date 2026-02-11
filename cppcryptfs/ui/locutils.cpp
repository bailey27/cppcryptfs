#include "locutils.h"
#define VC_EXTRALEAN
#include <atlstr.h>

std::wstring LocUtils::GetStringFromResources(unsigned int nID) {
    ATL::CStringW str;
    if (str.LoadString(nID)) {
        return std::wstring((LPCWSTR)str);
    }
    return L"";
}
