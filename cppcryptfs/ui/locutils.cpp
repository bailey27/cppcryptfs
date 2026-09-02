#include "locutils.h"
#include <windows.h>

// Load a string resource from the current module (the final EXE).
// Equivalent to MFC/ATL's CString::LoadString but without the ATL/MFC
// dependency, so it can be built on CI images that lack ATL.
// LoadStringW reads at most 255 characters per call; resources longer
// than that are truncated, but all resources here are short enough.
std::wstring LocUtils::GetStringFromResources(unsigned int nID) {
    wchar_t buf[256];
    int len = LoadStringW(GetModuleHandle(nullptr), nID, buf, _countof(buf));
    if (len > 0) {
        return std::wstring(buf, static_cast<size_t>(len));
    }
    return L"";
}
