#pragma once
#include <atlbase.h>
#include <atlstr.h>

class LocUtilsAlt {
public:
    static ATL::CString GetStringFromResources(UINT nID);
};
