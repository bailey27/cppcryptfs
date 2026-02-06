#pragma once
#include <atlbase.h>
#include <atlstr.h>

class LocUtilsAlt {
public:
    // »спользуем €вное указание пространства имен
    static ATL::CString GetStringFromResources(UINT nID);
};
