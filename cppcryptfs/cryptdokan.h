#pragma once

#include <windows.h>
#include <string>

int mount_crypt_fs(WCHAR driveletter, const WCHAR *path, const WCHAR *password, std::wstring& mes);

BOOL unmount_crypt_fs(WCHAR driveletter, bool wait);


BOOL wait_for_all_unmounted();

