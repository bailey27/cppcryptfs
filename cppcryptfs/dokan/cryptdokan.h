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

#pragma once

#include <windows.h>
#include <string>
#include <list>
#include <vector>

using namespace std;

typedef struct _struct_win32_find_data_pair {
  WIN32_FIND_DATAW fdata;
  WIN32_FIND_DATAW fdata_orig;
} FindDataPair;

struct FlushAfterWriteOptions {
    bool ntfs = 0;
    bool not_ntfs = 0;
    bool fat32 = 0;
    bool exFAT = 0;
    bool sparse_files_not_supported = 0;
};

struct CryptMountOptions {  
  int numbufferblocks = 0;
  int cachettl = 0; 
  bool caseinsensitive = 0;
  bool mountmanager = 0;
  bool mountmanagerwarn = 0;
  bool deletespurriousfiles = 0;
  bool encryptkeysinmemory = 0;
  bool cachekeysinmemory = 0;
  bool fastmounting = 0;
  bool denyothersessions = 0;
  bool denyservices = 0;
  bool multithreaded = 0;
  FlushAfterWriteOptions flushafterwrite;
};

class FsInfo;

int mount_crypt_fs(const WCHAR *mountpoint, const WCHAR *path,
                   const WCHAR *config_path, const WCHAR *password,
                   wstring &mes, bool reverse, bool readonly, const CryptMountOptions &ops);

BOOL unmount_crypt_fs(const WCHAR *mountpoint, bool wait, wstring &mes);

int get_open_handle_count(const wchar_t* mountpoint = nullptr);

BOOL wait_for_all_unmounted();

BOOL write_volume_name_if_changed(WCHAR dl, wstring &mes);

BOOL have_security_name_privilege();

void init_security_name_privilege();

BOOL list_files(const WCHAR *path, list<FindDataPair> &fileDatas,
                wstring &err_mes);

std::wstring transform_path(const wchar_t* path, wstring& mes);

bool get_dokany_version(wstring &ver, vector<int> &v);

bool check_dokany_version(wstring &mes);

bool get_fs_info(const wchar_t *mountpoint, FsInfo &info);

bool unmount_all(bool wait);

void crypt_at_exit();

void crypt_at_start();

bool have_sessionid() noexcept;

DWORD get_sessionid() noexcept;

