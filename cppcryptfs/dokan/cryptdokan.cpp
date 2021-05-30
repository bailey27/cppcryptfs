
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

/* 
	This file is based on the Dokan (actualy Dokany) sample program mirror.c.  
	Below is the copyright notice from that file.

	But a lot of this code is by Bailey Brown.
*/

/*
Dokan : user-mode file system library for Windows

Copyright (C) 2015 - 2016 Adrien J. <liryna.stark@gmail.com> and Maxime C. <maxime@islog.com>
Copyright (C) 2007 - 2011 Hiroki Asakawa <info@dokan-dev.net>

http://dokan-dev.github.io

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

#include <ntstatus.h>
#define WIN32_NO_STATUS

#include <assert.h>

#include "filename/cryptfilename.h"
#include "config/cryptconfig.h"
#include "context/cryptcontext.h"
#include "util/fileutil.h"
#include "file/cryptfile.h"
#include "crypt/cryptdefs.h"
#include "util/util.h"
#include "ui/uiutil.h"

#include "file/iobufferpool.h"

#include <vector>
#include <string>
#include <sstream>

#include <windows.h>
#include <Shlwapi.h>
#include "dokan/dokan.h"
#include "dokan/CryptThreadData.h"
#include "dokan/fileinfo.h"
#include <malloc.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>
#include <stdarg.h>
#include <varargs.h>

#include <unordered_map>

#include "cryptdokan.h"
#include "cryptdokanpriv.h"
#include "FileNameEnc.h"
#include "MountPointManager.h"

#include "../libcommonutil/commonutil.h"



static BOOL g_HasSeSecurityPrivilege;

#ifdef _DEBUG
static BOOL g_DebugMode = TRUE;
#else
static BOOL g_DebugMode = FALSE;
#endif
static BOOL g_UseStdErr = FALSE;
static BOOL g_UseLogFile = FALSE;

static FILE* g_DebugLogFile = nullptr;

int WINAPI
CryptCaseStreamsCallback(PWIN32_FIND_STREAM_DATA pfdata, LPCWSTR encrypted_name,
                         unordered_map<wstring, wstring> *pmap) {
  wstring stream_without_type;
  wstring type;

  remove_stream_type(pfdata->cStreamName, stream_without_type, type);

  wstring uc_stream;

  touppercase(stream_without_type.c_str(), uc_stream);

  pmap->insert(make_pair(uc_stream, stream_without_type.c_str()));

  return 0;
}

static void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo) {

// this function is expensive and doesn't seem to provide
// any useful information in the log
#if 0
  if (!g_DebugMode)
    return;

  HANDLE handle;
  UCHAR buffer[1024];
  DWORD returnLength;
  WCHAR accountName[256];
  WCHAR domainName[256];
  DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
  DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
  PTOKEN_USER tokenUser;
  SID_NAME_USE snu;

  handle = DokanOpenRequestorToken(DokanFileInfo);
  if (handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"  DokanOpenRequestorToken failed\n");
    return;
  }

  if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer),
                           &returnLength)) {
    DbgPrint(L"  GetTokenInformaiton failed: %d\n", GetLastError());
    CloseHandle(handle);
    return;
  }

  CloseHandle(handle);

  tokenUser = (PTOKEN_USER)buffer;
  if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName, &accountLength,
                        domainName, &domainLength, &snu)) {
    DbgPrint(L"  LookupAccountSid failed: %d\n", GetLastError());
    return;
  }

  DbgPrint(L"  AccountName: %s, DomainName: %s\n", accountName, domainName);
#endif // #if 0
}

NTSTATUS ToNtStatus(DWORD dwError) {

  // switch is for translating error codes we use that DokanNtStatusFromWin32() does not translate
  switch (dwError) {
  case ERROR_INVALID_DATA:
    return STATUS_DATA_ERROR;
  case ERROR_DATA_CHECKSUM_ERROR:
    return STATUS_CRC_ERROR;
  default:
    return DokanNtStatusFromWin32(dwError);
  }
}

static BOOL AddSeSecurityNamePrivilege() {

  HANDLE token = 0;
  DbgPrint(
      L"## Attempting to add SE_SECURITY_NAME privilege to process token ##\n");
  DWORD err;
  LUID luid;
  if (!LookupPrivilegeValue(0, SE_SECURITY_NAME, &luid)) {
    err = GetLastError();
    if (err != ERROR_SUCCESS) {
      DbgPrint(L"  failed: Unable to lookup privilege value. error = %u\n",
               err);
      return FALSE;
    }
  }

  LUID_AND_ATTRIBUTES attr;
  attr.Attributes = SE_PRIVILEGE_ENABLED;
  attr.Luid = luid;

  TOKEN_PRIVILEGES priv;
  priv.PrivilegeCount = 1;
  priv.Privileges[0] = attr;

  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
    err = GetLastError();
    if (err != ERROR_SUCCESS) {
      DbgPrint(L"  failed: Unable obtain process token. error = %u\n", err);
      return FALSE;
    }
  }

  TOKEN_PRIVILEGES oldPriv;
  DWORD retSize;
  AdjustTokenPrivileges(token, FALSE, &priv, sizeof(TOKEN_PRIVILEGES), &oldPriv,
                        &retSize);
  err = GetLastError();
  if (err != ERROR_SUCCESS) {
    DbgPrint(L"  failed: Unable to adjust token privileges: %u\n", err);
    CloseHandle(token);
    return FALSE;
  }

  BOOL privAlreadyPresent = FALSE;
  for (unsigned int i = 0; i < oldPriv.PrivilegeCount; i++) {
    if (oldPriv.Privileges[i].Luid.HighPart == luid.HighPart &&
        oldPriv.Privileges[i].Luid.LowPart == luid.LowPart) {
      privAlreadyPresent = TRUE;
      break;
    }
  }
  DbgPrint(privAlreadyPresent ? L"  success: privilege already present\n"
                              : L"  success: privilege added\n");
  if (token)
    CloseHandle(token);
  return TRUE;
}

#define CryptCheckFlag(val, flag)                                              \
  if (val & flag) {                                                            \
    DbgPrint(L"\t" L#flag L"\n");                                              \
  }

static NTSTATUS DOKAN_CALLBACK
CryptCreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
                ACCESS_MASK DesiredAccess, ULONG FileAttributes,
                ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
                PDOKAN_FILE_INFO DokanFileInfo) {

  string actual_encrypted;
  FileNameEnc filePath(DokanFileInfo, FileName, &actual_encrypted);
  HANDLE handle = NULL;
  DWORD fileAttr;
  NTSTATUS status = STATUS_SUCCESS;
  DWORD creationDisposition;
  DWORD fileAttributesAndFlags;
  DWORD error = 0;
  SECURITY_ATTRIBUTES securityAttrib;
  ACCESS_MASK genericDesiredAccess;

  bool is_virtual = rt_is_virtual_file(GetContext(), FileName);

  bool is_reverse_config = rt_is_reverse_config_file(GetContext(), FileName);

  securityAttrib.nLength = sizeof(securityAttrib);
  securityAttrib.lpSecurityDescriptor =
      SecurityContext->AccessState.SecurityDescriptor;
  securityAttrib.bInheritHandle = FALSE;

  DokanMapKernelToUserCreateFileFlags(
      DesiredAccess, FileAttributes, CreateOptions, CreateDisposition,
      &genericDesiredAccess, &fileAttributesAndFlags, &creationDisposition);

  DbgPrint(L"CreateFile : %s\n", FileName);

  PrintUserName(DokanFileInfo);

  // the block of code below was also commented out in the mirror.c sample
  // cppcryptfs modifies the flags after all the CheckFlag() stuff

  /*
  if (ShareMode == 0 && AccessMode & FILE_WRITE_DATA)
          ShareMode = FILE_SHARE_WRITE;
  else if (ShareMode == 0)
          ShareMode = FILE_SHARE_READ;
  */

  DbgPrint(L"\tShareMode = 0x%x\n", ShareAccess);

  CryptCheckFlag(ShareAccess, FILE_SHARE_READ);
  CryptCheckFlag(ShareAccess, FILE_SHARE_WRITE);
  CryptCheckFlag(ShareAccess, FILE_SHARE_DELETE);

  DbgPrint(L"DesiredAccess = 0x%x\n", DesiredAccess);

  CryptCheckFlag(DesiredAccess, GENERIC_READ);
  CryptCheckFlag(DesiredAccess, GENERIC_WRITE);
  CryptCheckFlag(DesiredAccess, GENERIC_EXECUTE);

  CryptCheckFlag(DesiredAccess, DELETE);
  CryptCheckFlag(DesiredAccess, FILE_READ_DATA);
  CryptCheckFlag(DesiredAccess, FILE_READ_ATTRIBUTES);
  CryptCheckFlag(DesiredAccess, FILE_READ_EA);
  CryptCheckFlag(DesiredAccess, READ_CONTROL);
  CryptCheckFlag(DesiredAccess, FILE_WRITE_DATA);
  CryptCheckFlag(DesiredAccess, FILE_WRITE_ATTRIBUTES);
  CryptCheckFlag(DesiredAccess, FILE_WRITE_EA);
  CryptCheckFlag(DesiredAccess, FILE_APPEND_DATA);
  CryptCheckFlag(DesiredAccess, WRITE_DAC);
  CryptCheckFlag(DesiredAccess, WRITE_OWNER);
  CryptCheckFlag(DesiredAccess, SYNCHRONIZE);
  CryptCheckFlag(DesiredAccess, FILE_EXECUTE);
  CryptCheckFlag(DesiredAccess, STANDARD_RIGHTS_READ);
  CryptCheckFlag(DesiredAccess, STANDARD_RIGHTS_WRITE);
  CryptCheckFlag(DesiredAccess, STANDARD_RIGHTS_EXECUTE);

  if (is_reverse_config) {
    DbgPrint(L"Reverse Mode: failing attempt to open reverse config file %s\n",
             FileName);
    return ToNtStatus(ERROR_FILE_NOT_FOUND);
  }

  // Windows sometimes gives us wildcarded filenames and expects us 
  // to return ERROR_INVALID_NAME 
  if (wcschr(FileName, L'*') || wcschr(FileName, L'?')) {
    error = ERROR_INVALID_NAME;
    SetLastError(error);
    DbgPrint(L"\terror code = %d\n\n", error);
    return ToNtStatus(error);
  }

  // When filePath is a directory, needs to change the flag so that the file can
  // be opened.
  fileAttr = is_virtual ? FILE_ATTRIBUTE_NORMAL : GetFileAttributes(filePath);

  BOOL bHasDirAttr = fileAttr != INVALID_FILE_ATTRIBUTES &&
                     (fileAttr & FILE_ATTRIBUTE_DIRECTORY);

  // The two blocks below are there because we generally can't write to file
  // unless we can also read from it.
  if (!(bHasDirAttr || (CreateOptions & FILE_DIRECTORY_FILE)) &&
      ((DesiredAccess & GENERIC_WRITE) || (DesiredAccess & FILE_WRITE_DATA) || (DesiredAccess & FILE_APPEND_DATA))) {
    DbgPrint(L"\tadded GENERIC_READ to genericDesiredAccess\n");
    genericDesiredAccess |= GENERIC_READ;
    if (DesiredAccess & FILE_APPEND_DATA) {
        // We need to be able to overwrite whole blocks. 
        // We can't just append data to the end of the file.
        // So we need write accesses too.
        DbgPrint(L"\tadded FILE_WRITE_DATA to genericDesiredAccess\n");
        genericDesiredAccess |= FILE_WRITE_DATA;
    }
  }

  if (!(bHasDirAttr || (CreateOptions & FILE_DIRECTORY_FILE)) &&
      (ShareAccess & FILE_SHARE_WRITE)) {
    DbgPrint(L"\tadded FILE_SHARE_READ to share access\n");
    ShareAccess |= FILE_SHARE_READ;
  }

  if (fileAttr != INVALID_FILE_ATTRIBUTES &&
      (fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
      !(CreateOptions & FILE_NON_DIRECTORY_FILE)) {
    DokanFileInfo->IsDirectory = TRUE;
    if (DesiredAccess & DELETE) {
      // Needed by FindFirstFile to see if directory is empty or not
      ShareAccess |= FILE_SHARE_READ;
    }
  }

  DbgPrint(L"\tFlagsAndAttributes = 0x%x\n", fileAttributesAndFlags);

  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ARCHIVE);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ENCRYPTED);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_HIDDEN);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NORMAL);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_OFFLINE);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_READONLY);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SYSTEM);
  CryptCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_TEMPORARY);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_WRITE_THROUGH);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_OVERLAPPED);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_NO_BUFFERING);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_RANDOM_ACCESS);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_SEQUENTIAL_SCAN);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_DELETE_ON_CLOSE);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_BACKUP_SEMANTICS);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_POSIX_SEMANTICS);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_REPARSE_POINT);
  CryptCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_NO_RECALL);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_ANONYMOUS);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_IDENTIFICATION);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_IMPERSONATION);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_DELEGATION);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_CONTEXT_TRACKING);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_EFFECTIVE_ONLY);
  CryptCheckFlag(fileAttributesAndFlags, SECURITY_SQOS_PRESENT);

  if (fileAttributesAndFlags & FILE_FLAG_NO_BUFFERING) {
    // we cannot guarantee sector-aligned reads or writes
    DbgPrint(L"\tremoving FILE_FLAG_NO_BUFFERING\n");
    fileAttributesAndFlags &= ~FILE_FLAG_NO_BUFFERING;
  }

  if (creationDisposition == CREATE_NEW) {
    DbgPrint(L"\tCREATE_NEW\n");
  } else if (creationDisposition == OPEN_ALWAYS) {
    DbgPrint(L"\tOPEN_ALWAYS\n");
  } else if (creationDisposition == CREATE_ALWAYS) {
    DbgPrint(L"\tCREATE_ALWAYS\n");
  } else if (creationDisposition == OPEN_EXISTING) {
    DbgPrint(L"\tOPEN_EXISTING\n");
  } else if (creationDisposition == TRUNCATE_EXISTING) {
    DbgPrint(L"\tTRUNCATE_EXISTING\n");
  } else {
    DbgPrint(L"\tUNKNOWN creationDisposition!\n");
  }

  if (DokanFileInfo->IsDirectory) {
    // It is a create directory request
    if (creationDisposition == CREATE_NEW ||
        creationDisposition == OPEN_ALWAYS) {
      if (!CreateDirectory(filePath, &securityAttrib)) {
        error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS ||
            creationDisposition == CREATE_NEW) {
          DbgPrint(L"\terror code = %d\n\n", error);
          status = ToNtStatus(error);
        }
      } else {

        if (!create_dir_iv(GetContext(), filePath)) {
          error = GetLastError();
          DbgPrint(L"\tcreate dir iv error code = %d\n\n", error);
          status = ToNtStatus(error);
        }

        if (actual_encrypted.size() > 0) {
          if (!write_encrypted_long_name(filePath, actual_encrypted)) {
            error = GetLastError();
            DbgPrint(L"\twrite long error code = %d\n\n", error);
            status = ToNtStatus(error);
            RemoveDirectory(filePath);
          }
        }

        if (GetContext()->IsCaseInsensitive()) {
          list<wstring> files;
          if (wcscmp(FileName, L"\\")) {
            files.push_front(L"..");
            files.push_front(L".");
          }
          GetContext()->m_case_cache.store(filePath.CorrectCasePath(), files);
        }
      }
    } else if (creationDisposition == OPEN_ALWAYS) {

      if (!CreateDirectory(filePath, &securityAttrib)) {

        error = GetLastError();

        if (error != ERROR_ALREADY_EXISTS) {
          DbgPrint(L"\terror code = %d\n\n", error);
          status = ToNtStatus(error);
        }
      } else {

        if (!create_dir_iv(GetContext(), filePath)) {
          error = GetLastError();
          DbgPrint(L"\tcreate dir iv error code = %d\n\n", error);
          status = ToNtStatus(error);
        }

        if (actual_encrypted.size() > 0) {
          if (!write_encrypted_long_name(filePath, actual_encrypted)) {
            error = GetLastError();
            DbgPrint(L"\twrite long name error code = %d\n\n", error);
            status = ToNtStatus(error);
            RemoveDirectory(filePath);
          }
        }

        if (GetContext()->IsCaseInsensitive()) {
          list<wstring> files;
          if (wcscmp(FileName, L"\\")) {
            files.push_front(L"..");
            files.push_front(L".");
          }
          GetContext()->m_case_cache.store(filePath.CorrectCasePath(), files);
        }
      }
    }

    if (status == STATUS_SUCCESS) {
      //Check first if we're trying to open a file as a directory.
      if (fileAttr != INVALID_FILE_ATTRIBUTES &&
          !(fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
          (CreateOptions & FILE_DIRECTORY_FILE)) {
        return STATUS_NOT_A_DIRECTORY;
      }

      // FILE_FLAG_BACKUP_SEMANTICS is required for opening directory handles
      handle =
          CreateFile(filePath, genericDesiredAccess, ShareAccess,
                     &securityAttrib, OPEN_EXISTING,

                     fileAttributesAndFlags | FILE_FLAG_BACKUP_SEMANTICS, NULL);

      if (handle == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        DbgPrint(L"\terror code = %d\n\n", error);

        status = ToNtStatus(error);
      } else {
        if (actual_encrypted.size() > 0) {
          if (!write_encrypted_long_name(filePath, actual_encrypted)) {
            error = GetLastError();
            DbgPrint(L"\terror code = %d\n\n", error);
            status = ToNtStatus(error);
            RemoveDirectory(filePath);
          }
        }
        
        DokanFileInfo->Context =
            (ULONG64)handle; // save the file handle in Context
        GetContext()->m_open_handles.insert(handle);

        // this is a directory so no need to store it in the openfiles map

        // Open succeed but we need to inform the driver
        // that the dir open and not created by returning STATUS_OBJECT_NAME_COLLISION
        if (creationDisposition == OPEN_ALWAYS &&
            fileAttr != INVALID_FILE_ATTRIBUTES)
          return STATUS_OBJECT_NAME_COLLISION;
      }
    }
  } else {
    // It is a create file request

    // Cannot overwrite a hidden or system file if flag not set
    if (fileAttr != INVALID_FILE_ATTRIBUTES &&
        ((!(fileAttributesAndFlags & FILE_ATTRIBUTE_HIDDEN) &&
          (fileAttr & FILE_ATTRIBUTE_HIDDEN)) ||
         (!(fileAttributesAndFlags & FILE_ATTRIBUTE_SYSTEM) &&
          (fileAttr & FILE_ATTRIBUTE_SYSTEM))) &&
        (creationDisposition == TRUNCATE_EXISTING ||
         creationDisposition == CREATE_ALWAYS))
      return STATUS_ACCESS_DENIED;

    // Cannot delete a read only file
    if ((fileAttr != INVALID_FILE_ATTRIBUTES &&
             (fileAttr & FILE_ATTRIBUTE_READONLY) ||
         (fileAttributesAndFlags & FILE_ATTRIBUTE_READONLY)) &&
        (fileAttributesAndFlags & FILE_FLAG_DELETE_ON_CLOSE))
      return STATUS_CANNOT_DELETE;

    // Truncate should always be used with write access
    if (creationDisposition == TRUNCATE_EXISTING)
      genericDesiredAccess |= GENERIC_WRITE;

    if (fileAttr != INVALID_FILE_ATTRIBUTES &&
        (fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
        CreateDisposition == FILE_CREATE) {
      if (GetContext()->IsCaseInsensitive() && handle != INVALID_HANDLE_VALUE &&
          !filePath.FileExisted()) {
        GetContext()->m_case_cache.store(filePath.CorrectCasePath());
      }
      return STATUS_OBJECT_NAME_COLLISION; // File already exist because
                                           // GetFileAttributes found it
    }

    if (is_virtual) {
      SetLastError(0);
      handle = INVALID_HANDLE_VALUE;
    } else {

      // Truncate should always be used with write access
      if (creationDisposition == TRUNCATE_EXISTING)
        genericDesiredAccess |= GENERIC_WRITE;

      DbgPrint(L"CreateFile 0x%08x, 0x%08x, 0x%08x, 0x%08x",
               genericDesiredAccess, ShareAccess, creationDisposition,
               fileAttributesAndFlags);

      handle = CreateFile(
          filePath,
          genericDesiredAccess, // GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
          ShareAccess,
          &securityAttrib, // security attribute
          creationDisposition,
          fileAttributesAndFlags, // |FILE_FLAG_NO_BUFFERING,
          NULL);                  // template file handle
    }

    status = ToNtStatus(GetLastError());

    if (!is_virtual && handle == INVALID_HANDLE_VALUE) {
      error = GetLastError();
      DbgPrint(L"\terror code = %d\n\n", error);

      status = ToNtStatus(error);
    } else {

      if (actual_encrypted.size() > 0) {
        if (!write_encrypted_long_name(filePath, actual_encrypted)) {
          error = GetLastError();
          DbgPrint(L"\twrite long name error code = %d\n\n", error);
          status = ToNtStatus(error);
          RemoveDirectory(filePath);
        }
      }

      //Need to update FileAttributes with previous when Overwrite file
      if (fileAttr != INVALID_FILE_ATTRIBUTES &&
          creationDisposition == TRUNCATE_EXISTING) {
        SetFileAttributes(filePath, fileAttributesAndFlags | fileAttr);
      }

      DokanFileInfo->Context =
          (ULONG64)handle; // save the file handle in Context
      GetContext()->m_open_handles.insert(handle);

      if (handle && handle != INVALID_HANDLE_VALUE) {
          GetContext()->m_openfiles.OpenFile(FileName, handle);
      }

      if (creationDisposition == OPEN_ALWAYS ||
          creationDisposition == CREATE_ALWAYS) {
        error = GetLastError();
        if (error == ERROR_ALREADY_EXISTS) {
          DbgPrint(L"\tOpen an already existing file\n");
          // Open succeed but we need to inform the driver
          // that the file open and not created by returning STATUS_OBJECT_NAME_COLLISION
          if (GetContext()->IsCaseInsensitive() &&
              handle != INVALID_HANDLE_VALUE && !filePath.FileExisted()) {
            GetContext()->m_case_cache.store(filePath.CorrectCasePath());
          }
          status = STATUS_OBJECT_NAME_COLLISION;
        }
      }
    }
  }
  DbgPrint(L"handle = %I64x", (ULONGLONG)handle);
  DbgPrint(L"\n");
  if (GetContext()->IsCaseInsensitive() && handle != INVALID_HANDLE_VALUE &&
      !filePath.FileExisted()) {
    GetContext()->m_case_cache.store(filePath.CorrectCasePath());
  }

  return status;
}

static void DOKAN_CALLBACK CryptCloseFile(LPCWSTR FileName,
                                          PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);

  if (DokanFileInfo->Context) {
    DbgPrint(L"CloseFile: %s, %x\n", FileName, (DWORD)DokanFileInfo->Context);
    DbgPrint(L"\terror : not cleanuped file\n\n");
    if ((HANDLE)DokanFileInfo->Context != INVALID_HANDLE_VALUE) {
      GetContext()->m_open_handles.erase((HANDLE)DokanFileInfo->Context);
      ::CloseHandle((HANDLE)DokanFileInfo->Context);
      if (!DokanFileInfo->IsDirectory) {
        GetContext()->m_openfiles.CloseFile(FileName,
                                            (HANDLE)DokanFileInfo->Context);
      }      
    }
    DokanFileInfo->Context = 0;
  } else {
    DbgPrint(L"Close (no handle): %s\n\n", FileName);
  }
}

static void DOKAN_CALLBACK CryptCleanup(LPCWSTR FileName,
                                        PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);

  if (DokanFileInfo->Context) {
    DbgPrint(L"Cleanup: %s, %x\n\n", FileName, (DWORD)DokanFileInfo->Context);
    if ((HANDLE)DokanFileInfo->Context != INVALID_HANDLE_VALUE) {
        GetContext()->m_open_handles.erase((HANDLE)DokanFileInfo->Context);
        CloseHandle((HANDLE)(DokanFileInfo->Context));
        if (!DokanFileInfo->IsDirectory)
            GetContext()->m_openfiles.CloseFile(FileName, (HANDLE)DokanFileInfo->Context);
    }
    DokanFileInfo->Context = 0;
  } else {
    DbgPrint(L"Cleanup: %s\n\tinvalid handle\n\n", FileName);
  }

  if (DokanFileInfo->DeleteOnClose) {
    DbgPrint(L"\tDeleteOnClose\n");
    if (DokanFileInfo->IsDirectory) {
      DbgPrint(L"  DeleteDirectory ");
      if (!delete_directory(GetContext(), filePath)) {
        DbgPrint(L"error code = %d\n\n", GetLastError());
      } else {
        if (GetContext()->IsCaseInsensitive()) {
          if (!GetContext()->m_case_cache.purge(FileName)) {
            DbgPrint(L"delete failed to purge dir %s\n", FileName);
          }
        }
        DbgPrint(L"success\n\n");
      }
    } else {
      DbgPrint(L"  DeleteFile ");
      if (!delete_file(GetContext(), filePath)) {
        DbgPrint(L" error code = %d\n\n", GetLastError());
      } else {
        if (GetContext()->IsCaseInsensitive()) {
          if (!GetContext()->m_case_cache.remove(filePath.CorrectCasePath())) {
            DbgPrint(L"delete failed to remove %s from case cache\n", FileName);
          }
        }
        DbgPrint(L"success\n\n");
      }
    }
  }
}

static NTSTATUS DOKAN_CALLBACK CryptReadFile(LPCWSTR FileName, LPVOID Buffer,
                                             DWORD BufferLength,
                                             LPDWORD ReadLength,
                                             LONGLONG Offset,
                                             PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);
  HANDLE handle = (HANDLE)DokanFileInfo->Context;
  BOOL opened = FALSE;
  NTSTATUS ret_status = STATUS_SUCCESS;

  DbgPrint(L"ReadFile : %s, %I64u, paging io = %u\n", FileName,
           (ULONGLONG)handle, DokanFileInfo->PagingIo);
  DbgPrint(L"ReadFile : attempting to read %u bytes from offset %ld\n",
           BufferLength, Offset);

  bool is_virtual = rt_is_virtual_file(GetContext(), FileName);

  if (!handle || (!is_virtual && handle == INVALID_HANDLE_VALUE)) {
    DbgPrint(L"\tinvalid handle, cleanuped?\n");
    handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DWORD error = GetLastError();
      DbgPrint(L"\tCreateFile error : %d\n\n", error);
      return ToNtStatus(error);
    }
    
    GetContext()->m_openfiles.OpenFile(FileName, handle);
    opened = TRUE;
  }

  CryptFile *file = CryptFile::NewInstance(GetContext());

  if (rt_is_config_file(GetContext(), FileName)) {
    OVERLAPPED ov;
    SetOverlapped(&ov, Offset);
   
    if (!ReadFile(handle, Buffer, BufferLength, ReadLength, &ov)) {
		ret_status = ToNtStatus(GetLastError());
    }
    
  } else if (is_virtual) {
    if (!read_virtual_file(GetContext(), FileName, (unsigned char *)Buffer,
                           BufferLength, ReadLength, Offset)) {
      DWORD error = GetLastError();
      if (error == 0)
        error = ERROR_ACCESS_DENIED;
      DbgPrint(L"\tread error = %u, buffer length = %d, read length = %d\n\n",
               error, BufferLength, *ReadLength);
      ret_status = ToNtStatus(error);
    }
  } else if (file->Associate(GetContext(), handle, FileName, false)) {

    if (!file->Read((unsigned char *)Buffer, BufferLength, ReadLength,
                    Offset)) {
      DWORD error = GetLastError();
      DbgPrint(L"\tread error = %u, buffer length = %d, read length = %d\n\n",
               error, BufferLength, *ReadLength);
      ret_status = ToNtStatus(error);
    }

    DbgPrint(L"file->Read read %u bytes\n", *ReadLength);

  } else {
    ret_status = STATUS_ACCESS_DENIED;
  }

  delete file;

  if (opened) {
    CloseHandle(handle);
    GetContext()->m_openfiles.CloseFile(FileName, handle);
  }

  return ret_status;
}

static NTSTATUS DOKAN_CALLBACK CryptWriteFile(LPCWSTR FileName, LPCVOID Buffer,
                                              DWORD NumberOfBytesToWrite,
                                              LPDWORD NumberOfBytesWritten,
                                              LONGLONG Offset,
                                              PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);
  HANDLE handle = (HANDLE)DokanFileInfo->Context;
  BOOL opened = FALSE;
  NTSTATUS ret_status = STATUS_SUCCESS;

  DbgPrint(L"WriteFile : %s, offset %I64d, length %d - paging io %u\n",
           FileName, Offset, NumberOfBytesToWrite, DokanFileInfo->PagingIo);

  if (DokanFileInfo->WriteToEndOfFile) {
    if (DokanFileInfo->PagingIo) {
      DbgPrint(L"paging io to end of file. doing nothing\n");
      *NumberOfBytesWritten = 0;
      return STATUS_SUCCESS;
    }
  }

  // reopen the file
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle, cleanuped?\n");
    handle = CreateFile(filePath, GENERIC_WRITE | GENERIC_READ,
                        FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_EXISTING,
                        0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DWORD error = GetLastError();
      DbgPrint(L"\tCreateFile error : %d\n\n", error);
      return ToNtStatus(error);
    }
    GetContext()->m_openfiles.OpenFile(FileName, handle);
    opened = TRUE;
  }

  CryptFile *file = CryptFile::NewInstance(GetContext());

  if (file->Associate(GetContext(), handle, FileName, true)) {
    if (!file->Write((const unsigned char *)Buffer, NumberOfBytesToWrite,
                     NumberOfBytesWritten, Offset,
                     DokanFileInfo->WriteToEndOfFile,
                     DokanFileInfo->PagingIo)) {
      DWORD error = GetLastError();
      DbgPrint(L"\twrite error = %u, buffer length = %d, write length = %d\n",
               error, NumberOfBytesToWrite, *NumberOfBytesWritten);
      ret_status = ToNtStatus(error);
    } else {
      DbgPrint(L"\twrote nbytes = %u\n", *NumberOfBytesWritten);
    }
  } else {
    ret_status = STATUS_ACCESS_DENIED;
  }

  delete file;

  // close the file when it is reopened
  if (opened) {
    CloseHandle(handle);
    GetContext()->m_openfiles.CloseFile(FileName, handle);
  }

  return ret_status;
}

static NTSTATUS DOKAN_CALLBACK
CryptFlushFileBuffers(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);
  HANDLE handle = (HANDLE)DokanFileInfo->Context;

  DbgPrint(L"FlushFileBuffers : %s\n", FileName);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_SUCCESS;
  }

  if (FlushFileBuffers(handle)) {
    return STATUS_SUCCESS;
  } else {
    DWORD error = GetLastError();
    DbgPrint(L"\tflush error code = %d\n", error);
    return ToNtStatus(error);
  }
}

static NTSTATUS DOKAN_CALLBACK CryptGetFileInformation(
    LPCWSTR FileName, LPBY_HANDLE_FILE_INFORMATION HandleFileInformation,
    PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);
  HANDLE handle = (HANDLE)DokanFileInfo->Context;
  BOOL opened = FALSE;

  DbgPrint(L"GetFileInfo : %s\n", FileName);

  if (!handle || (handle == INVALID_HANDLE_VALUE &&
                  !rt_is_virtual_file(GetContext(), FileName))) {
    DbgPrint(L"\tinvalid handle, cleanuped?\n");
    handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DWORD error = GetLastError();
      DbgPrint(L"\tCreateFile error : %d\n\n", error);
      return DokanNtStatusFromWin32(error);
    }
    GetContext()->m_openfiles.OpenFile(FileName, handle);
    opened = TRUE;
  }

  NTSTATUS status;

  if (get_file_information(GetContext(), filePath, FileName, handle,
                           HandleFileInformation) != 0) {
    DWORD error = GetLastError();
    DbgPrint(L"GetFileInfo failed(%d)\n", error);
    status = ToNtStatus(error);
  } else {
    LARGE_INTEGER l;
    l.LowPart = HandleFileInformation->nFileSizeLow;
    l.HighPart = HandleFileInformation->nFileSizeHigh;
    DbgPrint(L"GetFileInformation %s, filesize = %I64d, attr = 0x%08u\n",
             FileName, l.QuadPart, HandleFileInformation->dwFileAttributes);
    status = STATUS_SUCCESS;
  }

  if (opened) {
    CloseHandle(handle);
    GetContext()->m_openfiles.CloseFile(FileName, handle);
  }

  return status;
}

// use our own callback so rest of the code doesn't need to know about Dokany internals
static int WINAPI crypt_fill_find_data(PWIN32_FIND_DATAW fdata,
                                       PWIN32_FIND_DATAW fdata_orig,
                                       void *dokan_cb, void *dokan_ctx) {
  return ((PFillFindData)dokan_cb)(fdata, (PDOKAN_FILE_INFO)dokan_ctx);
}

static NTSTATUS DOKAN_CALLBACK
CryptFindFiles(LPCWSTR FileName,
               PFillFindData FillFindData, // function pointer
               PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);
  size_t fileLen = 0;
  HANDLE hFind = NULL;

  DWORD error;
  long long count = 0;
  
  DWORD result = 0;

  DbgPrint(L"FindFiles :%s\n", FileName);

  if (find_files(GetContext(), filePath.CorrectCasePath(), filePath,
                 crypt_fill_find_data, (void *)FillFindData,
                 (void *)DokanFileInfo) != 0) {
    error = GetLastError();
    DbgPrint(L"\tFindNextFile error. Error is %u\n", error);
    
    result = error ? error : ERROR_ACCESS_DENIED;
  }

  DbgPrint(L"\tCryptFindFiles returning %lu\n\n", result);

  return result == 0 ?  STATUS_SUCCESS : ToNtStatus(result);
}

static NTSTATUS DOKAN_CALLBACK CryptDeleteFile(LPCWSTR FileName,
                                               PDOKAN_FILE_INFO DokanFileInfo) {

  FileNameEnc filePath(DokanFileInfo, FileName);
  HANDLE handle = (HANDLE)DokanFileInfo->Context;

  DbgPrint(L"DeleteFile %s - %d\n", FileName, DokanFileInfo->DeleteOnClose);

  if (can_delete_file(filePath)) {

    DWORD dwAttrib = GetFileAttributes(filePath);

    if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        (dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
      return STATUS_ACCESS_DENIED;

    if (handle && handle != INVALID_HANDLE_VALUE) {
      FILE_DISPOSITION_INFO fdi;
      fdi.DeleteFile = DokanFileInfo->DeleteOnClose;
      if (!SetFileInformationByHandle(handle, FileDispositionInfo, &fdi,
                                      sizeof(FILE_DISPOSITION_INFO)))
        return DokanNtStatusFromWin32(GetLastError());
    }

    return STATUS_SUCCESS;
  } else {
    DWORD error = GetLastError();
    if (error == 0)
      error = ERROR_ACCESS_DENIED;
    DbgPrint(L"\tDeleteFile error code = %d\n\n", error);
    return ToNtStatus(error);
  }
}

static NTSTATUS DOKAN_CALLBACK
CryptDeleteDirectory(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {

  FileNameEnc filePath(DokanFileInfo, FileName);

  DbgPrint(L"DeleteDirectory %s - %d\n", FileName,
           DokanFileInfo->DeleteOnClose);

  if (!DokanFileInfo->DeleteOnClose) {
    //Dokan notify that the file is requested not to be deleted.
    return STATUS_SUCCESS;
  }

  if (can_delete_directory(filePath, FALSE, GetContext())) {
    return STATUS_SUCCESS;
  } else {
    DWORD error = GetLastError();
    DbgPrint(L"\tDeleteDirectory error code = %d\n\n", error);
    return ToNtStatus(error);
  }
}

// see comment in CryptMoveFile() about what the repair stuff is for

static NTSTATUS CryptMoveFileInternal(LPCWSTR FileName, // existing file name
                                      LPCWSTR NewFileName,
                                      BOOL ReplaceIfExisting,
                                      PDOKAN_FILE_INFO DokanFileInfo,
                                      bool &needRepair, bool repairName) {

  needRepair = false;

  string actual_encrypted;
  FileNameEnc filePath(DokanFileInfo, FileName);
  FileNameEnc newFilePath(DokanFileInfo, NewFileName, &actual_encrypted,
                          repairName);

  DbgPrint(L"MoveFile %s -> %s\n\n", FileName, NewFileName);

  HANDLE handle;
  DWORD bufferSize;
  BOOL result;
  size_t newFilePathLen;

  PFILE_RENAME_INFO renameInfo = NULL;

  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  auto new_path = static_cast<const WCHAR*>(newFilePath);

  if (new_path == nullptr) {
      // this can happen e.g. if we can't read a diriv in the "to" path
      auto lasterr = GetLastError();
      DbgPrint(L"\tnewFilePath is null, last error was %u\n", lasterr);
      // we return accessed denied because whatever error really happened might 
      // not make any sense to the caller.
      return STATUS_ACCESS_DENIED;
  }

  newFilePathLen = wcslen(newFilePath);

  // the FILE_RENAME_INFO struct has space for one WCHAR for the name at
  // the end, so that
  // accounts for the null terminator

  bufferSize = (DWORD)(sizeof(FILE_RENAME_INFO) +
                       newFilePathLen * sizeof(newFilePath[0]));

  renameInfo = (PFILE_RENAME_INFO)malloc(bufferSize);
  if (!renameInfo) {
    return STATUS_BUFFER_OVERFLOW;
  }
  ZeroMemory(renameInfo, bufferSize);

  renameInfo->ReplaceIfExists =
      ReplaceIfExisting
          ? TRUE
          : FALSE; // some warning about converting BOOL to BOOLEAN
  renameInfo->RootDirectory = NULL; // hope it is never needed, shouldn't be
  renameInfo->FileNameLength =
      (DWORD)newFilePathLen *
      sizeof(newFilePath[0]); // they want length in bytes

  wcscpy_s(renameInfo->FileName, newFilePathLen + 1, newFilePath);

  result = SetFileInformationByHandle(handle, FileRenameInfo, renameInfo,
                                      bufferSize);

  free(renameInfo);

  if (!result) {
    DWORD error = GetLastError();
    DbgPrint(L"\tMoveFile failed status = %d, code = %d\n", result, error);
    return ToNtStatus(error);
  } else {

    if (GetContext()->IsCaseInsensitive() && !repairName) {

      if (newFilePath.FileExisted()) {
        wstring existing_file_name;
        wstring new_file_name;

        if (get_dir_and_file_from_path(newFilePath.CorrectCasePath(), NULL,
                                       &existing_file_name) &&
            get_dir_and_file_from_path(NewFileName, NULL, &new_file_name)) {
          if (wcscmp(existing_file_name.c_str(), new_file_name.c_str())) {
            needRepair = true;
          }
        } else {
          DbgPrint(L"movefile get_dir_and_filename failed\n");
        }
      }
    }

    // clean up any longname
    if (!delete_file(GetContext(), filePath, true)) {
      DWORD error = GetLastError();
      DbgPrint(L"\tMoveFile failed code = %d\n", error);
      return ToNtStatus(error);
    }

    if (actual_encrypted.size() > 0) {
      if (!write_encrypted_long_name(newFilePath, actual_encrypted)) {
        DWORD error = GetLastError();
        DbgPrint(L"\tMoveFile failed2 code = %d\n", error);
        return ToNtStatus(error);
      }
    }

    if (GetContext()->IsCaseInsensitive()) {
      GetContext()->m_case_cache.remove(filePath.CorrectCasePath());
      if (!GetContext()->m_case_cache.store(newFilePath.CorrectCasePath())) {
        DbgPrint(L"move unable to store new filename %s in case cache\n",
                 newFilePath.CorrectCasePath());
        assert(false);
      }
      if (DokanFileInfo->IsDirectory) {
        if (!GetContext()->m_case_cache.rename(filePath.CorrectCasePath(),
                                               newFilePath.CorrectCasePath())) {
          DbgPrint(L"move unable to rename directory %s -> %s in case cache\n",
                   filePath.CorrectCasePath(), newFilePath.CorrectCasePath());
          assert(false);
        }
      }
    }

    // rename in openfiles if it's a file
    // openfiles is case insensitive so we don't want to do it
    // again if we're just repairing the name (the case)
    if (!DokanFileInfo->IsDirectory && !repairName) {
        bool rename_result = GetContext()->m_openfiles.Rename(FileName, NewFileName);
        assert(rename_result);       
    }

    return STATUS_SUCCESS;
  }
}

static int WINAPI StoreRenameStreamCallback(
    PWIN32_FIND_STREAM_DATA pfdata, LPCWSTR encrypted_name,
    unordered_map<wstring, wstring> *pmap) {

  pmap->insert(make_pair(encrypted_name, pfdata->cStreamName));

  return 0;
}

static NTSTATUS DOKAN_CALLBACK
CryptMoveFile(LPCWSTR FileName, // existing file name
              LPCWSTR NewFileName, BOOL ReplaceIfExisting,
              PDOKAN_FILE_INFO DokanFileInfo) {

  /*
	
	If we are case insensitive, then we need special handling if you have a situation like as follows:

		files boo.txt and foo.txt already exitst, and you do

		move boo.txt FOO.TXT

		In that case, we need to move boo.txt to foo.txt, then rename foo.txt to FOO.TXT

		The second step (the rename) is called "repair" here.
	*/

  bool needRepair = false;

  /* 
		If we are moving a file with an alternate data stream (besides the default "::$DATA" one) 
		to a different directory, then we need to rename the stream(s) (the encrypted name) using
		the new IV for its new dir.

		There is no API for renaming streams, so the rename must be done by copy and delete.

		If the rename_streams_map has more than one (the default) stream, then we know to 
		do this later.

		If we are operating on a (non-default) stream, then we don't need to do any of this.
	*/

  unordered_map<wstring, wstring> rename_streams_map;

  if (!GetContext()->GetConfig()->m_PlaintextNames) {
    wstring fromDir, toDir;
    get_file_directory(FileName, fromDir);
    get_file_directory(NewFileName, toDir);
    if (compare_names(GetContext(), fromDir.c_str(), toDir.c_str())) {
      wstring stream;
      bool is_stream = false;
      if (get_file_stream(FileName, NULL, &stream)) {
        is_stream = stream.length() > 0 && wcscmp(stream.c_str(), L":") &&
                    compare_names(GetContext(), stream.c_str(), L"::$DATA");
      }
      if (!is_stream)
        CryptFindStreamsInternal(FileName, NULL, DokanFileInfo,
                                 StoreRenameStreamCallback,
                                 &rename_streams_map);
    }
  }

  NTSTATUS status =
      CryptMoveFileInternal(FileName, NewFileName, ReplaceIfExisting,
                            DokanFileInfo, needRepair, false);

  if (GetContext()->IsCaseInsensitive() && status == 0 && needRepair) {
    status = CryptMoveFileInternal(NewFileName, NewFileName, TRUE,
                                   DokanFileInfo, needRepair, true);
  }

  if (status == 0) {
    if (rename_streams_map.size() > 1 && status == 0) {
      // rename streams by copying and deleting.  rename doesn't work
      for (auto it : rename_streams_map) {
        if (it.second.length() < 1 || !wcscmp(it.second.c_str(), L":") ||
            !compare_names(GetContext(), it.second.c_str(), L"::$DATA")) {
          DbgPrint(L"movefile skipping default stream %s\n", it.second.c_str());
          continue;
        }

        FileNameEnc newNameWithoutStream(DokanFileInfo, NewFileName);
        wstring newEncNameWithOldEncStream =
            (LPCWSTR)newNameWithoutStream + it.first;
        wstring newNameWithStream = NewFileName + it.second;
        FileNameEnc newEncNameWithNewEncStream(DokanFileInfo,
                                               newNameWithStream.c_str());

        HANDLE hStreamSrc = CreateFile(
            newEncNameWithOldEncStream.c_str(), GENERIC_READ | DELETE,
            FILE_SHARE_DELETE | FILE_SHARE_READ, NULL, OPEN_EXISTING,
            FILE_FLAG_DELETE_ON_CLOSE, NULL);

        if (hStreamSrc != INVALID_HANDLE_VALUE) {

          HANDLE hStreamDest = CreateFile(
              newEncNameWithNewEncStream, GENERIC_READ | GENERIC_WRITE,
              FILE_SHARE_DELETE | FILE_SHARE_READ, NULL, CREATE_NEW, 0, NULL);

          if (hStreamDest != INVALID_HANDLE_VALUE) {

            CryptFile *src = CryptFile::NewInstance(GetContext());
            CryptFile *dst = CryptFile::NewInstance(GetContext());

            // the below comment is out-dated
            // we don't need to pass pt_path to associate in forward mode so it can be null
            // we never get here in reverse mode because it is read-only

            if (src->Associate(GetContext(), hStreamSrc, FileName, false) &&
                dst->Associate(GetContext(), hStreamDest, NewFileName, true)) {

              const DWORD bufsize = 64 * 1024;

              BYTE *buf = (BYTE *)malloc(bufsize);

              if (buf) {

                LONGLONG offset = 0;
                DWORD nRead;

                while (src->Read(buf, bufsize, &nRead, offset)) {
                  if (nRead == 0)
                    break;
                  DWORD nWritten = 0;
                  if (!dst->Write(buf, nRead, &nWritten, offset, FALSE, FALSE))
                    break;
                  if (nRead != nWritten)
                    break;
                  offset += nRead;
                }

                free(buf);
              }
            }
            delete src;
            delete dst;
            CloseHandle(hStreamDest);
          }
          CloseHandle(hStreamSrc);
        } else {
          DbgPrint(
              L"movefile cannot open file to rename stream %s, error = %u\n",
              newEncNameWithOldEncStream.c_str(), GetLastError());
        }
      }
      SetLastError(0);
    }
  }

  return status;
}

static NTSTATUS DOKAN_CALLBACK CryptLockFile(LPCWSTR FileName,
                                             LONGLONG ByteOffset,
                                             LONGLONG Length,
                                             PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);
  HANDLE handle;

  DbgPrint(L"LockFile %s\n", FileName);

  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  CryptFile *file = CryptFile::NewInstance(GetContext());

  if (file->Associate(GetContext(), handle, FileName, false)) {

    if (!file->LockFile(ByteOffset, Length)) {
      DWORD error = GetLastError();
      DbgPrint(L"\tfailed(%d)\n", error);
      delete file;
      return ToNtStatus(error);
    }
  } else {
    delete file;
    return STATUS_ACCESS_DENIED;
  }

  delete file;

  DbgPrint(L"\tsuccess\n\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptSetEndOfFile(
    LPCWSTR FileName, LONGLONG ByteOffset, PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);
  HANDLE handle;

  DbgPrint(L"SetEndOfFile %s, %I64d\n", FileName, ByteOffset);

  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  CryptFile *file = CryptFile::NewInstance(GetContext());

  if (file->Associate(GetContext(), handle, FileName, true)) {
    if (!file->SetEndOfFile(ByteOffset)) {
      DWORD error = GetLastError();
      DbgPrint(L"\tSetEndOfFile error code = %d\n\n", error);
      delete file;
      return ToNtStatus(error);
    }
  } else {
    delete file;
    DbgPrint(L"\tSetEndOfFile unable to associate handle %I64x\n", handle);
    return STATUS_ACCESS_DENIED;
  }

  delete file;

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptSetAllocationSize(
    LPCWSTR FileName, LONGLONG AllocSize, PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);
  HANDLE handle;
  LARGE_INTEGER fileSize;

  DbgPrint(L"SetAllocationSize %s, %I64d\n", FileName, AllocSize);

  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  BY_HANDLE_FILE_INFORMATION finfo;
  DWORD error = 0;
  try {
    if (get_file_information(GetContext(), filePath, FileName, handle,
                             &finfo) != 0) {
      throw(-1);
    }
    fileSize.LowPart = finfo.nFileSizeLow;
    fileSize.HighPart = finfo.nFileSizeHigh;
    if (AllocSize < fileSize.QuadPart) {
      fileSize.QuadPart = AllocSize;
      CryptFile *file = CryptFile::NewInstance(GetContext());
      if (!file->Associate(GetContext(), handle, FileName, true)) {
        delete file;
        throw(-1);
      }
      if (!file->SetEndOfFile(fileSize.QuadPart)) {
        delete file;
        throw(-1);
      }
      delete file;
    }
  } catch (...) {
    error = GetLastError();
    DbgPrint(L"\terror code = %d\n\n", error);
    if (!error)
      error = ERROR_ACCESS_DENIED;
  }

  if (error)
    return ToNtStatus(error);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptSetFileAttributes(
    LPCWSTR FileName, DWORD FileAttributes, PDOKAN_FILE_INFO DokanFileInfo) {

  FileNameEnc filePath(DokanFileInfo, FileName);

  DbgPrint(L"SetFileAttributes %s, %x\n", FileName, FileAttributes);

  if (FileAttributes != 0) {
    if (!SetFileAttributes(filePath, FileAttributes)) {
      DWORD error = GetLastError();
      DbgPrint(L"\terror code = %d\n\n", error);
      return ToNtStatus(error);
    }
  } else {
    // case FileAttributes == 0 :
    // MS-FSCC 2.6 File Attributes : There is no file attribute with the value 0x00000000
    // because a value of 0x00000000 in the FileAttributes field means that the file attributes for this file MUST NOT be changed when setting basic information for the file
    DbgPrint(L"Set 0 to FileAttributes means MUST NOT be changed. Didn't call "
             L"SetFileAttributes function. \n");
  }

  DbgPrint(L"\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
CryptSetFileTime(LPCWSTR FileName, CONST FILETIME *CreationTime,
                 CONST FILETIME *LastAccessTime, CONST FILETIME *LastWriteTime,
                 PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);
  HANDLE handle;

  handle = (HANDLE)DokanFileInfo->Context;

  DbgPrint(L"SetFileTime %s, handle = %I64x\n", FileName, (ULONGLONG)handle);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  if (!SetFileTime(handle, CreationTime, LastAccessTime, LastWriteTime)) {
    DWORD error = GetLastError();
    DbgPrint(L"\terror code = %d\n\n", error);
    return ToNtStatus(error);
  }

  DbgPrint(L"\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptUnlockFile(LPCWSTR FileName,
                                               LONGLONG ByteOffset,
                                               LONGLONG Length,
                                               PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);
  HANDLE handle;

  DbgPrint(L"UnlockFile %s\n", FileName);

  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  CryptFile *file = CryptFile::NewInstance(GetContext());

  if (file->Associate(GetContext(), handle, FileName, false)) {

    if (!file->UnlockFile(ByteOffset, Length)) {
      DWORD error = GetLastError();
      DbgPrint(L"\terror code = %d\n\n", error);
      delete file;
      return ToNtStatus(error);
    }
  } else {
    delete file;
    return STATUS_ACCESS_DENIED;
  }
  delete file;
  DbgPrint(L"\tsuccess\n\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptGetFileSecurity(
    LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength,
    PULONG LengthNeeded, PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(DokanFileInfo, FileName);

  BOOLEAN requestingSaclInfo;

  UNREFERENCED_PARAMETER(DokanFileInfo);

  DbgPrint(L"GetFileSecurity %s\n", FileName);

  CryptCheckFlag(*SecurityInformation, FILE_SHARE_READ);
  CryptCheckFlag(*SecurityInformation, OWNER_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation, GROUP_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation, DACL_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation, SACL_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation, LABEL_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation, ATTRIBUTE_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation, SCOPE_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation,
                 PROCESS_TRUST_LABEL_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation, BACKUP_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation, PROTECTED_DACL_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation, PROTECTED_SACL_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation, UNPROTECTED_DACL_SECURITY_INFORMATION);
  CryptCheckFlag(*SecurityInformation, UNPROTECTED_SACL_SECURITY_INFORMATION);

  requestingSaclInfo = ((*SecurityInformation & SACL_SECURITY_INFORMATION) ||
                        (*SecurityInformation & BACKUP_SECURITY_INFORMATION));

  if (!g_HasSeSecurityPrivilege) {
    *SecurityInformation &= ~SACL_SECURITY_INFORMATION;
    *SecurityInformation &= ~BACKUP_SECURITY_INFORMATION;
  }

  DbgPrint(L"  Opening new handle with READ_CONTROL access\n");

  bool is_virtual = rt_is_virtual_file(GetContext(), FileName);

  wstring virt_path;

  if (is_virtual) {
    if (rt_is_dir_iv_file(GetContext(), FileName)) {
      if (!get_file_directory(filePath, virt_path)) {
        return ToNtStatus(ERROR_ACCESS_DENIED);
      }
    } else if (rt_is_name_file(GetContext(), FileName)) {

      wstring enc_path;

      remove_longname_suffix(FileName, enc_path);

      if (!decrypt_path(GetContext(), &enc_path[0], virt_path))
        return ToNtStatus(ERROR_ACCESS_DENIED);
    } else {
      return ToNtStatus(ERROR_ACCESS_DENIED);
    }
  }

  HANDLE handle = CreateFile(
      is_virtual ? &virt_path[0] : filePath,
      READ_CONTROL | ((requestingSaclInfo && g_HasSeSecurityPrivilege)
                          ? ACCESS_SYSTEM_SECURITY
                          : 0),
      FILE_SHARE_WRITE | FILE_SHARE_READ | FILE_SHARE_DELETE,
      NULL, // security attribute
      OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS, // |FILE_FLAG_NO_BUFFERING,
      NULL);

  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    int error = GetLastError();
    return DokanNtStatusFromWin32(error);
  }

  if (!GetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor,
                             BufferLength, LengthNeeded)) {
    int error = GetLastError();
    if (error == ERROR_INSUFFICIENT_BUFFER) {
      DbgPrint(L"  GetUserObjectSecurity error: ERROR_INSUFFICIENT_BUFFER\n");
      CloseHandle(handle);
      return STATUS_BUFFER_OVERFLOW;
    } else {
      DbgPrint(L"  GetUserObjectSecurity error: %d\n", error);
      CloseHandle(handle);
      return DokanNtStatusFromWin32(error);
    }
  }

  // Ensure the Security Descriptor Length is set
  DWORD securityDescriptorLength =
      GetSecurityDescriptorLength(SecurityDescriptor);
  DbgPrint(L"  GetUserObjectSecurity return true,  *LengthNeeded = "
           L"securityDescriptorLength \n");
  *LengthNeeded = securityDescriptorLength;

  CloseHandle(handle);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptSetFileSecurity(
    LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG SecurityDescriptorLength,
    PDOKAN_FILE_INFO DokanFileInfo) {
  HANDLE handle;
  FileNameEnc filePath(DokanFileInfo, FileName);

  UNREFERENCED_PARAMETER(SecurityDescriptorLength);

  DbgPrint(L"SetFileSecurity %s\n", FileName);

  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  if (!SetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor)) {
    int error = GetLastError();
    DbgPrint(L"  SetUserObjectSecurity error: %d\n", error);
    return DokanNtStatusFromWin32(error);
  }
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptGetVolumeInformation(
    LPWSTR VolumeNameBuffer, DWORD VolumeNameSize, LPDWORD VolumeSerialNumber,
    LPDWORD MaximumComponentLength, LPDWORD FileSystemFlags,
    LPWSTR FileSystemNameBuffer, DWORD FileSystemNameSize,
    PDOKAN_FILE_INFO DokanFileInfo) {

  DbgPrint(L"GetVolumeInformation\n");

  CryptContext *con = GetContext();

  CryptConfig *config = con->GetConfig();

  WCHAR dl = config->get_base_drive_letter();

  BOOL bGotVI = FALSE;

  DWORD max_component = 255;
  DWORD fs_flags;
  WCHAR fs_name[256];
  fs_name[0] = '\0';

  if (dl) {

    WCHAR rbuf[4];
    rbuf[0] = dl;
    rbuf[1] = ':';
    rbuf[2] = '\\';
    rbuf[3] = '\0';

    bGotVI = GetVolumeInformationW(rbuf, NULL, 0, NULL, &max_component,
                                   &fs_flags, fs_name,
                                   sizeof(fs_name) / sizeof(fs_name[0]) - 1);
  }
  if (bGotVI) {
    DbgPrint(L"max component length of underlying file system is %d\n",
             max_component);
  } else {
    DbgPrint(L"GetVolumeInformation failed, err = %u\n", GetLastError());
  }

  _ASSERT(max_component == 255);

  wcscpy_s(VolumeNameBuffer, VolumeNameSize, &config->m_VolumeName[0]);
  if (VolumeSerialNumber)
    *VolumeSerialNumber = con->GetConfig()->m_serial;
  if (MaximumComponentLength)
    *MaximumComponentLength =
        (config->m_PlaintextNames || config->m_LongNames) ? 255 : 160;
  DWORD defFlags = (FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
                    FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK |
                    FILE_PERSISTENT_ACLS
#ifdef ENABLE_FILE_NAMED_STREAMS_FLAG
                    | FILE_NAMED_STREAMS
#endif
                    );

  defFlags &= ~config->m_fs_feature_disable_mask;

  if (FileSystemFlags)
    *FileSystemFlags = defFlags & (bGotVI ? fs_flags : 0xffffffff);

  // File system name could be anything up to 10 characters.
  // But Windows check few feature availability based on file system name.
  // For this, it is recommended to set NTFS or FAT here.
  wcscpy_s(FileSystemNameBuffer, FileSystemNameSize,
           bGotVI ? fs_name : L"NTFS");

  return STATUS_SUCCESS;
}

/**
 * Avoid #include <winternl.h> which as conflict with FILE_INFORMATION_CLASS
 * definition.
 * This only for CryptFindStreams. Link with ntdll.lib still required.
 *
 * Not needed if you're not using NtQueryInformationFile!
 *
 * BEGIN
 */
typedef struct _IO_STATUS_BLOCK {
  union {
    NTSTATUS Status;
    PVOID Pointer;
  } DUMMYUNIONNAME;

  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationFile(
    _In_ HANDLE FileHandle, _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation, _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass);
/**
 * END
 */

NTSTATUS DOKAN_CALLBACK CryptFindStreamsInternal(
    LPCWSTR FileName, PFillFindStreamData FillFindStreamData,
    PDOKAN_FILE_INFO DokanFileInfo, PCryptStoreStreamName StoreStreamName,
    unordered_map<wstring, wstring> *pmap) {
  FileNameEnc filePath(DokanFileInfo, FileName);
  HANDLE hFind;
  WIN32_FIND_STREAM_DATA findData;
  DWORD error;
  int count = 0;

  DbgPrint(L"FindStreams :%s\n", FileName);

  if (rt_is_virtual_file(GetContext(), FileName)) {
    wcscpy_s(findData.cStreamName, L"::$DATA");
    if (rt_is_dir_iv_file(GetContext(), FileName)) {

      findData.StreamSize.QuadPart = DIR_IV_LEN;

    } else if (rt_is_name_file(GetContext(), FileName)) {
      BYTE dir_iv[DIR_IV_LEN];

      if (!derive_path_iv(GetContext(), FileName, dir_iv, TYPE_DIRIV)) {
        return ToNtStatus(ERROR_PATH_NOT_FOUND);
      }
      wstring storage, bare_filename;
      string actual_encrypted;
      if (!get_bare_filename(FileName, bare_filename))
        return ToNtStatus(ERROR_PATH_NOT_FOUND);
      const WCHAR *dname =
          encrypt_filename(GetContext(), dir_iv, bare_filename.c_str(), storage,
                           &actual_encrypted);
      if (!dname)
        return ToNtStatus(ERROR_PATH_NOT_FOUND);
      findData.StreamSize.QuadPart = actual_encrypted.length();
    } else {
      return ToNtStatus(ERROR_PATH_NOT_FOUND);
    }
    if (FillFindStreamData)
      FillFindStreamData(&findData, DokanFileInfo);

    DbgPrint(L"FindStreams on virtual file\n");
    return STATUS_SUCCESS;
    ;
  }

  wstring encrypted_name;

  hFind = FindFirstStreamW(filePath, FindStreamInfoStandard, &findData, 0);

  if (hFind == INVALID_HANDLE_VALUE) {
    error = GetLastError();
    DbgPrint(L"\tinvalid file handle. Error is %u\n\n", error);
    return ToNtStatus(error);
  }

  DbgPrint(L"found stream %s\n", findData.cStreamName);

  encrypted_name = findData.cStreamName;
  if (!convert_find_stream_data(GetContext(), FileName, filePath, findData)) {
    error = GetLastError();
    DbgPrint(L"\tconvert_find_stream_data returned false. Error is %u\n\n",
             error);
    if (error == 0)
      error = ERROR_ACCESS_DENIED;
    FindClose(hFind);
    return ToNtStatus(error);
  }
  DbgPrint(L"Stream %s size = %lld\n", findData.cStreamName,
           findData.StreamSize.QuadPart);
  if (FillFindStreamData)
    FillFindStreamData(&findData, DokanFileInfo);
  if (StoreStreamName && pmap) {
    StoreStreamName(&findData, encrypted_name.c_str(), pmap);
  }
  count++;

  while (FindNextStreamW(hFind, &findData) != 0) {
    DbgPrint(L"found stream %s\n", findData.cStreamName);
    encrypted_name = findData.cStreamName;
    if (!convert_find_stream_data(GetContext(), FileName, filePath, findData)) {
      error = GetLastError();
      DbgPrint(
          L"\tconvert_find_stream_data returned false (loop). Error is %u\n\n",
          error);
      if (error == 0)
        error = ERROR_ACCESS_DENIED;
      FindClose(hFind);
      return ToNtStatus(error);
    }
    DbgPrint(L"Stream %s size = %lld\n", findData.cStreamName,
             findData.StreamSize.QuadPart);
    if (FillFindStreamData && DokanFileInfo)
      FillFindStreamData(&findData, DokanFileInfo);
    if (StoreStreamName && pmap) {
      StoreStreamName(&findData, encrypted_name.c_str(), pmap);
    }
    count++;
  }

  error = GetLastError();
  FindClose(hFind);

  if (error != ERROR_HANDLE_EOF) {
    DbgPrint(L"\tFindNextStreamW error. Error is %u\n\n", error);
    return ToNtStatus(error);
  }

  DbgPrint(L"\tFindStreams return %d entries in %s\n\n", count, FileName);

  return STATUS_SUCCESS;
}

NTSTATUS DOKAN_CALLBACK CryptFindStreams(LPCWSTR FileName,
                                         PFillFindStreamData FillFindStreamData,
                                         PDOKAN_FILE_INFO DokanFileInfo) {

  return CryptFindStreamsInternal(FileName, FillFindStreamData, DokanFileInfo,
                                  NULL, NULL);
}

static NTSTATUS DOKAN_CALLBACK CryptMounted(PDOKAN_FILE_INFO DokanFileInfo) {

  CryptContext *con = GetContext();
  CryptConfig *config = con->GetConfig();

  SetEvent(con->m_mountEvent);

  DbgPrint(L"Mounted\n");
  //fwprintf(stdout, L"Mounted on %C:\\\n", config->GetDriveLetter());
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptUnmounted(PDOKAN_FILE_INFO DokanFileInfo) {
  CryptContext *con = GetContext();

  DbgPrint(L"Unmounted\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptGetDiskFreeSpace(
    PULONGLONG FreeBytesAvailable, PULONGLONG TotalNumberOfBytes,
    PULONGLONG TotalNumberOfFreeBytes, PDOKAN_FILE_INFO DokanFileInfo) {

  DbgPrint(L"GetDiskFreeSpace\n");

  CryptContext *con = GetContext();
  CryptConfig *config = con->GetConfig();

  if (config->m_basedir.size() > 0) {
    if (GetDiskFreeSpaceExW(&config->m_basedir[0],
                            (PULARGE_INTEGER)FreeBytesAvailable,
                            (PULARGE_INTEGER)TotalNumberOfBytes,
                            (PULARGE_INTEGER)TotalNumberOfFreeBytes)) {
      return STATUS_SUCCESS;
    } else {
      DWORD error = GetLastError();
      DbgPrint(L"\tGetDiskFreeSpaceExW error. Error is %u\n\n", error);
      return ToNtStatus(error);
    }
  } else {
    return STATUS_ACCESS_DENIED;
  }
}

static DWORD WINAPI CryptThreadProc(_In_ LPVOID lpParameter

                                    ) {
  CryptThreadData *tdata = (CryptThreadData *)lpParameter;

  NTSTATUS status = DokanMain(&tdata->options, &tdata->operations);

  return (DWORD)status;
}

int mount_crypt_fs(const WCHAR* mountpoint, const WCHAR *path,
                   const WCHAR *config_path, const WCHAR *password,
                   wstring &mes, const CryptMountOptions& opts) {
  mes.clear();

  if (config_path && *config_path == '\0')
    config_path = NULL;

  if (mountpoint == NULL) {
	  mes = L"invalid mountpoint";
	  return -1;
  }

  bool mount_point_is_a_dir = is_mountpoint_a_dir(mountpoint);

  if (mount_point_is_a_dir && !is_suitable_mountpoint(mountpoint)) {
	  if (!PathFileExists(mountpoint)) {
		  mes = L"the mount point directory does not exist";
	  } else {
		  mes = L"mount point directory must be empty and reside on NTFS volume";
	  }
	  return -1;
  }

  wstring dummy;
  bool already_mounted = MountPointManager::getInstance().find(mountpoint, dummy);

  if (already_mounted) {
    mes = L"drive letter/mount point already in use\n";
    return -1;
  }

  

  int retval = 0;
  CryptThreadData *tdata = NULL;
  HANDLE hThread = NULL;

  try {

    try {
      tdata = new CryptThreadData;
    } catch (...) {
    }

    if (!tdata) {
      mes = L"Failed to allocate tdata\n";
      throw(-1);
    }

    if (opts.encryptkeysinmemory) {
        tdata->con.m_encryptKeysInMemory = true;
        tdata->con.m_cacheKeysInMemory = opts.cachekeysinmemory;
        tdata->con.GetConfig()->m_keybuf_manager.Activate();
    }

    PDOKAN_OPERATIONS dokanOperations = &tdata->operations;

    init_security_name_privilege(); // make sure AddSecurityNamePrivilege() has been called, whether or not we can get it

    ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
    dokanOperations->ZwCreateFile = CryptCreateFile;
    dokanOperations->Cleanup = CryptCleanup;
    dokanOperations->CloseFile = CryptCloseFile;
    dokanOperations->ReadFile = CryptReadFile;
    dokanOperations->WriteFile = CryptWriteFile;
    dokanOperations->FlushFileBuffers = CryptFlushFileBuffers;
    dokanOperations->GetFileInformation = CryptGetFileInformation;
    dokanOperations->FindFiles = CryptFindFiles;
    dokanOperations->FindFilesWithPattern = NULL;
    dokanOperations->SetFileAttributes = CryptSetFileAttributes;
    dokanOperations->SetFileTime = CryptSetFileTime;
    dokanOperations->DeleteFile = CryptDeleteFile;
    dokanOperations->DeleteDirectory = CryptDeleteDirectory;
    dokanOperations->MoveFile = CryptMoveFile;
    dokanOperations->SetEndOfFile = CryptSetEndOfFile;
    dokanOperations->SetAllocationSize = CryptSetAllocationSize;
    dokanOperations->LockFile = CryptLockFile;
    dokanOperations->UnlockFile = CryptUnlockFile;
    // We seem to work better if we export Get/SetFileSecurity even if we don't have SE_SECURITY_NAME privilege.
    // It seems that GetFileSecurity() will work without that privilege, at least in the common cases.
    // So it seems better to do as much Get/SetFileSecurity() as we can regardless of whether we
    // we can get SE_SECURITY_NAME (getting it implies running as administrator).
    //
    // Dokany suggested setting the Get/Set callbacks to NULL if we don't have the privilege, but that keeps us from
    // being able to copy files out of the encrypted fs, or even copy a file within it to a new file within it.
    // So, whatever type of GetFileSecurity() that can work even without having SE_SECURITY_NAME
    // seems to be required for copying files.
    if (1 || have_security_name_privilege()) {
      dokanOperations->GetFileSecurity = CryptGetFileSecurity;
      dokanOperations->SetFileSecurity = CryptSetFileSecurity;
    } else {
      dokanOperations->GetFileSecurity = NULL;
      dokanOperations->SetFileSecurity = NULL;
    }
    dokanOperations->GetDiskFreeSpace = CryptGetDiskFreeSpace;
    dokanOperations->GetVolumeInformation = CryptGetVolumeInformation;
    dokanOperations->Unmounted = CryptUnmounted;
    dokanOperations->FindStreams = CryptFindStreams;
    dokanOperations->Mounted = CryptMounted;

    CryptContext *con = &tdata->con;

    con->m_bufferblocks = min(4096, max(1, opts.numbufferblocks));	 

    con->m_dir_iv_cache.SetTTL(opts.cachettl);
    con->m_case_cache.SetTTL(opts.cachettl);

    con->SetCaseSensitive(opts.caseinsensitive);

	con->m_delete_spurrious_files = opts.deletespurriousfiles;

	con->m_cache_ttl = opts.cachettl;

	con->m_threads = opts.numthreads ? opts.numthreads : 5;

    CryptConfig *config = con->GetConfig();

    PDOKAN_OPTIONS dokanOptions = &tdata->options;

    ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
    dokanOptions->Version = DOKAN_VERSION;

    dokanOptions->ThreadCount = opts.numthreads;

#ifdef _DEBUG
    dokanOptions->Timeout = 900000;
    g_DebugMode = 1;
#endif

    config->m_basedir = prepare_basedir(path);

    config->m_mountpoint = mountpoint;

    tdata->mountpoint = mountpoint;

    dokanOptions->MountPoint = tdata->mountpoint.c_str();

    if (!config->read(mes, config_path, opts.reverse)) {
      if (mes.length() < 1)
        mes = L"unable to load config\n";
      throw(-1);
    }

    wstring config_error_mes;

    if (!config->check_config(config_error_mes)) {
      mes = &config_error_mes[0];
      throw(-1);
    }

#ifdef WINDOWS_GRATUITOUS_UPPERCASING // was fixed by Dokany 1.2.0.1000
	// reverse-mode filesystems won't work when mounted to an empty dir for the reason given below.
	// i.e. because we don't support case-insensitive in reverse mode.
	if (config->m_reverse && is_mountpoint_a_dir(mountpoint)) {
		mes = L"Reverse fileystems must be mounted using a drive letter.\n";
		throw(-1);
	}
	// Windows uppercases filenames passed to CryptCreateFile() 
	// if the filesystem is mounted to an empty NTFS dir instead of to a drive letter.
	if (!con->IsCaseInsensitive() && is_mountpoint_a_dir(mountpoint)) {
		mes = L"Filesystems mounted using a directory for the mount point must be mounted case-insensitive.\n";
		throw(-1);
	}
#endif
	
    if (!config->decrypt_key(password)) {
      mes = L"password incorrect\n";
      throw(-1);
    }

    if (config->m_EMENames) {
      try {
        if (!con->InitEme(config->GetMasterKey(), config->m_HKDF)) {
          throw(-1);
        }
      } catch (...) {
        mes = L"unable to initialize eme context";
        throw(-1);
      }
    }

    if (config->m_AESSIV) {
      try {
        con->m_siv.SetKey(config->GetMasterKey(), 32, config->m_HKDF, config);
      } catch (...) {
        mes = L"unable to intialize AESSIV context";
        throw(-1);
      }
    }

    config->init_serial(con);

    WCHAR fs_name[256];

    DWORD fs_flags;

    WCHAR rbuf[4];
    rbuf[0] = config->get_base_drive_letter();
    rbuf[1] = ':';
    rbuf[2] = '\\';
    rbuf[3] = '\0';

    BOOL bGotVI =
        GetVolumeInformationW(rbuf, NULL, 0, NULL, NULL, &fs_flags, fs_name,
                              sizeof(fs_name) / sizeof(fs_name[0]) - 1);

    if (bGotVI) {

      size_t maxlength = !wcscmp(fs_name, L"NTFS") ? MAX_VOLUME_NAME_LENGTH
                                                   : MAX_FAT_VOLUME_NAME_LENGTH;

      if (config->m_VolumeName.size() > maxlength)
        config->m_VolumeName.erase(maxlength, wstring::npos);

	  if (fs_flags & FILE_READ_ONLY_VOLUME) {
		  dokanOptions->Options |= DOKAN_OPTION_WRITE_PROTECT;
		  con->m_read_only = true;
	  }

    } else {
      DWORD lasterr = GetLastError();
      DbgPrint(L"GetVolumeInformation failed, lasterr = %u\n", lasterr);
    }

    if (config->m_reverse || opts.readonly) {
      dokanOptions->Options |= DOKAN_OPTION_WRITE_PROTECT;
	  con->m_read_only = true;
    } else if (opts.mountmanager) {
      if (opts.mountmanagerwarn && !have_security_name_privilege()) {

        if (!mountmanager_continue_mounting()) {
          mes = L"operation cancelled by user";
          throw(-1);
        }
      }

      if (have_security_name_privilege()) {
		  dokanOptions->Options |= DOKAN_OPTION_MOUNT_MANAGER;
		  con->m_recycle_bin = true;
	  }
    }

	if (!con->FinalInitBeforeMounting(opts.cachekeysinmemory)) {
      mes = L"context final init failed";
      throw(-1);
	}

    dokanOptions->GlobalContext = (ULONG64)con;
    dokanOptions->Options |= DOKAN_OPTION_ALT_STREAM;

    hThread = CreateThread(NULL, 0, CryptThreadProc, tdata, 0, NULL);

    if (!hThread) {
      mes = L"unable to create thread for drive letter/mount point\n";
      throw(-1);
    }

	tdata->hThread = hThread;

	// MountPointManager owns tdata from this point on, even if it fails to add (will delete it)

	if (!MountPointManager::getInstance().add(mountpoint, tdata)) {
		mes = L"unable to add mount point to MountPointManager\n";
		throw(-1);
	}

    HANDLE handles[2];
    handles[0] = con->m_mountEvent;
    handles[1] = hThread;


    
    auto tick0 = ::GetTickCount64();

    decltype(tick0) elapsed = 0;

    DWORD wait_result = WAIT_TIMEOUT;

    // polling makes sense only on drive letters because a mount point dir will
    // already exist.  Also, Dokany calls back fast if the mount point is a dir

    bool do_fast_mounting = opts.fastmounting && !mount_point_is_a_dir;

    while (wait_result == WAIT_TIMEOUT && elapsed < MOUNT_TIMEOUT) {
       
        wait_result = WaitForMultipleObjects(
                sizeof(handles) / sizeof(handles[0]), handles, FALSE, do_fast_mounting ? FAST_MOUNTING_WAIT : MOUNT_TIMEOUT);

        if (do_fast_mounting) {
            // it currently takes about 5 seconds for Dokany to call back that the fs mounted
            // if the mount point is a drive letter, but the fs actually mounts almost instantly.
            // so we also poll on it existing and assume everything succeded if it does exist
            if (wait_result == WAIT_TIMEOUT && ::PathFileExists(con->GetConfig()->m_mountpoint.c_str())) {
                wait_result = WAIT_OBJECT_0;
            }
            elapsed = ::GetTickCount64() - tick0;
        } else {
            elapsed = MOUNT_TIMEOUT;          
        }       
    }    

    if (wait_result != WAIT_OBJECT_0) {
      if (wait_result == (WAIT_OBJECT_0 + 1)) {
        // thread exited without mounting
        mes = L"mount operation failed\n";
      } else if (wait_result == WAIT_TIMEOUT) {
        mes = L"mount operation timed out\n";
        tdata = NULL; // deleting it would probably cause crash
      } else {
        mes = L"error waiting for mount operation\n";
        tdata = NULL; // deleting it would probably cause crash
      }
      throw(-1);
    }

  } catch (...) {
    retval = -1;
  }

  if (retval != 0) {
	MountPointManager::getInstance().destroy(mountpoint);
  } 

  return retval;
}

BOOL unmount_crypt_fs(const WCHAR* mountpoint, bool wait, wstring& mes) {


  wstring mpstr;
  if (!MountPointManager::getInstance().find(mountpoint, mpstr)) {
	  mes += L"unable to find mount point";
	  return FALSE;
  }
  if (!DokanRemoveMountPoint(mpstr.c_str())) {
	  mes += GetWindowsErrorString(GetLastError());
	  return FALSE;
  }

  if (wait) {
	  bool res = MountPointManager::getInstance().wait_and_destroy(mpstr.c_str());
	  if (!res) {
		  mes += L"wait on umount returned an error " + GetWindowsErrorString(GetLastError());
	  }
	  return res;
  } else {
	  return TRUE;
  }
    
}

bool unmount_all(bool wait)
{
	return MountPointManager::getInstance().unmount_all(wait);
}



BOOL wait_for_all_unmounted() {
	return MountPointManager::getInstance().wait_all_and_destroy();
}



BOOL write_volume_name_if_changed(WCHAR dl, wstring& mes) {

  
  wstring fs_root;

  fs_root.push_back(dl);
  fs_root.push_back(':');

  CryptThreadData *tdata = MountPointManager::getInstance().get(fs_root.c_str());

  if (!tdata) {
	  mes += L"mount point not found";
	  return FALSE;
  }

  fs_root.push_back('\\');

  CryptContext *con = &tdata->con;

  if (!con) {
	  mes += L"mount point has null context";
	  return FALSE;
  }

  KeyDecryptor kdc(&con->GetConfig()->m_keybuf_manager);

  WCHAR volbuf[256];

  if (!GetVolumeInformationW(&fs_root[0], volbuf,
                             sizeof(volbuf) / sizeof(volbuf[0]) - 1, NULL, NULL,
                             NULL, NULL, 0)) {
    DWORD error = GetLastError();
    DbgPrint(L"update volume name error = %u\n", error);
	mes += L"Unable to get volume information, " + GetWindowsErrorString(error);
    return FALSE;
  }

  if (con->GetConfig()->m_VolumeName != volbuf) {
    con->GetConfig()->m_VolumeName = volbuf;
    bool res = con->GetConfig()->write_updated_config_file();
	if (!res) {
		mes += L"unable to write new volume name to config file";
		return FALSE;
	}
  }

  return TRUE;
}

BOOL have_security_name_privilege() {
  static BOOL bHaveName = FALSE;
  static BOOL bCheckedName = FALSE;

  if (!bCheckedName) {
    bHaveName = AddSeSecurityNamePrivilege();
    bCheckedName = TRUE;
    g_HasSeSecurityPrivilege = bHaveName;
  }

  return bHaveName;
}

void init_security_name_privilege() { have_security_name_privilege(); }

// use our own callback so rest of the code doesn't need to know about Dokany internals
static int WINAPI crypt_fill_find_data_list(PWIN32_FIND_DATAW fdata,
                                            PWIN32_FIND_DATAW fdata_orig,
                                            void *dokan_cb, void *dokan_ctx) {
  list<FindDataPair> *findDatas = (list<FindDataPair> *)dokan_ctx;

  FindDataPair pair;

  pair.fdata = *fdata;
  pair.fdata_orig = *fdata_orig;

  findDatas->push_back(pair);

  return 0;
}

// called to list files from the command line (not by Dokany)
BOOL list_files(const WCHAR *path, list<FindDataPair> &findDatas,
                wstring &err_mes) {
  err_mes = L"";

  if (!path) {
    err_mes = L"path is null";
    return FALSE;
  }

  if (wcslen(path) > MAX_PATH - 1) {
    err_mes = L"path is too long";
    return FALSE;
  }

  WCHAR newpath[MAX_PATH + 1];

  if (!PathCanonicalize(newpath, path)) {
    err_mes = L"failed to canonicalize path";
    return FALSE;
  }

  path = newpath;

  int dl = *path;

  if (dl < 'A' || dl > 'Z') {
    err_mes = L"invalid drive letter";
    return FALSE;
  }

  if (wcslen(path) < 3) {
    err_mes = L"path is too short";
    return FALSE;
  }

  if (path[1] != ':' || path[2] != '\\') {
    err_mes = L"invalid path";
    return FALSE;
  }


  // according to Microsoft, _wcsnicmp() uses the "C" locale by default, and it won't treat the lower and uppercase
  // versions of non-ascii characters the same unless you call setlocale() to some other locale first.
  // In order to avoid possible side-effects of setting the locale, we create a locale with "" (current thread locale)
  // and pass that in to _wcsnicmp_l()
  // this function is invoked from the command line, so performance isn't an issue.
  
  _locale_t locale = _create_locale(LC_ALL, ""); 

  if (locale == NULL) {
	  err_mes = L"cannot create locale";
	  return FALSE;
  }

  // iterate through MountPointManager's (our friend's) mount points and try to find a match
  // between a mount point and the path passed in.

  // This is needed to find the CryptContext for the mount point.

  CryptThreadData *tdata = NULL;

  auto findit = [&tdata, &path, &locale] (const wchar_t *mp, CryptThreadData *td) -> bool {
	  if (!_wcsnicmp_l(mp, path, wcslen(mp), locale)) {
		  tdata = td;
		  path += wcslen(mp);
		  return false; // stop looking
	  } else {
		  return true; // keep looking
	  }
  };

  MountPointManager::getInstance().apply(findit);

  _free_locale(locale);

  if (!tdata) {
    err_mes = L"drive not mounted";
    return FALSE;
  }

  wstring find_path = path;

  if (find_path[0] != '\\') {
	  find_path = L"\\" + find_path;
  }

  CryptContext *con = &tdata->con;

  DOKAN_FILE_INFO DokanFileInfo;
  DOKAN_OPTIONS DokanOptions;

  memset(&DokanFileInfo, 0, sizeof(DokanFileInfo));
  memset(&DokanOptions, 0, sizeof(DokanOptions));

  DokanOptions.GlobalContext = (ULONG_PTR)con;

  DokanFileInfo.DokanOptions = &DokanOptions;

  DokanFileInfo.DokanOptions->GlobalContext = (ULONG_PTR)con;

  FileNameEnc filePath(&DokanFileInfo, find_path.c_str());

  if (PathIsDirectory(filePath)) {

    if (find_files(con, filePath.CorrectCasePath(), filePath,
                   crypt_fill_find_data_list, NULL, &findDatas) != 0) {
      err_mes = L"error listing files";
      return FALSE;
    }
  } else if (PathFileExists(filePath)) {

    FindDataPair pair;
    memset(&pair, 0, sizeof(pair));

    wchar_t dl_colon[3];

    dl_colon[0] = dl;
    dl_colon[1] = ':';
    dl_colon[2] = '\0';

    wstring plain_path;

    plain_path += dl_colon;
    plain_path += filePath.CorrectCasePath();

    wcscpy_s(pair.fdata.cFileName, plain_path.c_str());
    wcscpy_s(pair.fdata_orig.cFileName,
             filePath + (wcslen(filePath) > 4 ? 4 : 0)); // +4 to skip the \\?\

    findDatas.push_back(pair);

  } else {

    err_mes = L"path does not exist";
    return FALSE;
  }

  return TRUE;
}

bool get_dokany_version(wstring& ver, vector<int>& v)
{
	// DokanVersion() is useless because it returns 100

	v.clear();

	HMODULE hDok = GetModuleHandle(L"dokan1.dll");
	if (!hDok)
		return false;
	WCHAR dokPath[MAX_PATH+1];
	dokPath[0] = '\0';

	

	wstring name;
	wstring copyright;

	if (!GetProductVersionInfo(name, ver, copyright, hDok)) {
		return false;
	}

	vector<wstring> strings;
	wistringstream f(ver);
	wchar_t buf[32];
	while (f.getline(buf, sizeof(buf) / sizeof(buf[0]) - 1, L'.')) {
		strings.push_back(buf);
	}

	if (strings.size() != 4) {
		return false;
	}

	v.push_back(_wtoi(strings[0].c_str()));
	v.push_back(_wtoi(strings[1].c_str()));
	v.push_back(_wtoi(strings[2].c_str()));
	v.push_back(_wtoi(strings[3].c_str()));

	return true;

}

// return false if won't work, returns true with no message if all ok, 
// returns true with message if there will maybe be a problem
bool check_dokany_version(wstring& mes)
{
	constexpr int required_major = 1;
	constexpr int required_middle = 5;
    const wstring required_ver =  to_wstring(required_major) + L"." + to_wstring(required_middle) +  L".x.x";
	
	mes = L"";

	wstring ver;

	vector<int> v;
	if (!get_dokany_version(ver, v)) {
		mes = L"unable to get dokany version";
		return false;
	}

	if (v.size() < 2) {
		return false;
	}

	int major = v[0];
	int middle = v[1];

	if (major == required_major && middle == required_middle) {
		return true;
	}
	
	if (major != required_major) {
		mes = L"The installed Dokany version " + ver + L" is not compatible.  Please install Dokany " + required_ver;
		return false; // error
	}
	
	if (major == required_major && middle < required_middle) {
		mes = L"The installed Dokany version " + ver + L" is not compatible.  Please install Dokany " + required_ver;
		return false; // error
	}

	if (major == required_major && middle > required_middle) {
		mes = L"The installed Dokany version is " + ver + L", and it has not been tested with cppcryptfs.  Please install Dokany " + required_ver;
		return true; // warning
	}

	return false;
}

bool get_fs_info(const wchar_t *mountpoint, FsInfo& info)
{
	MountPointManager& mp_man = MountPointManager::getInstance();

	CryptThreadData *tdata = mp_man.get(mountpoint);
	if (!tdata) {
		return false;
	}

	tdata->con.GetFsInfo(info);

	return true;
}

void crypt_at_exit()
{
    KeyCache::GetInstance()->StopClearThread();

    if (g_DebugLogFile) {      
        FILE* fl = g_DebugLogFile;
        g_DebugLogFile = nullptr;
        fclose(fl);       
    }
}


static void InitLogging()
{
    const WCHAR* logdir = L"C:\\cppcryptfslogs";

    if (!PathFileExists(logdir)) {
        ::MessageBox(NULL, (wstring(L"Unable to init logging.  Please create ") + logdir).c_str(), L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
        return;
    }

    auto pad2 = [](int n) {

        wchar_t buf[8];

        *buf = L'\0';

        swprintf_s(buf, L"%02d", n);

        return wstring(buf);
    };

    SYSTEMTIME st;

    memset(&st, 0, sizeof(st));

    GetLocalTime(&st);

    wstring year, month, day, hour, minute, second;

    year = to_wstring(st.wYear);
    month = pad2(st.wMonth);
    day = pad2(st.wDay);

    hour = pad2(st.wHour);
    minute = pad2(st.wMinute);
    second = pad2(st.wSecond);

    wstring logname = wstring(logdir) + L"\\cppcryptfs-" + year + L"-" + month + L"-" + day + L"_" + hour + L"." + minute + L"." + second + L".log";

    int result = _wfopen_s(&g_DebugLogFile, logname.c_str(), L"at+");

    if (result == 0) {
        ::MessageBox(NULL, (wstring(L"Logging to ") + logname).c_str(), L"cppcryptfs", MB_OK | MB_ICONINFORMATION);
    } else {
        ::MessageBox(NULL, (wstring(L"Unable to open ") + logname.c_str()).c_str(), L"cppcryptfs", MB_OK | MB_ICONERROR);
    }

}

void crypt_at_start()
{
    if (g_UseLogFile) {
        InitLogging();
    }
    SetDbgVars(g_DebugMode, g_UseStdErr, g_UseLogFile, g_DebugLogFile);
}
