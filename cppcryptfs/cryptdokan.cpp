
/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016 - Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include "cryptfilename.h"
#include "cryptconfig.h"
#include "cryptcontext.h"
#include "fileutil.h"
#include "cryptfile.h"
#include "cryptdefs.h"
#include "util.h"

#include <vector>
#include <string>

#include <windows.h>
#include "dokan/dokan.h"
#include "dokan/fileinfo.h"
#include <malloc.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>
#include <stdarg.h>
#include <varargs.h>


#define UNMOUNT_TIMEOUT 30000
#define MOUNT_TIMEOUT 30000

BOOL g_UseStdErr;
BOOL g_DebugMode; 

struct struct_CryptThreadData {
	PDOKAN_OPERATIONS operations;
	PDOKAN_OPTIONS options;
};

typedef struct struct_CryptThreadData CryptThreadData;

HANDLE g_DriveThreadHandles[26];
CryptThreadData *g_ThreadDatas[26];




void DbgPrint(LPCWSTR format, ...) {
  if (g_DebugMode) {
    const WCHAR *outputString;
    WCHAR *buffer = NULL;
    size_t length;
    va_list argp;

    va_start(argp, format);
    length = _vscwprintf(format, argp) + 1;
    buffer = (WCHAR*)_malloca(length * sizeof(WCHAR));
    if (buffer) {
      vswprintf_s(buffer, length, format, argp);
      outputString = buffer;
    } else {
      outputString = format;
    }
    if (g_UseStdErr)
      fputws(outputString, stderr);
    else
      OutputDebugStringW(outputString);
    if (buffer)
      _freea(buffer);
    va_end(argp);
  }
}


// The FileNameEnc class has a contstructor that takes the necessary inputs
// for doing the filename encryption.  It saves them for later, at almost zero cost.
// 
// If the encrypted filename is actually needed, then the instance of FileNameEnc
// is passed to one of various functions that take a const WCHAR * for the encrypted path 
// (and possibly an actual_encrypted parameter).  
//
// When the overloaded cast to const WCHAR * is performed, the filename will be encrypted, and
// the actual_encrypted data (if any) will be retrieved.
//
// A note on actual_encrypted:
//
// When creating a new file or directory, if a file or directory with a long name is being created,
// then the actual encrypted name must be written to the special gocryptfs.longname.XXXXX.name file.
// actual_encrypted will contain this data in that case.


class FileNameEnc {
private:
	std::wstring m_enc_path;
	std::string *m_actual_encrypted;
	const WCHAR *m_plain_path;
	CryptContext *m_con;
	const WCHAR *m_ret;
	

public:
	operator const WCHAR *()
	{
	
		if (!m_ret) {
			try {
				if (!encrypt_path(m_con, m_plain_path, m_enc_path, m_actual_encrypted))
					m_enc_path = L"";
				m_ret = &m_enc_path[0];
			} catch (...) {
				m_ret = L"";
			}
		}
		const WCHAR *rs = m_ret && *m_ret ? m_ret : NULL;
		if (rs) {
			DbgPrint(L"\tconverted filename %s => %s\n", m_plain_path, rs);
		} else {
			DbgPrint(L"\terror converting filenaem %s\n", m_plain_path);
		}
		return rs;
	};
	FileNameEnc(CryptContext *con, const WCHAR *fname, std::string *actual = NULL);
	virtual ~FileNameEnc();
};

FileNameEnc::FileNameEnc(CryptContext *con, const WCHAR *fname, std::string *actual_encrypted)
{
	m_con = con;
	m_plain_path = fname;
	m_actual_encrypted = actual_encrypted;
	m_ret = NULL;
}

FileNameEnc::~FileNameEnc()
{

}



static void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo) {

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
}

NTSTATUS ToNtStatus(DWORD dwError) {
  switch (dwError) {
  case ERROR_DIR_NOT_EMPTY:
	  return STATUS_DIRECTORY_NOT_EMPTY;
  case ERROR_FILE_NOT_FOUND:
    return STATUS_OBJECT_NAME_NOT_FOUND;
  case ERROR_PATH_NOT_FOUND:
    return STATUS_OBJECT_PATH_NOT_FOUND;
  case ERROR_INVALID_PARAMETER:
    return STATUS_INVALID_PARAMETER;
  case ERROR_ACCESS_DENIED:
    return STATUS_ACCESS_DENIED;
  case ERROR_SHARING_VIOLATION:
    return STATUS_SHARING_VIOLATION;
  case ERROR_INVALID_NAME:
    return STATUS_OBJECT_NAME_NOT_FOUND;
  case ERROR_FILE_EXISTS:
  case ERROR_ALREADY_EXISTS:
    return STATUS_OBJECT_NAME_COLLISION;
  case ERROR_PRIVILEGE_NOT_HELD:
    return STATUS_PRIVILEGE_NOT_HELD;
  case ERROR_NOT_READY:
    return STATUS_DEVICE_NOT_READY;
  case ERROR_DIRECTORY:
	  return STATUS_NOT_A_DIRECTORY;
  case ERROR_HANDLE_EOF:
	  return STATUS_END_OF_FILE;
  default:
    DbgPrint(L"Unknown error code %d\n", dwError);
    return STATUS_ACCESS_DENIED;
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

#define CryptCheckFlag(val, flag)                                             \
  if (val & flag) {                                                            \
    DbgPrint(L"\t" L#flag L"\n");                                              \
  }


#define GetContext() ((CryptContext*)DokanFileInfo->DokanOptions->GlobalContext)

static NTSTATUS DOKAN_CALLBACK
CryptCreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
                 ACCESS_MASK DesiredAccess, ULONG FileAttributes,
                 ULONG ShareAccess, ULONG CreateDisposition,
                 ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo) {
  std::string actual_encrypted;
  FileNameEnc filePath(GetContext(), FileName, &actual_encrypted);
  HANDLE handle = NULL;
  DWORD fileAttr;
  NTSTATUS status = STATUS_SUCCESS;
  DWORD creationDisposition;
  DWORD fileAttributesAndFlags;
  DWORD error = 0;
  SECURITY_ATTRIBUTES securityAttrib;

 

  securityAttrib.nLength = sizeof(securityAttrib);
  securityAttrib.lpSecurityDescriptor =
      SecurityContext->AccessState.SecurityDescriptor;
  securityAttrib.bInheritHandle = FALSE;

  DokanMapKernelToUserCreateFileFlags(
      FileAttributes, CreateOptions, CreateDisposition, &fileAttributesAndFlags,
      &creationDisposition);



  DbgPrint(L"CreateFile : %s\n", FileName);

  PrintUserName(DokanFileInfo);

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

  DbgPrint(L"\tAccessMode = 0x%x\n", DesiredAccess);

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

  if (!(CreateOptions & FILE_DIRECTORY_FILE) && !(DesiredAccess & FILE_READ_DATA)) {
	  DbgPrint(L"\tadded FILE_READ_DATA to desired access\n");
	  DesiredAccess |= FILE_READ_DATA;
  }
  if (!(CreateOptions & FILE_DIRECTORY_FILE) && !(ShareAccess & FILE_SHARE_READ)) {
	  DbgPrint(L"\tadded FILE_SHARE_READ to share access\n");
	  ShareAccess |= FILE_SHARE_READ;
  }

  // When filePath is a directory, needs to change the flag so that the file can
  // be opened.
  fileAttr = GetFileAttributes(filePath);

  if (fileAttr != INVALID_FILE_ATTRIBUTES &&
      (fileAttr & FILE_ATTRIBUTE_DIRECTORY &&
       DesiredAccess != DELETE)) { // Directory cannot be open for DELETE
    fileAttributesAndFlags |= FILE_FLAG_BACKUP_SEMANTICS;
    // AccessMode = 0;
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

  if ((CreateOptions & FILE_DIRECTORY_FILE) == FILE_DIRECTORY_FILE) {
    // It is a create directory request
    if (CreateDisposition == FILE_CREATE) {
      if (!CreateDirectory(filePath, &securityAttrib)) {
        error = GetLastError();
        DbgPrint(L"\terror code = %d\n\n", error);
        status = ToNtStatus(error);
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
	  }
    } else if (CreateDisposition == FILE_OPEN_IF) {

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
	  }
    }

    if (status == STATUS_SUCCESS) {
      // FILE_FLAG_BACKUP_SEMANTICS is required for opening directory handles
      handle = CreateFileW(filePath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           &securityAttrib, OPEN_EXISTING,
                           FILE_FLAG_BACKUP_SEMANTICS, NULL);

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
      }
    }
  } else {
	  // It is a create file request

	  if (fileAttr != INVALID_FILE_ATTRIBUTES &&
		  (fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
		  CreateDisposition == FILE_CREATE) {
		  return STATUS_OBJECT_NAME_COLLISION; // File already exist because
											   // GetFileAttributes found it
	  }
	  else {
		  handle = CreateFile(
			  filePath,
			  DesiredAccess, // GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
			  ShareAccess,
			  &securityAttrib, // security attribute
			  creationDisposition,
			  fileAttributesAndFlags, // |FILE_FLAG_NO_BUFFERING,
			  NULL);                  // template file handle
	}


    if (handle == INVALID_HANDLE_VALUE) {
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

      DokanFileInfo->Context =
          (ULONG64)handle; // save the file handle in Context

      if (creationDisposition == OPEN_ALWAYS ||
          creationDisposition == CREATE_ALWAYS) {
        error = GetLastError();
        if (error == ERROR_ALREADY_EXISTS) {
          DbgPrint(L"\tOpen an already existing file\n");
          SetLastError(ERROR_ALREADY_EXISTS); // Inform the driver that we have
                                              // open a already existing file
          return STATUS_SUCCESS;
        }
      }
    }
  }
  DbgPrint(L"handle = %I64x", (ULONGLONG)handle);
  DbgPrint(L"\n");
  return status;
}

static void DOKAN_CALLBACK CryptCloseFile(LPCWSTR FileName,
                                           PDOKAN_FILE_INFO DokanFileInfo) {
   FileNameEnc filePath(GetContext(), FileName);

  if (DokanFileInfo->Context) {
    DbgPrint(L"CloseFile: %s, %x\n", FileName, (DWORD)DokanFileInfo->Context);
    DbgPrint(L"\terror : not cleanuped file\n\n");
    CloseHandle((HANDLE)DokanFileInfo->Context);
    DokanFileInfo->Context = 0;
  } else {
    DbgPrint(L"Close (no handle): %s\n\n", FileName);
  }
}

static void DOKAN_CALLBACK CryptCleanup(LPCWSTR FileName,
                                         PDOKAN_FILE_INFO DokanFileInfo) {
	FileNameEnc filePath(GetContext(), FileName);
 

  if (DokanFileInfo->Context) {
    DbgPrint(L"Cleanup: %s, %x\n\n", FileName, (DWORD)DokanFileInfo->Context);
    CloseHandle((HANDLE)DokanFileInfo->Context);
    DokanFileInfo->Context = 0;

    if (DokanFileInfo->DeleteOnClose) {
      DbgPrint(L"\tDeleteOnClose\n");
      if (DokanFileInfo->IsDirectory) {
        DbgPrint(L"  DeleteDirectory ");
        if (!delete_directory(GetContext(), filePath)) {
          DbgPrint(L"error code = %d\n\n", GetLastError());
        } else {
          DbgPrint(L"success\n\n");
        }
      } else {
        DbgPrint(L"  DeleteFile ");
        if (!delete_file(GetContext(), filePath)) {
          DbgPrint(L" error code = %d\n\n", GetLastError());
        } else {
          DbgPrint(L"success\n\n");
        }
      }
    }

  } else {
    DbgPrint(L"Cleanup: %s\n\tinvalid handle\n\n", FileName);
  }
}

static NTSTATUS DOKAN_CALLBACK CryptReadFile(LPCWSTR FileName, LPVOID Buffer,
	DWORD BufferLength,
	LPDWORD ReadLength,
	LONGLONG Offset,
	PDOKAN_FILE_INFO DokanFileInfo) {
	FileNameEnc filePath(GetContext(), FileName);
	HANDLE handle = (HANDLE)DokanFileInfo->Context;
	ULONG offset = (ULONG)Offset;
	BOOL opened = FALSE;
	NTSTATUS ret_status = STATUS_SUCCESS;


	DbgPrint(L"ReadFile : %s, %I64u\n", FileName, (ULONGLONG)handle);

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"\tinvalid handle, cleanuped?\n");
		handle = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
			OPEN_EXISTING, 0, NULL);
		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			DbgPrint(L"\tCreateFile error : %d\n\n", error);
			return ToNtStatus(error);
		}
		opened = TRUE;
	}

	CryptFile file;
	if (file.Associate(GetContext(), handle)) {

		if (!file.Read((unsigned char *)Buffer, BufferLength, ReadLength, offset)) {
			DWORD error = GetLastError();
			DbgPrint(L"\tread error = %u, buffer length = %d, read length = %d\n\n",
				error, BufferLength, *ReadLength);
			ret_status = ToNtStatus(error);
		}

    } else {
		ret_status = STATUS_ACCESS_DENIED;
    }

    if (opened)
      CloseHandle(handle);

    return ret_status;
}

static NTSTATUS DOKAN_CALLBACK CryptWriteFile(LPCWSTR FileName, LPCVOID Buffer,
                                               DWORD NumberOfBytesToWrite,
                                               LPDWORD NumberOfBytesWritten,
                                               LONGLONG Offset,
                                               PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(GetContext(), FileName);
  HANDLE handle = (HANDLE)DokanFileInfo->Context;
  ULONG offset = (ULONG)Offset;
  BOOL opened = FALSE;
  NTSTATUS ret_status = STATUS_SUCCESS;



  DbgPrint(L"WriteFile : %s, offset %I64d, length %d\n", FileName, Offset,
           NumberOfBytesToWrite);

  // reopen the file
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle, cleanuped?\n");
    handle = CreateFile(filePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
      DWORD error = GetLastError();
      DbgPrint(L"\tCreateFile error : %d\n\n", error);
      return ToNtStatus(error);
    }
    opened = TRUE;
  }

  CryptFile file;
  if (file.Associate(GetContext(), handle)) {
	  if (!file.Write((const unsigned char *)Buffer, NumberOfBytesToWrite, NumberOfBytesWritten, offset, DokanFileInfo->WriteToEndOfFile)) {
		  DWORD error = GetLastError();
		  DbgPrint(L"\twrite error = %u, buffer length = %d, write length = %d\n",
			  error, NumberOfBytesToWrite, *NumberOfBytesWritten);
		  ret_status = ToNtStatus(error);
	  }
	  else {
		  DbgPrint(L"\twrote nbytes = %u\n", *NumberOfBytesWritten);
	  }
  } else {
	  ret_status = STATUS_ACCESS_DENIED;
  }

  // close the file when it is reopened
  if (opened)
    CloseHandle(handle);

  return ret_status;
}

static NTSTATUS DOKAN_CALLBACK
CryptFlushFileBuffers(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(GetContext(), FileName);
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
	FileNameEnc filePath(GetContext(), FileName);
  HANDLE handle = (HANDLE)DokanFileInfo->Context;
  BOOL opened = FALSE;


  DbgPrint(L"GetFileInfo : %s\n", FileName);

  if (get_file_information(filePath, handle, HandleFileInformation) != 0) {
	  DWORD error = GetLastError();
	  DbgPrint(L"GetFileInfo failed(%d)\n", error);
	  return ToNtStatus(error);
  } else {
	  LARGE_INTEGER l;
	  l.LowPart = HandleFileInformation->nFileSizeLow;
	  l.HighPart = HandleFileInformation->nFileSizeHigh;
	  DbgPrint(L"GetFileInformation %s, filesize = %I64d\n", FileName, l.QuadPart);
	  return STATUS_SUCCESS;
  }

}

static NTSTATUS DOKAN_CALLBACK
CryptFindFiles(LPCWSTR FileName,
                PFillFindData FillFindData, // function pointer
                PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(GetContext(), FileName);
  size_t fileLen = 0;
  HANDLE hFind = NULL;
  WIN32_FIND_DATAW findData;
  DWORD error;
  long long count = 0;

  DbgPrint(L"FindFiles :%s\n", FileName);

  std::vector<WIN32_FIND_DATAW> file_data;

  if (find_files(GetContext(), FileName, filePath, file_data) != 0) {
	  error = GetLastError();
	  DbgPrint(L"\tFindNextFile error. Error is %u\n\n", error);
	  return ToNtStatus(error);
  }

  count = file_data.size();

  int i;

  for (i = 0; i < count; i++) {
	  findData = file_data[i];
	  FillFindData(&findData, DokanFileInfo);
  }

  DbgPrint(L"\tFindFiles return %d entries in %s\n\n", count, FileName);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
CryptDeleteFile(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
  UNREFERENCED_PARAMETER(DokanFileInfo);

  FileNameEnc filePath(GetContext(), FileName);
  // HANDLE	handle = (HANDLE)DokanFileInfo->Context;

  DbgPrint(L"DeleteFile %s\n", FileName);

  if (can_delete_file(filePath)) {

	  DWORD dwAttrib = GetFileAttributes(filePath);

	  if (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		  (dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
		  return STATUS_ACCESS_DENIED;

	  return STATUS_SUCCESS;
  } else {
	  DWORD error = GetLastError();
	  DbgPrint(L"\tDeleteFile error code = %d\n\n", error);
	  return ToNtStatus(error);
  }

  
}

static NTSTATUS DOKAN_CALLBACK
CryptDeleteDirectory(LPCWSTR FileName, PDOKAN_FILE_INFO DokanFileInfo) {
  UNREFERENCED_PARAMETER(DokanFileInfo);

  FileNameEnc filePath(GetContext(), FileName);

  DbgPrint(L"DeleteDirectory %s\n", FileName);

  if (can_delete_directory(filePath)) {
	  return STATUS_SUCCESS;
  } else {
	  DWORD error = GetLastError();
	  DbgPrint(L"\tDeleteDirectory error code = %d\n\n", error);
	  return ToNtStatus(error);
  }

}

static NTSTATUS DOKAN_CALLBACK
CryptMoveFile(LPCWSTR FileName, // existing file name
               LPCWSTR NewFileName, BOOL ReplaceIfExisting,
               PDOKAN_FILE_INFO DokanFileInfo) {

  std::string actual_encrypted;
  FileNameEnc filePath(GetContext(), FileName);
  FileNameEnc newFilePath(GetContext(), NewFileName, &actual_encrypted);
  BOOL status;


  DbgPrint(L"MoveFile %s -> %s\n\n", FileName, newFilePath);

  if (DokanFileInfo->Context) {
    // should close? or rename at closing?
    CloseHandle((HANDLE)DokanFileInfo->Context);
    DokanFileInfo->Context = 0;
  }

  if (ReplaceIfExisting)
    status = MoveFileEx(filePath, newFilePath, MOVEFILE_REPLACE_EXISTING);
  else
    status = MoveFile(filePath, newFilePath);

  if (status == FALSE) {
    DWORD error = GetLastError();
    DbgPrint(L"\tMoveFile failed status = %d, code = %d\n", status, error);
    return ToNtStatus(error);
  } else {
	  // clean up any longname
	  if (!delete_file(GetContext(), filePath)) {
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
    return STATUS_SUCCESS;
  }
}

static NTSTATUS DOKAN_CALLBACK CryptLockFile(LPCWSTR FileName,
                                              LONGLONG ByteOffset,
                                              LONGLONG Length,
                                              PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(GetContext(), FileName);
  HANDLE handle;

  DbgPrint(L"LockFile %s\n", FileName);

  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  CryptFile file;

  if (file.Associate(GetContext(), handle)) {

	  if (!file.LockFile(ByteOffset, Length)) {
		  DWORD error = GetLastError();
		  DbgPrint(L"\tfailed(%d)\n", error);
		  return ToNtStatus(error);
	  }
  } else {
	  return STATUS_ACCESS_DENIED;
  }

  DbgPrint(L"\tsuccess\n\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptSetEndOfFile(
    LPCWSTR FileName, LONGLONG ByteOffset, PDOKAN_FILE_INFO DokanFileInfo) {
	FileNameEnc filePath(GetContext(), FileName);
  HANDLE handle;


  DbgPrint(L"SetEndOfFile %s, %I64d\n", FileName, ByteOffset);

  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  CryptFile file;
  if (file.Associate(GetContext(), handle)) {
	  if (!file.SetEndOfFile(ByteOffset)) {
		  DWORD error = GetLastError();
		  DbgPrint(L"\tSetEndOfFile error code = %d\n\n", error);
		  return ToNtStatus(error);
	  }
  } else {
	  return STATUS_ACCESS_DENIED;
  }

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptSetAllocationSize(
    LPCWSTR FileName, LONGLONG AllocSize, PDOKAN_FILE_INFO DokanFileInfo) {
	FileNameEnc filePath(GetContext(), FileName);
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
	  if (get_file_information(filePath, handle, &finfo) != 0) {
		  throw(-1);
	  }
	  fileSize.LowPart = finfo.nFileSizeLow;
	  fileSize.HighPart = finfo.nFileSizeHigh;
	  if (AllocSize < fileSize.QuadPart) {
		fileSize.QuadPart = AllocSize;
		CryptFile file;
		if (!file.Associate(GetContext(), handle))
			throw(-1);
		if (!file.SetEndOfFile(fileSize.QuadPart)) {
			throw(-1);
		}
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
  UNREFERENCED_PARAMETER(DokanFileInfo);

  FileNameEnc filePath(GetContext(), FileName);


  DbgPrint(L"SetFileAttributes %s, %x\n", FileName, FileAttributes);

  if (!SetFileAttributes(filePath, FileAttributes)) {
    DWORD error = GetLastError();
    DbgPrint(L"\terror code = %d\n\n", error);
    return ToNtStatus(error);
  }

  DbgPrint(L"\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK
CryptSetFileTime(LPCWSTR FileName, CONST FILETIME *CreationTime,
                  CONST FILETIME *LastAccessTime, CONST FILETIME *LastWriteTime,
                  PDOKAN_FILE_INFO DokanFileInfo) {
	FileNameEnc filePath(GetContext(), FileName);
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

static NTSTATUS DOKAN_CALLBACK
CryptUnlockFile(LPCWSTR FileName, LONGLONG ByteOffset, LONGLONG Length,
                 PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(GetContext(), FileName);
  HANDLE handle;
  

  DbgPrint(L"UnlockFile %s\n", FileName);

  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  CryptFile file;

  if (file.Associate(GetContext(), handle)) {

	  if (!file.UnlockFile(ByteOffset, Length)) {
		  DWORD error = GetLastError();
		  DbgPrint(L"\terror code = %d\n\n", error);
		  return ToNtStatus(error);
	  }
  } else {
	  return STATUS_ACCESS_DENIED;
  }

  DbgPrint(L"\tsuccess\n\n");
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptGetFileSecurity(
    LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG BufferLength,
    PULONG LengthNeeded, PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(GetContext(), FileName);


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

  DbgPrint(L"  Opening new handle with READ_CONTROL access\n");
  HANDLE handle = CreateFile(
	  filePath,
	  READ_CONTROL | (((*SecurityInformation & SACL_SECURITY_INFORMATION) ||
		  (*SecurityInformation & BACKUP_SECURITY_INFORMATION))
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
    return ToNtStatus(error);
  }

  if (!GetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor,
                             BufferLength, LengthNeeded)) {
    int error = GetLastError();
    if (error == ERROR_INSUFFICIENT_BUFFER) {
      DbgPrint(L"  GetUserObjectSecurity failed: ERROR_INSUFFICIENT_BUFFER\n");
      CloseHandle(handle);
	  return STATUS_BUFFER_OVERFLOW;
    } else {
      DbgPrint(L"  GetUserObjectSecurity failed: %d\n", error);
      CloseHandle(handle);
      return ToNtStatus(error);
    }
  }
  CloseHandle(handle);

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptSetFileSecurity(
    LPCWSTR FileName, PSECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG SecurityDescriptorLength,
    PDOKAN_FILE_INFO DokanFileInfo) {
  HANDLE handle;
  FileNameEnc filePath(GetContext(), FileName);

  UNREFERENCED_PARAMETER(SecurityDescriptorLength);


  DbgPrint(L"SetFileSecurity %s\n", FileName);

  handle = (HANDLE)DokanFileInfo->Context;
  if (!handle || handle == INVALID_HANDLE_VALUE) {
    DbgPrint(L"\tinvalid handle\n\n");
    return STATUS_INVALID_HANDLE;
  }

  if (!SetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor)) {
    int error = GetLastError();
    DbgPrint(L"  SetUserObjectSecurity failed: %d\n", error);
    return ToNtStatus(error);
  }

  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptGetVolumeInformation(
    LPWSTR VolumeNameBuffer, DWORD VolumeNameSize, LPDWORD VolumeSerialNumber,
    LPDWORD MaximumComponentLength, LPDWORD FileSystemFlags,
    LPWSTR FileSystemNameBuffer, DWORD FileSystemNameSize,
    PDOKAN_FILE_INFO DokanFileInfo) {
  UNREFERENCED_PARAMETER(DokanFileInfo);

  CryptContext *con = GetContext();

  CryptConfig *config = con->GetConfig();

  const WCHAR *p = &config->m_basedir[0];

  while (*p && *p != ':')
	  p++;

  BOOL bGotVI = FALSE;

  DWORD max_component = 255;
  DWORD fs_flags;
  WCHAR fs_name[256];
  fs_name[0] = '\0';

  if (p > &config->m_basedir[0] && *p == ':') {

	  WCHAR rbuf[4];
	  rbuf[0] = *(p - 1);
	  rbuf[1] = ':';
	  rbuf[2] = '\\';
	  rbuf[3] = '\0';

	  bGotVI = GetVolumeInformationW(rbuf, NULL, 0, NULL, &max_component, &fs_flags, fs_name, sizeof(fs_name) / sizeof(fs_name[0]) - 1);
  }
  if (bGotVI) {
	  DbgPrint(L"max compent length of underlying filey system is %d\n", max_component);
  } else {
	  DbgPrint(L"GetVolumeInformation failed, err = %u\n", GetLastError());
  }

  wcscpy_s(VolumeNameBuffer, VolumeNameSize, config->m_VolumeName.size() > 0 ? &config->m_VolumeName[0] : L"");
  *VolumeSerialNumber = con->m_serial;
  *MaximumComponentLength = (config->m_PlaintextNames || config->m_LongNames) ? 255 : 160;
  DWORD defFlags = (FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES |
	  FILE_SUPPORTS_REMOTE_STORAGE | FILE_UNICODE_ON_DISK |
	  FILE_PERSISTENT_ACLS);

  *FileSystemFlags = defFlags & (bGotVI ? fs_flags : 0xffffffff);

  // File system name could be anything up to 10 characters.
  // But Windows check few feature availability based on file system name.
  // For this, it is recommended to set NTFS or FAT here.
  wcscpy_s(FileSystemNameBuffer, FileSystemNameSize, bGotVI ? fs_name : L"NTFS");

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

NTSTATUS DOKAN_CALLBACK
CryptFindStreams(LPCWSTR FileName, PFillFindStreamData FillFindStreamData,
                  PDOKAN_FILE_INFO DokanFileInfo) {
  FileNameEnc filePath(GetContext(), FileName);
  HANDLE hFind;
  WIN32_FIND_STREAM_DATA findData;
  DWORD error;
  int count = 0;


  DbgPrint(L"FindStreams :%s\n", FileName);

  hFind = FindFirstStreamW(filePath, FindStreamInfoStandard, &findData, 0);

  if (hFind == INVALID_HANDLE_VALUE) {
    error = GetLastError();
    DbgPrint(L"\tinvalid file handle. Error is %u\n\n", error);
    return ToNtStatus(error);
  }

  FillFindStreamData(&findData, DokanFileInfo);
  count++;

  while (FindNextStreamW(hFind, &findData) != 0) {
    FillFindStreamData(&findData, DokanFileInfo);
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

static NTSTATUS DOKAN_CALLBACK CryptMounted(PDOKAN_FILE_INFO DokanFileInfo) {
	
  CryptContext *con = GetContext();
  CryptConfig *config = con->GetConfig();

  con->m_mounted = TRUE;

  DbgPrint(L"Mounted\n");
  fwprintf(stdout, L"Mounted on %C:\\\n", config->GetDriveLetter());
  return STATUS_SUCCESS;
}

static NTSTATUS DOKAN_CALLBACK CryptUnmounted(PDOKAN_FILE_INFO DokanFileInfo) {
  CryptContext *con = GetContext();

  con->m_mounted = FALSE;
  DbgPrint(L"Unmounted\n");
  return STATUS_SUCCESS;
}



static NTSTATUS DOKAN_CALLBACK CryptGetDiskFreeSpace(PULONGLONG FreeBytesAvailable,
	PULONGLONG TotalNumberOfBytes,
	PULONGLONG TotalNumberOfFreeBytes,
	PDOKAN_FILE_INFO DokanFileInfo) {

	UNREFERENCED_PARAMETER(DokanFileInfo);

	DbgPrint(L"GetDiskFreeSpace\n");

	CryptContext *con = GetContext();
	CryptConfig *config = con->GetConfig();

	if (config->m_basedir.size() > 0) {
		if (GetDiskFreeSpaceExW(&config->m_basedir[0], (PULARGE_INTEGER)FreeBytesAvailable,
			(PULARGE_INTEGER)TotalNumberOfBytes, (PULARGE_INTEGER)TotalNumberOfFreeBytes)) {
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





static DWORD WINAPI CryptThreadProc(
	_In_ LPVOID lpParameter
	
	) 
{
	CryptThreadData *tdata = (CryptThreadData*)lpParameter;

	NTSTATUS status = DokanMain(tdata->options, tdata->operations);

	return (DWORD)status;
}

static void cleanup_tdata(CryptThreadData *tdata)
{
	CryptContext *con = (CryptContext*)tdata->options->GlobalContext;

	delete con;

	free((void*)tdata->options->MountPoint);

	free(tdata->options);
	free(tdata->operations);

	free(tdata);
}

static bool bAddedSecurityNamePrivilege = false;

int mount_crypt_fs(WCHAR driveletter, const WCHAR *path, const WCHAR *password, std::wstring& mes) 
{

	if (driveletter < 'A' || driveletter > 'Z') {
		mes = L"Invalid drive letter\n";
		return -1;
	}
	// Add security name privilege. Required here to handle GetFileSecurity
	// properly.
	if (!bAddedSecurityNamePrivilege) {
		if (!AddSeSecurityNamePrivilege()) {
			mes = L"Failed to add security name privilege to process.  Try running as administrator.\n";
			return -1;
		}
	}

	bAddedSecurityNamePrivilege = true;

	PDOKAN_OPERATIONS dokanOperations =
		(PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));

	if (!dokanOperations) {
		mes = L"Failed to allocate doakan operations\n";
		return -1;
	}

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
	dokanOperations->GetFileSecurity = CryptGetFileSecurity;
	dokanOperations->SetFileSecurity = CryptSetFileSecurity;
	dokanOperations->GetDiskFreeSpace = CryptGetDiskFreeSpace;
	dokanOperations->GetVolumeInformation = CryptGetVolumeInformation;
	dokanOperations->Unmounted = CryptUnmounted;
	dokanOperations->FindStreams = CryptFindStreams;
	dokanOperations->Mounted = CryptMounted;

	

	CryptContext *con;

	try {

		con = new CryptContext;
	} catch (...) {
		mes = L"Failed to allocate context\n";
		return -1;
	}

	CryptConfig *config = con->GetConfig();

	PDOKAN_OPTIONS dokanOptions = (PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));

	if (!dokanOptions) {
		free(dokanOperations);
		delete con;
		mes = L"Failed to allocate dokanOptions";
		return -1;
	}


	ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
	dokanOptions->Version = DOKAN_VERSION;

	dokanOptions->ThreadCount = 0; // use default

#ifdef _DEBUG
	dokanOptions->Timeout = 900000;
	dokanOptions->ThreadCount = 1;
	g_DebugMode = 1;
#else
	dokanOptions->ThreadCount = 1;  // even the mirror sample has problems launching some executables with default number of threads
#endif
	

	config->m_basedir = path;

	std::wstring holder = config->m_basedir;

	config->m_basedir = L"\\\\?\\";  // this prefix enables up to 32K long file paths on NTFS

	config->m_basedir += holder;

	config->m_driveletter = (char)driveletter;

	WCHAR *mountpoint = (WCHAR *)malloc(4 * sizeof(WCHAR));

	if (!mountpoint) {
		free(dokanOptions);
		free(dokanOperations);
		delete con;
		mes = L"Failed to allocated mountpoint\n";
		return -1;
	}

	mountpoint[0] = driveletter;
	mountpoint[1] = L':';
	mountpoint[2] = L'\\';
	mountpoint[3] = 0;

	dokanOptions->MountPoint = mountpoint;


	if (!config->read()) {
		mes = L"unable to load config\n";
		free(dokanOperations);
		free(dokanOptions);
		delete con;
		return EXIT_FAILURE;
	}

	std::wstring config_error_mes;

	if (!config->check_config(config_error_mes)) {
		mes = &config_error_mes[0];
		free(dokanOperations);
		free(dokanOptions);
		delete con;
		return EXIT_FAILURE;
	}

	if (!config->decrypt_key(password)) {
		mes = L"password incorrect\n";
		free(dokanOperations);
		free(dokanOptions);
		delete con;
		return EXIT_FAILURE;
	}

	if (config->m_EMENames)
		con->InitEme(config->m_key);

	CryptThreadData *tdata = (CryptThreadData*)malloc(sizeof(CryptThreadData));

	if (!tdata) {
		free(dokanOperations);
		free(dokanOptions);
		delete con;
		return EXIT_FAILURE;
	}

	BYTE diriv[DIR_IV_LEN];

	if (config->DirIV() && get_dir_iv(con, &config->m_basedir[0], diriv)) {

		con->m_serial = *(DWORD*)diriv;

	}

	if (!con->m_serial) {

		std::wstring str = L"XjyG7KDokdqpxtjUh6oCVJ92FmPFJ1Fg"; // salt

		str += config->m_basedir;

		BYTE sum[32];

		std::string utf8;

		if (unicode_to_utf8(&str[0], utf8)) {

			sha256(utf8, sum);

			con->m_serial = *(DWORD*)sum;
		}
	}

	dokanOptions->GlobalContext = (ULONG64)con;
	dokanOptions->Options |= DOKAN_OPTION_ALT_STREAM;

	tdata->operations = dokanOperations;
	tdata->options = dokanOptions;

	HANDLE hThread = CreateThread(NULL, 0, CryptThreadProc, tdata, 0, NULL);

	if (!hThread) {
		free(dokanOperations);
		free(dokanOptions);
		delete con;
		free(tdata);
		return EXIT_FAILURE;
	}

	g_DriveThreadHandles[driveletter - 'A'] = hThread;
	g_ThreadDatas[driveletter - 'A'] = tdata;

	DWORD waited = 0;
	while (!con->m_mounted && waited < MOUNT_TIMEOUT) {
		const DWORD wait = 100;
		WaitForSingleObject(hThread, wait);
		waited += wait;
	}

	if (!con->m_mounted) {
		mes = L"mount operation timed out\n";
		return EXIT_FAILURE;
	}

	return STATUS_SUCCESS;
}

BOOL unmount_crypt_fs(WCHAR driveletter, bool wait)
{
	if (driveletter < 'A' || driveletter > 'Z')
		return false;

	BOOL result = DokanUnmount(driveletter);
	if (!result)
		return FALSE;

	if (!g_DriveThreadHandles[driveletter - 'A'])
		return FALSE;

	if (wait) {
		DWORD wait_timeout = UNMOUNT_TIMEOUT;
		DWORD status = WaitForSingleObject(g_DriveThreadHandles[driveletter - 'A'], wait_timeout);

		if (status == WAIT_OBJECT_0) {
			result = TRUE;
			CloseHandle(g_DriveThreadHandles[driveletter - 'A']);
			g_DriveThreadHandles[driveletter - 'A'] = NULL;
			if (g_ThreadDatas[driveletter - 'A']) {
				cleanup_tdata(g_ThreadDatas[driveletter - 'A']);
				g_ThreadDatas[driveletter - 'A'] = NULL;
			}
		} else {
			result = FALSE;
		}
	}

	return result;

}



BOOL wait_for_all_unmounted()
{
	HANDLE handles[26];

	DWORD timeout = UNMOUNT_TIMEOUT;

	int count = 0;
	for (int i = 0; i < 26; i++) {
		if (g_DriveThreadHandles[i])
			handles[count++] = g_DriveThreadHandles[i];
	}
	if (!count)
		return TRUE;

	DWORD status = WaitForMultipleObjects(count, handles, TRUE, timeout);

	DWORD first = WAIT_OBJECT_0;
	DWORD last = WAIT_OBJECT_0 + (count - 1);

	if (status >= first && status <= last) {
		for (int i = 0; i < 26; i++) {
			if (g_DriveThreadHandles[i]) {
				CloseHandle(g_DriveThreadHandles[i]);
				g_DriveThreadHandles[i] = NULL;

				if (g_ThreadDatas[i]) {
					cleanup_tdata(g_ThreadDatas[i]);
					g_ThreadDatas[i] = NULL;
				}
			}
		}
		return TRUE;
	} else {
		return FALSE;
	}
}

BOOL write_volume_name_if_changed(WCHAR dl)
{
	CryptThreadData *tdata = g_ThreadDatas[dl - 'A'];

	if (!tdata)
		return FALSE;

	if (!tdata->options)
		return FALSE;

	CryptContext *con = (CryptContext*)tdata->options->GlobalContext;

	if (!con)
		return false;

	std::wstring fs_root;

	fs_root.push_back(dl);
	fs_root.push_back(':');
	fs_root.push_back('\\');
	

	WCHAR volbuf[256];

	if (!GetVolumeInformationW(&fs_root[0], volbuf, sizeof(volbuf) / sizeof(volbuf[0]) - 1, NULL, NULL, NULL, NULL, 0)) {
		DWORD error = GetLastError();
		DbgPrint(L"update volume name error = %u\n", error);
		return FALSE;
	}

	if (con->GetConfig()->m_VolumeName != volbuf) {
		con->GetConfig()->m_VolumeName = volbuf;
		return con->GetConfig()->write_volume_name();
	}

	return TRUE;
}
