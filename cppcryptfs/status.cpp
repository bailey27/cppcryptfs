#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <malloc.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>


#include "status.h"

static NTSTATUS ToNtStatus(DWORD dwError) 
{

	switch (dwError) {
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
	case ERROR_OUTOFMEMORY:
		return STATUS_MEMORY_NOT_ALLOCATED;
	case ERROR_DIR_NOT_EMPTY:
		return STATUS_DIRECTORY_NOT_EMPTY;
	default:
		
		return STATUS_ACCESS_DENIED;
	}
}

LONG GetErrorStatus(DWORD default_error)
{
	DWORD err = GetLastError();

	if (err != 0) {
		return ToNtStatus(err);
	} else if (default_error != 0) {
		return ToNtStatus(default_error);
	} else {
		return STATUS_ACCESS_DENIED;
	}
}


