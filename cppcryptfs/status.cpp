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
This file is based on code from the Dokan (actualy Dokany) sample program mirror.c.
Below is the copyright notice from that file.
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


