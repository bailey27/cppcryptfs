#pragma once
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

#include <unordered_map>

typedef int(WINAPI *PCryptStoreStreamName)(
	PWIN32_FIND_STREAM_DATA, LPCWSTR encrypted_name,
	unordered_map<wstring, wstring> *pmap);

NTSTATUS DOKAN_CALLBACK CryptFindStreamsInternal(
	LPCWSTR FileName, PFillFindStreamData FillFindStreamData,
	PDOKAN_FILE_INFO DokanFileInfo, PCryptStoreStreamName StoreStreamName,
	unordered_map<wstring, wstring> *pmap);

int WINAPI
CryptCaseStreamsCallback(PWIN32_FIND_STREAM_DATA pfdata, LPCWSTR encrypted_name,
	unordered_map<wstring, wstring> *pmap);

#define GetContext()                                                           \
  ((CryptContext *)DokanFileInfo->DokanOptions->GlobalContext)

#define UNMOUNT_TIMEOUT 30000
#define MOUNT_TIMEOUT 30000
#define FAST_MOUNTING_WAIT 20

#define ENABLE_FILE_NAMED_STREAMS_FLAG 1

