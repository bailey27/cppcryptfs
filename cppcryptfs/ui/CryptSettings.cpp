/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2021 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include "stdafx.h"
#include "cppcryptfs.h"
#include "cryptdefaults.h"
#include "CryptSettings.h"
#include "dokan/cryptdokan.h"
#include "util/util.h"

void GetSettings(CryptMountOptions &opts)
{

	opts.numthreads = theApp.GetProfileInt(L"Settings", L"Threads", PER_FILESYSTEM_THREADS_DEFAULT);

	opts.numbufferblocks = theApp.GetProfileInt(L"Settings", L"BufferBlocks", BUFFERBLOCKS_DEFAULT);

	if (opts.numbufferblocks < 1 || opts.numbufferblocks * 4 > MAX_IO_BUFFER_KB || !is_power_of_two(opts.numbufferblocks))
		opts.numbufferblocks = BUFFERBLOCKS_DEFAULT;

	opts.cachettl = theApp.GetProfileInt(L"Settings", L"CacheTTL", CACHETTL_DEFAULT);

	opts.caseinsensitive = theApp.GetProfileInt(L"Settings", L"CaseInsensitive", CASEINSENSITIVE_DEFAULT) != 0;

	opts.mountmanager = theApp.GetProfileInt(L"Settings", L"MountManager", MOUNTMANAGER_DEFAULT) != 0;

	opts.mountmanagerwarn = theApp.GetProfileInt(L"Settings", L"MountManagerWarn", MOUNTMANAGERWARN_DEFAULT) != 0;

	opts.deletespurriousfiles = theApp.GetProfileInt(L"Settings", L"DeleteSpurriousFiles", DELETE_SPURRIOUS_FILES_DEFAULT) != 0;

	opts.encryptkeysinmemory = theApp.GetProfileInt(L"Settings", L"EncryptKeysInMemory", ENCRYPT_KEYS_IN_MEMORY_DEFAULT) != 0;

	opts.cachekeysinmemory = theApp.GetProfileInt(L"Settings", L"CacheKeysInMemory", CACHE_KEYS_IN_MEMORY_DEFAULT) != 0;

	opts.fastmounting = theApp.GetProfileInt(L"Settings", L"FastMounting", FAST_MOUNTING_DEFAULT) != 0;

	opts.denyothersessions = theApp.GetProfileInt(L"Settings", L"DenyOtherSessions", DENY_OTHER_SESSIONS_DEFAULT) != 0;

	opts.denyservices = theApp.GetProfileInt(L"Settings", L"DenyServices", DENY_SERVICES_DEFAULT) != 0;

	opts.flushafterwrite.exFAT = theApp.GetProfileInt(L"Settings", L"FlushAfterWriteExFAT", FLUSH_AFTER_WRITE_EXFAT_DEFAULT) != 0;
	opts.flushafterwrite.fat32 = theApp.GetProfileInt(L"Settings", L"FlushAfterWriteFAT32", FLUSH_AFTER_WRITE_FAT32_DEFAULT) != 0;
	opts.flushafterwrite.ntfs = theApp.GetProfileInt(L"Settings", L"FlushAfterWriteNTFS", FLUSH_AFTER_WRITE_NTFS_DEFAULT) != 0;
	opts.flushafterwrite.not_ntfs = theApp.GetProfileInt(L"Settings", L"FlushAfterWriteNotNTFS", FLUSH_AFTER_WRITE_NOT_NTFS_DEFAULT) != 0;
	opts.flushafterwrite.sparse_files_not_supported = theApp.GetProfileInt(L"Settings", L"FlushAfterWriteNoSparseFiles", FLUSH_AFTER_WRITE_NO_SPARSE_FILES_DEFAULT) != 0;
}