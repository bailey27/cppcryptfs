/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2017 Bailey Brown (github.com/bailey27/cppcryptfs)

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

#include "cryptconfig.h"
#include <windows.h>
#include <vector>
#include "eme.h"
#include "randombytes.h"
#include "dirivcache.h"
#include "longfilenamecache.h"
#include "siv.h"
#include "CaseCache.h"

class CryptContext {
private:

	CryptConfig *m_config;
public:
	RandomBytes *m_prand_bytes;
	DirIvCache m_dir_iv_cache;
	LongFilenameCache m_lfn_cache;
	CaseCache m_case_cache;
	EmeCryptContext m_eme;
	SivContext m_siv;
	int m_bufferblocks;
private:
	bool m_caseinsensitive;
	CRITICAL_SECTION m_case_insensitive_createfile_crit;
public:

	bool IsCaseInsensitive() { return m_caseinsensitive && !m_config->m_reverse && !m_config->m_PlaintextNames; };
	void SetCaseSensitive(bool bCaseSensitive) { m_caseinsensitive = bCaseSensitive; };
	void LockCaseInsensitiveCreateFile() { if (IsCaseInsensitive()) EnterCriticalSection(&m_case_insensitive_createfile_crit); };
	void UnlockCaseInsensitiveCreateFile() { if (IsCaseInsensitive()) LeaveCriticalSection(&m_case_insensitive_createfile_crit);  };

	HANDLE m_mountEvent;

	void InitEme(const BYTE *key);

	CryptContext();

	CryptConfig *GetConfig() const { return m_config; };

	virtual ~CryptContext();
};