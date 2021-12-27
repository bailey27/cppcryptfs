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
#include "crypt/crypt.h"
#include "util/fileutil.h"
#include "filename/cryptfilename.h"
#include "cryptcontext.h"

static RandomBytes random_bytes;



bool CryptContext::InitEme(const BYTE *key, bool hkdf)
{

	return m_eme.init(key, hkdf, m_config);

}


CryptContext::CryptContext()
{
	m_mountEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

	m_caseinsensitive = false;

	m_recycle_bin = false;
	m_read_only = false;
	m_delete_spurrious_files = false;

	m_cache_ttl = 1;

	m_bufferblocks = 1;

	m_threads = 0;

	if (!m_mountEvent)
		throw((int)GetLastError());

	m_config = new CryptConfig;

	m_prand_bytes = &random_bytes;

	m_case_cache.m_con = this;

	m_encryptKeysInMemory = false;
	m_cacheKeysInMemory = false;

	m_denyOtherSessions = false;
	m_denyServices = false;

	m_flushafterwrite = false;
}

static void get_deletable_files(CryptContext *con, vector<wstring>& files)
{

	files.clear();

	assert(con);

	if (!con)
		return;

	if (con->GetConfig()->DirIV()) {
		files.push_back(DIR_IV_NAME);
	}

	if (con->m_delete_spurrious_files && !con->GetConfig()->m_PlaintextNames 
			&& !con->GetConfig()->m_reverse) {
		files.push_back(L"desktop.ini");
	}
}

bool CryptContext::FinalInitBeforeMounting(bool use_key_cache)
{
	get_deletable_files(this, m_deletable_files);

	auto get_snmax = [&](int lnmax)
	{
		int snmax = 0;
		auto set_snmax = [&](int lnmax_val, int snmax_val) {
			if (snmax < 1 && lnmax <= lnmax_val) {
				snmax = snmax_val;
			}
		};
		set_snmax(63, 31);
		set_snmax(85, 47);
		set_snmax(106, 63);
		set_snmax(127, 79);
		set_snmax(149, 95);
		set_snmax(170, 111);
		set_snmax(191, 127);
		set_snmax(213, 143);
		set_snmax(234, 159);
		set_snmax(MAX_FILENAME_LEN, SHORT_NAME_MAX_DEFAULT);

		if (snmax < 1) {
			return  -1;
		}
		return snmax;
	};

	if (m_config->m_LongNames) {
		
		auto short_name_max = get_snmax(m_config->m_LongNameMax);
		if (short_name_max < 1) {
			return false;
		}
		m_shortNameMax = short_name_max;
	};

	auto result =  m_config->m_keybuf_manager.Finalize(use_key_cache);

#if 0 // test code below
#ifdef _DEBUG 
	if (m_config->m_LongNames && !m_encryptKeysInMemory) {
		unsigned char diriv[DIR_IV_LEN];
		get_sys_random_bytes(diriv, static_cast<int>(std::size(diriv)));
		wstring storage;
		string actual_encrypted;		
		wstring filename;
		auto save_long_name_max = m_config->m_LongNameMax;
		for (int i = MIN_LONGNAMEMAX; i <= MAX_FILENAME_LEN; ++i) {
			m_config->m_LongNameMax = i;
			for (int j = 1; j <= MAX_FILENAME_LEN; ++j) {
				storage.clear();
				actual_encrypted.clear();
				filename.resize(j, L'_');
				encrypt_filename(this, diriv, filename.c_str(), storage, &actual_encrypted);
				if (is_long_name(storage.c_str())) {
					auto snmax = get_snmax(i);
					assert(snmax == j - 1);
					break;
				}
			}
		}
		m_config->m_LongNameMax = save_long_name_max;
	}
#endif // ifdef _DEBUG
#endif // if 0

	return result;
}


CryptContext::~CryptContext()
{
	if (m_mountEvent)
		CloseHandle(m_mountEvent);

	if (m_config)
		delete m_config;
}

void CryptContext::GetFsInfo(FsInfo & info)
{
	info.deleteSpurriousFiles = this->m_delete_spurrious_files;
	info.flushAfterWrite = this->m_flushafterwrite;
	info.denyServices = this->m_denyServices;
	info.denyOtherSessions = this->m_denyOtherSessions;
	info.encryptKeysInMemory = this->m_encryptKeysInMemory;
	info.cacheKeysInMemory = this->m_cacheKeysInMemory;
	info.cacheTTL = m_cache_ttl;
	info.caseInsensitive = IsCaseInsensitive();
	info.configPath = GetConfig()->m_configPath;
	info.dataEncryption = GetConfig()->m_AESSIV ? L"AES256-SIV" : L"AES256-GCM";
	info.fileNameEncryption = GetConfig()->m_PlaintextNames ? L"none" : L"AES256-EME";
	info.fsThreads = m_threads ? m_threads : CRYPT_DOKANY_DEFAULT_NUM_THREADS;
	info.ioBufferSize = m_bufferblocks * 4;
	info.longFileNames = GetConfig()->m_LongNames;
	info.mountManager = m_recycle_bin;
	info.readOnly = m_read_only;
	info.reverse = GetConfig()->m_reverse;
	info.path = GetConfig()->m_basedir;

	// get rid of leading \\?\ for display
	if (!wcsncmp(info.path.c_str(), L"\\\\?\\", wcslen(L"\\\\?\\"))) {
		info.path = info.path.c_str() + wcslen(L"\\\\?\\");
	}
	if (!wcsncmp(info.configPath.c_str(), L"\\\\?\\", wcslen(L"\\\\?\\"))) {
		info.configPath = info.configPath.c_str() + wcslen(L"\\\\?\\");
	}

	long long hits, lookups;

	if (info.reverse && info.longFileNames) {
		hits = m_lfn_cache.hits();
		lookups = m_lfn_cache.lookups();
		info.lfnCacheHitRatio = lookups ? (float)hits / (float)lookups : 0.0f;
	} else {
		info.lfnCacheHitRatio = -1.0;
	}
	
	if (info.caseInsensitive) {
		hits = m_case_cache.hits();
		lookups = m_case_cache.lookups();
		info.caseCacheHitRatio = lookups ? (float)hits / (float)lookups : 0.0f;
	} else {
		info.caseCacheHitRatio = -1.0f;
	}

	hits = m_dir_iv_cache.hits();
	lookups = m_dir_iv_cache.lookups();
	info.dirIvCacheHitRatio = lookups ? (float)hits / (float)lookups : 0.0f;

	info.longNameMax = m_config->m_LongNameMax;
}
