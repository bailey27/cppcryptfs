/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2024 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include <assert.h>
#include <afx.h>




CryptSettings& CryptSettings::getInstance()
{
	static CryptSettings instance;

	return instance;
}


CryptSettings::CryptSettings() 
{

#define INIT_SETTINGS_REGISTRY_MAP_ENTRY(key, val) \
	m_settings_registry_map[key] = CryptSettingConsts(L#val, key##_DEFAULT, key##_RECOMMENDED)

	INIT_SETTINGS_REGISTRY_MAP_ENTRY(MULTITHREADED, MultiThreaded);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(BUFFERBLOCKS, BufferBlocks);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(CACHETTL, CacheTTL);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(CASEINSENSITIVE, CaseInsensitive);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(MOUNTMANAGER, MountManager);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(MOUNTMANAGERWARN, MountManagerWarn);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(ENABLE_SAVING_PASSWORDS, EnableSavingPasswords);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(NEVER_SAVE_HISTORY, NeverSaveHistory);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(DELETE_SPURRIOUS_FILES, DeleteSpurriousFiles);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(OPEN_ON_MOUNTING, OpenOnMounting);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(ENCRYPT_KEYS_IN_MEMORY, EncryptKeysInMemory);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(CACHE_KEYS_IN_MEMORY, CacheKeysInMemory);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(FAST_MOUNTING, FastMounting);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(WARN_IF_IN_USE_ON_DISMOUNT, WarnIfInUseOnDismounting);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(DENY_OTHER_SESSIONS, DenyOtherSessions);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(DENY_SERVICES, DenyServices);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(FLUSH_AFTER_WRITE_EXFAT, FlushAfterWriteExFAT);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(FLUSH_AFTER_WRITE_FAT32, FlushAfterWriteFAT32);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(FLUSH_AFTER_WRITE_NTFS, FlushAfterWriteNTFS);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(FLUSH_AFTER_WRITE_NOT_NTFS, FlushAfterWriteNotNTFS);
	INIT_SETTINGS_REGISTRY_MAP_ENTRY(FLUSH_AFTER_WRITE_NO_SPARSE_FILES, FlushAfterWriteNoSparseFiles);
}


bool CryptSettings::GetSettingDefault(CryptSettingsRegistryValuesKeys key, int& default)
{
	auto it = m_settings_registry_map.find(key);
	assert(it != m_settings_registry_map.end());
	if (it == m_settings_registry_map.end())
		return false;

	default = it->second.default;

	return true;
}

bool CryptSettings::GetSettingDefault(CryptSettingsRegistryValuesKeys key, bool& default)
{
	int val;
	if (!GetSettingRecommended(key, val))
		return false;

	default = val != 0;

	return true;
}

bool CryptSettings::GetSettingRecommended(CryptSettingsRegistryValuesKeys key, int& recommended)
{
	auto it = m_settings_registry_map.find(key);
	assert(it != m_settings_registry_map.end());
	if (it == m_settings_registry_map.end())
		return false;

	recommended = it->second.recommended;

	return true;
}

bool CryptSettings::GetSettingRecommended(CryptSettingsRegistryValuesKeys key, bool& recommended)
{
	int val;
	if (!GetSettingRecommended(key, val))
		return false;

	recommended = val != 0;

	return true;
}


bool CryptSettings::GetSettingCurrent(CryptSettingsRegistryValuesKeys key, int& current)
{
	auto it = m_settings_registry_map.find(key);
	assert(it != m_settings_registry_map.end());
	if (it == m_settings_registry_map.end())
		return false;

	auto val = theApp.GetProfileInt(CryptSettingsRegValName, it->second.regval_name.c_str(), it->second.default);

	current = val;

	return true;
}

bool CryptSettings::GetSettingCurrent(CryptSettingsRegistryValuesKeys key, bool& current)
{
	int val = 0;	
	if (!GetSettingCurrent(key, val))
		return false;

	current = val != 0;

	return true;
}


void CryptSettings::GetSettings(CryptMountOptions &opts)
{
		
	VERIFY(GetSettingCurrent(MULTITHREADED, opts.multithreaded));

	VERIFY(GetSettingCurrent(BUFFERBLOCKS, opts.numbufferblocks));
	
	if (opts.numbufferblocks < 1 || opts.numbufferblocks * 4 > MAX_IO_BUFFER_KB || !is_power_of_two(opts.numbufferblocks))
		opts.numbufferblocks = BUFFERBLOCKS_DEFAULT;

	VERIFY(GetSettingCurrent(CACHETTL, opts.cachettl));
	
	VERIFY(GetSettingCurrent(CASEINSENSITIVE, opts.caseinsensitive));
	
	VERIFY(GetSettingCurrent(MOUNTMANAGER, opts.mountmanager));
	
	VERIFY(GetSettingCurrent(MOUNTMANAGERWARN, opts.mountmanagerwarn));
	
	VERIFY(GetSettingCurrent(DELETE_SPURRIOUS_FILES, opts.deletespurriousfiles));
	
	VERIFY(GetSettingCurrent(ENCRYPT_KEYS_IN_MEMORY, opts.encryptkeysinmemory));
	
	VERIFY(GetSettingCurrent(CACHE_KEYS_IN_MEMORY, opts.cachekeysinmemory));
	
	VERIFY(GetSettingCurrent(FAST_MOUNTING, opts.fastmounting));
	
	VERIFY(GetSettingCurrent(DENY_OTHER_SESSIONS, opts.denyothersessions));

	VERIFY(GetSettingCurrent(DENY_SERVICES, opts.denyservices));

	VERIFY(GetSettingCurrent(FLUSH_AFTER_WRITE_EXFAT, opts.flushafterwrite.exFAT));
	
	VERIFY(GetSettingCurrent(FLUSH_AFTER_WRITE_FAT32, opts.flushafterwrite.fat32));
	
	VERIFY(GetSettingCurrent(FLUSH_AFTER_WRITE_NTFS, opts.flushafterwrite.ntfs));	

	VERIFY(GetSettingCurrent(FLUSH_AFTER_WRITE_NOT_NTFS, opts.flushafterwrite.not_ntfs));
	
	VERIFY(GetSettingCurrent(FLUSH_AFTER_WRITE_NO_SPARSE_FILES, opts.flushafterwrite.sparse_files_not_supported));	
}


bool CryptSettings::SaveSetting(CryptSettingsRegistryValuesKeys key, int val)
{
	auto it = m_settings_registry_map.find(key);

	if (it == m_settings_registry_map.end())
		return false;

	return theApp.WriteProfileInt(CryptSettingsRegValName, it->second.regval_name.c_str(), val) != FALSE;
}
