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

// SettingsPropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "SettingsPropertyPage.h"
#include "afxdialogex.h"
#include "util/util.h"
#include "context/cryptcontext.h"
#include "ui/cryptdefaults.h"
#include "ui/savedpasswords.h"
#include "ui/uiutil.h"

// CSettingsPropertyPage dialog

IMPLEMENT_DYNAMIC(CSettingsPropertyPage, CCryptPropertyPage)

CSettingsPropertyPage::CSettingsPropertyPage()
	: CCryptPropertyPage(IDD_SETTINGS)
{
	m_bCaseInsensitive = false;
	m_bMountManager = false;
	m_bEnableSavingPasswords = false;
	m_bNeverSaveHistory = false;
	m_bWarnIfInUseOnDismounting = false;
	m_bDenyOtherSessions = false;
	m_bDenyServices = false;
}

CSettingsPropertyPage::~CSettingsPropertyPage()
{
}

void CSettingsPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CSettingsPropertyPage, CPropertyPage)
	ON_CBN_SELCHANGE(IDC_THREADS, &CSettingsPropertyPage::OnSelchangeThreads)
	ON_CBN_SELCHANGE(IDC_BUFFERSIZE, &CSettingsPropertyPage::OnSelchangeBuffersize)
	ON_BN_CLICKED(IDC_CASEINSENSITIVE, &CSettingsPropertyPage::OnBnClickedCaseinsensitive)
	ON_CBN_SELCHANGE(IDC_CACHETTL, &CSettingsPropertyPage::OnCbnSelchangeCachettl)
	ON_BN_CLICKED(IDC_DEFAULTS, &CSettingsPropertyPage::OnBnClickedDefaults)
	ON_BN_CLICKED(IDC_RECOMMENDED, &CSettingsPropertyPage::OnBnClickedRecommended)
	ON_BN_CLICKED(IDC_MOUNTMANAGER, &CSettingsPropertyPage::OnClickedMountmanager)
	ON_BN_CLICKED(IDC_RESETWARNINGS, &CSettingsPropertyPage::OnClickedResetwarnings)
	ON_BN_CLICKED(IDC_ENABLE_SAVING_PASSWORDS, &CSettingsPropertyPage::OnClickedEnableSavingPasswords)
	ON_BN_CLICKED(IDC_NEVER_SAVE_HISTORY, &CSettingsPropertyPage::OnClickedNeverSaveHistory)
	ON_BN_CLICKED(IDC_DELETE_SPURRIOUS_FILES, &CSettingsPropertyPage::OnClickedDeleteSpurriousFiles)
	ON_BN_CLICKED(IDC_OPEN_ON_MOUNTING, &CSettingsPropertyPage::OnClickedOpenOnMounting)
	ON_BN_CLICKED(IDC_ENCRYPT_KEYS_IN_MEMORY, &CSettingsPropertyPage::OnClickedEncryptKeysInMemory)
	ON_BN_CLICKED(IDC_CACHE_KEYS_IN_MEMORY, &CSettingsPropertyPage::OnClickedCacheKeysInMemory)
	ON_BN_CLICKED(IDC_FAST_MOUNTING, &CSettingsPropertyPage::OnBnClickedFastMounting)
	ON_BN_CLICKED(IDC_WARN_IF_IN_USE_ON_DISMOUNTING, &CSettingsPropertyPage::OnClickedWarnIfInUseOnDismounting)
	ON_BN_CLICKED(IDC_DENY_OTHER_SESSIONS, &CSettingsPropertyPage::OnClickedDenyOtherSessions)
	ON_BN_CLICKED(IDC_DENY_SERVICES, &CSettingsPropertyPage::OnClickedDenyServices)
END_MESSAGE_MAP()


// CSettingsPropertyPage message handlers

typedef int buffer_size_t;

static buffer_size_t buffer_sizes[] = { 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, MAX_IO_BUFFER_KB };

static int ttls[] = { 0, 1, 2, 5, 10, 15, 30, 45, 60, 90, 120, 300, 600, 900, 1800, 3600};

static const WCHAR* ttl_strings[] = { L"infinite", L"1 second", L"2 seconds", L"5 seconds", 
									  L"10 seconds", L"15 seconds", L"30 seconds", L"45 seconds", 
									  L"60 seconds", L"90 seconds", L"2 minutes", L"5 minutes", 
									  L"10 minutes", L"15 minutes", L"30 minutes", L"1 hour" };

BOOL CSettingsPropertyPage::OnInitDialog()
{
	CCryptPropertyPage::OnInitDialog();

	auto threads_set_from_registry = [](CComboBox* pBox, int val) {
		int i;		

		if (!pBox)
			return;

		pBox->ResetContent();

		WCHAR buf[80];

#define DOKAN_MAX_THREAD 63 // this is defined in a header file that Dokany doesn't distribute

		for (i = 0; i <= DOKAN_MAX_THREAD; i++) {

			if (i == 0) {
				CString def = L"Dokany default (";
				WCHAR buf[32];
				*buf = '\0';
				_snwprintf_s(buf, _TRUNCATE, L"%d", CRYPT_DOKANY_DEFAULT_NUM_THREADS);
				def += buf;
				def += L")";
				pBox->AddString(def);
			} else {
				swprintf_s(buf, L"%d", i);
				pBox->AddString(buf);
			}
		}
		pBox->SetCurSel(val);
	};

	auto threads_get_from_control = [](CComboBox* pBox, int& val) { val = pBox->GetCurSel(); return true;  };

	m_controls.emplace(IDC_THREADS, make_unique<CryptComboBoxSetting>(*this, IDC_THREADS, PER_FILESYSTEM_THREADS, threads_set_from_registry, threads_get_from_control));

	auto bufferblocks_set_from_registry = [](CComboBox* pBox, int val) {

		int bufferblocks = val;

		buffer_size_t kb = bufferblocks * 4;

		auto p = bsearch(&kb, buffer_sizes, _countof(buffer_sizes), sizeof(buffer_size_t), [](const void* pkey, const void* pval) -> int {
			return *reinterpret_cast<const buffer_size_t*>(pkey) - *reinterpret_cast<const buffer_size_t*>(pval);
			});

		if (!p)
			bufferblocks = BUFFERBLOCKS_DEFAULT;

		WCHAR buf[80];
		if (!pBox)
			return;

		pBox->ResetContent();

		for (int i = 0; i < sizeof(buffer_sizes) / sizeof(buffer_sizes[0]); i++) {
			swprintf_s(buf, L"%d", buffer_sizes[i]);
			pBox->AddString(buf);
		}

		int bits = 0;

		int n = bufferblocks;
		while (n) {
			bits++;
			n >>= 1;
		}

		pBox->SetCurSel(bits - 1);
	}; 

	auto bufferblocks_get_from_control = [](CComboBox* pBox, int &val) { val = 1 << pBox->GetCurSel(); return true; };

	m_controls.emplace(IDC_BUFFERSIZE, make_unique<CryptComboBoxSetting>(*this, IDC_BUFFERSIZE, BUFFERBLOCKS, bufferblocks_set_from_registry, bufferblocks_get_from_control));


	auto cachettl_set_from_registry = [](CComboBox* pBox, int val) {
		pBox->ResetContent();

		static_assert(sizeof(ttls) / sizeof(ttls[0]) == sizeof(ttl_strings) / sizeof(ttl_strings[0]),
			"mismatch in sizes of ttls/ttl_strings");

		int selitem = 0;

		for (int i = 0; i < sizeof(ttls) / sizeof(ttls[0]); i++) {
			pBox->AddString(ttl_strings[i]);
			if (val == ttls[i]) {
				selitem = i;
			}
		}

		pBox->SetCurSel(selitem);
	};

	auto cachettl_get_from_control = [](CComboBox* pBox, int& val) {
		int selIndex = pBox->GetCurSel();

		int cachettl = ttls[selIndex];

		val = cachettl;

		return true;
	};

	m_controls.emplace(IDC_CACHETTL, make_unique<CryptComboBoxSetting>(*this, IDC_CACHETTL, CACHETTL, cachettl_set_from_registry, cachettl_get_from_control));

#define DO_CHECKBOX(tok) \
	m_controls.emplace(IDC_##tok, make_unique<CryptCheckBoxSetting>(*this, IDC_##tok, tok));
	

	DO_CHECKBOX(CASEINSENSITIVE);

	DO_CHECKBOX(MOUNTMANAGER);

	DO_CHECKBOX(ENABLE_SAVING_PASSWORDS);

	DO_CHECKBOX(NEVER_SAVE_HISTORY);

	DO_CHECKBOX(DELETE_SPURRIOUS_FILES);

	DO_CHECKBOX(OPEN_ON_MOUNTING);

	DO_CHECKBOX(ENCRYPT_KEYS_IN_MEMORY);

	DO_CHECKBOX(CACHE_KEYS_IN_MEMORY);

	DO_CHECKBOX(FAST_MOUNTING);

	DO_CHECKBOX(WARN_IF_IN_USE_ON_DISMOUNT);

	DO_CHECKBOX(DENY_OTHER_SESSIONS);

	DO_CHECKBOX(DENY_SERVICES);

	SetControls(CryptSetting::SetType::Current);  
	
	// return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE

	return TRUE;
}

void CSettingsPropertyPage::SetControls(CryptSetting::SetType set_type)
{
	for (auto& c : m_controls) {
		c.second->Set(set_type);
	}	
}

void CSettingsPropertyPage::SetControlChanged(int id)
{
	auto it = m_controls.find(id);

	assert(it != m_controls.end());

	if (it == m_controls.end())
		return;

	it->second->Set(CryptSetting::Changed);
}



void CSettingsPropertyPage::OnSelchangeThreads()
{
	SetControlChanged(IDC_THREADS);
}


void CSettingsPropertyPage::OnSelchangeBuffersize()
{
	SetControlChanged(IDC_BUFFERSIZE);
}

void CSettingsPropertyPage::OnCbnSelchangeCachettl()
{
	SetControlChanged(IDC_CACHETTL);
}


void CSettingsPropertyPage::OnBnClickedCaseinsensitive()
{
	SetControlChanged(IDC_CASEINSENSITIVE);
}



void CSettingsPropertyPage::OnBnClickedDefaults()
{
	SetControls(CryptSetting::SetType::Default);
}


void CSettingsPropertyPage::OnBnClickedRecommended()
{
	SetControls(CryptSetting::SetType::Recommended);
}



void CSettingsPropertyPage::OnClickedMountmanager()
{
	SetControlChanged(IDC_MOUNTMANAGER);	
}


void CSettingsPropertyPage::OnClickedResetwarnings()
{
	CryptSettings::getInstance().SaveSetting(MOUNTMANAGERWARN, MOUNTMANAGERWARN_DEFAULT);
}


void CSettingsPropertyPage::OnClickedEnableSavingPasswords()
{
	

	SetControlChanged(IDC_ENABLE_SAVING_PASSWORDS);	

	bool enablesavingpasswords = false;
	CryptSettings::getInstance().GetSettingCurrent(ENABLE_SAVING_PASSWORDS, enablesavingpasswords);

	if (enablesavingpasswords) {
		bool neversavehistory = false;
		CryptSettings::getInstance().GetSettingCurrent(NEVER_SAVE_HISTORY, neversavehistory);
		if (neversavehistory) {
			MessageBox(L"Passwords will not be saved if \"Never save history\" is turned on.",
				L"cppcryptfs", MB_OK | MB_ICONINFORMATION);
		}		
	} else {
		theApp.WriteProfileInt(L"Settings", L"EnableSavingPasswords", FALSE);
		int numSavedPasswords = SavedPasswords::ClearSavedPasswords(FALSE);
		if (numSavedPasswords < 0) {
			MessageBox(L"unable to count saved passwords", L"cppcryptfs", MB_ICONEXCLAMATION | MB_OK);
		} else if (numSavedPasswords > 0) {
			int result = MessageBox(L"Delete all saved passwords?", L"cppcryptfs", MB_ICONWARNING | MB_YESNO);
			if (result == IDYES) {
				if (SavedPasswords::ClearSavedPasswords(TRUE) != numSavedPasswords) {
					MessageBox(L"unable to delete saved passwords", L"cppcryptfs", MB_ICONEXCLAMATION | MB_OK);
				}
			}
		}
	}
}


void CSettingsPropertyPage::OnClickedNeverSaveHistory()
{
	

	SetControlChanged(IDC_NEVER_SAVE_HISTORY);

	bool neversavehistory = false;
	CryptSettings::getInstance().GetSettingCurrent(NEVER_SAVE_HISTORY, neversavehistory);

	if (neversavehistory) {

		bool enablesavingpasswords = false;
		CryptSettings::getInstance().GetSettingCurrent(ENABLE_SAVING_PASSWORDS, enablesavingpasswords);

		if (enablesavingpasswords) {
			MessageBox(L"If you turn on \"Never save history\", saved passwords will not be deleted, but new passwords will not "
						   L"be saved.  To delete any saved passwords, uncheck \"Enable saved passwords\".",
				L"cppcryptfs", MB_OK | MB_ICONINFORMATION);
		}
		
		wstring mes;
		wstring error;

		// DeleteAllRegistryValues() returns false if there is nothing to delete and
		// with an empty error message.  So use the message to accumulate real errors
		DeleteAllRegisteryValues(CPPCRYPTFS_REG_PATH CPPCRYPTFS_FOLDERS_SECTION, mes);
		error += mes;
		DeleteAllRegisteryValues(CPPCRYPTFS_REG_PATH CPPCRYPTFS_CONFIGPATHS_SECTION, mes);
		error += mes;
		DeleteAllRegisteryValues(CPPCRYPTFS_REG_PATH CPPCRYPTFS_MOUNTPOINTS_SECTION, mes);
		error += mes;
		DeleteAllRegisteryValues(CPPCRYPTFS_REG_PATH L"MountPoint", mes);
		error += mes;
		DeleteAllRegisteryValues(CPPCRYPTFS_REG_PATH L"MountFlags", mes);
		error += mes;
		DeleteAllRegisteryValues(CPPCRYPTFS_REG_PATH L"MountOptions", mes);
		error += mes;
		DeleteAllRegisteryValues(CPPCRYPTFS_REG_PATH L"CreateOptions", mes);
		error += mes;
		if (!error.empty()) {
			MessageBox(L"unable to delete history from registry", L"cppcryptfs", 
							MB_OK | MB_ICONEXCLAMATION);
		}
	}
}


void CSettingsPropertyPage::OnClickedDeleteSpurriousFiles()
{	
	SetControlChanged(IDC_DELETE_SPURRIOUS_FILES);	
}


void CSettingsPropertyPage::OnClickedOpenOnMounting()
{
	SetControlChanged(IDC_OPEN_ON_MOUNTING);
}


void CSettingsPropertyPage::OnClickedEncryptKeysInMemory()
{
	SetControlChanged(IDC_ENCRYPT_KEYS_IN_MEMORY);	
}


void CSettingsPropertyPage::OnClickedCacheKeysInMemory()
{
	SetControlChanged(IDC_CACHE_KEYS_IN_MEMORY);	
}


void CSettingsPropertyPage::OnBnClickedFastMounting()
{
	SetControlChanged(IDC_FAST_MOUNTING);	
}


void CSettingsPropertyPage::OnClickedWarnIfInUseOnDismounting()
{
	SetControlChanged(IDC_WARN_IF_IN_USE_ON_DISMOUNTING);	
}


void CSettingsPropertyPage::OnClickedDenyOtherSessions()
{	
	SetControlChanged(IDC_DENY_OTHER_SESSIONS);
}


void CSettingsPropertyPage::OnClickedDenyServices()
{
	SetControlChanged(IDC_DENY_SERVICES);	
}
