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

	// TODO:  Add extra initialization here

	int nThreads = theApp.GetProfileInt(L"Settings", L"Threads", PER_FILESYSTEM_THREADS_DEFAULT);

	int bufferblocks = theApp.GetProfileInt(L"Settings", L"BufferBlocks", BUFFERBLOCKS_DEFAULT);

	buffer_size_t kb = bufferblocks * 4;
	
	auto p = bsearch(&kb, buffer_sizes, _countof(buffer_sizes), sizeof(buffer_size_t), [](const void* pkey, const void* pval) -> int {
		return *reinterpret_cast<const buffer_size_t*>(pkey) - *reinterpret_cast<const buffer_size_t*>(pval);
	});

	if (!p)
		bufferblocks = BUFFERBLOCKS_DEFAULT;

	int cachettl = theApp.GetProfileInt(L"Settings", L"CacheTTL", CACHETTL_DEFAULT);

	bool bCaseInsensitive = theApp.GetProfileInt(L"Settings", L"CaseInsensitive", CASEINSENSITIVE_DEFAULT) != 0;

	bool bMountManager = theApp.GetProfileInt(L"Settings", L"MountManager", MOUNTMANAGER_DEFAULT) != 0;

	bool bEnableSavingPasswords = theApp.GetProfileInt(L"Settings", L"EnableSavingPasswords", 
											ENABLE_SAVING_PASSWORDS_DEFAULT) != 0;

	bool bNeverSaveHistory = NeverSaveHistory();

	bool bDeleteSpurriousFiles = theApp.GetProfileInt(L"Settings", L"DeleteSpurriousFiles",
											DELETE_SPURRIOUS_FILES_DEFAULT) != 0;

	bool bOpenOnMounting = theApp.GetProfileIntW(L"Settings", L"OpenOnMounting",
											OPEN_ON_MOUNTING_DEFAULT) != 0;

	bool bEncryptKeysInMemory = theApp.GetProfileIntW(L"Settings", L"EncryptKeysInMemory",
											ENCRYPT_KEYS_IN_MEMORY_DEFAULT) != 0;

	bool bCacheKeysInMemory = theApp.GetProfileIntW(L"Settings", L"CacheKeysInMemory",
											CACHE_KEYS_IN_MEMORY_DEFAULT) != 0;

	bool bFastMounting = theApp.GetProfileIntW(L"Settings", L"FastMounting",
		FAST_MOUNTING_DEFAULT) != 0;


	bool bWarnIfInUseOnDismounting = theApp.GetProfileIntW(L"Settings", L"WarnIfInUseOnDismounting",
		WARN_IF_IN_USE_ON_DISMOUNT_DEFAULT) != 0;

	bool bDenyOtherSessions = theApp.GetProfileIntW(L"Settings", L"DenyOtherSessions",
		DENY_OTHER_SESSIONS_DEFAULT) != 0;

	bool bDenyServices = theApp.GetProfileIntW(L"Settings", L"DenyServices",
		DENY_SERVICES_DEFAULT) != 0;


	return SetControls(nThreads, bufferblocks, cachettl, bCaseInsensitive, bMountManager, 
								bEnableSavingPasswords, bNeverSaveHistory, bDeleteSpurriousFiles, bOpenOnMounting,
								bEncryptKeysInMemory, bCacheKeysInMemory, bFastMounting, bWarnIfInUseOnDismounting,
								bDenyOtherSessions, bDenyServices);
}

BOOL CSettingsPropertyPage::SetControls(int nThreads, int bufferblocks, int cachettl, 
						bool bCaseInsensitive, bool bMountManager, bool bEnableSavingPasswords, bool bNeverSaveHistory,
						bool bDeleteSpurriousFiles, bool bOpenOnMounting, bool bEncryptKeysInMemory,
						bool bCacheKeysInMemory, bool bFastMounting, bool bWarnIfInUseOnDismounting,
						bool bDenyOtherSessions, bool bDenyServices)
{

	m_bCaseInsensitive =  bCaseInsensitive;
	m_bMountManager = bMountManager;
	m_bEnableSavingPasswords = bEnableSavingPasswords;
	m_bNeverSaveHistory = bNeverSaveHistory;
	m_bDeleteSpurriousFiles = bDeleteSpurriousFiles;
	m_bOpenOnMounting = bOpenOnMounting;
	m_bEncryptKeysInMemory = bEncryptKeysInMemory;
	m_bCacheKeysInMemory = bCacheKeysInMemory;
	m_bFastMounting = bFastMounting;
	m_bWarnIfInUseOnDismounting = bWarnIfInUseOnDismounting;
	m_bDenyOtherSessions = bDenyOtherSessions;
	m_bDenyServices = bDenyServices;

	int i;

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_THREADS);

	if (!pBox)
		return FALSE;

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

	pBox->SetCurSel(nThreads);

	pBox = (CComboBox*)GetDlgItem(IDC_BUFFERSIZE);

	if (!pBox)
		return FALSE;

	pBox->ResetContent();

	for (i = 0; i < sizeof(buffer_sizes)/sizeof(buffer_sizes[0]); i++) {
		swprintf_s(buf, L"%d", buffer_sizes[i]);
		pBox->AddString(buf);
	}

	int bits = 0;

	int n = bufferblocks;
	while (n) {
		bits++;
		n >>= 1;
	}

	pBox->SetCurSel(bits-1);

	pBox = (CComboBox*)GetDlgItem(IDC_CACHETTL);

	if (!pBox)
		return FALSE;

	pBox->ResetContent();

	static_assert(sizeof(ttls) / sizeof(ttls[0]) == sizeof(ttl_strings) / sizeof(ttl_strings[0]), 
					"mismatch in sizes of ttls/ttl_strings");

	int selitem = 0;

	for (i = 0; i < sizeof(ttls) / sizeof(ttls[0]); i++) {
		pBox->AddString(ttl_strings[i]);
		if (cachettl == ttls[i]) {
			selitem = i;
		}
	}

	pBox->SetCurSel(selitem);

	CheckDlgButton(IDC_CASEINSENSITIVE, m_bCaseInsensitive ? 1 : 0);

	CheckDlgButton(IDC_MOUNTMANAGER, m_bMountManager ? 1 : 0);

	CheckDlgButton(IDC_ENABLE_SAVING_PASSWORDS, m_bEnableSavingPasswords ? 1 : 0);

	CheckDlgButton(IDC_NEVER_SAVE_HISTORY, m_bNeverSaveHistory ? 1 : 0);

	CheckDlgButton(IDC_DELETE_SPURRIOUS_FILES, m_bDeleteSpurriousFiles ? 1 : 0);

	CheckDlgButton(IDC_OPEN_ON_MOUNTING, m_bOpenOnMounting ? 1 : 0);

	CheckDlgButton(IDC_ENCRYPT_KEYS_IN_MEMORY, m_bEncryptKeysInMemory ? 1 : 0);

	CheckDlgButton(IDC_CACHE_KEYS_IN_MEMORY, m_bCacheKeysInMemory ? 1 : 0);

	CheckDlgButton(IDC_FAST_MOUNTING, m_bFastMounting ? 1 : 0);

	CheckDlgButton(IDC_WARN_IF_IN_USE_ON_DISMOUNTING, m_bWarnIfInUseOnDismounting ? 1 : 0);

	CheckDlgButton(IDC_DENY_OTHER_SESSIONS, m_bDenyOtherSessions ? 1 : 0);

	CheckDlgButton(IDC_DENY_SERVICES, m_bDenyServices ? 1 : 0);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


void CSettingsPropertyPage::OnSelchangeThreads()
{
	// TODO: Add your control notification handler code here

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_THREADS);

	if (!pBox)
		return;

	int nThreads = pBox->GetCurSel();

	theApp.WriteProfileInt(L"Settings", L"Threads", nThreads);
}


void CSettingsPropertyPage::OnSelchangeBuffersize()
{
	// TODO: Add your control notification handler code here

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_BUFFERSIZE);

	if (!pBox)
		return;

	int selIndex = pBox->GetCurSel();

	int nBlocks = 1 << selIndex;

	theApp.WriteProfileInt(L"Settings",  L"BufferBlocks", nBlocks);
}

void CSettingsPropertyPage::OnCbnSelchangeCachettl()
{
	// TODO: Add your control notification handler code here

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_CACHETTL);

	if (!pBox)
		return;

	int selIndex = pBox->GetCurSel();

	int cachettl = ttls[selIndex];

	theApp.WriteProfileInt(L"Settings",  L"CacheTTL", cachettl);
}


void CSettingsPropertyPage::OnBnClickedCaseinsensitive()
{
	// TODO: Add your control notification handler code here

	m_bCaseInsensitive = !m_bCaseInsensitive;

	CheckDlgButton(IDC_CASEINSENSITIVE, m_bCaseInsensitive ? 1 : 0);

	theApp.WriteProfileInt(L"Settings", L"CaseInsensitive", m_bCaseInsensitive ? 1 : 0);
}


void CSettingsPropertyPage::SaveSettings()
{
	OnSelchangeThreads();
	OnSelchangeBuffersize();
	OnCbnSelchangeCachettl();

	m_bCaseInsensitive = !m_bCaseInsensitive; // OnBnClickedCaseinsensitive() flips it
	m_bMountManager = !m_bMountManager; // ditto
	m_bEnableSavingPasswords = !m_bEnableSavingPasswords; // ditto
	m_bNeverSaveHistory = !m_bNeverSaveHistory; // ditto
	m_bDeleteSpurriousFiles = !m_bDeleteSpurriousFiles; // ditto
	m_bOpenOnMounting = !m_bOpenOnMounting; // ditto
	m_bEncryptKeysInMemory = !m_bEncryptKeysInMemory; // ditto
	m_bCacheKeysInMemory = !m_bCacheKeysInMemory; // ditto
	m_bFastMounting = !m_bFastMounting; // ditto
	m_bWarnIfInUseOnDismounting = !m_bWarnIfInUseOnDismounting; // ditto
	m_bDenyOtherSessions = !m_bDenyOtherSessions; // ditto
	m_bDenyServices = !m_bDenyServices; // ditto

	OnBnClickedCaseinsensitive();
	OnClickedMountmanager();
	OnClickedEnableSavingPasswords();
	OnClickedNeverSaveHistory();
	OnClickedDeleteSpurriousFiles();
	OnClickedOpenOnMounting();
	OnClickedEncryptKeysInMemory();
	OnClickedCacheKeysInMemory();
	OnBnClickedFastMounting();
	OnClickedWarnIfInUseOnDismounting();
	OnClickedDenyOtherSessions();
	OnClickedDenyServices();
}

void CSettingsPropertyPage::OnBnClickedDefaults()
{
	// TODO: Add your control notification handler code here

	SetControls(PER_FILESYSTEM_THREADS_DEFAULT, BUFFERBLOCKS_DEFAULT, CACHETTL_DEFAULT, 
		CASEINSENSITIVE_DEFAULT, MOUNTMANAGER_DEFAULT, ENABLE_SAVING_PASSWORDS_DEFAULT,
		NEVER_SAVE_HISTORY_DEFAULT, DELETE_SPURRIOUS_FILES_DEFAULT, OPEN_ON_MOUNTING_DEFAULT,
		ENCRYPT_KEYS_IN_MEMORY_DEFAULT, CACHE_KEYS_IN_MEMORY_DEFAULT, FAST_MOUNTING_DEFAULT,
		WARN_IF_IN_USE_ON_DISMOUNT_DEFAULT, DENY_OTHER_SESSIONS_DEFAULT, DENY_SERVICES_DEFAULT);

	SaveSettings();
}


void CSettingsPropertyPage::OnBnClickedRecommended()
{
	// TODO: Add your control notification handler code here

	SetControls(PER_FILESYSTEM_THREADS_RECOMMENDED, BUFFERBLOCKS_RECOMMENDED, CACHETTL_RECOMMENDED, 
		CASEINSENSITIVE_RECOMMENDED, MOUNTMANAGER_RECOMMENDED, ENABLE_SAVING_PASSWORDS_RECOMMENDED,
		NEVER_SAVE_HISTORY_RECOMMENDED, DELETE_SUPRRIOUS_FILES_RECOMMENDED, OPEN_ON_MOUNTING_RECOMMENDED,
		ENCRYPT_KEYS_IN_MEMORY_RECOMMENDED, CACHE_KEYS_IN_MEMORY_RECOMMENDED, FAST_MOUNTING_RECOMMENDED,
		WARN_IF_IN_USE_ON_DISMOUNT_RECOMMENDED, DENY_OTHER_SESSIONS_RECOMMENDED, DENY_SERVICES_RECOMMENDED);

	SaveSettings();
}



void CSettingsPropertyPage::OnClickedMountmanager()
{
	// TODO: Add your control notification handler code here

	m_bMountManager = !m_bMountManager;

	CheckDlgButton(IDC_MOUNTMANAGER, m_bMountManager ? 1 : 0);

	theApp.WriteProfileInt(L"Settings", L"MountManager", m_bMountManager ? 1 : 0);
}


void CSettingsPropertyPage::OnClickedResetwarnings()
{
	// TODO: Add your control notification handler code here

	theApp.WriteProfileInt(L"Settings", L"MountManagerWarn", MOUNTMANAGERWARN_DEFAULT);
}


void CSettingsPropertyPage::OnClickedEnableSavingPasswords()
{
	// TODO: Add your control notification handler code here

	m_bEnableSavingPasswords = !m_bEnableSavingPasswords;

	CheckDlgButton(IDC_ENABLE_SAVING_PASSWORDS, m_bEnableSavingPasswords ? 1 : 0);

	if (m_bEnableSavingPasswords) {

		if (m_bNeverSaveHistory) {
			MessageBox(L"Passwords will not be saved if \"Never save history\" is turned on.",
				L"cppcryptfs", MB_OK | MB_ICONINFORMATION);
		}
		theApp.WriteProfileInt(L"Settings", L"EnableSavingPasswords", TRUE);
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
	// TODO: Add your control notification handler code here

	m_bNeverSaveHistory = !m_bNeverSaveHistory;

	CheckDlgButton(IDC_NEVER_SAVE_HISTORY, !!m_bNeverSaveHistory);

	theApp.WriteProfileInt(L"Settings", L"NeverSaveHistory", !!m_bNeverSaveHistory);

	if (m_bNeverSaveHistory) {

		if (m_bEnableSavingPasswords) {
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
	// TODO: Add your control notification handler code here
	m_bDeleteSpurriousFiles = !m_bDeleteSpurriousFiles;

	CheckDlgButton(IDC_DELETE_SPURRIOUS_FILES, m_bDeleteSpurriousFiles ? 1 : 0);

	theApp.WriteProfileInt(L"Settings", L"DeleteSpurriousFiles", m_bDeleteSpurriousFiles ? 1 : 0);
}


void CSettingsPropertyPage::OnClickedOpenOnMounting()
{
	// TODO: Add your control notification handler code here
	m_bOpenOnMounting = !m_bOpenOnMounting;

	CheckDlgButton(IDC_OPEN_ON_MOUNTING, m_bOpenOnMounting ? 1 : 0);

	theApp.WriteProfileInt(L"Settings", L"OpenOnMounting", m_bOpenOnMounting ? 1 : 0);
}


void CSettingsPropertyPage::OnClickedEncryptKeysInMemory()
{
	// TODO: Add your control notification handler code here

	m_bEncryptKeysInMemory = !m_bEncryptKeysInMemory;

	CheckDlgButton(IDC_ENCRYPT_KEYS_IN_MEMORY, m_bEncryptKeysInMemory ? 1 : 0);

	theApp.WriteProfileInt(L"Settings", L"EncryptKeysInMemory", m_bEncryptKeysInMemory ? 1 : 0);
}


void CSettingsPropertyPage::OnClickedCacheKeysInMemory()
{
	// TODO: Add your control notification handler code here

	m_bCacheKeysInMemory = !m_bCacheKeysInMemory;

	CheckDlgButton(IDC_CACHE_KEYS_IN_MEMORY, m_bCacheKeysInMemory ? 1 : 0);

	theApp.WriteProfileInt(L"Settings", L"CacheKeysInMemory", m_bCacheKeysInMemory ? 1 : 0);
}


void CSettingsPropertyPage::OnBnClickedFastMounting()
{
	// TODO: Add your control notification handler code here

	m_bFastMounting = !m_bFastMounting;

	CheckDlgButton(IDC_FAST_MOUNTING, m_bFastMounting ? 1 : 0);

	theApp.WriteProfileInt(L"Settings", L"FastMounting", m_bFastMounting ? 1 : 0);
}


void CSettingsPropertyPage::OnClickedWarnIfInUseOnDismounting()
{
	// TODO: Add your control notification handler code here

	m_bWarnIfInUseOnDismounting = !m_bWarnIfInUseOnDismounting;

	CheckDlgButton(IDC_WARN_IF_IN_USE_ON_DISMOUNTING, m_bWarnIfInUseOnDismounting ? 1 : 0);

	theApp.WriteProfileInt(L"Settings", L"WarnIfInUseOnDismounting", m_bWarnIfInUseOnDismounting ? 1 : 0);
}


void CSettingsPropertyPage::OnClickedDenyOtherSessions()
{
	// TODO: Add your control notification handler code here

	m_bDenyOtherSessions = !m_bDenyOtherSessions;

	CheckDlgButton(IDC_DENY_OTHER_SESSIONS, m_bDenyOtherSessions ? 1 : 0);

	theApp.WriteProfileInt(L"Settings", L"DenyOtherSessions", m_bDenyOtherSessions ? 1 : 0);
}


void CSettingsPropertyPage::OnClickedDenyServices()
{
	// TODO: Add your control notification handler code here

	m_bDenyServices = !m_bDenyServices;

	CheckDlgButton(IDC_DENY_SERVICES, m_bDenyServices ? 1 : 0);

	theApp.WriteProfileInt(L"Settings", L"DenyServices", m_bDenyServices ? 1 : 0);
}
