
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

// CreatePropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "CreatePropertyPage.h"
#include "afxdialogex.h"
#include "FolderDialog.h"
#include "util/fileutil.h"
#include "config/cryptconfig.h"
#include "RecentItems.h"
#include "crypt/cryptdefs.h"
#include "util/LockZeroBuffer.h"
#include "util/util.h"

static const WCHAR *filename_encryption_types[] = {
	L"AES256-EME",
	L"Plain text"
};

#define NUM_FN_ENC_TYPES (sizeof(filename_encryption_types)/sizeof(filename_encryption_types[0]))

static const WCHAR *data_encryption_types[] = {
	L"AES256-GCM",
	L"AES256-SIV"
};

#define AES256_GCM_INDEX 0
#define AES256_SIV_INDEX 1

#define NUM_DATA_ENC_TYPES (sizeof(data_encryption_types)/sizeof(data_encryption_types[0]))


// CCreatePropertyPage dialog

IMPLEMENT_DYNAMIC(CCreatePropertyPage, CCryptPropertyPage)

CCreatePropertyPage::CCreatePropertyPage()
	: CCryptPropertyPage(IDD_CREATE)
{

}

CCreatePropertyPage::~CCreatePropertyPage()
{
}

void CCreatePropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PASSWORD, m_password);
	DDX_Control(pDX, IDC_PASSWORD2, m_password2);
}


BEGIN_MESSAGE_MAP(CCreatePropertyPage, CPropertyPage)
	ON_BN_CLICKED(IDC_SELECT, &CCreatePropertyPage::OnClickedSelect)
	ON_BN_CLICKED(IDC_CREATE, &CCreatePropertyPage::OnClickedCreate)
	ON_LBN_SELCHANGE(IDC_FILENAME_ENCRYPTION, &CCreatePropertyPage::OnLbnSelchangeFilenameEncryption)
	ON_CBN_SELCHANGE(IDC_PATH, &CCreatePropertyPage::OnCbnSelchangePath)
	ON_BN_CLICKED(IDC_REVERSE, &CCreatePropertyPage::OnClickedReverse)
	ON_BN_CLICKED(IDC_SELECT_CONFIG_PATH, &CCreatePropertyPage::OnClickedSelectConfigPath)
	ON_CBN_SELCHANGE(IDC_LONGNAMEMAX, &CCreatePropertyPage::OnSelchangeLongnamemax)
	ON_BN_CLICKED(IDC_LONG_FILE_NAMES, &CCreatePropertyPage::OnClickedLongFileNames)
END_MESSAGE_MAP()

void CCreatePropertyPage::DefaultAction()
{
	CreateCryptfs();
}

void CCreatePropertyPage::CreateCryptfs()
{
	CWnd *pWnd = GetDlgItem(IDC_PATH);
	if (!pWnd)
		return;

	LockZeroBuffer<WCHAR> password(MAX_PASSWORD_LEN + 1, false);
	LockZeroBuffer<WCHAR> password2(MAX_PASSWORD_LEN + 1, false);

	if (!password.IsLocked() || !password2.IsLocked()) {
		MessageBox(L"could not lock password buffers", L"cppcryptefs", MB_OK | MB_ICONERROR);
		return;
	}

	CSecureEdit *pPass = &m_password;

	if (wcscpy_s(password.m_buf, MAX_PASSWORD_LEN + 1, pPass->m_strRealText))
		return;

	if (wcslen(password.m_buf) < 1) {
		MessageBox(L"please enter a password", L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	CSecureEdit *pPass2 = &m_password2;

	if (wcscpy_s(password2.m_buf, MAX_PASSWORD_LEN + 1, pPass2->m_strRealText))
		return;

	if (wcslen(password2.m_buf) < 1) {
		MessageBox(L"please repeat the password", L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	if (wcscmp(password.m_buf, password2.m_buf)) {
		MessageBox(L"passwords do not match", L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	pPass->SetRealText(L"");
	pPass2->SetRealText(L"");

	CString cpath;

	pWnd->GetWindowTextW(cpath);

	if (cpath.GetLength() < 1) {
		MessageBox(L"please enter a path", L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	if (!PathFileExists(cpath)) {
		CString mes;
		mes += cpath;
		mes += L" does not exist.  Do you want to create it?";
		if (MessageBox(mes, L"cppcryptfs", MB_YESNO | MB_ICONINFORMATION) == IDYES) {
				if (!CreateDirectory(cpath, NULL)) {
					mes = L"Could not create ";
					mes += cpath;
					MessageBox(mes, L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
					return;
				}
		} else {
			return;
		}
	}

	pWnd = GetDlgItem(IDC_CONFIG_PATH);
	if (!pWnd)
		return;

	CString config_path;

	pWnd->GetWindowText(config_path);

	

	CryptConfig config;

	wstring error_mes;

	

	bool siv = false;
	bool eme = false;
	bool plaintext = false;
	bool longfilenames = false;
	int longnamemax = MAX_LONGNAMEMAX;
	bool reverse = false;
	bool disablestreams = false;

	CComboBox *pBox = (CComboBox *)GetDlgItem(IDC_FILENAME_ENCRYPTION);

	int nsel = pBox->GetCurSel();

	CString cfenc;

	if (nsel >= 0 && nsel < NUM_FN_ENC_TYPES)
		cfenc = filename_encryption_types[nsel];

	if (cfenc == L"AES256-EME")
		eme = true;
	else if (cfenc == "Plain text")
		plaintext = true;

	if (!plaintext) {
		longfilenames = IsDlgButtonChecked(IDC_LONG_FILE_NAMES) != 0;
		if (longfilenames) {
			longnamemax = GetDlgItemInt(IDC_LONGNAMEMAX);
			longnamemax = min(longnamemax, MAX_LONGNAMEMAX);
			longnamemax = max(MIN_LONGNAMEMAX, longnamemax);
		}
	}

	disablestreams = IsDlgButtonChecked(IDC_DISABLE_STREAMS) != 0;

	reverse = IsDlgButtonChecked(IDC_REVERSE) != 0;

	pBox = (CComboBox *)GetDlgItem(IDC_DATA_ENCRYPTION);

	nsel = pBox->GetCurSel();

	CString cdataenc;

	if (nsel >= 0 && nsel < NUM_DATA_ENC_TYPES)
		cfenc = data_encryption_types[nsel];

	if (cfenc == L"AES256-SIV")
		siv = true;

	CString volume_name;
	GetDlgItemText(IDC_VOLUME_NAME, volume_name);

	theApp.DoWaitCursor(1);
	bool bResult = config.create(cpath, config_path, password.m_buf, eme, plaintext, longfilenames, siv, reverse, volume_name, disablestreams, longnamemax, error_mes);
	theApp.DoWaitCursor(-1);

	if (!bResult) {
		MessageBox(&error_mes[0], L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	CString mes;

	mes = reverse ? L"Created reverse encrypted filesystem in " : L"Created encrypted filesystem in ";

	mes.Append(cpath);

	MessageBox(mes, L"cppcryptfs", MB_OK | MB_ICONINFORMATION);

	SetDlgItemText(IDC_VOLUME_NAME, L"");

	CString clfns = IsDlgButtonChecked(IDC_LONG_FILE_NAMES) ? L"1" : L"0";

	theApp.WriteProfileStringW(L"CreateOptions", L"LongFileNames", clfns);

	theApp.WriteProfileInt(L"CreateOptions", L"LongNameMax", longnamemax);

	CString cdisablestreams = IsDlgButtonChecked(IDC_DISABLE_STREAMS) ? L"1" : L"0";

	theApp.WriteProfileStringW(L"CreateOptions", L"DisableStreams", cdisablestreams);

	CString creverse = IsDlgButtonChecked(IDC_REVERSE) ? L"1" : L"0";

	theApp.WriteProfileStringW(L"CreateOptions", L"Reverse", creverse);

	CComboBox* pLbox = (CComboBox*)GetDlgItem(IDC_FILENAME_ENCRYPTION);
	if (!pLbox)
		return;

	int nenc = pLbox->GetCurSel();

	if (nenc < 0 || nenc >= NUM_FN_ENC_TYPES)
		return;

	theApp.WriteProfileStringW(L"CreateOptions", L"FilenameEncryption", filename_encryption_types[nenc]);

	pLbox = (CComboBox*)GetDlgItem(IDC_DATA_ENCRYPTION);
	if (!pLbox)
		return;

	nenc = pLbox->GetCurSel();

	if (nenc < 0 || nenc >= NUM_DATA_ENC_TYPES)
		return;

	theApp.WriteProfileStringW(L"CreateOptions", L"DataEncryption", data_encryption_types[nenc]);

	RecentItems ritems(TEXT("Folders"), TEXT("LastDir"), m_numLastDirs);
	ritems.Add(cpath);

	if (config_path.GetLength() > 0) {
		RecentItems ri(TEXT("ConfigPaths"), TEXT("LastConfig"), m_numLastConfigs);
		ri.Add(config_path);
	}

	CString path_hash;
	wstring hash;
	if (GetPathHash(cpath, hash)) {
		path_hash = hash.c_str();
		theApp.WriteProfileString(L"ConfigPaths", path_hash, config_path);
		int flags = 0;
		if (reverse)
			flags |= REVERSE_FLAG;
		theApp.WriteProfileInt(L"MountFlags", path_hash, flags);
	}
}

// CCreatePropertyPage message handlers


void CCreatePropertyPage::OnClickedSelect()
{
	// TODO: Add your control notification handler code here

	CFolderDialog fdlg;

	if (fdlg.DoModal() == IDCANCEL)
		return;

	CString cpath = fdlg.GetPathName();

	if (cpath.GetLength() < 1)
		return;

	if (!IsDlgButtonChecked(IDC_REVERSE) && !can_delete_directory(cpath, TRUE)) {
		MessageBox(L"directory must be empty", L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	CWnd *pWnd = GetDlgItem(IDC_PATH);
	if (pWnd)
		pWnd->SetWindowTextW(cpath);
	
}


void CCreatePropertyPage::OnClickedCreate()
{
	// TODO: Add your control notification handler code here

	CreateCryptfs();
}


BOOL CCreatePropertyPage::OnInitDialog()
{
	CPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here

	CString clfns = theApp.GetProfileStringW(L"CreateOptions", L"LongFileNames", L"1");

	int longnamemax = theApp.GetProfileIntW(L"CreateOptions", L"LongNameMax", MAX_LONGNAMEMAX);

	CString cdisablestreams = theApp.GetProfileStringW(L"CreateOptions", L"DisableStreams", L"0");

	CString creverse = theApp.GetProfileStringW(L"CreateOptions", L"Reverse", L"0");

	CString cfnenc = theApp.GetProfileStringW(L"CreateOptions", L"FilenameEncryption", L"AES256-EME");

	CString cdataenc = theApp.GetProfileStringW(L"CreateOptions", L"DataEncryption", L"AES256-GCM");

	CheckDlgButton(IDC_LONG_FILE_NAMES, clfns == L"1");

	CheckDlgButton(IDC_DISABLE_STREAMS, cdisablestreams == L"1");

	CheckDlgButton(IDC_REVERSE, creverse == L"1");

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_PATH);

	int i;

	if (pBox) {
		for (i = 0; i < m_numLastDirs; i++) {
			if (m_lastDirs[i].GetLength())
				pBox->InsertString(i, m_lastDirs[i]);
		}
	}

	pBox = (CComboBox*)GetDlgItem(IDC_CONFIG_PATH);

	if (pBox) {
		for (i = 0; i < m_numLastConfigs; i++) {
			if (m_lastConfigs[i].GetLength())
				pBox->InsertString(i, m_lastConfigs[i]);
		}
	}

	CComboBox *pLbox = (CComboBox*)GetDlgItem(IDC_FILENAME_ENCRYPTION);

	if (!pLbox)
		return FALSE;

	for (i = 0; i < NUM_FN_ENC_TYPES; i++) {
		pLbox->InsertString(i, filename_encryption_types[i]);
		if (cfnenc == filename_encryption_types[i]) {
			pLbox->SelectString(-1, cfnenc);
		}
	}

	pLbox = (CComboBox*)GetDlgItem(IDC_DATA_ENCRYPTION);

	if (!pLbox)
		return FALSE;

	for (i = 0; i < NUM_DATA_ENC_TYPES; i++) {
		pLbox->InsertString(i, data_encryption_types[i]);
		if (cdataenc == data_encryption_types[i]) {
			pLbox->SelectString(-1, cdataenc);
		}
	}

	pLbox = (CComboBox*)GetDlgItem(IDC_LONGNAMEMAX);

	if (!pLbox)
		return FALSE;

	wstring lnm;
	for (i = MIN_LONGNAMEMAX; i <= MAX_LONGNAMEMAX; ++i) {
		lnm = to_wstring(i);
		pLbox->InsertString(i - MIN_LONGNAMEMAX, lnm.c_str());
		if (i == longnamemax) {
			pLbox->SelectString(-1, lnm.c_str());
		}
	}
	pLbox->EnableWindow(IsDlgButtonChecked(IDC_LONG_FILE_NAMES));

	if (!m_password.ArePasswordBuffersLocked() || !m_password2.ArePasswordBuffersLocked()) {
		MessageBox(L"unable to lock password buffers", L"cppcryptfs", MB_OK | MB_ICONERROR);
	}

	// limit input lengths

	m_password.SetLimitText(MAX_PASSWORD_LEN);

	m_password2.SetLimitText(MAX_PASSWORD_LEN);

	CEdit *pEdit = (CEdit*)GetDlgItem(IDC_VOLUME_NAME);
	if (pEdit)
		pEdit->SetLimitText(MAX_VOLUME_NAME_LENGTH);

	CComboBox *pCombo = (CComboBox*)GetDlgItem(IDC_PATH);
	if (pCombo)
		pCombo->LimitText(MAX_PATH);

	pCombo = (CComboBox*)GetDlgItem(IDC_CONFIG_PATH);
	if (pCombo)
		pCombo->LimitText(MAX_PATH);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


void CCreatePropertyPage::OnLbnSelchangeFilenameEncryption()
{
	// TODO: Add your control notification handler code here
}


void CCreatePropertyPage::OnCbnSelchangePath()
{
	// TODO: Add your control notification handler code here
}


void CCreatePropertyPage::OnClickedReverse()
{
	// TODO: Add your control notification handler code here

	CComboBox *pEncBox = (CComboBox*)GetDlgItem(IDC_DATA_ENCRYPTION);

	if (!pEncBox)
		return;

	BOOL bIsChecked = IsDlgButtonChecked(IDC_REVERSE);

	pEncBox->SelectString(-1, data_encryption_types[bIsChecked ? AES256_SIV_INDEX : AES256_GCM_INDEX]);
	
}


void CCreatePropertyPage::OnClickedSelectConfigPath()
{
	// TODO: Add your control notification handler code here

	bool reverse = IsDlgButtonChecked(IDC_REVERSE) != 0;

	CFileDialog fdlg(FALSE, L"conf", reverse ? L"gocryptfs.reverse" : L"gocryptfs", 
		OFN_DONTADDTORECENT | OFN_LONGNAMES | OFN_OVERWRITEPROMPT |
		OFN_PATHMUSTEXIST);

	if (fdlg.DoModal() == IDCANCEL)
		return;

	CString cpath = fdlg.GetPathName();

	if (cpath.GetLength() < 1)
		return;

	CWnd *pWnd = GetDlgItem(IDC_CONFIG_PATH);
	if (pWnd)
		pWnd->SetWindowTextW(cpath);
}



void CCreatePropertyPage::OnSelchangeLongnamemax()
{
	// TODO: Add your control notification handler code here
}


void CCreatePropertyPage::OnClickedLongFileNames()
{
	// TODO: Add your control notification handler code here

	auto pLbox = (CComboBox*)GetDlgItem(IDC_LONGNAMEMAX);
	if (pLbox) {
		pLbox->EnableWindow(IsDlgButtonChecked(IDC_LONG_FILE_NAMES));
	}
}
