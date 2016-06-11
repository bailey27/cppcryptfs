
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

// CreatePropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "CreatePropertyPage.h"
#include "afxdialogex.h"
#include "FolderDialog.h"
#include "fileutil.h"
#include "cryptconfig.h"
#include "RecentItems.h"
#include "cryptdefs.h"
#include "LockZeroBuffer.h"


static const WCHAR *filename_encryption_types[] = {
	L"AES256-EME",
	L"AES256-CBC",
	L"Plain text"
};

#define NUM_ENC_TYPES (sizeof(filename_encryption_types)/sizeof(filename_encryption_types[0]))


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
}


BEGIN_MESSAGE_MAP(CCreatePropertyPage, CPropertyPage)
	ON_BN_CLICKED(IDC_SELECT, &CCreatePropertyPage::OnClickedSelect)
	ON_BN_CLICKED(IDC_CREATE, &CCreatePropertyPage::OnClickedCreate)
	ON_LBN_SELCHANGE(IDC_FILENAME_ENCRYPTION, &CCreatePropertyPage::OnLbnSelchangeFilenameEncryption)
	ON_CBN_SELCHANGE(IDC_PATH, &CCreatePropertyPage::OnCbnSelchangePath)
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

	CString cpath;

	pWnd->GetWindowTextW(cpath);

	if (cpath.GetLength() < 1)
		return;

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

	LockZeroBuffer<WCHAR> password(MAX_PASSWORD_LEN + 1);
	LockZeroBuffer<WCHAR> password2(MAX_PASSWORD_LEN + 1);
	
	pWnd = GetDlgItem(IDC_PASSWORD);

	if (!pWnd)
		return;

	if (pWnd->GetWindowText(password.m_buf, password.m_len - 1) < 1)
		return;

	pWnd = GetDlgItem(IDC_PASSWORD2);

	if (!pWnd)
		return;

	if (pWnd->GetWindowText(password2.m_buf, password2.m_len - 1) < 1)
		return;

	if (wcscmp(password.m_buf, password2.m_buf)) {
		MessageBox(L"passwords do not match", L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	GetDlgItem(IDC_PASSWORD)->SetWindowTextW(L"");
	GetDlgItem(IDC_PASSWORD2)->SetWindowTextW(L"");

	CryptConfig config;

	std::wstring error_mes;

	CComboBox *pBox = (CComboBox *)GetDlgItem(IDC_FILENAME_ENCRYPTION);

	int nsel = pBox->GetCurSel();

	bool eme = false;
	bool plaintext = false;
	bool longfilenames = false;

	CString cfenc;

	if (nsel >= 0 && nsel < NUM_ENC_TYPES)
		cfenc = filename_encryption_types[nsel];

	if (cfenc == L"AES256-EME")
		eme = true;
	else if (cfenc == "Plain text")
		plaintext = true;

	if (!plaintext) {
		longfilenames = IsDlgButtonChecked(IDC_LONG_FILE_NAMES) != 0;
	}

	CString volume_name;
	GetDlgItemText(IDC_VOLUME_NAME, volume_name);

	theApp.DoWaitCursor(1);
	bool bResult = config.create(cpath, password.m_buf, eme, plaintext, longfilenames, volume_name, error_mes);
	theApp.DoWaitCursor(-1);

	if (!bResult) {
		MessageBox(&error_mes[0], L"cppcryptfs", MB_OK | MB_ICONERROR);
		return;
	}

	CString mes;

	mes = L"Created encrypted filesystem in ";

	mes.Append(cpath);

	MessageBox(mes, L"cppcryptfs", MB_OK | MB_ICONINFORMATION);

	CString clfns = IsDlgButtonChecked(IDC_LONG_FILE_NAMES) ? L"1" : L"0";

	theApp.WriteProfileStringW(L"createoptions", L"LongFileNames", clfns);

	CComboBox* pLbox = (CComboBox*)GetDlgItem(IDC_FILENAME_ENCRYPTION);
	if (!pLbox)
		return;

	int nenc = pLbox->GetCurSel();

	if (nenc < 0 || nenc >= NUM_ENC_TYPES)
		return;

	RecentItems ritems(TEXT("Folders"), TEXT("LastDir"), m_numLastDirs);
	ritems.Add(cpath);

	theApp.WriteProfileStringW(L"createoptions", L"FilenameEncryption", filename_encryption_types[nenc]);
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

	if (!can_delete_directory(cpath, TRUE)) {
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

	CString clfns = theApp.GetProfileStringW(L"createoptions", L"LongFileNames", L"1");

	CString cfnenc = theApp.GetProfileStringW(L"createoptions", L"FilenameEncryption", L"AES256-EME");

	CheckDlgButton(IDC_LONG_FILE_NAMES, clfns == L"1");

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_PATH);

	int i;

	if (pBox) {
		for (i = 0; i < m_numLastDirs; i++) {
			if (m_lastDirs[i].GetLength())
				pBox->InsertString(i, m_lastDirs[i]);
		}
	}

	CComboBox *pLbox = (CComboBox*)GetDlgItem(IDC_FILENAME_ENCRYPTION);

	if (!pLbox)
		return FALSE;

	for (i = 0; i < NUM_ENC_TYPES; i++) {
		pLbox->InsertString(i, filename_encryption_types[i]);
		if (cfnenc == filename_encryption_types[i]) {
			pLbox->SelectString(-1, cfnenc);
		}
	}


	CEdit *pEdit = (CEdit*)GetDlgItem(IDC_VOLUME_NAME);

	if (pEdit)
		pEdit->SetLimitText(MAX_VOLUME_NAME_LENGTH);



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
