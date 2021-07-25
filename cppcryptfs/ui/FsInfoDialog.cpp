
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

// FsInfoDialog.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "FsInfoDialog.h"
#include "afxdialogex.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CFsInfoDialog dialog


CFsInfoDialog::CFsInfoDialog(CWnd* pParent /*=NULL*/)
	: CDialog(IDD_FSINFO /*CFsInfoDialog::IDD*/, pParent)
{
	//{{AFX_DATA_INIT(CFsInfoDialog)
	
	//}}AFX_DATA_INIT
}


void CFsInfoDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CFsInfoDialog)
	
	//}}AFX_DATA_MAP
	
}


BEGIN_MESSAGE_MAP(CFsInfoDialog, CDialog)
	//{{AFX_MSG_MAP(CFsInfoDialog)
		// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDOK, &CFsInfoDialog::OnBnClickedOk)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CFsInfoDialog message handlers


void CFsInfoDialog::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	CDialog::OnOK();
}


BOOL CFsInfoDialog::OnInitDialog()
{
	CDialog::OnInitDialog();

	LPCWSTR yes = L"Yes";
	LPCWSTR no = L"No";
	LPCWSTR na = L"n/a";
	LPCWSTR path = m_info.path.c_str();
	if (!wcsncmp(path, L"\\\\?\\", wcslen(L"\\\\?\\"))) {
		path += wcslen(L"\\\\?\\");
	}
	SetDlgItemText(IDC_PATH, m_info.path.c_str());
	SetDlgItemText(IDC_MOUNT_POINT, m_mountPoint);
	SetDlgItemText(IDC_CONFIG_PATH, m_info.configPath.c_str());
	SetDlgItemText(IDC_FILE_NAME_ENCRYPTION, m_info.fileNameEncryption.c_str());
	SetDlgItemText(IDC_DATA_ENCRYPTION, m_info.dataEncryption.c_str());
	SetDlgItemText(IDC_READ_ONLY, m_info.readOnly ? yes : no);
	SetDlgItemText(IDC_MODE, m_info.reverse ? L"Reverse" : L"Forward");
	SetDlgItemText(IDC_MOUNT_MANAGER, m_info.mountManager ? yes : no);
	SetDlgItemText(IDC_CASE_INSENSITIVE, m_info.caseInsensitive ? yes : no);
	SetDlgItemText(IDC_LONG_FILE_NAMES, m_info.longFileNames ? yes : no);	
	SetDlgItemText(IDC_ENCRYPT_KEYS_IN_MEM, m_info.encryptKeysInMemory ? yes : no);
	SetDlgItemText(IDC_CACHE_KEYS_IN_MEM, m_info.encryptKeysInMemory ? (m_info.cacheKeysInMemory ? yes : no) : na);
	SetDlgItemText(IDC_DENY_OTHER_USERS_TXT, m_info.denyOtherUsers ? yes : no);
	SetDlgItemText(IDC_DENY_SERVICES_TXT, m_info.denyServices ? yes : no);

	wstring txt;
	txt = to_wstring(m_info.ioBufferSize);
	txt += L" KB";
	SetDlgItemText(IDC_IO_BUF_SIZE, txt.c_str());
	txt = to_wstring(m_info.fsThreads);
	SetDlgItemText(IDC_THREADS, txt.c_str());
	if (m_info.cacheTTL > 0) {
		txt = to_wstring(m_info.cacheTTL);
		txt += L" sec";
	} else {
		txt = L"infinite";
	}
	SetDlgItemText(IDC_CACHE_TTL, txt.c_str());
	WCHAR buf[32];
	*buf = '\0';
	float r;
	r = m_info.caseCacheHitRatio;
	if (r < 0.0f) {
		txt = na;
	} else {
		_snwprintf_s(buf, _TRUNCATE, L"%.2f", r*100.0f);
		txt = buf;
		txt += L"%";
	}
	SetDlgItemText(IDC_CASE_CACHE_HR, txt.c_str());
	r = m_info.lfnCacheHitRatio;
	if (r < 0.0f) {
		txt = L"n/a";
	} else {
		_snwprintf_s(buf, _TRUNCATE, L"%.2f", r*100.0f);
		txt = buf;
		txt += L"%";
	}
	SetDlgItemText(IDC_LFN_CACHE_HR, txt.c_str());
	r = m_info.dirIvCacheHitRatio;
	if (r < 0.0f) {
		txt = L"n/a";
	} else {
		_snwprintf_s(buf, _TRUNCATE, L"%.2f", r*100.0f);
		txt = buf;
		txt += L"%";
	}
	SetDlgItemText(IDC_DIRIV_CACHE_HR, txt.c_str());

	// TODO:  Add extra initialization here

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


