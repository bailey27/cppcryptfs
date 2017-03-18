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

// SettingsPropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "SettingsPropertyPage.h"
#include "afxdialogex.h"
#include "cppcryptfs.h"


// CSettingsPropertyPage dialog

IMPLEMENT_DYNAMIC(CSettingsPropertyPage, CCryptPropertyPage)

CSettingsPropertyPage::CSettingsPropertyPage()
	: CCryptPropertyPage(IDD_SETTINGS)
{

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
END_MESSAGE_MAP()


// CSettingsPropertyPage message handlers

static int buffer_sizes[] = { 4, 8, 16, 32, 64, 128, 256, 512, 1024 };

static int ttls[] = { 0, 1, 2, 5, 10, 15, 30, 45, 60, 90, 120, 300, 600, 900, 1800, 3600};

static const WCHAR* ttl_strings[] = { L"infinite", L"1 second", L"2 seconds", L"5 seconds", L"10 seconds", L"15 seconds", L"30 seconds", L"45 seconds", L"60 seconds", L"90 seconds", L"2 minutes", L"5 minutes", L"10 minutes", L"15 minutes", L"30 minutes", L"1 hour" };

BOOL CSettingsPropertyPage::OnInitDialog()
{
	CCryptPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here

	int nThreads = theApp.GetProfileInt(L"Settings", L"Threads", 1);

	int bufferblocks = theApp.GetProfileInt(L"Settings", L"BufferBlocks", 1);

	int cachettl = theApp.GetProfileInt(L"Settings", L"CacheTTL", 1);

	m_bCaseInsensitive = theApp.GetProfileInt(L"Settings", L"CaseInsensitive", 0) != 0;

	int i;

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_THREADS);

	if (!pBox)
		return FALSE;

	WCHAR buf[80];

	for (i = 0; i < 15; i++) {
		if (i == 0) {
			lstrcpy(buf, L"Dokany default (5)");
		} else if (i == 1) {
			lstrcpy(buf, L"1 (cppcryptfs default)");
		} else {
			wsprintf(buf, L"%d", i);
		}
		pBox->AddString(buf);
	}

	pBox->SetCurSel(nThreads);

	pBox = (CComboBox*)GetDlgItem(IDC_BUFFERSIZE);

	if (!pBox)
		return FALSE;

	for (i = 0; i < sizeof(buffer_sizes)/sizeof(buffer_sizes[0]); i++) {
		wsprintf(buf, L"%d", buffer_sizes[i]);
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

	static_assert(sizeof(ttls) / sizeof(ttls[0]) == sizeof(ttl_strings) / sizeof(ttl_strings[0]), "mismatch in sizes of ttls/ttl_strings");

	int selitem = 0;

	for (i = 0; i < sizeof(ttls) / sizeof(ttls[0]); i++) {
		wsprintf(buf, ttl_strings[i]);
		pBox->AddString(buf);
		if (cachettl == ttls[i]) {
			selitem = i;
		}
	}

	pBox->SetCurSel(selitem);

	CheckDlgButton(IDC_CASEINSENSITIVE, m_bCaseInsensitive ? 1 : 0);

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

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_BUFFERSIZE);

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


