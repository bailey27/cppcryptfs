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
END_MESSAGE_MAP()


// CSettingsPropertyPage message handlers


BOOL CSettingsPropertyPage::OnInitDialog()
{
	CCryptPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here

	int nThreads = theApp.GetProfileInt(L"Settings", L"Threads", 1);

	int i;

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_THREADS);

	if (!pBox)
		return FALSE;

	for (i = 0; i < 15; i++) {
		WCHAR buf[4];
		wsprintf(buf, L"%d", i);
		pBox->AddString(buf);
	}

	pBox->SetCurSel(nThreads);

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
