// CMoreSettingsPropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "MoreSettingsPropertyPage.h"
#include "afxdialogex.h"


// CMoreSettingsPropertyPage dialog

IMPLEMENT_DYNAMIC(CMoreSettingsPropertyPage, CCryptPropertyPage)

CMoreSettingsPropertyPage::CMoreSettingsPropertyPage()
	: CCryptPropertyPage(IDD_MORESETTINGS)
{

}

CMoreSettingsPropertyPage::~CMoreSettingsPropertyPage()
{
}

void CMoreSettingsPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CCryptPropertyPage::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CMoreSettingsPropertyPage, CCryptPropertyPage)
	ON_BN_CLICKED(IDC_EXFAT, &CMoreSettingsPropertyPage::OnClickedExfat)
END_MESSAGE_MAP()


// CMoreSettingsPropertyPage message handlers


void CMoreSettingsPropertyPage::OnClickedExfat()
{
	// TODO: Add your control notification handler code here
	atoi("1");
}
