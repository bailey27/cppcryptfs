// MountMangerDialog.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "MountMangerDialog.h"
#include "afxdialogex.h"
#include "cryptdefaults.h"
#include "ui/CryptSettings.h"


// CMountMangerDialog dialog

IMPLEMENT_DYNAMIC(CMountMangerDialog, CDialogEx)

CMountMangerDialog::CMountMangerDialog(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_MOUNTMANAGER, pParent)
{
	m_bOkPressed = FALSE;
}

CMountMangerDialog::~CMountMangerDialog()
{
}

void CMountMangerDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CMountMangerDialog, CDialogEx)
	ON_BN_CLICKED(IDOK, &CMountMangerDialog::OnBnClickedOk)
	ON_BN_CLICKED(IDC_DONTSHOWAGAIN, &CMountMangerDialog::OnBnClickedDontshowagain)
END_MESSAGE_MAP()


// CMountMangerDialog message handlers


void CMountMangerDialog::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	CDialogEx::OnOK();

	m_bOkPressed = TRUE;

	
}


void CMountMangerDialog::OnBnClickedDontshowagain()
{
	// TODO: Add your control notification handler code here
	
	CryptSettings::getInstance().SaveSetting(MOUNTMANAGERWARN, !IsDlgButtonChecked(IDC_DONTSHOWAGAIN));
}
