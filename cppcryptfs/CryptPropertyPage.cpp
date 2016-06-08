// CryptPropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "CryptPropertyPage.h"
#include "afxdialogex.h"


// CCryptPropertyPage dialog

IMPLEMENT_DYNAMIC(CCryptPropertyPage, CPropertyPage)

CCryptPropertyPage::CCryptPropertyPage()
	: CPropertyPage(IDD_CRYPTPROPERTYPAGE)
{

}

CCryptPropertyPage::CCryptPropertyPage(int id)
	: CPropertyPage(id)
{
	
}

CCryptPropertyPage::~CCryptPropertyPage()
{
}

void CCryptPropertyPage::DefaultAction()
{
}

void CCryptPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CCryptPropertyPage, CPropertyPage)
END_MESSAGE_MAP()


// CCryptPropertyPage message handlers
