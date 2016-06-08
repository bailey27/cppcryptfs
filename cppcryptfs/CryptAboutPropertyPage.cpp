// CryptAboutPropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "CryptAboutPropertyPage.h"
#include "afxdialogex.h"


// CCryptAboutPropertyPage dialog

IMPLEMENT_DYNAMIC(CCryptAboutPropertyPage, CCryptPropertyPage)

CCryptAboutPropertyPage::CCryptAboutPropertyPage()
	: CCryptPropertyPage(IDD_ABOUTBOX)
{

}

CCryptAboutPropertyPage::~CCryptAboutPropertyPage()
{
}

void CCryptAboutPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CCryptPropertyPage::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CCryptAboutPropertyPage, CCryptPropertyPage)
	ON_EN_CHANGE(IDC_INFO, &CCryptAboutPropertyPage::OnEnChangeInfo)
	ON_EN_SETFOCUS(IDC_INFO, &CCryptAboutPropertyPage::OnSetfocusInfo)
END_MESSAGE_MAP()


// CCryptAboutPropertyPage message handlers


BOOL CCryptAboutPropertyPage::OnInitDialog()
{
	CCryptPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here

	const WCHAR *info_text =

		L"The MIT License (MIT)"
		L"\r\n\r\n"
		L"Permission is hereby granted, free of charge, to any person obtaining a copy"
		L"of this software and associated documentation files (the \"Software\"), to deal"
		L"in the Software without restriction, including without limitation the rights"
		L"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell"
		L"copies of the Software, and to permit persons to whom the Software is"
		L"furnished to do so, subject to the following conditions:"
		L"\r\n\r\n"
		L"The above copyright notice and this permission notice shall be included in"
		L"all copies or substantial portions of the Software."
		L"\r\n\r\n"
		L"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR"
		L"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,"
		L"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE"
		L"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER"
		L"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,"
		L"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN"
		L"THE SOFTWARE."
		L"";



	CWnd *pWnd = GetDlgItem(IDC_INFO);

	if (pWnd) {
		pWnd->SetWindowTextW(info_text);
		pWnd->PostMessageW(WM_CLEAR, 0, 0);
	}

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


void CCryptAboutPropertyPage::OnEnChangeInfo()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CCryptPropertyPage::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
}


void CCryptAboutPropertyPage::OnSetfocusInfo()
{
	// TODO: Add your control notification handler code here

	CEdit *pWnd = (CEdit*)GetDlgItem(IDC_INFO);

	if (!pWnd)
		return;

	pWnd->SetSel(-1, 0, TRUE);


}
