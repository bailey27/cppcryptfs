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

// CryptPropertySheet.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "CryptPropertySheet.h"
#include "CryptPropertyPage.h"
#include "cryptdokan.h"

// CryptPropertySheet

IMPLEMENT_DYNAMIC(CCryptPropertySheet, CPropertySheet)

CCryptPropertySheet::CCryptPropertySheet(UINT nIDCaption, CWnd* pParentWnd, UINT iSelectPage)
	:CPropertySheet(nIDCaption, pParentWnd, iSelectPage)
{
	m_bHideAfterInit = FALSE;
}

CCryptPropertySheet::CCryptPropertySheet(LPCTSTR pszCaption, CWnd* pParentWnd, UINT iSelectPage)
	:CPropertySheet(pszCaption, pParentWnd, iSelectPage)
{
	m_bHideAfterInit = FALSE;
}

CCryptPropertySheet::~CCryptPropertySheet()
{
}

BOOL CCryptPropertySheet::CanClose()
{
	if (theApp.m_mountedDrives) {
		if (MessageBox(L"All mounted cppcryptfs filesystems will be dismounted. Do you really wish to exit?", L"cppcryptfs",
			MB_YESNO | MB_ICONEXCLAMATION) == IDYES) {
			int i;
			for (i = 0; i < 26; i++) {
				if (theApp.m_mountedDrives & (1<<i)) {
					write_volume_name_if_changed(i + 'A');
					unmount_crypt_fs(i + 'A', false);
				}
			}
			theApp.DoWaitCursor(1);
			wait_for_all_unmounted();
			theApp.DoWaitCursor(-1);
			return TRUE;
		} else {
			return FALSE;
		}
	} else {
		return TRUE;
	}
}


BEGIN_MESSAGE_MAP(CCryptPropertySheet, CPropertySheet)
	ON_WM_NCCREATE()
	ON_WM_SYSCOMMAND()
	ON_COMMAND(ID_IDR_SHOWCPPCRYPTFS, &CCryptPropertySheet::OnIdrShowcppcryptfs)
	ON_COMMAND(ID_IDR_EXITCPPCRYPTFS, &CCryptPropertySheet::OnIdrExitcppcryptfs)
	ON_WM_CLOSE()
	ON_WM_COPYDATA()
	ON_WM_WINDOWPOSCHANGING()
END_MESSAGE_MAP()


// CryptPropertySheet message handlers


BOOL CCryptPropertySheet::OnInitDialog()
{

	BOOL bResult = CPropertySheet::OnInitDialog();

	// TODO:  Add your specialized code here

	CWnd *pWnd;

	pWnd = GetDlgItem(IDOK);

	if (pWnd)
		pWnd->ShowWindow(SW_HIDE);

	pWnd = GetDlgItem(IDCANCEL);

	if (pWnd)
		pWnd->ShowWindow(SW_HIDE);


	return bResult;
}


BOOL CCryptPropertySheet::OnCommand(WPARAM wParam, LPARAM lParam)
{
	// TODO: Add your specialized code here and/or call the base class
	
	CCryptPropertyPage *page = NULL;

	switch (wParam & 0xffff) { // prevent pressing ENTER or ESC from closing dialog
	case IDOK:
		page = (CCryptPropertyPage*)GetActivePage();
		if (page) {
			page->DefaultAction();
		}
		return 1;
	case IDCANCEL:
		return 1;
	default:
		break;
	}
	return CPropertySheet::OnCommand(wParam, lParam);
}


BOOL CCryptPropertySheet::OnNcCreate(LPCREATESTRUCT lpCreateStruct)
{

	if (!CPropertySheet::OnNcCreate(lpCreateStruct))
		return FALSE;

	// TODO:  Add your specialized creation code here

	// Modify the window style
	LONG dwStyle = ::GetWindowLong(m_hWnd, GWL_STYLE);
	::SetWindowLong(m_hWnd, GWL_STYLE, dwStyle | WS_MINIMIZEBOX | 0*WS_MAXIMIZEBOX);

	return TRUE;
}


void CCryptPropertySheet::OnSysCommand(UINT nID, LPARAM lParam)
{
	// TODO: Add your message handler code here and/or call default

	switch (nID & 0xFFF0) {
	case SC_CLOSE:
		if (lParam) ShowWindow(SW_HIDE); else SetForegroundWindow(); return;
		break;
	//case IDM_ABOUTBOX: CAboutDlg().DoModal();    return; // This line is only for a Dialog Application with an About Box.
	default: CPropertySheet::OnSysCommand(nID, lParam); return;

	}
}


void CCryptPropertySheet::OnIdrShowcppcryptfs()
{
	// TODO: Add your command handler code here

	m_bHideAfterInit = FALSE;

	theApp.m_pMainWnd->ShowWindow(SW_SHOW);

}


void CCryptPropertySheet::OnIdrExitcppcryptfs()
{
	// TODO: Add your command handler code here

	if (CanClose())
		EndDialog(IDCLOSE);
}




INT_PTR CCryptPropertySheet::DoModal()
{
	// TODO: Add your specialized code here and/or call the base class
	
	return CPropertySheet::DoModal();
	
}


BOOL CCryptPropertySheet::OnCopyData(CWnd* pWnd, COPYDATASTRUCT* pCopyDataStruct)
{
	// TODO: Add your message handler code here and/or call default

	if (pCopyDataStruct && pCopyDataStruct->dwData == CPPCRYPTFS_COPYDATA_CMDLINE) {
		CCryptPropertyPage *page = (CCryptPropertyPage*)GetPage(0);
		if (page) {
			page->ProcessCommandLine(*(LPDWORD)pCopyDataStruct->lpData, (LPCTSTR)((BYTE*)pCopyDataStruct->lpData+sizeof(DWORD)));
			return TRUE;
		} else {
			return FALSE;
		}
	} else {
		return CPropertySheet::OnCopyData(pWnd, pCopyDataStruct);
	}
}


void CCryptPropertySheet::OnWindowPosChanging(WINDOWPOS* lpwndpos)
{
	
	if (this->m_bHideAfterInit)
		lpwndpos->flags &= ~SWP_SHOWWINDOW;

	CPropertySheet::OnWindowPosChanging(lpwndpos);

	// TODO: Add your message handler code here
}
