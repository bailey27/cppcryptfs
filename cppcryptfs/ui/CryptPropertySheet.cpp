/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2020 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include <Dbt.h>
#include "cppcryptfs.h"
#include "../libipc/server.h"
#include "../libipc/certutil.h"
#include "CryptPropertySheet.h"
#include "CryptPropertyPage.h"
#include "dokan/cryptdokan.h"
#include "util/LockZeroBuffer.h"
#include "util/util.h"
#include "dokan/MountPointManager.h"
#include "ui/uiutil.h"
#include "crypt/crypt.h"

// CryptPropertySheet

IMPLEMENT_DYNAMIC(CCryptPropertySheet, CPropertySheet)

CCryptPropertySheet::CCryptPropertySheet(UINT nIDCaption, CWnd* pParentWnd, UINT iSelectPage)
	:CPropertySheet(nIDCaption, pParentWnd, iSelectPage)
{
	m_nMountPageIndex = 0;
	m_bHideAfterInit = FALSE;
	m_psh.dwFlags |= PSH_NOAPPLYNOW;
	m_psh.dwFlags &= ~PSH_HASHELP;
}

CCryptPropertySheet::CCryptPropertySheet(LPCTSTR pszCaption, CWnd* pParentWnd, UINT iSelectPage)
	:CPropertySheet(pszCaption, pParentWnd, iSelectPage)
{
	m_nMountPageIndex = 0;
	m_bHideAfterInit = FALSE;
	m_psh.dwFlags |= PSH_NOAPPLYNOW;
	m_psh.dwFlags &= ~PSH_HASHELP;
}

CCryptPropertySheet::~CCryptPropertySheet()
{
}

BOOL CCryptPropertySheet::CanClose()
{
	if (!MountPointManager::getInstance().empty()) {
		
		if (MessageBox(L"All mounted cppcryptfs filesystems will be dismounted. Do you really wish to exit?", L"cppcryptfs",
			MB_YESNO | MB_ICONEXCLAMATION) == IDYES) {

			int i;
			for (i = 0; i < 26; i++) {
				if (theApp.m_mountedLetters & (1<<i)) {
					wstring mes;
					write_volume_name_if_changed(i + 'A', mes);
				}
			}
			unmount_all(false);
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
	ON_WM_DEVICECHANGE()
//	ON_WM_QUERYENDSESSION()
ON_WM_ENDSESSION()
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

	if (CanClose()) {
		
		int pageCount = GetPageCount();
		for (int i = 0; i < pageCount; i++) {
			CCryptPropertyPage *page = (CCryptPropertyPage*)GetPage(i);
			if (page)
				page->OnExit();
		}
		EndDialog(IDCLOSE);
	}
}




INT_PTR CCryptPropertySheet::DoModal()
{
	// TODO: Add your specialized code here and/or call the base class
	
	return CPropertySheet::DoModal();
	
}

BOOL CCryptPropertySheet::OnCopyData(CWnd* pWnd, COPYDATASTRUCT* pCopyDataStruct)
{
	// TODO: Add your message handler code here and/or call default

	if (pCopyDataStruct && 
		pCopyDataStruct->dwData == CPPCRYPTFS_COPYDATA_PIPE &&
		pCopyDataStruct->cbData == sizeof(HANDLE)) {

		auto hPipe = *reinterpret_cast<HANDLE*>(pCopyDataStruct->lpData);

		DWORD client_process_id = 0;

		if (!GetNamedPipeClientProcessId(hPipe, &client_process_id)) {
			return FALSE;
		}

		if (!ValidateNamedPipeConnection(client_process_id)) {
			CloseHandle(hPipe);
			return FALSE;
		}

		CCryptPropertyPage *page = (CCryptPropertyPage*)GetPage(m_nMountPageIndex);

		if (page) {
			
			LockZeroBuffer<WCHAR> cmdLine(CMD_PIPE_MAX_ARGS_LEN, false, nullptr);
			if (!cmdLine.IsLocked()) {
				MessageBox(L"unable to lock command line buffer", L"cppcryptfs", MB_ICONERROR | MB_OK);
				return FALSE;
			}
			if (auto args = ReadFromNamedPipe(hPipe, cmdLine.m_buf, cmdLine.m_len)) {
				page->ProcessCommandLine(args, FALSE, hPipe);
				return TRUE;
			} else {
				ConsoleErrMesPipe(L"unable to read command line", hPipe);
				return FALSE;
			}
		} else {
			ConsoleErrMesPipe(L"unable to get mount page", hPipe);
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


BOOL CCryptPropertySheet::OnDeviceChange( UINT nEventType, DWORD_PTR dwData )
{
	if (nEventType == DBT_DEVICEARRIVAL || nEventType == DBT_DEVICEREMOVECOMPLETE) {

		PDEV_BROADCAST_HDR pHdr = (PDEV_BROADCAST_HDR)dwData;

		if (pHdr->dbch_devicetype == DBT_DEVTYP_VOLUME) {
			PDEV_BROADCAST_VOLUME pVolHdr = (PDEV_BROADCAST_VOLUME)dwData;
			if ((pVolHdr->dbcv_unitmask & theApp.m_mountedLetters) != pVolHdr->dbcv_unitmask) {
				CCryptPropertyPage *page = (CCryptPropertyPage*)GetPage(m_nMountPageIndex);
				if (page)
					page->DeviceChange();
			}
		}
	}

	return CPropertySheet::OnDeviceChange(nEventType, dwData);
}


void CCryptPropertySheet::OnEndSession(BOOL bEnding)
{
	CPropertySheet::OnEndSession(bEnding);

	if (bEnding) {
		unmount_all(false);
		wait_for_all_unmounted();
	}
}
