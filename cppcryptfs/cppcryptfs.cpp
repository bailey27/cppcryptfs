
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


// cppcryptfs.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "crypt/cryptdefs.h"
#include "ui/CryptPropertySheet.h"
#include "ui/MountPropertyPage.h"
#include "ui/CreatePropertyPage.h"
#include "ui/SettingsPropertyPage.h"
#include "ui/CryptAboutPropertyPage.h"
#include "ui/RecentItems.h"
#include "ui/TrayIcon.h"
#include "dokan/cryptdokan.h"
#include "util/getopt.h"
#include "util/LockZeroBuffer.h"
#include "util/util.h"
#include "crypt/crypt.h"
#include "file/iobufferpool.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CcppcryptfsApp

BEGIN_MESSAGE_MAP(CcppcryptfsApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CcppcryptfsApp construction

CcppcryptfsApp::CcppcryptfsApp()
{
	// support Restart Manager
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: add construction code here,
	// Place all significant initialization in InitInstance

	m_mountedLetters = 0;

	// get an OpenSSL EVP context to force detection of AES-NI instructions
	// so we can use AES-NI even if EVP is never used

	void *context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);

	if (context)
		free_crypt_context(context);
}


// The one and only CcppcryptfsApp object

CcppcryptfsApp theApp;


// CcppcryptfsApp initialization




BOOL CcppcryptfsApp::InitInstance()
{	 

	const WCHAR *szUniqueNamedMutex = L"cppcryptfs-A7DDB0CF-A856-4E8A-A4E9-722473FB5E49";

	HANDLE hAppMutex = CreateMutex(NULL, TRUE, szUniqueNamedMutex);
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		// Program already running - but hAppMutex is NOT NULL.
		// Aparently it is not necessary to close it in this case.

		// Do something and then return FALSE to exit the app.

		// we can't use classname because our main window is a PropertySheet and has 
		// class name "DIALOG".  I've seen info about how to change the class
		// name of a dialog-based app, but not for one based on a PropertySheet
		// TODO - it may be possible to use a custom class name

		// currently use "#32770" for the class (which is the class string for generic dialog boxes)

		HWND hWnd = FindWindow(L"#32770", L"cppcryptfs");

		if (hWnd) {
			if (have_args()) {
				static_assert(sizeof(WCHAR) == sizeof(wchar_t), "sizeof(WCHAR) != sizeof(wchar_t).");
				COPYDATASTRUCT cd;
				memset(&cd, 0, sizeof(cd));
				cd.dwData = CPPCRYPTFS_COPYDATA_CMDLINE;
				LPCWSTR cmdLine = GetCommandLineW();
				size_t cmdLineLen = wcslen(cmdLine);
				size_t dataLen = sizeof(CopyDataCmdLine) + cmdLineLen*sizeof(WCHAR); // WCHAR in CmdLineCopyData accounts for null terminator
				if (dataLen <= CPPCRYPTFS_COPYDATA_CMDLINE_MAXLEN) {
					cd.cbData = (DWORD)dataLen;
					LockZeroBuffer<BYTE> buf(cd.cbData);
					if (buf.IsLocked()) {
						CopyDataCmdLine *pcd = (CopyDataCmdLine*)buf.m_buf;
						pcd->dwPid = getppid();
						cd.lpData = (PVOID)pcd;
						if (wcscpy_s(pcd->szCmdLine, cmdLineLen + 1, cmdLine) == 0) {
							SetLastError(0);
							SendMessageW(hWnd, WM_COPYDATA, NULL, (LPARAM)&cd);
							DWORD dwErr = GetLastError();
							if (dwErr) {
								if (dwErr == ERROR_ACCESS_DENIED) {
									ConsoleErrMes(L"SendMessage() returned error \"access denied\".\n\nPerhaps there is"
										" already an instance of cppcryptfs running with administrator\nprivileges, but"
										" you invoked this instance of cppcryptfs from a command prompt\nthat is not running"
										" with administrator privileges.\n\nIf this is the case, then you should start a"
										" CMD.exe window using\n\"Run as administrator\" and invoke cppcryptfs from within it.");
								} else {
									WCHAR buf[80];
									_snwprintf_s(buf, _TRUNCATE, L"SendMessage() returned error code %u", dwErr);
									ConsoleErrMes(buf);
								}
							}
						}
					} else {
						ConsoleErrMes(L"unable to lock command line buffer in source");
					}
				} else {
					ConsoleErrMes(L"command line too long");
				}
			} else {
				ShowWindow(hWnd, SW_SHOWNORMAL);
			}
		} else {
			::MessageBox(NULL, L"cppcryptfs is already running!", L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		}
		
		return FALSE;
	}


	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


	AfxEnableControlContainer();

	// Create the shell manager, in case the dialog contains
	// any shell tree view or shell list view controls.
	CShellManager *pShellManager = new CShellManager;

	// Activate "Windows Native" visual manager for enabling themes in MFC controls
	CMFCVisualManager::SetDefaultManager(RUNTIME_CLASS(CMFCVisualManagerWindows));

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	SetRegistryKey(_T("cppcryptfs"));



	CCryptPropertySheet dlg(L"cppcryptfs");

	dlg.m_psh.dwFlags |= PSH_NOAPPLYNOW;
	dlg.m_psh.dwFlags &= ~PSH_HASHELP;

	CMountPropertyPage mount;

	mount.m_psp.dwFlags &= ~PSP_HASHELP;

	RecentItems ritems(TEXT("Folders"), TEXT("LastDir"), mount.m_numLastDirs);

	ritems.Populate(mount.m_lastDirs, TEXT("C:\\"));

	RecentItems ritems4(TEXT("ConfigPaths"), TEXT("LastConfig"), mount.m_numLastConfigs);

	ritems4.Populate(mount.m_lastConfigs, TEXT("C:\\"));

	dlg.AddPage(&mount);

	dlg.m_nMountPageIndex = dlg.GetPageCount() - 1;

	CCreatePropertyPage create;

	create.m_psp.dwFlags &= ~PSP_HASHELP;

	RecentItems ritems2(TEXT("Folders"), TEXT("LastDir"), create.m_numLastDirs);

	ritems2.Populate(create.m_lastDirs, TEXT("C:\\"));

	RecentItems ritems3(TEXT("ConfigPaths"), TEXT("LastConfig"), create.m_numLastConfigs);

	ritems3.Populate(create.m_lastConfigs, TEXT("C:\\"));

	dlg.AddPage(&create);

	CSettingsPropertyPage settings;

	settings.m_psp.dwFlags &= ~PSP_HASHELP;

	dlg.AddPage(&settings);

	CCryptAboutPropertyPage about;

	about.m_psp.dwFlags &= ~PSP_HASHELP;

	dlg.AddPage(&about);

	m_pMainWnd = &dlg;

	HICON hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

	CMenuTrayIcon TI(L"cppcryptfs", hIcon, IDR_PopUps, ID_IDR_SHOWCPPCRYPTFS);

	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}
	else if (nResponse == -1)
	{
		TRACE(traceAppMsg, 0, "Warning: dialog creation failed, so application is terminating unexpectedly.\n");
		TRACE(traceAppMsg, 0, "Warning: if you are using MFC controls on the dialog, you cannot #define _AFX_NO_MFC_CONTROLS_IN_DIALOGS.\n");
	}

	// Delete the shell manager created above.
	if (pShellManager != NULL)
	{
		delete pShellManager;
	}

	// Upon app closing:
	if (hAppMutex) {
		ReleaseMutex(hAppMutex); // Explicitly release mutex
		CloseHandle(hAppMutex); // close handle before terminating
	}

	if (g_IoBufferPool)
		delete g_IoBufferPool;

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.

	return FALSE;
}

