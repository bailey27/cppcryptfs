
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


// cppcryptfs.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "cryptdefs.h"
#include "CryptPropertySheet.h"
#include "MountPropertyPage.h"
#include "CreatePropertyPage.h"
#include "CryptAboutPropertyPage.h"
#include "RecentItems.h"
#include "TrayIcon.h"
#include "cryptdokan.h"


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

	m_mountedDrives = 0;

	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CcppcryptfsApp object

CcppcryptfsApp theApp;


// CcppcryptfsApp initialization



BOOL CcppcryptfsApp::InitInstance()
{

	CString UniqueNamedMutex = L"cppcryptfs-A7DDB0CF-A856-4E8A-A4E9-722473FB5E49";

	if (have_security_name_privilege())
		UniqueNamedMutex += L"-admin";

	HANDLE hAppMutex = CreateMutex(NULL, TRUE, UniqueNamedMutex);
	if (GetLastError() == ERROR_ALREADY_EXISTS)
	{
		// Program already running somewhere
		::MessageBox(NULL, L"cppcryptfs is already running!", L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
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
	SetRegistryKey(_T("Local AppWizard-Generated Applications"));



	CCryptPropertySheet dlg(L"cppcryptfs");

	dlg.m_psh.dwFlags |= PSH_NOAPPLYNOW;
	dlg.m_psh.dwFlags &= ~PSH_HASHELP;

	CMountPropertyPage mount;

	mount.m_psp.dwFlags &= ~PSP_HASHELP;

	RecentItems ritems(TEXT("Folders"), TEXT("LastDir"), mount.m_numLastDirs);

	ritems.Populate(mount.m_lastDirs, TEXT("C:\\"));

	dlg.AddPage(&mount);

	CCreatePropertyPage create;

	create.m_psp.dwFlags &= ~PSP_HASHELP;

	RecentItems ritems2(TEXT("Folders"), TEXT("LastDir"), create.m_numLastDirs);

	ritems2.Populate(create.m_lastDirs, TEXT("C:\\"));

	dlg.AddPage(&create);

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
	ReleaseMutex(hAppMutex); // Explicitly release mutex
	CloseHandle(hAppMutex); // close handle before terminating

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}

