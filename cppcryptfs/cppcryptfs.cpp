
/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2025 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include <iostream>
#include "cppcryptfs.h"
#include "dokan/cryptdokan.h"
#include "crypt/cryptdefs.h"
#include "ui/CryptPropertySheet.h"
#include "ui/MountPropertyPage.h"
#include "ui/CreatePropertyPage.h"
#include "ui/SettingsPropertyPage.h"
#include "ui/MoreSettingsPropertyPage.h"
#include "ui/CryptAboutPropertyPage.h"
#include "ui/RecentItems.h"
#include "ui/TrayIcon.h"
#include "dokan/cryptdokan.h"
#include "util/getopt.h"
#include "util/LockZeroBuffer.h"
#include "../libcommonutil/commonutil.h"
#include "util/util.h"
#include "crypt/crypt.h"
#include "ui/uiutil.h"
#include "../libipc/server.h"
#include "../libipc/client.h"
#include "ui/locutils.h"


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
	m_bIsRunningAsAdministrator = ::IsRunningAsAdministrator(&m_bIsReallyAdministrator);

	// support Restart Manager
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: add construction code here,
	// Place all significant initialization in InitInstance

	// get a shared ptr to an OpenSSL EVP context to force detection of AES-NI instructions
	// so we can use AES-NI even if EVP is never used

	auto context = get_crypt_context(BLOCK_IV_LEN, AES_MODE_GCM);	
}

// Callback function for searching language sections in the EXE string block
BOOL CALLBACK EnumLangsCallback(HMODULE hModule, LPCTSTR lpType, LPCTSTR lpName, WORD wLang, LONG_PTR lParam) {
    auto* pList = reinterpret_cast<std::vector<LanguageOption>*>(lParam);
    
	// Exclude duplicates when scanning String Table blocks
    for (const auto& item : *pList) { 
        if (item.langID == wLang) return TRUE; 
    }

    LanguageOption opt;
    opt.langID = wLang;
	// Extract language names
    opt.name = theApp.GetStringForLang(hModule, IDS_LANGUAGE_NAME, wLang);

    if (!opt.name.IsEmpty()) {
        pList->push_back(opt);
    }
    return TRUE;
}

// Scan EXE resources for translated sections
void CcppcryptfsApp::ScanResourcesForLanguages() {
	m_vAvailableLangs.clear();
	// (IDS_LANGUAGE_NAME >> 4) + 1 - formula for calculating the block number in String Table
	EnumResourceLanguages(NULL, RT_STRING, MAKEINTRESOURCE((IDS_LANGUAGE_NAME >> 4) + 1),
		EnumLangsCallback, (LONG_PTR)&m_vAvailableLangs);
}

// Direct reading of a string from a specific language section (bypassing the current thread locale)
CString CcppcryptfsApp::GetStringForLang(HMODULE hInst, UINT nID, WORD wLang) {
	HRSRC hRes = FindResourceEx(hInst, RT_STRING, MAKEINTRESOURCE((nID >> 4) + 1), wLang);
	if (!hRes) return _T("");

	HGLOBAL hGlobal = LoadResource(hInst, hRes);
	DWORD resourceSize = SizeofResource(hInst, hRes);

	LPWSTR pData = (LPWSTR)LockResource(hGlobal);
	LPWSTR pResourceEnd = (LPWSTR)((LPBYTE)pData + resourceSize);

	if (!pData || resourceSize < sizeof(WCHAR)) return _T("");

	int nIndex = nID & 0x000F;
	for (int i = 0; i < nIndex; i++) {
		if (pData >= pResourceEnd) return _T("");  // Out of bounds

		DWORD stringLen = *pData;
		if (stringLen > 0xFFFF) return _T("");     // Unreasonable length
		if ((LPBYTE)pData + (stringLen + 1) * sizeof(WCHAR) > (LPBYTE)pResourceEnd)
			return _T("");                         // Exceeds boundary

		pData += stringLen + 1;
	}

	if (pData >= pResourceEnd) return _T("");
	DWORD finalLen = *pData;
	if (finalLen == 0) return _T("");

	return CString(pData + 1, (int)min(finalLen, MAXINT));
}

// Check: does this language exist in the resources (protection against outdated registry entries)
bool CcppcryptfsApp::IsLanguageAvailable(WORD wLangID) {
	for (const auto& opt : m_vAvailableLangs) {
		if (opt.langID == wLangID) return true;
	}
	return false;
}

// Saving user selection to the registry
void CcppcryptfsApp::SaveLanguageToRegistry(WORD wLangID) {
	WriteProfileInt(_T("Settings"), _T("LanguageID"), (int)wLangID);
}

// Reading the selection from the registry (0 - if the entry does not exist)
WORD CcppcryptfsApp::LoadLanguageFromRegistry() {
	return (WORD)GetProfileInt(_T("Settings"), _T("LanguageID"), 0);
}


// The one and only CcppcryptfsApp object

CcppcryptfsApp theApp;




static void NamedPipeServerCallback(void* ctx, HANDLE hPipe) 
{
	auto pApp = reinterpret_cast<CcppcryptfsApp*>(ctx);

	pApp->SendCmdArgsToSelf(hPipe);
}

static bool StartNamedPipeServer()
{
	static NamedPipeServerContext ctx;

	ctx.context = &theApp;
	ctx.callback = NamedPipeServerCallback;

	auto hThread = CreateThread(NULL, 0, NamedPipeServerThreadProc, &ctx, 0, NULL);

	if (hThread != NULL)
		CloseHandle(hThread);

	return hThread != NULL;
}

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

				bool have_console = OpenConsole(0); 

				wstring err_mes;
				wstring result;

				if (SendArgsToRunningInstance(GetCommandLine(), result, err_mes)) {
					if (err_mes.length() > 0)
						err_mes += L"\n";
					else
						err_mes = L"cppcryptfsctl: Unable to send command. Is cppcryptfs really already running?\n";
				} else {
					if (result.length() >= CMD_PIPE_RESPONSE_LENGTH) {
						if (wcsncmp(result.c_str(), CMD_PIPE_SUCCESS_STR, CMD_PIPE_RESPONSE_LENGTH) == 0) {
							wstring mes = result.c_str() + CMD_PIPE_RESPONSE_LENGTH;
							if (mes.length() > 0) {
								if (have_console)
									wcout << mes << endl;
								else
									::MessageBox(NULL, mes.c_str(), L"cppcryptfs", MB_OK);
							}
						} else {
							err_mes = wstring(result.c_str() + CMD_PIPE_RESPONSE_LENGTH);
						}
					} else {
						err_mes = L"cppcryptfs: got a mal-formed response from running instance of cppcryptfs\n";
					}
				}

				if (err_mes.length() > 0) {
					if (have_console) {
						wcerr << err_mes;
					} else {
						::MessageBox(NULL, err_mes.c_str(), L"cppcryptfs", MB_ICONERROR | MB_OK);
					}
				}

				if (have_console)
					CloseConsole();
				
			} else { // if no args, then restore window of running instance
				ShowWindow(hWnd, SW_SHOWNORMAL);
			}
		} else {
			::MessageBox(NULL, LocUtils::GetStringFromResources(IDS_RUN_WINDOW_NOT_FOUND).c_str(), L"cppcryptfs", MB_OK | MB_ICONERROR);
		}
		
		return FALSE;
	} else {
		wstring mes;
		bool dokVerCheck = check_dokany_version(mes);
		if (!dokVerCheck && mes.length() < 1) {
			mes = LocUtils::GetStringFromResources(IDS_PROBLEM_DOKANY_VERSION);
		}
		if (mes.length()) {
			::MessageBox(NULL, mes.c_str(), L"cppcryptfs", MB_OK | (dokVerCheck ? MB_ICONEXCLAMATION :  MB_ICONERROR));
		}
		if (!dokVerCheck) {
			return FALSE;
		}
	}	

	StartNamedPipeServer();

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

	ScanResourcesForLanguages();
	WORD wSavedID = LoadLanguageFromRegistry();

	// Apply the language only if it is found in the EXE (protection against "junk" in the registry)
	if (wSavedID != 0 && IsLanguageAvailable(wSavedID)) {
		SetThreadUILanguage(wSavedID);
		SetThreadLocale(MAKELCID(wSavedID, SORT_DEFAULT));
	}
	// for FindResource to work correctly in MFC
	AfxSetResourceHandle(GetModuleHandle(NULL));

	CCryptPropertySheet dlg(L"cppcryptfs");

	CMountPropertyPage mount;

	RecentItems ritems(CPPCRYPTFS_FOLDERS_SECTION, TEXT("LastDir"), mount.m_numLastDirs);

	ritems.Populate(mount.m_lastDirs, TEXT("C:\\"));

	RecentItems ritems4(CPPCRYPTFS_CONFIGPATHS_SECTION, TEXT("LastConfig"), mount.m_numLastConfigs);

	ritems4.Populate(mount.m_lastConfigs, TEXT("C:\\"));

	dlg.AddPage(&mount);

	dlg.m_nMountPageIndex = dlg.GetPageCount() - 1;

	CCreatePropertyPage create;

	RecentItems ritems2(CPPCRYPTFS_FOLDERS_SECTION, TEXT("LastDir"), create.m_numLastDirs);

	ritems2.Populate(create.m_lastDirs, TEXT("C:\\"));

	RecentItems ritems3(CPPCRYPTFS_CONFIGPATHS_SECTION, TEXT("LastConfig"), create.m_numLastConfigs);

	ritems3.Populate(create.m_lastConfigs, TEXT("C:\\"));

	dlg.AddPage(&create);

	CSettingsPropertyPage settings;

	dlg.AddPage(&settings);

	CMoreSettingsPropertyPage more_settings;

	dlg.AddPage(&more_settings);

	CCryptAboutPropertyPage about;

	dlg.AddPage(&about);

	m_pMainWnd = &dlg;

	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);

	RecreateSystemTrayIcon();

	crypt_at_start();

	INT_PTR nResponse = dlg.DoModal();

	m_system_tray_icon = nullptr;

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

	// any at app exit cleanup of the encryted filesystems occurs here
	crypt_at_exit();

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.

	return FALSE;
}

void CcppcryptfsApp::RecreateSystemTrayIcon()
{
	// Destroy it first in case there's any singleton behavior with the CMenuTrayIcon class or anything that
	// replaces it in the future.
	m_system_tray_icon.reset(); 

	m_system_tray_icon = make_shared<CMenuTrayIcon>(L"cppcryptfs", m_hIcon, IDR_PopUps, ID_IDR_SHOWCPPCRYPTFS);
}

BOOL CcppcryptfsApp::WriteProfileInt(LPCWSTR section, LPCWSTR entry, INT val)
{
	if (lstrcmpi(section, CryptSettingsRegValName) && NeverSaveHistory()) {
		return TRUE;
	}

	return CWinApp::WriteProfileInt(section, entry, val);
}

BOOL CcppcryptfsApp::WriteProfileString(LPCWSTR section, LPCWSTR entry, LPCWSTR val)
{
	if (lstrcmpi(section, CryptSettingsRegValName) && NeverSaveHistory()) {
		return TRUE;
	}

	return CWinApp::WriteProfileString(section, entry, val);
}

BOOL CcppcryptfsApp::WriteProfileBinary(LPCWSTR section, LPCWSTR entry, LPBYTE pData, UINT nBytes)
{
	if (lstrcmpi(section, CryptSettingsRegValName) && NeverSaveHistory()) {
		return TRUE;
	}

	return CWinApp::WriteProfileBinary(section, entry, pData, nBytes);
}


void CcppcryptfsApp::SendCmdArgsToSelf(HANDLE hPipe)
{

	HWND hWnd = ::FindWindow(L"#32770", L"cppcryptfs");
	if (!hWnd)
		return;

	DWORD win_proc_id = 0;

	GetWindowThreadProcessId(hWnd, &win_proc_id);

	if (win_proc_id != ::GetCurrentProcessId())
		return;

	static_assert(sizeof(WCHAR) == sizeof(wchar_t), "sizeof(WCHAR) != sizeof(wchar_t).");
	COPYDATASTRUCT cd;
	memset(&cd, 0, sizeof(cd));
	cd.dwData = CPPCRYPTFS_COPYDATA_PIPE;

	std::vector<HANDLE> pipe_v;

	pipe_v.push_back(hPipe);
	
	cd.cbData =static_cast<DWORD>(sizeof(hPipe));
	
	cd.lpData = static_cast<PVOID>(&pipe_v[0]);
	
	SetLastError(0);
	SendMessageW(hWnd, WM_COPYDATA, NULL, (LPARAM)&cd);
	DWORD dwErr = GetLastError();
	if (dwErr) {
		if (dwErr == ERROR_ACCESS_DENIED) {
			ConsoleErrMesPipe(L"SendMessage() returned error \"access denied\".\n\nPerhaps there is"
				" already an instance of cppcryptfs running with administrator\nprivileges, but"
				" you invoked this instance of cppcryptfs from a command prompt\nthat is not running"
				" with administrator privileges.\n\nIf this is the case, then you should start a"
				" CMD.exe window using\n\"Run as administrator\" and invoke cppcryptfs from within it.", hPipe);
		} else {
			WCHAR buf[80];
			_snwprintf_s(buf, _TRUNCATE, L"SendMessage() returned error code %u", dwErr);
			ConsoleErrMesPipe(buf, hPipe);
		}
	}
				
}

