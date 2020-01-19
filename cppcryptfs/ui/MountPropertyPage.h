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

#pragma once

#include "CryptPropertyPage.h"
#include "SecureEdit.h"

#define DL_INDEX 0
#define PATH_INDEX 1

// helper class for responses to command line usage
class OutputHandler {
private:
	bool m_have_console;
	wstring m_output_str;
	vector<wchar_t> m_buf;
	HANDLE m_hPipe = INVALID_HANDLE_VALUE;
public:
	OutputHandler(HANDLE hPipe);
	virtual ~OutputHandler();
	bool have_pipe() { return m_hPipe != INVALID_HANDLE_VALUE && m_hPipe != NULL; }
	int print(int type, const wchar_t* fmt, ...);
};

// CMountPropertyPage dialog

class CMountPropertyPage : public CCryptPropertyPage
{
	DECLARE_DYNAMIC(CMountPropertyPage)

private:
	static  void HandleTooltipsActivation(MSG *pMsg, CWnd *This, CWnd *disabledCtrls[], int numOfCtrls, CToolTipCtrl *pTooltip);
	int OpenFileExplorer(const CString& mp);
protected:
	CToolTipCtrl m_ToolTip;
	void AddMountPoint(const CString& path);
	void GetMountPoints(CStringArray& mountPoints); // builds array of all mountpoints inclding available drive letters
	void DeleteMountPoint(int item);
public:
	// disallow copying
	CMountPropertyPage(CMountPropertyPage const&) = delete;
	void operator=(CMountPropertyPage const&) = delete;

	CMountPropertyPage();
	virtual ~CMountPropertyPage();

	CString m_lastDirs[10];
	CString m_lastConfigs[10];
	const int m_numLastDirs = 10;
	const int m_numLastConfigs = 10;
	CImageList m_imageList;
	int m_imageIndex;

public:
	virtual void DefaultAction();

	virtual void ProcessCommandLine(LPCWSTR szCmd, BOOL bOnStartup = FALSE, HANDLE hPipe = INVALID_HANDLE_VALUE) override;

	virtual void DeviceChange() override;

	CString Mount(LPCWSTR argPath = NULL, LPCWSTR argMountPoint = NULL, LPCWSTR argPassword = NULL, bool argReadOnly = false, LPCWSTR argConfigPath = NULL, bool argReverse = false);

	CString Dismount(LPCWSTR argMountPoint = NULL);

	CString DismountAll();

	DWORD GetUsedDrives();

	BOOL IsDriveLetterAvailable(WCHAR dl);

	BOOL IsValidMountPointColumnWidth(int cw);

	void PrintInfo(OutputHandler& output_handler, LPCWSTR mountpoint);

	virtual void OnExit() override;


// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MOUNT };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	afx_msg void OnClickedSelect();
	afx_msg void OnClickedMount();
	afx_msg void OnClickedDismount();
	afx_msg void OnClickedDismountAll();
	virtual BOOL OnSetActive();
	CSecureEdit m_password;
	afx_msg void OnClickedExit();
	afx_msg void OnCbnSelchangePath();
	afx_msg void OnClickedSelectConfigPath();
	afx_msg void OnEditchangePath();
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	afx_msg void OnContextMenu(CWnd* /*pWnd*/, CPoint /*point*/);
	afx_msg void OnDblclkDriveLetters(NMHDR *pNMHDR, LRESULT *pResult);
};
