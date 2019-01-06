/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2019 Bailey Brown (github.com/bailey27/cppcryptfs)

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

// CSettingsPropertyPage dialog

class CSettingsPropertyPage : public CCryptPropertyPage
{
	DECLARE_DYNAMIC(CSettingsPropertyPage)

public:

	bool m_bCaseInsensitive;
	bool m_bMountManager;
	bool m_bEnableSavingPasswords;
	bool m_bNeverSaveHistory;

	// disallow copying
	CSettingsPropertyPage(CSettingsPropertyPage const&) = delete;
	void operator=(CSettingsPropertyPage const&) = delete;

	CSettingsPropertyPage();
	virtual ~CSettingsPropertyPage();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SETTINGS };
#endif
protected:
	BOOL SetControls(int nThreads, int nBufferBlocks, int nCacheTTL, bool bCaseInsensitive, bool bMountManager, bool bEnableSavingPasswords,
						bool bNeverSaveHistory);
	void SaveSettings();
protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	afx_msg void OnSelchangeThreads();
	afx_msg void OnSelchangeBuffersize();
	afx_msg void OnBnClickedCaseinsensitive();
	afx_msg void OnCbnSelchangeCachettl();
	afx_msg void OnBnClickedDefaults();
	afx_msg void OnBnClickedRecommended();
	afx_msg void OnClickedMountmanager();
	afx_msg void OnClickedResetwarnings();
	afx_msg void OnClickedEnableSavingPasswords();
	afx_msg void OnClickedNeverSaveHistory();
};
