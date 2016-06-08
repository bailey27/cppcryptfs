#pragma once

#include "CryptPropertyPage.h"


// CCreatePropertyPage dialog

class CCreatePropertyPage : public CCryptPropertyPage
{
	DECLARE_DYNAMIC(CCreatePropertyPage)

public:

	CString m_lastDirs[10];
	const int m_numLastDirs = 10;

	virtual void DefaultAction();
	CCreatePropertyPage();
	virtual ~CCreatePropertyPage();

	void CreateCryptfs();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CREATE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnClickedSelect();
	afx_msg void OnClickedCreate();
	virtual BOOL OnInitDialog();
	afx_msg void OnLbnSelchangeFilenameEncryption();
	afx_msg void OnCbnSelchangePath();
};
