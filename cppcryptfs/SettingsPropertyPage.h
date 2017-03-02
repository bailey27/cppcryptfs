#pragma once

#include "CryptPropertyPage.h"

// CSettingsPropertyPage dialog

class CSettingsPropertyPage : public CCryptPropertyPage
{
	DECLARE_DYNAMIC(CSettingsPropertyPage)

public:
	CSettingsPropertyPage();
	virtual ~CSettingsPropertyPage();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SETTINGS };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	afx_msg void OnSelchangeThreads();
};
