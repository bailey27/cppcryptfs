#pragma once

#include "CryptPropertyPage.h"

// CCryptAboutPropertyPage dialog

class CCryptAboutPropertyPage : public CCryptPropertyPage
{
	DECLARE_DYNAMIC(CCryptAboutPropertyPage)

public:
	CCryptAboutPropertyPage();
	virtual ~CCryptAboutPropertyPage();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	afx_msg void OnEnChangeInfo();
	afx_msg void OnSetfocusInfo();
};
