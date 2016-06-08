#pragma once

#include "CryptPropertyPage.h"

#define DL_INDEX 0
#define PATH_INDEX 1

// CMountPropertyPage dialog

class CMountPropertyPage : public CCryptPropertyPage
{
	DECLARE_DYNAMIC(CMountPropertyPage)

public:
	CMountPropertyPage();
	virtual ~CMountPropertyPage();

	CString m_lastDirs[10];
	const int m_numLastDirs = 10;
	CImageList m_imageList;

	virtual void DefaultAction();

	void Mount();

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
};
