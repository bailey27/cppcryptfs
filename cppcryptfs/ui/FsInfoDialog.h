
#pragma once


// FsInfoDialog.h : header file
//

/////////////////////////////////////////////////////////////////////////////
// CFsInfoDialog dialog

#include "context/cryptcontext.h"

class CFsInfoDialog : public CDialog
{
private:
	
// Construction
public:
	CFsInfoDialog(CWnd* pParent = NULL);   // standard constructor

	FsInfo m_info;
	CString m_mountPoint;
	

// Dialog Data
	//{{AFX_DATA(CFsInfoDialog)
	// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_FSINFO };
#endif
	
	//}}AFX_DATA


// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CFsInfoDialog)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:

	// Generated message map functions
	//{{AFX_MSG(CFsInfoDialog)
		// NOTE: the ClassWizard will add member functions here
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:

	afx_msg void OnBnClickedOk();
	virtual BOOL OnInitDialog();

};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

