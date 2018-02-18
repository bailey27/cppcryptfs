#pragma once


// CMountMangerDialog dialog

class CMountMangerDialog : public CDialogEx
{
	DECLARE_DYNAMIC(CMountMangerDialog)

public:

	BOOL m_bOkPressed;

	// disallow copying
	CMountMangerDialog(CMountMangerDialog const&) = delete;
	void operator=(CMountMangerDialog const&) = delete;

	CMountMangerDialog(CWnd* pParent = NULL);   // standard constructor
	virtual ~CMountMangerDialog();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MOUNTMANAGER };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedDontshowagain();
};
