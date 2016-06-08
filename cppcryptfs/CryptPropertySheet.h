#pragma once



// CryptPropertySheet

class CCryptPropertySheet : public CPropertySheet
{
	DECLARE_DYNAMIC(CCryptPropertySheet)

public:
	CCryptPropertySheet(UINT nIDCaption, CWnd* pParentWnd = NULL, UINT iSelectPage = 0);
	CCryptPropertySheet(LPCTSTR pszCaption, CWnd* pParentWnd = NULL, UINT iSelectPage = 0);
	virtual ~CCryptPropertySheet();

	BOOL CanClose();

protected:
	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	virtual BOOL OnCommand(WPARAM wParam, LPARAM lParam);
	afx_msg BOOL OnNcCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnIdrShowcppcryptfs();
	afx_msg void OnIdrExitcppcryptfs();
};


