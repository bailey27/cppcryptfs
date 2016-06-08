#pragma once


// CCryptPropertyPage dialog

class CCryptPropertyPage : public CPropertyPage
{
	DECLARE_DYNAMIC(CCryptPropertyPage)

public:
	CCryptPropertyPage();
	CCryptPropertyPage(int id);
	virtual ~CCryptPropertyPage();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CRYPTPROPERTYPAGE };
#endif
	virtual void DefaultAction();

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
};
