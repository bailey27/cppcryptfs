// 100% free Secure Edit control MFC class
// Copyright (c) 2003 Dominik Reichl
// If you use this class I would be more than happy if you mention
// my name somewhere in your application. Thanks!
// Do you have any questions or want to tell me that you are using
// my class, e-mail me: <dominik.reichl@t-online.de>.

#ifndef AFX_SECUREEDIT_H__92F72B4B_8867_11D7_BF16_0050BF14F5CC__INCLUDED_
#define AFX_SECUREEDIT_H__92F72B4B_8867_11D7_BF16_0050BF14F5CC__INCLUDED_

// You can change this character to any you want.
// But remember this character mustn't be entered by the user.
#define SE_PASSWORD_CHAR ((WCHAR)0xd7) // high-ascii char that looks like 'x'

// cppcryptfs uses ES_PASSWORD style on edit control so you see the default windows 
// password char, but the window text is stored as SE_PASSWORD_CHAR


// Use LockZeroBuffers instead of CStrings for enhanced security for cppcryptfs
#include "util/LockZeroBuffer.h"

/////////////////////////////////////////////////////////////////////////////

class CSecureEdit : public CEdit
{
public:

	// disallow copying
	CSecureEdit(CSecureEdit const&) = delete;
	void operator=(CSecureEdit const&) = delete;

	CSecureEdit();
	virtual ~CSecureEdit();

	void SetRealText(const WCHAR *pszNewString);
	WCHAR * m_strRealText;

	BOOL ArePasswordBuffersLocked() { return m_pBuf && m_pBufOld ? m_pBuf->IsLocked() && m_pBufOld->IsLocked() : FALSE; };

	//{{AFX_VIRTUAL(CSecureEdit)
	//}}AFX_VIRTUAL

private:
	WCHAR * m_strOldText;
	LockZeroBuffer<WCHAR> *m_pBuf;
	LockZeroBuffer<WCHAR> *m_pBufOld;
	int m_nOldLen;

protected:
	//{{AFX_MSG(CSecureEdit)
	afx_msg void OnUpdate();
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}

#endif // AFX_SECUREEDIT_H__92F72B4B_8867_11D7_BF16_0050BF14F5CC__INCLUDED_
