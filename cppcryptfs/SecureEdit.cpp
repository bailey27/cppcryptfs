// 100% free Secure Edit control MFC class
// Copyright (c) 2003 Dominik Reichl
// If you use this class I would be more than happy if you mention
// my name somewhere in your application. Thanks!
// Do you have any questions or want to tell me that you are using
// my class, e-mail me: <dominik.reichl@t-online.de>.

#include "stdafx.h"
#include "SecureEdit.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CSecureEdit

CSecureEdit::CSecureEdit()
{
}

CSecureEdit::~CSecureEdit()
{
}

BEGIN_MESSAGE_MAP(CSecureEdit, CEdit)
	//{{AFX_MSG_MAP(CSecureEdit)
	ON_CONTROL_REFLECT(EN_UPDATE, OnUpdate)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////

void CSecureEdit::OnUpdate() 
{
	CString strWnd;
	LPTSTR lpWnd = NULL;
	int iWndLen = 0, iDiff = 0;
	int i = 0;
	int inxLeft = -1, inxRight = -1;
	int nLeft = -1, nRight = -1;
	DWORD dwPos = 0;
	CString strNew;
	BOOL bHasChanged = FALSE;

	// Get information about the new contents of the edit control
	GetWindowText(strWnd); // The current window text (Windows has updated it already)
	dwPos = GetSel() & 0xFFFF; // The current cursor position
	iWndLen = strWnd.GetLength(); // The length of the hidden buffer
	iDiff = iWndLen - m_nOldLen; // The difference between the new and the old

	// Scan buffer for non-password-chars (fast scan, using LockBuffer)
	lpWnd = strWnd.GetBuffer(strWnd.GetLength());
	for(i = 0; i < iWndLen; i++)
	{
		if(lpWnd[i] != SE_PASSWORD_CHAR) // This is a new character!
		{
			if(inxLeft == -1) inxLeft = i; // Only allow one change
			bHasChanged = TRUE; // We have found a new character
		}

		// If we have found a new character and now find a password character
		// again, this _must_ be the end of the new (clip-pasted?) string
		if((lpWnd[i] == SE_PASSWORD_CHAR) && (bHasChanged == TRUE))
			if(inxRight == -1) inxRight = i - 1; // Change only once
	}
	strWnd.ReleaseBuffer();

	if(iDiff < 0) // User has deleted one or more characters
	{
		iDiff = -iDiff; // Make positive, so we can handle indexes
		strNew = m_strRealText.Left(dwPos) +
			m_strRealText.Right(m_nOldLen - dwPos - iDiff);
		m_strRealText = strNew; // This is the new secret text

		strNew.Empty(); // Fill strNew with password-chars
		for(i = 0; i < m_strRealText.GetLength(); i++) strNew += SE_PASSWORD_CHAR;

		if(bHasChanged == FALSE) // If the encrypted buffer has not changed
		{ // execute this code only if no new code has been pasted (clipboard)
			m_strOldText = strNew;
			m_nOldLen = strNew.GetLength();
			SetWindowText(strNew);
			SetSel(dwPos, dwPos, FALSE);
		}
	}
	if(bHasChanged == FALSE) return; // Everything is encrypted/hidden

	// Compute numbers of unchanged chars from left and right
	if(inxRight == -1) inxRight = iWndLen - 1;
	nLeft = inxLeft;
	nRight = iWndLen - 1 - inxRight;

	// Get the new string part (extract from password-char-string)
	strNew = strWnd.Mid(inxLeft, inxRight - nLeft + 1);

	// Insert to old string
	strWnd = m_strRealText.Left(nLeft) + strNew + m_strRealText.Right(nRight);
	m_strRealText = strWnd;
	m_strOldText = strWnd; // Save the new secret text

	strNew.Empty(); // Build password-char string with correct length
	for(i = 0; i < iWndLen; i++) strNew += SE_PASSWORD_CHAR;

	// Set the correct data again, just in case something went wrong with sim
	m_nOldLen = iWndLen; // m_strOld is already set a few lines before
	SetWindowText(strNew);
	SetSel(dwPos, dwPos, FALSE); // Just to not confuse the user ;-)
}

void CSecureEdit::SetRealText(const TCHAR *pszNewString)
{
	CString strWnd;
	int i = 0;

	if(pszNewString == NULL) return;

	m_strRealText = pszNewString;
	m_strOldText = pszNewString;
	m_nOldLen = m_strRealText.GetLength();

	strWnd.Empty(); // Build password-char string with correct length
	for(i = 0; i < m_nOldLen; i++) strWnd += SE_PASSWORD_CHAR;

	SetWindowText(strWnd);
}
