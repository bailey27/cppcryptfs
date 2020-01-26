// 100% free Secure Edit control MFC class
// Copyright (c) 2003 Dominik Reichl
// If you use this class I would be more than happy if you mention
// my name somewhere in your application. Thanks!
// Do you have any questions or want to tell me that you are using
// my class, e-mail me: <dominik.reichl@t-online.de>.

#include "stdafx.h"
#include "SecureEdit.h"
#include "crypt/cryptdefs.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CSecureEdit

CSecureEdit::CSecureEdit()
{
	m_pBuf = new LockZeroBuffer<WCHAR>(MAX_PASSWORD_LEN + 1, true, nullptr);
	m_strRealText = m_pBuf->m_buf;

	m_pBufOld = new LockZeroBuffer<WCHAR>(MAX_PASSWORD_LEN + 1, true, nullptr);
	m_strOldText = m_pBufOld->m_buf;
}

CSecureEdit::~CSecureEdit()
{
	if (m_pBuf)
		delete m_pBuf;
	if (m_pBufOld)
		delete m_pBufOld;
}

BEGIN_MESSAGE_MAP(CSecureEdit, CEdit)
	//{{AFX_MSG_MAP(CSecureEdit)
	ON_CONTROL_REFLECT(EN_UPDATE, OnUpdate)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////

void CSecureEdit::OnUpdate() 
{
	LockZeroBuffer<WCHAR> wndBuf(MAX_PASSWORD_LEN + 1, true, nullptr);
	WCHAR *strWnd = wndBuf.m_buf;
	LPWSTR lpWnd = NULL;
	int iWndLen = 0, iDiff = 0;
	int i = 0;
	int inxLeft = -1, inxRight = -1;
	int nLeft = -1, nRight = -1;
	DWORD dwPos = 0;
	LockZeroBuffer<WCHAR> newBuf(MAX_PASSWORD_LEN + 1, true, nullptr);
	WCHAR* strNew = newBuf.m_buf;
	BOOL bHasChanged = FALSE;
	LockZeroBuffer<WCHAR> dotsBuf(MAX_PASSWORD_LEN + 1, true, nullptr);
	WCHAR * strDots = dotsBuf.m_buf;

	// Get information about the new contents of the edit control
	GetWindowText(strWnd, wndBuf.m_len-1); // The current window text (Windows has updated it already)
	dwPos = GetSel() & 0xFFFF; // The current cursor position
	iWndLen = lstrlen(strWnd); // The length of the hidden buffer
	iDiff = iWndLen - m_nOldLen; // The difference between the new and the old

	// Scan buffer for non-password-chars (fast scan, using LockBuffer)
	lpWnd = strWnd;
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
	

	if(iDiff < 0) // User has deleted one or more characters
	{
		iDiff = -iDiff; // Make positive, so we can handle indexes

		wcsncpy_s(strNew, MAX_PASSWORD_LEN+1, m_strRealText, dwPos);
		wcsncat_s(strNew, MAX_PASSWORD_LEN+1, m_strRealText + wcslen(m_strRealText)-(m_nOldLen - dwPos - iDiff), _TRUNCATE);
		wcscpy_s(m_strRealText, MAX_PASSWORD_LEN+1, strNew);

		for (i = 0; i < lstrlen(m_strRealText); i++) strDots[i] = SE_PASSWORD_CHAR;

		if(bHasChanged == FALSE) // If the encrypted buffer has not changed
		{ // execute this code only if no new code has been pasted (clipboard)
			wcscpy_s(m_strOldText, MAX_PASSWORD_LEN+1, strNew);
			m_nOldLen = (int)wcslen(strDots);
			SetWindowText(strDots);
			SetSel(dwPos, dwPos, FALSE);
		}
	}
	if(bHasChanged == FALSE) return; // Everything is encrypted/hidden

	// Compute numbers of unchanged chars from left and right
	if(inxRight == -1) inxRight = iWndLen - 1;
	nLeft = inxLeft;
	nRight = iWndLen - 1 - inxRight;


	wcsncpy_s(strNew, MAX_PASSWORD_LEN+1, strWnd + inxLeft, inxRight - nLeft + 1);

	// Insert to old string

	wcsncpy_s(strWnd, MAX_PASSWORD_LEN+1, m_strRealText, nLeft);
	wcsncat_s(strWnd, MAX_PASSWORD_LEN+1, strNew, _TRUNCATE);
	wcsncat_s(strWnd, MAX_PASSWORD_LEN+1, m_strRealText + wcslen(m_strRealText)-nRight , _TRUNCATE);
	wcscpy_s(m_strRealText, MAX_PASSWORD_LEN+1, strWnd);

	wcscpy_s(m_strOldText, MAX_PASSWORD_LEN+1, strWnd); // Save the new secret text

	for(i = 0; i < iWndLen; i++) strDots[i] = SE_PASSWORD_CHAR;
	strDots[i] = '\0';

	// Set the correct data again, just in case something went wrong with sim
	m_nOldLen = iWndLen; // m_strOld is already set a few lines before
	SetWindowText(strDots);
	SetSel(dwPos, dwPos, FALSE); // Just to not confuse the user ;-)
}

void CSecureEdit::SetRealText(const WCHAR *pszNewString)
{
	LockZeroBuffer<WCHAR> dotsBuf(MAX_PASSWORD_LEN+1, true, nullptr);
	WCHAR * strDots = dotsBuf.m_buf;
	int i = 0;

	if(pszNewString == NULL) return;

	wcscpy_s(m_strRealText, MAX_PASSWORD_LEN+1, pszNewString);
	wcscpy_s(m_strOldText, MAX_PASSWORD_LEN+1, pszNewString);
	m_nOldLen = (int)wcslen(m_strRealText);

	for(i = 0; i < m_nOldLen; i++) strDots[i] = SE_PASSWORD_CHAR;
	strDots[i] = '\0';

	SetWindowText(strDots);

	if (wcslen(pszNewString) < 1) {
		m_pBuf->Clear();
		m_pBufOld->Clear();
	}
}

