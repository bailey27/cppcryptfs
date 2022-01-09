/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2022 Bailey Brown (github.com/bailey27/cppcryptfs)

cppcryptfs is based on the design of gocryptfs (github.com/rfjakob/gocryptfs)

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// CryptPropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "CryptPropertyPage.h"
#include "afxdialogex.h"


// CCryptPropertyPage dialog

IMPLEMENT_DYNAMIC(CCryptPropertyPage, CPropertyPage)

CCryptPropertyPage::CCryptPropertyPage()
	: CPropertyPage(IDD_CRYPTPROPERTYPAGE)
{
	m_psp.dwFlags &= ~PSP_HASHELP;
}

CCryptPropertyPage::CCryptPropertyPage(int id)
	: CPropertyPage(id)
{
	m_psp.dwFlags &= ~PSP_HASHELP;
}

CCryptPropertyPage::~CCryptPropertyPage()
{
}

void CCryptPropertyPage::DefaultAction()
{
}

void CCryptPropertyPage::ProcessCommandLine(LPCTSTR szCmd, BOOL bOnStartup, HANDLE hPipe)
{
}

void CCryptPropertyPage::DeviceChange()
{
}

void CCryptPropertyPage::OnExit()
{
	return;
}

void CCryptPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CCryptPropertyPage, CPropertyPage)
END_MESSAGE_MAP()


// CCryptPropertyPage message handlers
