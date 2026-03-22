/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2026 Bailey Brown (github.com/bailey27/cppcryptfs)

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


// CryptAboutPropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "CryptAboutPropertyPage.h"
#include "afxdialogex.h"
#include <dokan/cryptdokan.h>
#include <string>
#include "util/util.h"
#include "crypt/aes.h"
#include "openssl/crypto.h"
#include "../libcommonutil/commonutil.h"
#include "locutils.h"

const int LICENSES_COUNT = 8; // Adjust when the number of licenses is changed
static const WCHAR* licenses[LICENSES_COUNT + 1] = { 0 };
static CStringW storage[LICENSES_COUNT];

void LoadLicensesFromResource() {
	static bool loaded = false;
	if (loaded) return;

	UINT startId = IDR_LICENSE_CPPCRYPTFS;

	for (int i = 0; i < LICENSES_COUNT; i++) {
		UINT currentId = startId + i;
		licenses[i] = L"";

		HRSRC hRes = FindResource(AfxGetResourceHandle(), MAKEINTRESOURCE(currentId), RT_RCDATA);
		if (!hRes) continue;

		HGLOBAL hData = LoadResource(AfxGetResourceHandle(), hRes);
		DWORD size = SizeofResource(AfxGetResourceHandle(), hRes);
		const void* pData = LockResource(hData);

		if (pData && size >= sizeof(WCHAR) && (size % sizeof(WCHAR)) == 0) {
			const WCHAR* pSrc = static_cast<const WCHAR*>(pData);
			int charCount = static_cast<int>(size / sizeof(WCHAR));

			if (charCount > 0 && pSrc[0] == 0xFEFF) {
				++pSrc;
				--charCount;
			}

			if (charCount > 0 && pSrc[charCount - 1] == L'\0')
				--charCount;

			storage[i].SetString(pSrc, charCount);
			licenses[i] = (const WCHAR*)storage[i];
		}
	}

	licenses[LICENSES_COUNT] = NULL;
	loaded = true;
}

// CCryptAboutPropertyPage dialog

IMPLEMENT_DYNAMIC(CCryptAboutPropertyPage, CCryptPropertyPage)

CCryptAboutPropertyPage::CCryptAboutPropertyPage()
	: CCryptPropertyPage(IDD_ABOUTBOX)
{
	LoadLicensesFromResource();
}

CCryptAboutPropertyPage::~CCryptAboutPropertyPage()
{
}

void CCryptAboutPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CCryptPropertyPage::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CCryptAboutPropertyPage, CCryptPropertyPage)
	ON_EN_CHANGE(IDC_INFO, &CCryptAboutPropertyPage::OnEnChangeInfo)
	ON_EN_SETFOCUS(IDC_INFO, &CCryptAboutPropertyPage::OnSetfocusInfo)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_COMPONENTS_LIST, &CCryptAboutPropertyPage::OnItemchangedComponentsList)
END_MESSAGE_MAP()

static CString lf_to_crlf(const wchar_t* txt)
{
	CString fixed;

	auto len = wcslen(txt);

	if (len < 1)
		return fixed;

	fixed += txt[0];

	for (size_t i = 1; i < len; i++) {
		if (txt[i] == '\n' && txt[i - 1] != '\r') {
			fixed += '\r';
			fixed += '\n';
		} else {
			fixed += txt[i];
		}
	}
	return fixed;
}

// CCryptAboutPropertyPage message handlers


BOOL CCryptAboutPropertyPage::OnInitDialog()
{
	CCryptPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here
	//Moved, otherwise the array will be loaded before we determine the GUI language at program startup.
	static const CString listViewStringCppcryptfs = LocUtils::GetStringFromResources(IDS_LVIEW_COPYRIGHT_CPPCRYPTFS).c_str();
	static const CString listViewStringOpenSSL = LocUtils::GetStringFromResources(IDS_LVIEW_COPYRIGHT_OPENSSL).c_str();
	static const CString listViewStringRapidJSON = LocUtils::GetStringFromResources(IDS_LVIEW_COPYRIGHT_RAPIDJSON).c_str();
	static const CString listViewStringDokanyMir = LocUtils::GetStringFromResources(IDS_LVIEW_COPYRIGHT_DOKANY_MIR).c_str();
	static const CString listViewStringDokanyLib = LocUtils::GetStringFromResources(IDS_LVIEW_COPYRIGHT_DOKANY_LIB).c_str();
	static const CString listViewStringSecuryEdit = LocUtils::GetStringFromResources(IDS_LVIEW_COPYRIGHT_SECURE_EDIT).c_str();
	static const CString listViewStringGetOpt = LocUtils::GetStringFromResources(IDS_LVIEW_COPYRIGHT_GETOPT_PORT).c_str();
	static const CString listViewStringAESSIV = LocUtils::GetStringFromResources(IDS_LVIEW_COPYRIGHT_AES_SIV).c_str();

	static const WCHAR* components[] = {
		listViewStringCppcryptfs,
		listViewStringOpenSSL,
		listViewStringRapidJSON,
		listViewStringDokanyMir,
		listViewStringDokanyLib,
		listViewStringSecuryEdit,
		listViewStringGetOpt,
		listViewStringAESSIV,
		NULL
	};

	wstring prod = L"cppryptfs";
	wstring ver = L"1.0";
	wstring copyright = LocUtils::GetStringFromResources(IDS_COPYRIGHT);

	GetProductVersionInfo(prod, ver, copyright);

	string openssl_ver_s = SSLeay_version(SSLEAY_VERSION);

	// get rid of openssl build date

	int nspaces = 0;

	for (size_t i = 0; i < openssl_ver_s.length(); i++) {
		if (openssl_ver_s[i] == ' ') {
			if (nspaces) {
				openssl_ver_s.resize(i);
				break;
			}
			nspaces++;
		}
	}

	wstring openssl_ver_w;

	if (!utf8_to_unicode(openssl_ver_s.c_str(), openssl_ver_w))
		openssl_ver_w = LocUtils::GetStringFromResources(IDS_ERR_GET_OPENSSL_VERSION);

	CString openssl_ver = openssl_ver_w.c_str();

	std::vector<int> dv;
	std::wstring dok_ver;
	CString dokany_version;
	if (get_dokany_version(dok_ver, dv)) {
		dokany_version = dok_ver.c_str();
	}

	CString aes_ni;
	if (AES::use_aes_ni()) {
		aes_ni = LocUtils::GetStringFromResources(IDS_AESNI_DETECTED).c_str();
	} else {
		aes_ni = LocUtils::GetStringFromResources(IDS_AESNI_NOT_DETECTED).c_str();
	}
 
	CString strMsgLibraryVersions;
	strMsgLibraryVersions.Format(LocUtils::GetStringFromResources(IDS_LIBRARY_VERSIONS).c_str(), openssl_ver, dokany_version);
	SetDlgItemText(IDC_LINKAGES, strMsgLibraryVersions);

	bool is_admin = theApp.IsRunningAsAdministrator();

	int prod_bit_depth = sizeof(void*) == 8 ? 64 : 32;
	CString prod_admin = (is_admin ? CString(L" ") + LocUtils::GetStringFromResources(IDS_ADMIN).c_str() : CString(L""));
	CString strMsgCopyright;
	strMsgCopyright.Format(LocUtils::GetStringFromResources(IDS_ABOUT_COPYRIGHT).c_str(), ver.c_str(), prod_bit_depth, prod_admin, aes_ni);

	SetDlgItemText(IDC_PROD_VERSION, strMsgCopyright);
	SetDlgItemText(IDC_COPYRIGHT, copyright.c_str());

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_COMPONENTS_LIST);

	if (!pList)
		return FALSE;

	LRESULT Style = ::SendMessage(pList->m_hWnd, LVM_GETEXTENDEDLISTVIEWSTYLE, 0, 0);
	Style |= LVS_EX_FULLROWSELECT;
	::SendMessage(pList->m_hWnd, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, Style);
	
	pList->InsertColumn(0, L"Component", 0, 720);
	
	int i;

	for (i = 0; components[i]; i++)
		pList->InsertItem(i, components[i]);

	pList->SetItemState(0, LVIS_SELECTED, LVIS_SELECTED);
	


	CWnd *pWnd = GetDlgItem(IDC_INFO);

	if (pWnd) {
		pWnd->SetWindowTextW(lf_to_crlf(licenses[0]));
		pWnd->PostMessageW(WM_CLEAR, 0, 0);
	}

//#define DUMP_LICENSE_INFO 1
#ifdef DUMP_LICENSE_INFO

	FILE *fl = NULL;

	if (fopen_s(&fl, "c:\\tmp\\foo4za8GeQG.txt", "wb") == 0) {

		for (i = 0; components[i]; i++) {
			std::string str;
			unicode_to_utf8(components[i], str);
			fwrite(str.c_str(), 1, str.length(), fl);
			unicode_to_utf8(licenses[i], str);
			fwrite(str.c_str(), 1, str.length(), fl);
		}

		fclose(fl);
	}
#endif

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


void CCryptAboutPropertyPage::OnEnChangeInfo()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CCryptPropertyPage::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
}


void CCryptAboutPropertyPage::OnSetfocusInfo()
{
	// TODO: Add your control notification handler code here

	CEdit *pWnd = (CEdit*)GetDlgItem(IDC_INFO);

	if (!pWnd)
		return;

	pWnd->SetSel(-1, 0, TRUE);


}


void CCryptAboutPropertyPage::OnItemchangedComponentsList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: Add your control notification handler code here
	*pResult = 0;

	if (pNMLV->uNewState & LVIS_SELECTED) {

		CWnd *pWnd = GetDlgItem(IDC_INFO);

		if (pWnd) {
			if (pNMLV->iItem < sizeof(licenses) / sizeof(licenses[0])) {
				pWnd->SetWindowTextW(lf_to_crlf(licenses[pNMLV->iItem]));
			} else {
				pWnd->SetWindowTextW(L"");
			}
			pWnd->PostMessageW(WM_CLEAR, 0, 0);
		}
	}
}