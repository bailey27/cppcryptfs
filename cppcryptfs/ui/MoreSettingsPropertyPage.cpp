/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2025 Bailey Brown (github.com/bailey27/cppcryptfs)

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


// CMoreSettingsPropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "ui/cryptdefaults.h"
#include "MoreSettingsPropertyPage.h"
#include "afxdialogex.h"
#include "locutils.h"


// CMoreSettingsPropertyPage dialog

IMPLEMENT_DYNAMIC(CMoreSettingsPropertyPage, CCryptPropertyPage)

CMoreSettingsPropertyPage::CMoreSettingsPropertyPage()
	: CCryptPropertyPage(IDD_MORESETTINGS)
{

}

CMoreSettingsPropertyPage::~CMoreSettingsPropertyPage()
{
}

void CMoreSettingsPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CCryptPropertyPage::DoDataExchange(pDX);
	// This line links the ID from the resources to a variable in C++
	DDX_Control(pDX, IDC_LANGUAGE, m_ctrlComboBox);
}


BEGIN_MESSAGE_MAP(CMoreSettingsPropertyPage, CCryptPropertyPage)
	ON_BN_CLICKED(IDC_FLUSH_AFTER_WRITE_EXFAT, &CMoreSettingsPropertyPage::OnClickedExfat)
	ON_BN_CLICKED(IDC_DEFAULTS, &CMoreSettingsPropertyPage::OnClickedDefaults)
	ON_BN_CLICKED(IDC_RECOMMENDED, &CMoreSettingsPropertyPage::OnClickedRecommended)
	ON_BN_CLICKED(IDC_FLUSH_AFTER_WRITE_FAT32, &CMoreSettingsPropertyPage::OnClickedFat32)
	ON_BN_CLICKED(IDC_FLUSH_AFTER_WRITE_NTFS, &CMoreSettingsPropertyPage::OnClickedNtfs)
	ON_BN_CLICKED(IDC_FLUSH_AFTER_WRITE_NOT_NTFS, &CMoreSettingsPropertyPage::OnClickedNotntfs)
	ON_BN_CLICKED(IDC_FLUSH_AFTER_WRITE_NO_SPARSE_FILES, &CMoreSettingsPropertyPage::OnClickedNosparsefiles)
	// List selection event (activates the button)
	ON_CBN_SELCHANGE(IDC_LANGUAGE, &CMoreSettingsPropertyPage::OnCbnSelchangeLanguage)
	// Clicking on the button itself
	ON_BN_CLICKED(IDC_APPLY, &CMoreSettingsPropertyPage::OnBnClickedApply)
END_MESSAGE_MAP()


// CMoreSettingsPropertyPage message handlers




BOOL CMoreSettingsPropertyPage::OnInitDialog()
{
	CCryptPropertyPage::OnInitDialog();

	if (::IsWindow(m_ctrlComboBox.GetSafeHwnd())) {
		m_ctrlComboBox.ResetContent();

		// Fill in from a pre-prepared vector in theApp
		for (const auto& lang : theApp.m_vAvailableLangs) {
			int nIdx = m_ctrlComboBox.AddString(lang.name);
			m_ctrlComboBox.SetItemData(nIdx, (DWORD_PTR)lang.langID);

			// Select the language in which the interface is currently running
			if (lang.langID == GetThreadUILanguage()) {
				m_ctrlComboBox.SetCurSel(nIdx);
			}
		}
		// Make the "Apply" button grayed out on startup
		GetDlgItem(IDC_APPLY)->EnableWindow(FALSE);
	}

#define DO_CHECKBOX(tok) \
	m_controls.emplace(IDC_##tok, make_unique<CryptCheckBoxSetting>(*this, IDC_##tok, tok));

	DO_CHECKBOX(FLUSH_AFTER_WRITE_EXFAT);

	DO_CHECKBOX(FLUSH_AFTER_WRITE_FAT32);

	DO_CHECKBOX(FLUSH_AFTER_WRITE_NTFS);

	DO_CHECKBOX(FLUSH_AFTER_WRITE_NOT_NTFS);

	DO_CHECKBOX(FLUSH_AFTER_WRITE_NO_SPARSE_FILES);
	
	SetControls(CryptSetting::SetType::Current);
	
	// return TRUE unless you set the focus to a control
	// EXCEPTION: OCX Property Pages should return FALSE

	return TRUE;
}


void CMoreSettingsPropertyPage::SetControls(CryptSetting::SetType set_type)
{
	for (auto& c : m_controls) {
		c.second->Set(set_type);
	}	
}

void CMoreSettingsPropertyPage::SetControlChanged(int id)
{
	auto it = m_controls.find(id);

	assert(it != m_controls.end());

	if (it == m_controls.end())
		return;

	it->second->Set(CryptSetting::Changed);
}

void CMoreSettingsPropertyPage::OnClickedDefaults()
{
	SetControls(CryptSetting::SetType::Default);
}


void CMoreSettingsPropertyPage::OnClickedRecommended()
{
	SetControls(CryptSetting::SetType::Recommended);
}


void CMoreSettingsPropertyPage::OnClickedExfat()
{
	SetControlChanged(IDC_FLUSH_AFTER_WRITE_EXFAT);
}


void CMoreSettingsPropertyPage::OnClickedFat32()
{
	SetControlChanged(IDC_FLUSH_AFTER_WRITE_FAT32);
}


void CMoreSettingsPropertyPage::OnClickedNtfs()
{
	SetControlChanged(IDC_FLUSH_AFTER_WRITE_NTFS);
}


void CMoreSettingsPropertyPage::OnClickedNotntfs()
{
	SetControlChanged(IDC_FLUSH_AFTER_WRITE_NOT_NTFS);
}


void CMoreSettingsPropertyPage::OnClickedNosparsefiles()
{
	SetControlChanged(IDC_FLUSH_AFTER_WRITE_NO_SPARSE_FILES);
}

void CMoreSettingsPropertyPage::OnCbnSelchangeLanguage() {
	// The user has selected something — the button becomes active
	GetDlgItem(IDC_APPLY)->EnableWindow(TRUE);
}


void CMoreSettingsPropertyPage::OnBnClickedApply() {
	int nIdx = m_ctrlComboBox.GetCurSel();
	if (nIdx != CB_ERR) {
		WORD selectedLangID = (WORD)m_ctrlComboBox.GetItemData(nIdx);
		if (selectedLangID != (WORD)GetThreadUILanguage()) {
			theApp.SaveLanguageToRegistry(selectedLangID);
			AfxMessageBox(LocUtils::GetStringFromResources(IDS_APLLY_LANGUAGE_RESTART).c_str(), MB_OK | MB_ICONINFORMATION);

			// Settings applied, button turns gray until next change
			GetDlgItem(IDC_APPLY)->EnableWindow(FALSE);
		}
	}
}


