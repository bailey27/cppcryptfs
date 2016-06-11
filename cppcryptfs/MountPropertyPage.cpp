/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016 - Bailey Brown (github.com/bailey27/cppcryptfs)

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

// MountPropertyPage.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "MountPropertyPage.h"
#include "afxdialogex.h"
#include "FolderDialog.h"
#include "cryptdokan.h"
#include "RecentItems.h"
#include "LockZeroBuffer.h"
#include "cryptdefs.h"


// CMountPropertyPage dialog

IMPLEMENT_DYNAMIC(CMountPropertyPage, CCryptPropertyPage)

CMountPropertyPage::CMountPropertyPage()
	: CCryptPropertyPage(IDD_MOUNT)
{

}

CMountPropertyPage::~CMountPropertyPage()
{
	HIMAGELIST himl = m_imageList.Detach();
	if (himl) {
		ImageList_Destroy(himl);
	}
}

void CMountPropertyPage::DefaultAction()
{
	Mount();
}

void CMountPropertyPage::Mount()
{
	POSITION pos = NULL;

	CWnd *pWnd = GetDlgItem(IDC_PASSWORD);

	if (!pWnd)
		return;

	LockZeroBuffer<WCHAR> password(MAX_PASSWORD_LEN+1);

	if (!password.IsLocked()) {
		MessageBox(L"unable to lock password buffer", L"cppcryptfs", MB_OK | MB_ICONERROR);
	}

	if (pWnd->GetWindowTextW(password.m_buf, password.m_len - 1) < 1)
		return;

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return;

	pos = pList->GetFirstSelectedItemPosition();

	if (!pos)
		return;

	int nItem = pList->GetNextSelectedItem(pos);

	CString cdl = pList->GetItemText(nItem, DL_INDEX);

	if (cdl.GetLength() < 1)
		return;

	bool dlInUse = false;

	DWORD used_drives = ::GetLogicalDrives() | 1; // A: doesn't work

	if (used_drives & (1<<(*(LPCWSTR)cdl-'A'))) 
		dlInUse = true;

	CString mounted_path = pList->GetItemText(nItem, PATH_INDEX);

	if (mounted_path.GetLength() > 0)
		dlInUse = true;

	if (dlInUse) {
		CString mes = L"Drive ";
		mes += cdl;
		mes += L" is already being used.";
		MessageBox(mes, L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	pWnd = GetDlgItem(IDC_PATH);

	if (!pWnd)
		return;

	CString cpath;

	pWnd->GetWindowTextW(cpath);

	if (cpath.GetLength() < 1)
		return;

	bool pathInUse = false;
	CString mdl;

	int count = pList->GetItemCount();
	int i;
	for (i = 0; i < count; i++) {
		CString mpath = pList->GetItemText(i, PATH_INDEX);
		if (!lstrcmpi(mpath, cpath)) {
			mdl = pList->GetItemText(i, DL_INDEX);
			pathInUse = true;
			break;
		}
	}

	if (pathInUse) {
		CString mes = L"";
		mes += cpath;
		mes += L" is already mounted on ";
		mes += mdl;
		MessageBox(mes, L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	pWnd = GetDlgItem(IDC_PASSWORD);

	if (!pWnd)
		return;

	if (pWnd->GetWindowText(password.m_buf, password.m_len - 1) < 1)
		return;

	pWnd->SetWindowTextW(L"");

	std::wstring error_mes;

	
	theApp.DoWaitCursor(1);
	int result = mount_crypt_fs(*(const WCHAR *)cdl, (const WCHAR *)cpath, password.m_buf, error_mes);
	theApp.DoWaitCursor(-1);

	if (result != 0) {
		MessageBoxW(&error_mes[0], L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	theApp.m_mountedDrives |= 1 << (*(const WCHAR*)cdl - 'A');

	pList->SetItemText(nItem, PATH_INDEX, cpath);

	RecentItems ritems(TEXT("Folders"), TEXT("LastDir"), m_numLastDirs);
	ritems.Add(cpath);

	WCHAR dl[2];
	dl[0] = *(const WCHAR *)cdl;
	dl[1] = 0;

	theApp.WriteProfileString(L"MountPoints", L"LastMountPoint", dl);
}

void CMountPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CMountPropertyPage, CPropertyPage)
	ON_BN_CLICKED(IDC_SELECT, &CMountPropertyPage::OnClickedSelect)
	ON_BN_CLICKED(IDC_MOUNT, &CMountPropertyPage::OnClickedMount)
	ON_BN_CLICKED(IDC_DISMOUNT, &CMountPropertyPage::OnClickedDismount)
	ON_BN_CLICKED(IDC_DISMOUNT_ALL, &CMountPropertyPage::OnClickedDismountAll)
END_MESSAGE_MAP()


#include <atlbase.h>

struct ICONDIRENTRY
{
	UCHAR nWidth;
	UCHAR nHeight;
	UCHAR nNumColorsInPalette; // 0 if no palette
	UCHAR nReserved; // should be 0
	WORD nNumColorPlanes; // 0 or 1
	WORD nBitsPerPixel;
	ULONG nDataLength; // length in bytes
	ULONG nOffset; // offset of BMP or PNG data from beginning of file
};

// Helper class to release GDI object handle when scope ends:
class CGdiHandle
{
public:
	CGdiHandle(HGDIOBJ handle) : m_handle(handle) {};
	~CGdiHandle() { DeleteObject(m_handle); };
private:
	HGDIOBJ m_handle;
};


// CMountPropertyPage message handlers


BOOL CMountPropertyPage::OnInitDialog()
{
	CPropertyPage::OnInitDialog();

	// TODO:  Add extra initialization here

	CEdit *pEdit = (CEdit*)GetDlgItem(IDC_PASSWORD);

	if (pEdit)
		pEdit->SetLimitText(MAX_PASSWORD_LEN);

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_PATH);

	int i;

	if (pBox) {
		for (i = 0; i < m_numLastDirs; i++) {
			if (m_lastDirs[i].GetLength())
				pBox->InsertString(i, m_lastDirs[i]);
		}
	}

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return FALSE;

	LRESULT Style = ::SendMessage(pList->m_hWnd, LVM_GETEXTENDEDLISTVIEWSTYLE, 0, 0);
	Style |= LVS_EX_FULLROWSELECT;
	::SendMessage(pList->m_hWnd, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, Style);

	pList->InsertColumn(DL_INDEX, L"Drive", LVCFMT_LEFT, 48);

	pList->InsertColumn(PATH_INDEX, L"Path", LVCFMT_LEFT, 393);

	CString lastLetter = theApp.GetProfileString(L"MountPoints", L"LastMountPoint", L"");

	DWORD drives = ::GetLogicalDrives() | 1; // A: doesn't work

	int bit;

	i = 0;

	bool bFirst = true;

	int lastIndex = -1;

	WCHAR dl[3];


	if (lastLetter.GetLength() > 0) {
		for (bit = 0; bit < 26; bit++) {
			if (drives & (1 << bit))
				continue;

			dl[0] = 'A' + bit;
			dl[1] = ':';
			dl[2] = 0;

			if (*(const WCHAR *)lastLetter == dl[0]) {
				lastIndex = i;
				break;
			}

			i++;
		}
	}

	int imageIndex = -1;

	if (m_imageList.m_hImageList == NULL) {
		HIMAGELIST himlIcons = ImageList_Create(16, 16, ILC_MASK | ILC_COLOR32 | ILC_HIGHQUALITYSCALE, 1, 1);
		if (himlIcons) {
			// Load the icon resources, and add the icons to the image list. 
			HICON hicon = (HICON)LoadImage(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DRIVE), IMAGE_ICON, 16, 16, 0);
			if (hicon) {
				imageIndex = ImageList_AddIcon(himlIcons, hicon);
				if (imageIndex >= 0) {
					if (!m_imageList.Attach(himlIcons)) {
						imageIndex = -1;
					}
				}
			} else {
				ImageList_Destroy(himlIcons);
			}
		}
	}

	pList->SetImageList(&m_imageList, LVSIL_SMALL);

	i = 0;

	for (bit = 0; bit < 26; bit++) {
		if (drives & (1 << bit))
			continue;	

		dl[0] = 'A' + bit;
		dl[1] = ':';
		dl[2] = 0;

		bool isSelected;

		if (lastIndex >= 0) {
			isSelected = i == lastIndex;
		} else {
			isSelected = bFirst;
		}

		pList->InsertItem(LVIF_TEXT | (imageIndex >= 0 ? LVIF_IMAGE : 0) | LVIF_STATE, i++, dl,
			isSelected ? LVIS_SELECTED : 0, LVIS_SELECTED, imageIndex >= 0 ? imageIndex : 0, 0);

		bFirst = false;
	}

	
	if (lastIndex >= 0)
		pList->EnsureVisible(lastIndex, FALSE);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


void CMountPropertyPage::OnClickedSelect()
{
	// TODO: Add your control notification handler code here

	CFolderDialog fdlg;

	fdlg.m_bi.ulFlags |= BIF_NONEWFOLDERBUTTON;

	if (fdlg.DoModal() == IDCANCEL)
		return;

	CString cpath = fdlg.GetPathName();

	if (cpath.GetLength()) {
		CWnd *pWnd = GetDlgItem(IDC_PATH);
		if (pWnd)
			pWnd->SetWindowTextW(cpath);
	}


}


void CMountPropertyPage::OnClickedMount()
{
	// TODO: Add your control notification handler code here

	Mount();
}


void CMountPropertyPage::OnClickedDismount()
{
	// TODO: Add your control notification handler code here

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return;

	POSITION pos = pList->GetFirstSelectedItemPosition();

	if (!pos)
		return;

	int nItem = pList->GetNextSelectedItem(pos);

	CString cdl = pList->GetItemText(nItem, DL_INDEX);

	if (cdl.GetLength() < 1)
		return;

	CString cpath = pList->GetItemText(nItem, PATH_INDEX);

	if (cpath.GetLength() < 1)
		return;

	if (!write_volume_name_if_changed(*(const WCHAR *)cdl))
		MessageBox(L"unable to update volume label", L"cppcryptfs", MB_OK | MB_ICONERROR);

	theApp.DoWaitCursor(1);
	BOOL bresult = unmount_crypt_fs(*(const WCHAR *)cdl, true);
	theApp.DoWaitCursor(-1);

	if (!bresult) {
		CString mes = L"cannot umount ";
		mes.Append(cdl);
		MessageBox(mes, L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	theApp.m_mountedDrives &= ~(1 << (*(const WCHAR *)cdl - 'A'));

	pList->SetItemText(nItem, PATH_INDEX, L"");

}


void CMountPropertyPage::OnClickedDismountAll()
{
	// TODO: Add your control notification handler code here

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return;

	int count = pList->GetItemCount();

	int i;

	bool hadSuccess = false;
	bool hadFailure = false;

	bool volnameFailure = false;

	for (i = 0; i < count; i++) {
		CString cdl;
		CString cpath;
		cpath = pList->GetItemText(i, PATH_INDEX);
		if (cpath.GetLength() > 1) {
			cdl = pList->GetItemText(i, DL_INDEX);
			if (cdl.GetLength() < 1) {
				hadFailure = true;
				continue;
			}
			if (!write_volume_name_if_changed(*(const WCHAR *)cdl))
				volnameFailure = true;
			if (unmount_crypt_fs(*(const WCHAR *)cdl, false)) {
				theApp.m_mountedDrives &= ~(1 << (*(const WCHAR *)cdl - 'A'));
				hadSuccess = true;
				pList->SetItemText(i, PATH_INDEX, L"");
			} else {
				hadFailure = true;
			}
		}
	}

	theApp.DoWaitCursor(1);
	wait_for_all_unmounted();
	theApp.DoWaitCursor(-1);

	if (hadFailure) {
		if (hadSuccess) {
			MessageBox(L"Some of the drives could not be dismounted", L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		} else {
			MessageBox(L"Unable to dismount", L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
		}
	}

	if (volnameFailure)
		MessageBox(L"unable to update one or more volume labels", L"cppcryptfs", MB_OK | MB_ICONERROR);
}


BOOL CMountPropertyPage::OnSetActive()
{
	// TODO: Add your specialized code here and/or call the base class

	RecentItems ritems(TEXT("Folders"), TEXT("LastDir"), m_numLastDirs);

	ritems.Populate(m_lastDirs, TEXT("C:\\"));

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_PATH);

	if (pBox) {

		CString cur;

		pBox->GetWindowText(cur);

		pBox->ResetContent();

		pBox->SetWindowTextW(cur);

		int i;

		if (pBox) {
			for (i = 0; i < m_numLastDirs; i++) {
				if (m_lastDirs[i].GetLength()) {
					if (i == 0) {
						pBox->SetWindowTextW(m_lastDirs[i]);
					}
					pBox->InsertString(i, m_lastDirs[i]);
				}
			}
		}
	}

	return CCryptPropertyPage::OnSetActive();
}
