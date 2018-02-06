/*
cppcryptfs : user-mode cryptographic virtual overlay filesystem.

Copyright (C) 2016-2018 Bailey Brown (github.com/bailey27/cppcryptfs)

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
#include "dokan/cryptdokan.h"
#include "RecentItems.h"
#include "util/LockZeroBuffer.h"
#include "crypt/cryptdefs.h"
#include "CryptPropertySheet.h"
#include "crypt/crypt.h"
#include "util/util.h"
#include "util/fileutil.h"
#include "util/getopt.h"
#include "cryptdefaults.h"
#include "util/savedpasswords.h"


// CMountPropertyPage dialog

IMPLEMENT_DYNAMIC(CMountPropertyPage, CCryptPropertyPage)

void CMountPropertyPage::HandleTooltipsActivation(MSG * pMsg, CWnd * This, CWnd * disabledCtrls[], int numOfCtrls, CToolTipCtrl * pTooltip)
{
	CRect  rect;
	POINT  pt;

	HWND   hWnd = pMsg->hwnd;
	LPARAM lParam = pMsg->lParam;

	//---------------------------------------------------------------------------
	//      Disabled control do not show tool tips, in modal dialog
	//
	//
	//      The hwnd of the WM_MOUSEMOVE above a disabled control
	//      is the hWnd of the Dialog itself, this confuse the tooltip
	//
	//      To correct this, if we get WM_MOUSEMOVE and the hwnd is the dialog's hwnd
	//
	//      We check on all the controls that are Visible, but disabled if the point is in their
	//  rectangle.
	//
	// In this case we alter the msg to the controls hWnd and coordinates before
	// Relaying it to the toolTip control
	//----------------------------------------


	if ((pMsg->message == WM_MOUSEMOVE) && (pMsg->hwnd == This->m_hWnd)) {

		//---------------------------
		// The point is in the dialog 
		// client coordinates
		//---------------------------
		pt.x = LOWORD(pMsg->lParam);  // horizontal position of cursor 
		pt.y = HIWORD(pMsg->lParam);  // vertical position of cursor 

		for (int i = 0; i < numOfCtrls; i++) {

			//---------------------------------
			// rect is the control rectangel in
			// Dialog client coordinates
			//----------------------------------
			disabledCtrls[i]->GetWindowRect(&rect);
			This->ScreenToClient(&rect);

			if (rect.PtInRect(pt)) {
				//----------------------------------------------------------------
				// The mouse is inside the control
				//
				// 1. We change the Msg hwnd    to the controls hWnd
				// 2. We change the Msg lParam  to the controls client coordinates
				//
				//----------------------------------------------------------------

				pMsg->hwnd = disabledCtrls[i]->m_hWnd;

				This->ClientToScreen(&pt);
				disabledCtrls[i]->ScreenToClient(&pt);
				pMsg->lParam = MAKELPARAM(pt.x, pt.y);
				break;
			}
		}
	}


	//---------------------------------------
	//      Relay the msg to the tool tip control
	//---------------------------------------
	pTooltip->RelayEvent(pMsg);

	//--------------------------------------
	//      Restore the original msg
	//--------------------------------------
	pMsg->hwnd = hWnd;
	pMsg->lParam = lParam;
}



CMountPropertyPage::CMountPropertyPage()
	: CCryptPropertyPage(IDD_MOUNT)
{
	m_imageIndex = -1;
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
	CString mes = Mount();

	if (mes.GetLength() > 0 && mes != L"password cannot be empty")
		MessageBox(mes, L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
}

CString CMountPropertyPage::Mount(LPCWSTR argPath, LPCWSTR argMountPoint, LPCWSTR argPassword, bool argReadOnly, LPCWSTR argConfigPath, bool argReverse)
{
	

	POSITION pos = NULL;

	CSecureEdit *pPass = &m_password;

	LockZeroBuffer<WCHAR> password(MAX_PASSWORD_LEN + 1);

	if (!password.IsLocked()) {
		return CString(L"unable to lock password buffer");
	}

	if (wcscpy_s(password.m_buf, MAX_PASSWORD_LEN + 1, argPassword ? argPassword : pPass->m_strRealText))
		return CString(L"unable to get password");

	if (wcslen(password.m_buf) < 1)
		return CString(L"password cannot be empty");

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return CString(L"unable to get list control");

	pos = pList->GetFirstSelectedItemPosition();

	if (!pos)
		return CString(L"unable to get selected entry");

	int nItem = -1;

	if (argMountPoint != NULL && wcslen(argMountPoint) > 0) {
		LVFINDINFO fi;
		memset(&fi, 0, sizeof(fi));
		fi.flags = LVFI_STRING;
		CString str = wcslen(argMountPoint) == 1 ? CString(*argMountPoint) + L":" : argMountPoint;
		fi.psz = str;
		nItem = pList->FindItem(&fi);
		if (nItem < 0)
			return CString(L"Mount point ") + str + CString(L" is already in use.");
		int nOldItem = pList->GetNextSelectedItem(pos);
		if (nOldItem >= 0)
			pList->SetItemState(nOldItem, ~LVIS_SELECTED, LVIS_SELECTED);
		if (nItem >= 0)
			pList->SetItemState(nItem, LVIS_SELECTED, LVIS_SELECTED);
	} else {
		nItem = pList->GetNextSelectedItem(pos);
	}

	if (nItem < 0)
		return CString(L"unable to find item");

	CString cmp = argMountPoint && wcslen(argMountPoint) > 0 ? 
		(wcslen(argMountPoint) == 1 ? CString(*argMountPoint) + L":" : argMountPoint) 
		: pList->GetItemText(nItem, DL_INDEX);

	if (cmp.GetLength() < 1)
		return CString(L"unable to get drive letter");;

	BOOL dlInUse = is_mountpoint_a_drive(cmp) && !IsDriveLetterAvailable(*(LPCWSTR)cmp);

	CString mounted_path = pList->GetItemText(nItem, PATH_INDEX);

	if (mounted_path.GetLength() > 0)
		dlInUse = true;

	if (dlInUse) {
		CString mes = L"Mount point ";
		mes += cmp;
		mes += L" is already being used.";
		return mes;
	}

	CWnd *pWnd = GetDlgItem(IDC_PATH);

	if (!pWnd)
		return CString(L"unable to get window");

	CString cpath;

	if (argPath)
		cpath = argPath;
	else
		pWnd->GetWindowTextW(cpath);

	if (cpath.GetLength() < 1)
		return CString(L"path length is zero");

	CString config_path;

	if (argConfigPath && *argConfigPath) {
		config_path = argConfigPath;
	} else {
		pWnd = GetDlgItem(IDC_CONFIG_PATH);
		if (!pWnd)
			return CString(L"unable to get window for config path");
		pWnd->GetWindowTextW(config_path);
	}

	bool reverse = false;

	if (config_path.GetLength() > 0) {
		if (argMountPoint != NULL) {
			reverse = argReverse;
		} else {
			reverse = IsDlgButtonChecked(IDC_REVERSE) != 0;
		}
	}

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
		return mes;
	}

	pPass->SetRealText(L"");

	std::wstring error_mes;

	std::wstring basedir = (const WCHAR *)cpath;

	// strip any trailing backslashes
	while (basedir.size() > 0 && basedir[basedir.size() - 1] == '\\')
		basedir.erase(basedir.size() - 1);

	cpath = &basedir[0];

	if (is_mountpoint_a_drive(cmp))
		theApp.m_mountedLetters |= 1 << (*(const WCHAR*)cmp - 'A');

	// if non-zero dl is specified as arg, then use arg for readonly

	bool readonly = argMountPoint != NULL ? argReadOnly : IsDlgButtonChecked(IDC_READONLY) != 0;

	int nThreads = theApp.GetProfileInt(L"Settings", L"Threads", PER_FILESYSTEM_THREADS_DEFAULT);

	int bufferblocks = theApp.GetProfileInt(L"Settings", L"BufferBlocks", BUFFERBLOCKS_DEFAULT);

	int cachettl = theApp.GetProfileInt(L"Settings", L"CacheTTL", CACHETTL_DEFAULT);

	bool bCaseInsensitive = theApp.GetProfileInt(L"Settings", L"CaseInsensitive", CASEINSENSITIVE_DEFAULT) != 0;

	bool bMountManager = theApp.GetProfileInt(L"Settings", L"MountManager", MOUNTMANAGER_DEFAULT) != 0;

	bool bMountManagerWarn = theApp.GetProfileInt(L"Settings", L"MountManagerWarn", MOUNTMANAGERWARN_DEFAULT) != 0;

	bool bSavePassword = argMountPoint == NULL && (IsDlgButtonChecked(IDC_SAVE_PASSWORD) != 0);

	theApp.DoWaitCursor(1);
	int result = mount_crypt_fs(cmp, cpath, config_path, password.m_buf, error_mes, readonly, reverse, nThreads, bufferblocks, cachettl, bCaseInsensitive, bMountManager, bMountManagerWarn);
	theApp.DoWaitCursor(-1);

	if (result != 0) {
		if (is_mountpoint_a_drive(cmp))
			theApp.m_mountedLetters &= ~(1 << (*(const WCHAR *)cmp - 'A'));
		return CString(&error_mes[0]);
	}

	theApp.m_mountedMountPoints.emplace((LPCWSTR)cmp, cpath);

	// otherwise if fs in root dir of the drive, we get "d:" displayed for the path instead of "d:\"
	if (cpath.GetLength() == 2 && ((LPCWSTR)cpath)[1] == ':')
		cpath += L"\\";

	pList->SetItemText(nItem, PATH_INDEX, cpath);

	// update saved settings in registry only when the GUI is used (not command line)
	if (argMountPoint == NULL) {

		if (IsDlgButtonChecked(IDC_SAVE_PASSWORD)) {
			if (!SavedPasswords::SavePassword(cpath, password.m_buf)) {
				MessageBox(L"unable to save password", L"cppcryptfs", MB_ICONEXCLAMATION | MB_OK);
			}
		}

		RecentItems ritems(TEXT("Folders"), TEXT("LastDir"), m_numLastDirs);
		ritems.Add(cpath);

		WCHAR dl[2];
		dl[0] = *(const WCHAR *)cmp;
		dl[1] = 0;

		theApp.WriteProfileString(L"MountPoints", L"LastMountPoint", is_mountpoint_a_drive(cmp) ? dl : cmp);

		theApp.WriteProfileStringW(L"MountOptions", L"ReadOnly", readonly ? L"1" : L"0");

		CString path_hash;
		std::wstring hash;
		if (GetPathHash(cpath, hash)) {
			path_hash = hash.c_str();
			theApp.WriteProfileString(L"MountPoints", path_hash, is_mountpoint_a_drive(cmp) ? dl : cmp);
			theApp.WriteProfileString(L"ConfigPaths", path_hash, config_path);
			int flags = 0;
			if (readonly)
				flags |= READONLY_FLAG;
			if (reverse)
				flags |= REVERSE_FLAG;
			if (bSavePassword)
				flags |= SAVE_PASSWORD_FLAG;
			theApp.WriteProfileInt(L"MountFlags", path_hash, flags);
		}

	}
		
	return CString(L"");
}

DWORD CMountPropertyPage::GetUsedDrives()
{
	return ::GetLogicalDrives() | 1; // A: doesn't work
}

BOOL CMountPropertyPage::IsDriveLetterAvailable(WCHAR dl)
{
	if (dl >= 'A' && dl <= 'Z')
		return (GetUsedDrives() & (1 << (dl - 'A'))) == 0;
	else
		return FALSE;
}


void CMountPropertyPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PASSWORD, m_password);
}


BEGIN_MESSAGE_MAP(CMountPropertyPage, CPropertyPage)
	ON_BN_CLICKED(IDC_SELECT, &CMountPropertyPage::OnClickedSelect)
	ON_BN_CLICKED(IDC_MOUNT, &CMountPropertyPage::OnClickedMount)
	ON_BN_CLICKED(IDC_DISMOUNT, &CMountPropertyPage::OnClickedDismount)
	ON_BN_CLICKED(IDC_DISMOUNT_ALL, &CMountPropertyPage::OnClickedDismountAll)
	ON_BN_CLICKED(IDC_EXIT, &CMountPropertyPage::OnClickedExit)
	ON_CBN_SELCHANGE(IDC_PATH, &CMountPropertyPage::OnCbnSelchangePath)
	ON_BN_CLICKED(IDC_SELECT_CONFIG_PATH, &CMountPropertyPage::OnClickedSelectConfigPath)
	ON_CBN_EDITCHANGE(IDC_PATH, &CMountPropertyPage::OnEditchangePath)
	ON_WM_CONTEXTMENU()
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

	//Create the ToolTip control
	if (!m_ToolTip.Create(this))
	{
		TRACE0("Unable to create the ToolTip!");
	} else
	{
		// Add tool tips to the controls, either by hard coded string 
		// or using the string table resource
		CWnd *pWnd = GetDlgItem(IDC_SAVE_PASSWORD);
		if (pWnd) {
			m_ToolTip.AddTool(pWnd, _T("To enable \"Save password\", turn on \"Enable saved passwords\" in the Settings tab."));
		}
	}

	CComboBox *pBox = (CComboBox*)GetDlgItem(IDC_PATH);

	int i;

	if (pBox) {
		for (i = 0; i < m_numLastDirs; i++) {
			if (m_lastDirs[i].GetLength())
				pBox->InsertString(i, m_lastDirs[i]);
		}
	}

	pBox = (CComboBox*)GetDlgItem(IDC_CONFIG_PATH);

	if (pBox) {
		for (i = 0; i < m_numLastConfigs; i++) {
			if (m_lastConfigs[i].GetLength())
				pBox->InsertString(i, m_lastConfigs[i]);
		}
	}

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return FALSE;

	LRESULT Style = ::SendMessage(pList->m_hWnd, LVM_GETEXTENDEDLISTVIEWSTYLE, 0, 0);
	Style |= LVS_EX_FULLROWSELECT;
	::SendMessage(pList->m_hWnd, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, Style);

	int mountPointColumnWidth = theApp.GetProfileInt(L"MountPoint", L"MountPointColumnWidth", 79);

	if (!IsValidMountPointColumnWidth(mountPointColumnWidth)) {
		mountPointColumnWidth = 79;
	}

	pList->InsertColumn(DL_INDEX, L"Mount Point", LVCFMT_LEFT, mountPointColumnWidth);

	pList->InsertColumn(PATH_INDEX, L"Path", LVCFMT_LEFT, 454-mountPointColumnWidth);

	CString lastMountPoint = theApp.GetProfileString(L"MountPoints", L"LastMountPoint", L"");

	if (lastMountPoint.GetLength() > 0 && lastMountPoint.GetLength() < 2)
		lastMountPoint += L":";

	DWORD drives = GetUsedDrives();

	i = 0;

	bool bFirst = true;

	int lastIndex = -1;

	CStringArray mountPoints;
	GetMountPoints(mountPoints);


	if (lastMountPoint.GetLength() > 0) {
		for (i = 0; i < mountPoints.GetCount(); i++) {

			if (!_wcsicmp(lastMountPoint, mountPoints.GetAt(i))) {
				lastIndex = i;
				break;
			}

		}
	}

	m_imageIndex = -1;

	if (m_imageList.m_hImageList == NULL) {
		HIMAGELIST himlIcons = ImageList_Create(16, 16, ILC_MASK | ILC_COLOR32 | ILC_HIGHQUALITYSCALE, 1, 1);
		if (himlIcons) {
			// Load the icon resources, and add the icons to the image list. 
			HICON hicon = (HICON)LoadImage(AfxGetInstanceHandle(), MAKEINTRESOURCE(IDI_DRIVE), IMAGE_ICON, 16, 16, 0);
			if (hicon) {
				m_imageIndex = ImageList_AddIcon(himlIcons, hicon);
				if (m_imageIndex >= 0) {
					if (!m_imageList.Attach(himlIcons)) {
						m_imageIndex = -1;
					}
				}
			} else {
				ImageList_Destroy(himlIcons);
			}
		}
	}

	pList->SetImageList(&m_imageList, LVSIL_SMALL);

	for (i = 0; i < mountPoints.GetCount(); i++) {
	

		bool isSelected;

		if (lastIndex >= 0) {
			isSelected = i == lastIndex;
		} else {
			isSelected = bFirst;
		}

		pList->InsertItem(LVIF_TEXT | (m_imageIndex >= 0 ? LVIF_IMAGE : 0) | LVIF_STATE, i, mountPoints.GetAt(i),
			isSelected ? LVIS_SELECTED : 0, LVIS_SELECTED, m_imageIndex >= 0 ? m_imageIndex : 0, 0);

		bFirst = false;
	}

	
	if (lastIndex >= 0)
		pList->EnsureVisible(lastIndex, FALSE);

	// limit input lengths

	m_password.SetLimitText(MAX_PASSWORD_LEN);

	CComboBox *pCombo = (CComboBox*)GetDlgItem(IDC_PATH);
	if (pCombo)
		pCombo->LimitText(MAX_PATH);

	pCombo = (CComboBox*)GetDlgItem(IDC_CONFIG_PATH);
	if (pCombo)
		pCombo->LimitText(MAX_PATH);

	if (!m_password.ArePasswordBuffersLocked())
		MessageBox(L"unable to lock password buffer", L"cppcryptfs", MB_OK | MB_ICONERROR);

	ProcessCommandLine(0, GetCommandLine(), TRUE);

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}

void CMountPropertyPage::DeviceChange()
{

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return;

	
	int nItems = pList->GetItemCount();
	int i;
	bool selected_was_visible = false;
	CString selected;
	CString cmp, cpath;
	for (i = 0; i < nItems; i++) {
		cmp = pList->GetItemText(i, 0);
		if (pList->GetItemState(i, LVIS_SELECTED) == LVIS_SELECTED) {
			selected = cmp;
			if (pList->IsItemVisible(i))
				selected_was_visible = true;
		}
	}

	pList->DeleteAllItems();


	i = 0;
	bool selected_something = false;
	int new_selected_index = -1;

	CStringArray mountPoints;
	GetMountPoints(mountPoints);

	for (i = 0; i < mountPoints.GetCount(); i++) {
		
		CString dls = mountPoints.GetAt(i);

		if (!_wcsicmp(dls, selected)) {
			selected_something = true;
			new_selected_index = i;
		}

		pList->InsertItem(LVIF_TEXT | (m_imageIndex >= 0 ? LVIF_IMAGE : 0) | LVIF_STATE, i, dls,
			!_wcsicmp(dls, selected) ? LVIS_SELECTED : 0, LVIS_SELECTED, m_imageIndex >= 0 ? m_imageIndex : 0, 0);
		auto it = theApp.m_mountedMountPoints.find((LPCWSTR)dls);
		if (it != theApp.m_mountedMountPoints.end())
			pList->SetItemText(i, 1, it->second.c_str());
		
		
	}
	if (pList->GetItemCount() > 0) {
		if (!selected_something) {
			pList->SetItemState(-1, 0, LVIS_SELECTED);
			pList->SetItemState(0, LVIS_SELECTED, LVIS_SELECTED);
		} else if (selected_was_visible && !pList->IsItemVisible(new_selected_index)) {
			pList->EnsureVisible(new_selected_index, FALSE);
		}
	}

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

	BOOL save_passwords_enabled = theApp.GetProfileInt(L"Settings", L"EnableSavingPasswords", ENABLE_SAVING_PASSWORDS_DEFAULT) != 0;

	CSecureEdit *pEd = (CSecureEdit*)GetDlgItem(IDC_PASSWORD);
	if (pEd && save_passwords_enabled) {
		if (IsDlgButtonChecked(IDC_SAVE_PASSWORD)) {
			if (pEd->m_strRealText == NULL || wcslen(pEd->m_strRealText) < 1) {
				CWnd *pPath = GetDlgItem(IDC_PATH);
				if (pPath) {
					LockZeroBuffer<WCHAR> password(MAX_PASSWORD_LEN + 1, true);
					CString cpath;
					pPath->GetWindowTextW(cpath);
					if (cpath.GetLength() > 0 && SavedPasswords::RetrievePassword(cpath, password.m_buf, password.m_len)) {
						pEd->SetRealText(password.m_buf);
					}
				}
			}
		}	
	}

	CString mes = Mount();
	if (mes.GetLength() > 0)
		MessageBox(mes, L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
}


void CMountPropertyPage::OnClickedDismount()
{
	CString mes = Dismount();
	if (mes.GetLength() > 0)
		MessageBox(mes, L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
}

CString CMountPropertyPage::Dismount(LPCWSTR argMountPoint)
{
	

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return CString(L"unable to get list");

	POSITION pos = pList->GetFirstSelectedItemPosition();

	if (!pos)
		return CString(L"unable to get selection");

	int nItem;
	
	if (argMountPoint && wcslen(argMountPoint) > 0) {
		LVFINDINFO fi;
		memset(&fi, 0, sizeof(fi));
		fi.flags = LVFI_STRING;
		CString str = wcslen(argMountPoint) == 1 ? CString(*argMountPoint) + L":" : argMountPoint;
		fi.psz = str;
		nItem = pList->FindItem(&fi);
		if (nItem < 0)
			return CString(L"Drive ") + str + CString(L" does not have a mounted cppcryptfs filesystem.");
	} else {
		nItem = pList->GetNextSelectedItem(pos);
	}

	if (nItem < 0)
		return CString(L"unable to find item");

	CString cmp = pList->GetItemText(nItem, DL_INDEX);

	if (cmp.GetLength() < 1)
		return CString(L"unable to get drive letter");

	CString cpath = pList->GetItemText(nItem, PATH_INDEX);

	if (cpath.GetLength() < 1)
		return CString(L"Drive ") + cmp + CString(L" does not have a mounted cppcryptfs filesystem.");

	CString mes;

	if (is_mountpoint_a_drive(cmp)) {
		if (!write_volume_name_if_changed(*(const WCHAR *)cmp))
			mes += L"unable to update volume label";
	}

	theApp.DoWaitCursor(1);
	BOOL bresult = unmount_crypt_fs(cmp, true);
	theApp.DoWaitCursor(-1);

	if (!bresult) {
		if (mes.GetLength() > 0)
			mes += L". ";
		mes += L"cannot umount ";
		mes.Append(cmp);
		return mes;
	}

	if (is_mountpoint_a_drive(cmp))
		theApp.m_mountedLetters &= ~(1 << (*(const WCHAR *)cmp - 'A'));

	theApp.m_mountedMountPoints.erase((LPCWSTR)cmp);

	pList->SetItemText(nItem, PATH_INDEX, L"");

	return mes;

}


void CMountPropertyPage::OnClickedDismountAll()
{

	DismountAll();
}

CString CMountPropertyPage::DismountAll()
{
	// TODO: Add your control notification handler code here

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return CString(L"unable to get list");

	int count = pList->GetItemCount();

	int i;

	bool hadSuccess = false;
	bool hadFailure = false;

	bool volnameFailure = false;

	DWORD mounted_letters = theApp.m_mountedLetters;

	for (i = 0; i < count; i++) {
		CString cmp;
		CString cpath;
		cpath = pList->GetItemText(i, PATH_INDEX);
		if (cpath.GetLength() > 1) {
			cmp = pList->GetItemText(i, DL_INDEX);
			if (cmp.GetLength() < 1) {
				hadFailure = true;
				continue;
			}
			if (is_mountpoint_a_drive(cmp)) {
				if (!write_volume_name_if_changed(*(const WCHAR *)cmp))
					volnameFailure = true;
			}
			if (unmount_crypt_fs(cmp, false)) {
				if (is_mountpoint_a_drive(cmp))
					mounted_letters &= ~(1 << (*(const WCHAR *)cmp - 'A'));
				theApp.m_mountedMountPoints.erase((LPCWSTR)cmp);
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

	theApp.m_mountedLetters = mounted_letters;

	CString mes;

	if (hadFailure) {
		if (hadSuccess) {
			mes = L"Some of the drives could not be dismounted";
		} else {
			mes = L"Unable to dismount";
		}
	}

	if (volnameFailure) {
		if (mes.GetLength() > 0)
			mes += L". ";
		mes += L"unable to update one or more volume labels";
	}

	return mes;
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

	RecentItems ritems2(TEXT("ConfigPaths"), TEXT("LastConfig"), m_numLastConfigs);

	ritems2.Populate(m_lastConfigs, TEXT("C:\\"));

	BOOL save_passwords_enabled = theApp.GetProfileInt(L"Settings", L"EnableSavingPasswords", ENABLE_SAVING_PASSWORDS_DEFAULT) != 0;

	m_ToolTip.Activate(!save_passwords_enabled);

	pBox = (CComboBox*)GetDlgItem(IDC_CONFIG_PATH);

	if (pBox) {

		CString cur;

		pBox->GetWindowText(cur);

		pBox->ResetContent();

		pBox->SetWindowTextW(cur);

		int i;

		if (pBox) {
			for (i = 0; i < m_numLastConfigs; i++) {
				if (m_lastConfigs[i].GetLength()) {
					if (i == 0) {
						pBox->SetWindowTextW(m_lastConfigs[i]);
					}
					pBox->InsertString(i, m_lastConfigs[i]);
				}
			}

			CComboBox *pBoxPath = (CComboBox*)GetDlgItem(IDC_PATH);
			if (pBoxPath) {
				CString cpath;
				pBoxPath->GetWindowText(cpath);
				if (cpath.GetLength() > 0) {
					CString path_hash;
					std::wstring hash;
					if (GetPathHash(cpath, hash)) {
						path_hash = hash.c_str();
						CString config_path = theApp.GetProfileString(L"ConfigPaths", path_hash, L"");
						pBox->SetWindowText(config_path);
						int flags = theApp.GetProfileInt(L"MountFlags", path_hash, 0);
						CheckDlgButton(IDC_READONLY, (flags & READONLY_FLAG) != 0);
						CheckDlgButton(IDC_REVERSE, (flags & REVERSE_FLAG) != 0);

						LockZeroBuffer<WCHAR> password(MAX_PASSWORD_LEN + 1, true);

						if ((flags & SAVE_PASSWORD_FLAG) && save_passwords_enabled && SavedPasswords::RetrievePassword(cpath, password.m_buf, password.m_len)) {

							password.m_buf[MAX_PASSWORD_LEN] = '\0';
							CSecureEdit *pEd = (CSecureEdit*)GetDlgItem(IDC_PASSWORD);
							if (pEd) {
								pEd->SetRealText(password.m_buf);
							}
						} else {
							CSecureEdit *pEd = (CSecureEdit*)GetDlgItem(IDC_PASSWORD);
							if (pEd) {
								pEd->SetRealText(L"");
							}
						}
						CheckDlgButton(IDC_SAVE_PASSWORD, (flags & SAVE_PASSWORD_FLAG) != 0);
					}
				}
			}
		}
	}

	

	CWnd *pSavePwWnd = GetDlgItem(IDC_SAVE_PASSWORD);
	if (pSavePwWnd)
		pSavePwWnd->EnableWindow(save_passwords_enabled);

	if (!save_passwords_enabled)
		CheckDlgButton(IDC_SAVE_PASSWORD, FALSE);

	return CCryptPropertyPage::OnSetActive();
}


void CMountPropertyPage::OnClickedExit()
{
	// TODO: Add your control notification handler code here

	CCryptPropertySheet *pParent = (CCryptPropertySheet*)GetParent();

	if (pParent)
		pParent->OnIdrExitcppcryptfs();
}


void CMountPropertyPage::OnCbnSelchangePath()
{
	// TODO: Add your control notification handler code here

	CComboBox *pWnd = (CComboBox*)GetDlgItem(IDC_PATH);

	if (!pWnd)
		return;

	CString cpath;

	int sel = pWnd->GetCurSel();

	if (sel == CB_ERR)
		return;

	pWnd->GetLBText(sel, cpath);

	if (cpath.GetLength() < 1)
		return;

	CString path_hash;
	std::wstring hash;
	if (!GetPathHash(cpath, hash))
		return;

	path_hash = hash.c_str();


	CString config_path = theApp.GetProfileString(L"ConfigPaths", path_hash, L"");

	CWnd *pConfigPathWnd = GetDlgItem(IDC_CONFIG_PATH);

	if (!pConfigPathWnd)
		return;

	pConfigPathWnd->SetWindowTextW(config_path);

	int flags = theApp.GetProfileInt(L"MountFlags", path_hash, 0);
	CheckDlgButton(IDC_READONLY, (flags & READONLY_FLAG) != 0);
	CheckDlgButton(IDC_REVERSE, (flags & REVERSE_FLAG) != 0);

	BOOL save_passwords_enabled = theApp.GetProfileInt(L"Settings", L"EnableSavingPasswords", ENABLE_SAVING_PASSWORDS_DEFAULT) != 0;

	CheckDlgButton(IDC_SAVE_PASSWORD, (flags & SAVE_PASSWORD_FLAG) && save_passwords_enabled);

	LockZeroBuffer<WCHAR> password(MAX_PASSWORD_LEN+1, true);

	if ((flags & SAVE_PASSWORD_FLAG) && save_passwords_enabled && SavedPasswords::RetrievePassword(cpath, password.m_buf, password.m_len)) {

		password.m_buf[MAX_PASSWORD_LEN] = '\0';
		CSecureEdit *pEd = (CSecureEdit*)GetDlgItem(IDC_PASSWORD);
		if (pEd) {
			pEd->SetRealText(password.m_buf);
		}
	} else {
		CSecureEdit *pEd = (CSecureEdit*)GetDlgItem(IDC_PASSWORD);
		if (pEd) {
			pEd->SetRealText(L"");
		}
	}

	CString cmp = theApp.GetProfileString(L"MountPoints", path_hash, L"");

	if (cmp.GetLength() == 1 && !IsDriveLetterAvailable(*((LPCWSTR)cmp)))
		return;

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return;

	LVFINDINFO fi;

	memset(&fi, 0, sizeof(fi));

	fi.flags = LVFI_STRING;

	if (cmp.GetLength() == 1)
		cmp += L":";

	fi.psz = (LPCWSTR)cmp;

	int index = pList->FindItem(&fi);

	if (index < 0)
		return;

	pList->SetItemState(index, LVIS_SELECTED, LVIS_SELECTED);

	pList->EnsureVisible(index, FALSE);

}

extern wchar_t *optarg;
extern int optind, opterr, optopt;

static void usage()
{

	fprintf(stderr, "Usage: cppcryptfs [OPTIONS]\n");
	fprintf(stderr, "\nMounting:\n");
	fprintf(stderr, "  -m, --mount=PATH\tmount filesystem located at PATH\n");
	fprintf(stderr, "  -d, --drive=D\t\tmount to drive letter D or empty dir DIR\n");
	fprintf(stderr, "  -p, --password=PASS\tuse password PASS\n");
	fprintf(stderr, "  -P, --saved-password\tuse saved password\n");
	fprintf(stderr, "  -r, --readonly\tmount read-only\n");
	fprintf(stderr, "  -c, --config=PATH\tpath to config file\n");
	fprintf(stderr, "  -s, --reverse\t\tmount reverse filesystem\n");
	fprintf(stderr, "\nUnmounting:\n");
	fprintf(stderr, "  -u, --unmount=D\tumount drive letter D or dir DIR\n");
	fprintf(stderr, "  -u, --umount=all\tunmount all drives\n");
	fprintf(stderr, "\nMisc:\n");
	fprintf(stderr, "  -t, --tray\t\thide in system tray\n");
	fprintf(stderr, "  -x, --exit\t\texit if no drives mounted\n");
	fprintf(stderr, "  -l, --list\t\tlist available and mounted drive letters (with paths)\n");
	fprintf(stderr, "  -ld:\\p, --list=d:\\p\tlist encrypted and plaintext filenames\n");
	fprintf(stderr, "  -v, --version\t\tprint version\n");
	fprintf(stderr, "  -h, --help\t\tdisplay this help message\n");
	
}


static bool compair_find_datas(const FindDataPair& p1, const FindDataPair& p2)
{
	return _wcsicmp(p1.fdata.cFileName, p2.fdata.cFileName) < 0;
}

void CMountPropertyPage::ProcessCommandLine(DWORD pid, LPCWSTR szCmd, BOOL bOnStartup)
{

	optarg = NULL;
	optind = 1;
	opterr = 1;
	optopt = 0;

	CString errMes;

	int argc = 1;

	LPWSTR *argv = NULL;

	if (szCmd)
		argv = CommandLineToArgvW(szCmd, &argc);

	if (argv == NULL || argc < 2) {
		if (argv)
			LocalFree(argv);
		return;
	}

	OpenConsole(bOnStartup ? 0 : pid);

	CString path;
	CString mountPoint;
	LockZeroBuffer<WCHAR> password((DWORD)(wcslen(szCmd) + 1));
	BOOL mount = FALSE;
	BOOL dismount = FALSE;
	BOOL dismount_all = FALSE;

	BOOL invalid_opt = FALSE;

	BOOL do_help = FALSE;
	BOOL do_version = FALSE;
	BOOL exit_if_no_mounted = FALSE;
	BOOL hide_to_system_tray = FALSE;
	BOOL do_list = FALSE;
	bool readonly = false;
	bool reverse = false;
	CString config_path;
	bool use_saved_password = false;

	CString list_arg;

	try {

		static struct option long_options[] =
		{
			{L"mount",   required_argument,  0, 'm'},
			{L"drive",   required_argument,  0, 'd'},
			{L"password", required_argument, 0, 'p'},
			{ L"config", required_argument, 0, 'c' },
			{L"unmount",  required_argument, 0, 'u'},
			{L"readonly",  no_argument, 0, 'r'},
			{ L"reverse",  no_argument, 0, 's' },
			{ L"saved-password",  no_argument, 0, 'P' },
			{L"tray",  no_argument, 0, 't'},
			{L"exit",  no_argument, 0, 'x'},
			{L"list",  optional_argument, 0, 'l'},
			{ L"version",  no_argument, 0, 'v' },
			{L"help",  no_argument, 0, 'h'},
			{0, 0, 0, 0}
		};

		int c;
		int option_index = 0;

		while (1) {

			c = getopt_long(argc, argv, L"m:d:p:u:vhxtl::rsc:P", long_options, &option_index);

			if (c == -1)
				break;

			switch (c) {
			case '?':
				invalid_opt = TRUE;
				break;
			case 'r':
				readonly = true;
				break;
			case 's':
				reverse = true;
				break;
			case 'm':
				mount = TRUE;
				path = optarg;
				break;
			case 'c':
				config_path = optarg;
				break;
			case 'd':
				mountPoint = optarg;
				break;
			case 'P':
				use_saved_password = true;
				break;
			case 'p':
				wcscpy_s(password.m_buf, password.m_len, optarg);
				break;
			case 'u':
				dismount = TRUE;
				if (wcscmp(optarg, L"all") == 0)
					dismount_all = TRUE;
				else
					mountPoint = optarg;
				break;
			case 'v':
				do_version = TRUE;
				break;
			case 'h':
				do_help = TRUE;
				break;
			case 'l':
				do_list = TRUE;
				if (optarg)
					list_arg = optarg;
				break;
			case 't':
				hide_to_system_tray = TRUE;
				break;
			case 'x':
				exit_if_no_mounted = TRUE;
				break;
			default:
				throw(-1);
			}
		}

		if (mountPoint.GetLength() > 0) {
			WCHAR driveletter = *(LPCWSTR)mountPoint;
			if (driveletter >= 'a' && driveletter <= 'z') {
				driveletter -= 'a' - 'A';
				mountPoint.SetAt(0, driveletter);
			}
		}

	} catch (int err) {
		if (err) {
			if (errMes.GetLength() == 0)
				errMes = L"unexpected exception";
		}
	}

	LocalFree(argv);

	if (errMes.GetLength() > 0) {
		fwprintf(stderr, L"cppcryptfs: %s\n", (LPCWSTR)errMes);
	} else if (invalid_opt) {
		fwprintf(stderr, L"Try 'cppcryptfs --help' for more information.\n");
	} else if (do_version || do_help) {
		if (do_version) {
			std::wstring prod, ver, copyright;
			GetProductVersionInfo(prod, ver, copyright);
			fwprintf(stderr, L"%s %s %s\n", prod.c_str(), ver.c_str(), copyright.c_str());
			if (do_help)
				fwprintf(stderr, L"\n");
		}
		if (do_help)
			usage();
	} else if (do_list) {
		CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS); 
		if (pList) {
			if (list_arg.GetLength() > 0) {
				const WCHAR *path = (const WCHAR *)list_arg;
				int dl = *path;
				if (!iswupper(dl))
					dl = towupper(dl);
				if (dl < 'A' || dl > 'Z') {
					errMes = L"invalid drive letter"; 
				} else { // list_files will figure out of this path is really mounted or not
					std::wstring err_mes;
					list_arg.SetAt(0, dl);
					std::list<FindDataPair> findDatas;
					if (!list_files(list_arg, findDatas, err_mes)) {
						errMes = err_mes.c_str();
					} else {
						findDatas.sort(compair_find_datas);
						for (auto &it : findDatas) {
							fwprintf(stdout, L"%s => %s\n", it.fdata.cFileName, it.fdata_orig.cFileName);
						}
					}
				}  
				if (errMes.GetLength() > 0) {
					LPCWSTR str = errMes;
					if (str[wcslen(str) - 1] != '\n')
						errMes += L"\n";
					fwprintf(stderr, L"cppcryptfs: %s", (LPCWSTR)errMes);
				}
			} else {
				int nItems = pList->GetItemCount();
				int i;
				CString cmp, cpath;
				for (i = 0; i < nItems; i++) {
					cmp = pList->GetItemText(i, 0);
					if (cmp.GetLength() > 0) {
						fwprintf(stdout, L"%s", (LPCWSTR)cmp);
						
						cpath = pList->GetItemText(i, 1);
						if (cpath.GetLength() > 0)
							fwprintf(stdout, L" %s", (LPCWSTR)cpath);
						
						fwprintf(stdout, L"\n");
					}
				}
			}
		}
	} else {
		if (mount) {
			if (use_saved_password) {
				if (!SavedPasswords::RetrievePassword(path, password.m_buf, password.m_len)) {
					errMes = L"unable to retrieve password";
				}
			}
			if (errMes.GetLength() < 1) {
				if (mountPoint.GetLength() > 0)
					errMes = Mount(path, mountPoint, password.m_buf, readonly, config_path.GetLength() > 0 ? config_path : NULL, reverse);
				else
					errMes = L"drive letter/mount point must be specified";
			}
		} else if (dismount) {
			if (dismount_all) {
				errMes = DismountAll();
			} else {
				if (mountPoint.GetLength() > 0)
					errMes = Dismount(mountPoint);
				else
					errMes = L"drive letter/mount point must be specified";			
			}
		} 
		if (errMes.GetLength() > 0) {
			LPCWSTR str = errMes;
			if (str[wcslen(str) - 1] != '\n')
				errMes += L"\n";
			fwprintf(stderr, L"cppcryptfs: %s", (LPCWSTR)errMes);
		}
	}

	CCryptPropertySheet *pParent = (CCryptPropertySheet*)GetParent();

	if (pParent) {
		if (theApp.m_mountedMountPoints.empty() && exit_if_no_mounted) {
			pParent->OnIdrExitcppcryptfs();
		} else if (hide_to_system_tray) {
			if (bOnStartup)
				pParent->m_bHideAfterInit = TRUE;
			else
				pParent->ShowWindow(SW_HIDE);
		}
	}

	CloseConsole();

}




void CMountPropertyPage::OnClickedSelectConfigPath()
{
	// TODO: Add your control notification handler code here

	bool reverse = IsDlgButtonChecked(IDC_REVERSE) != 0;

	CFileDialog fdlg(TRUE, L"conf", reverse ? L"gocryptfs.reverse" : L"gocryptfs",
		OFN_DONTADDTORECENT | OFN_LONGNAMES | 0*OFN_OVERWRITEPROMPT |
		OFN_PATHMUSTEXIST);

	if (fdlg.DoModal() == IDCANCEL)
		return;

	CString cpath = fdlg.GetPathName();

	if (cpath.GetLength() < 1)
		return;

	CWnd *pWnd = GetDlgItem(IDC_CONFIG_PATH);
	if (pWnd)
		pWnd->SetWindowTextW(cpath);
}


void CMountPropertyPage::OnEditchangePath()
{
	// TODO: Add your control notification handler code here

	CSecureEdit *pEd = (CSecureEdit*)GetDlgItem(IDC_PASSWORD);

	if (pEd)
		pEd->SetRealText(L"");
}



BOOL CMountPropertyPage::PreTranslateMessage(MSG* pMsg)
{
	// TODO: Add your specialized code here and/or call the base class

	

	CWnd *pSavePass = GetDlgItem(IDC_SAVE_PASSWORD);

	if (pSavePass && !pSavePass->IsWindowEnabled()) {

		CMountPropertyPage::HandleTooltipsActivation(pMsg, this, &pSavePass, 1, &m_ToolTip);

	} else {
		m_ToolTip.RelayEvent(pMsg);
	}

	return CCryptPropertyPage::PreTranslateMessage(pMsg);
}


void CMountPropertyPage::OnContextMenu(CWnd* pWnd, CPoint point)
{
	// TODO: Add your message handler code here

	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if ((CWnd*)pList == pWnd) {
		CMenu menu;
		
		if (!menu.CreatePopupMenu())
			return;

		menu.AppendMenu(MF_ENABLED, 1, L"&Add Mount Point");

		int item = -1;

		for (int i = 0; i < pList->GetItemCount(); i++) {
			if (pList->GetItemState(i, LVIS_SELECTED) & LVIS_SELECTED) {
				item = i;
				break;
			}
		}

		if (item >= 0) {
			CString cmp = pList->GetItemText(item, 0);
			if (is_mountpoint_a_dir(cmp)) {
				bool mounted = theApp.m_mountedMountPoints.find((LPCWSTR)cmp) != theApp.m_mountedMountPoints.end();
				menu.AppendMenu(mounted ? MF_DISABLED : MF_ENABLED, 2, L"&Delete Mount Point");
			}
		}

		int retVal = menu.TrackPopupMenu(TPM_LEFTALIGN | TPM_TOPALIGN | TPM_NONOTIFY | TPM_RETURNCMD, point.x, point.y, this);

		

		switch (retVal) {
		case 1:
			{	
				CFolderDialog fdlg; 
				fdlg.DoModal();
				CString path = fdlg.GetPathName();
				if (path.GetLength())
					AddMountPoint(path);
			}
			break;
		case 2:
		{
			DeleteMountPoint(item);
			return;

		}
		default:
			break;
		}

		// Handle your returns here.
	}
}

void CMountPropertyPage::AddMountPoint(const CString & path)
{
	if (path.GetLength() < 1)
		return;

	if (!is_suitable_mountpoint(path)) {
		MessageBox(L"The path is not suitable for use as a mount point.  The folder must be empty, and it must reside on an NTFS filesystem",
			L"cppcyrptfs", MB_OK | MB_ICONEXCLAMATION);
		return;
	}

	CString mountPointsStr = theApp.GetProfileString(L"MountPoint", L"MountPoints", NULL);

	int i = 0;
	for (CString mp = mountPointsStr.Tokenize(L"|", i); i >= 0; mp = mountPointsStr.Tokenize(L"|", i)) {
		if (!_wcsicmp(path, mp)) {
			MessageBox(L"Mount point has already been added.", L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
			return;
		}
	}

	if (mountPointsStr.GetLength() > 0)
		mountPointsStr += L"|";

	mountPointsStr += path;

	theApp.WriteProfileString(L"MountPoint", L"MountPoints", mountPointsStr);

	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	i = pList->GetItemCount();

	pList->InsertItem(LVIF_TEXT | (m_imageIndex >= 0 ? LVIF_IMAGE : 0) | LVIF_STATE, i, path,
		true ? LVIS_SELECTED : 0, LVIS_SELECTED, m_imageIndex >= 0 ? m_imageIndex : 0, 0);

	pList->EnsureVisible(i, FALSE);

}

// builds array of all mountpoints inclding available drive letters
void CMountPropertyPage::GetMountPoints(CStringArray & mountPoints)
{
	CString mountpoints = theApp.GetProfileString(L"MountPoint", L"MountPoints", NULL);
	
	int i;

	for (i = 'A'; i <= 'Z'; i++) {
		WCHAR buf[3];
		buf[0] = (WCHAR)i;
		buf[1] = ':';
		buf[2] = '\0';
		if (theApp.m_mountedMountPoints.find(buf) != theApp.m_mountedMountPoints.end() || IsDriveLetterAvailable((WCHAR)i)) {
			WCHAR buf[3];
			buf[0] = (WCHAR)i;
			buf[1] = ':';
			buf[2] = '\0';
			mountPoints.Add(buf);
		}
	}

	i = 0;
	for (CString path = mountpoints.Tokenize(L"|", i); i >= 0; path = mountpoints.Tokenize(L"|", i)) {
		mountPoints.Add(path);
	}

}

void CMountPropertyPage::DeleteMountPoint(int item)
{
	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return;

	CString delmp = pList->GetItemText(item, 0);

	CString mountPointsStr = theApp.GetProfileString(L"MountPoint", L"MountPoints", NULL);

	CStringArray mountPoints;

	int i = 0;
	for (CString path = mountPointsStr.Tokenize(L"|", i); i >= 0; path = mountPointsStr.Tokenize(L"|", i)) {
		mountPoints.Add(path);
	}

	mountPointsStr = L"";

	for (i = 0; i < mountPoints.GetCount(); i++) {
		if (!_wcsicmp(mountPoints.GetAt(i), delmp))
			continue;
		if (i > 0)
			mountPointsStr += "|";
		mountPointsStr += mountPoints.GetAt(i);
		
	}

	theApp.WriteProfileString(L"MountPoint", L"MountPoints", mountPointsStr);

	pList->DeleteItem(item);


}

void CMountPropertyPage::OnExit()
{
	CListCtrl* pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (pList) {
		int mountPointColumnWidth = pList->GetColumnWidth(0);
		if (IsValidMountPointColumnWidth(mountPointColumnWidth)) {
			theApp.WriteProfileInt(L"MountPoint", L"MountPointColumnWidth", mountPointColumnWidth);
		}
	}
	CCryptPropertyPage::OnExit();
}

BOOL CMountPropertyPage::IsValidMountPointColumnWidth(int cw)
{
	return cw >= 50 && cw <= 350;
}
