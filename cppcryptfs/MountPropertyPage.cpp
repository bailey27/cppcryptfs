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
#include "CryptPropertySheet.h"
#include "crypt.h"
#include "util.h"
#include "getopt.h"

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
	CString mes = Mount();

	if (mes.GetLength() > 0 && mes != L"password cannot be empty")
		MessageBox(mes, L"cppcryptfs", MB_OK | MB_ICONEXCLAMATION);
}

CString CMountPropertyPage::Mount(LPCWSTR argPath, WCHAR argDriveLetter, LPCWSTR argPassword)
{
	if (argDriveLetter != 0 && (argDriveLetter < 'A' || argDriveLetter > 'Z'))
		return CString(L"invalid drive letter");

	POSITION pos = NULL;

	CSecureEdit *pPass = &m_password;

	LockZeroBuffer<WCHAR> password(MAX_PASSWORD_LEN+1);

	if (!password.IsLocked()) {
		return CString(L"unable to lock password buffer");
	}

	if (wcscpy_s(password.m_buf, MAX_PASSWORD_LEN+1, argPassword ? argPassword : pPass->m_strRealText))
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
	
	if (argDriveLetter) {
		LVFINDINFO fi;
		memset(&fi, 0, sizeof(fi));
		fi.flags = LVFI_STRING;
		CString str = CString(argDriveLetter) + L":";
		fi.psz = str;
		nItem = pList->FindItem(&fi);
		if (nItem < 0)
			return CString(L"Drive ") + str + CString(L" is already in use.");
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

	CString cdl = argDriveLetter ? CString(argDriveLetter) + L":" : pList->GetItemText(nItem, DL_INDEX);

	if (cdl.GetLength() < 1)
		return CString(L"unable to get drive letter");;

	BOOL dlInUse = !IsDriveLetterAvailable(*(LPCWSTR)cdl);

	CString mounted_path = pList->GetItemText(nItem, PATH_INDEX);

	if (mounted_path.GetLength() > 0)
		dlInUse = true;

	if (dlInUse) {
		CString mes = L"Drive ";
		mes += cdl;
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
	
	theApp.DoWaitCursor(1);
	int result = mount_crypt_fs(*(const WCHAR *)cdl, cpath, password.m_buf, error_mes);
	theApp.DoWaitCursor(-1);

	if (result != 0) {
		return CString(&error_mes[0]);
	}

	theApp.m_mountedDrives |= 1 << (*(const WCHAR*)cdl - 'A');

	pList->SetItemText(nItem, PATH_INDEX, cpath);

	RecentItems ritems(TEXT("Folders"), TEXT("LastDir"), m_numLastDirs);
	ritems.Add(cpath);

	WCHAR dl[2];
	dl[0] = *(const WCHAR *)cdl;
	dl[1] = 0;

	theApp.WriteProfileString(L"MountPoints", L"LastMountPoint", dl);

	CString path_hash;

	if (GetPathHash(cpath, path_hash)) {
		theApp.WriteProfileString(L"MountPoints", path_hash, dl);
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

BOOL CMountPropertyPage::GetPathHash(LPCWSTR path, CString& hashstr)
{

	hashstr = L"";

	std::string str;

	if (!unicode_to_utf8(path, str))
		return FALSE;

	BYTE sum[32];

	if (!sha256(str, sum))
		return FALSE;

	int i;

	// use only 64bits of the sha256 to keep registry key length short

	for (i = 0; i < 8; i++) {
		WCHAR buf[3];
		wsprintf(buf, L"%02x", sum[i]);
		hashstr += buf;
	}

	return TRUE;
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

	DWORD drives = GetUsedDrives();

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

	// limit input lengths

	m_password.SetLimitText(MAX_PASSWORD_LEN);

	CComboBox *pCombo = (CComboBox*)GetDlgItem(IDC_PATH);
	if (pCombo)
		pCombo->LimitText(MAX_PATH);

	if (!m_password.ArePasswordBuffersLocked())
		MessageBox(L"unable to lock password buffer", L"cppcryptfs", MB_OK | MB_ICONERROR);

	ProcessCommandLine(GetCurrentProcessId(), GetCommandLine(), TRUE);

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

CString CMountPropertyPage::Dismount(WCHAR argDriveLetter)
{
	if (argDriveLetter != 0 && (argDriveLetter < 'A' || argDriveLetter > 'Z'))
		return CString(L"invalid drive letter");

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return CString(L"unable to get list");

	POSITION pos = pList->GetFirstSelectedItemPosition();

	if (!pos)
		return CString(L"unable to get selection");

	int nItem;
	
	if (argDriveLetter) {
		LVFINDINFO fi;
		memset(&fi, 0, sizeof(fi));
		fi.flags = LVFI_STRING;
		CString str = CString(argDriveLetter) + L":";
		fi.psz = str;
		nItem = pList->FindItem(&fi);
		if (nItem < 0)
			return CString(L"Drive ") + str + CString(L" does not have a mounted cppcryptfs filesystem.");
	} else {
		nItem = pList->GetNextSelectedItem(pos);
	}

	if (nItem < 0)
		return CString(L"unable to find item");

	CString cdl = pList->GetItemText(nItem, DL_INDEX);

	if (cdl.GetLength() < 1)
		return CString(L"unable to get drive letter");

	CString cpath = pList->GetItemText(nItem, PATH_INDEX);

	if (cpath.GetLength() < 1)
		return CString(L"Drive ") + cdl + CString(L" does not have a mounted cppcryptfs filesystem.");

	CString mes;

	if (!write_volume_name_if_changed(*(const WCHAR *)cdl))
		mes += L"unable to update volume label";

	theApp.DoWaitCursor(1);
	BOOL bresult = unmount_crypt_fs(*(const WCHAR *)cdl, true);
	theApp.DoWaitCursor(-1);

	if (!bresult) {
		if (mes.GetLength() > 0)
			mes += L". ";
		mes += L"cannot umount ";
		mes.Append(cdl);
		return mes;
	}

	theApp.m_mountedDrives &= ~(1 << (*(const WCHAR *)cdl - 'A'));

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

	if (!GetPathHash(cpath, path_hash))
		return;

	CString cdl = theApp.GetProfileString(L"MountPoints", path_hash, L"");

	if (cdl.GetLength() != 1)
		return;

	if (!IsDriveLetterAvailable(*((LPCWSTR)cdl)))
		return;

	CListCtrl *pList = (CListCtrl*)GetDlgItem(IDC_DRIVE_LETTERS);

	if (!pList)
		return;

	LVFINDINFO fi;

	memset(&fi, 0, sizeof(fi));

	fi.flags = LVFI_STRING;

	cdl += L":";

	fi.psz = (LPCWSTR)cdl;

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
	fprintf(stderr, "Mounting:\n");
	fprintf(stderr, "  -m, --mount=PATH\tmount filesystem locate at PATH\n");
	fprintf(stderr, "  -d, --drive=D\t\tmount to drive letter D\n");
	fprintf(stderr, "  -p, password=PASSWORD\tuse password PASSWORD\n");
	fprintf(stderr, "Unmounting:\n");
	fprintf(stderr, "  -u, --unmount=D\tumount drive letter D\n");
	fprintf(stderr, "  -u, --umount=all\tunmount all drives\n");
	fprintf(stderr, "Misc:\n");
	fprintf(stderr, "  -t, --tray\thide in system tray\n");
	fprintf(stderr, "  -x, --exit\texit if no drives mounted\n");
	fprintf(stderr, "  -h, --help\tdisplay this help message\n");
	
}

void CMountPropertyPage::ProcessCommandLine(DWORD pid, LPCWSTR szCmd, BOOL bOnStartup)
{

	optarg = NULL;
	optind = 1;
	opterr = 1;
	optopt = 0;

	int argc = 1;

	LPWSTR *argv = NULL;

	if (szCmd)
		argv = CommandLineToArgvW(szCmd, &argc);

	if (argv == NULL)
		argc = 1;

	if (argc == 1)
		return;

	CString mes;

	if (AttachConsole(bOnStartup ? ATTACH_PARENT_PROCESS : pid)) {
#pragma warning( push )
#pragma warning(disable : 4996)
		freopen("CONOUT$", "wt", stdout);
		freopen("CONOUT$", "wt", stderr);
#pragma warning( pop )
	}

	CString path;
	WCHAR driveletter = 0;
	LockZeroBuffer<WCHAR> password((DWORD)(wcslen(szCmd) + 1));
	BOOL mount = FALSE;
	BOOL dismount = FALSE;
	BOOL dismount_all = FALSE;

	BOOL invalid_opt = FALSE;

	BOOL do_help = FALSE;
	BOOL exit_if_no_mounted = FALSE;
	BOOL hide_to_system_tray = FALSE;

	try {

		static struct option long_options[] =
		{
			{L"mount",   required_argument,  0, 'm'},
			{L"drive",   required_argument,  0, 'd'},
			{L"password", required_argument, 0, 'p'},
			{L"unmount",  required_argument, 0, 'u'},
			{L"tray",  no_argument, 0, 't'},
			{L"exit",  no_argument, 0, 'x'},
			{L"help",  no_argument, 0, 'h'},
			{0, 0, 0, 0}
		};

		int c;
		int option_index = 0;

		while (1) {

			c = getopt_long(argc, argv, L"m:d:p:u:hxt", long_options, &option_index);

			if (c == -1)
				break;

			switch (c) {
			case '?':
				invalid_opt = TRUE;
				break;
			case 'm':
				mount = TRUE;
				path = optarg;
				break;
			case 'd':
				driveletter = *optarg;
				break;
			case 'p':
				wcscpy_s(password.m_buf, password.m_len, optarg);
				break;
			case 'u':
				dismount = TRUE;
				if (wcscmp(optarg, L"all") == 0)
					dismount_all = TRUE;
				else
					driveletter = *optarg;
				break;
			case 'h':
				do_help = TRUE;
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
	
		if (IsCharLower(driveletter))
				driveletter = towupper(driveletter);		

	} catch (int err) {
		if (err) {
			if (mes.GetLength() == 0)
				mes = L"unexpected exception";
		}
	}

	if (argv)
		LocalFree(argv);

	if (mes.GetLength() > 0) {
		fwprintf(stderr, L"cppcryptfs: %s\n", (LPCWSTR)mes);
	} else if (do_help) {
		usage();
	} else if (invalid_opt) {
		fprintf(stderr, "Try 'cppcryptfs --help' for more information.\n");
	} else {
		CString errMes;
		if (mount) {
			errMes = Mount(path, driveletter, password.m_buf);
		} else if (dismount) {
			if (dismount_all) {
				errMes = DismountAll();
			} else {
				errMes = Dismount(driveletter);
			}
		} else {
			//errMes = "nothing to do";
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
		if (theApp.m_mountedDrives == 0 && exit_if_no_mounted) {
			pParent->OnIdrExitcppcryptfs();
		} else if (hide_to_system_tray) {
			if (bOnStartup)
				pParent->m_bHideAfterInit = TRUE;
			else
				pParent->ShowWindow(SW_HIDE);
		}
	}

}