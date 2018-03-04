// FsInfoDialog.cpp : implementation file
//

#include "stdafx.h"
#include "cppcryptfs.h"
#include "FsInfoDialog.h"
#include "afxdialogex.h"


#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CFsInfoDialog dialog


CFsInfoDialog::CFsInfoDialog(CWnd* pParent /*=NULL*/)
	: CDialog(IDD_FSINFO /*CFsInfoDialog::IDD*/, pParent)
{
	//{{AFX_DATA_INIT(CFsInfoDialog)
	
	//}}AFX_DATA_INIT
}


void CFsInfoDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CFsInfoDialog)
	
	//}}AFX_DATA_MAP
	
}


BEGIN_MESSAGE_MAP(CFsInfoDialog, CDialog)
	//{{AFX_MSG_MAP(CFsInfoDialog)
		// NOTE: the ClassWizard will add message map macros here
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDOK, &CFsInfoDialog::OnBnClickedOk)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CFsInfoDialog message handlers


void CFsInfoDialog::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	CDialog::OnOK();
}


BOOL CFsInfoDialog::OnInitDialog()
{
	CDialog::OnInitDialog();

	LPCWSTR yes = L"Yes";
	LPCWSTR no = L"No";

	SetDlgItemText(IDC_PATH, m_info.path.c_str());
	SetDlgItemText(IDC_MOUNT_POINT, m_mountPoint);
	LPCWSTR cfgpath = m_info.configPath.c_str();
	if (!wcsncmp(cfgpath, L"\\\\?\\", wcslen(L"\\\\?\\"))) {
		cfgpath += wcslen(L"\\\\?\\");
	}
	SetDlgItemText(IDC_CONFIG_PATH, cfgpath);
	SetDlgItemText(IDC_FILE_NAME_ENCRYPTION, m_info.fileNameEncryption.c_str());
	SetDlgItemText(IDC_DATA_ENCRYPTION, m_info.dataEncryption.c_str());
	SetDlgItemText(IDC_READ_ONLY, m_info.readOnly ? yes : no);
	SetDlgItemText(IDC_MODE, m_info.reverse ? L"reverse" : L"forward");
	SetDlgItemText(IDC_RECYCLE_BIN, m_info.mountManager ? yes : no);
	SetDlgItemText(IDC_CASE_INSENSITIVE, m_info.caseInsensitive ? yes : no);

	wstring txt;
	txt = to_wstring(m_info.ioBufferSize);
	txt += L"KB";
	SetDlgItemText(IDC_IO_BUFFER_SIZE, txt.c_str());
	txt = to_wstring(m_info.fsThreads);
	SetDlgItemText(IDC_THREADS, txt.c_str());
	txt = to_wstring(m_info.cacheTTL);
	txt += L" sec";
	SetDlgItemText(IDC_CACHE_TTL, txt.c_str());
	WCHAR buf[128];
	float r;
	r = m_info.caseCacheHitRatio;
	if (r < 0.0f) {
		txt = L"N/A";
	} else {
		_snwprintf_s(buf, sizeof(buf) / sizeof(buf[0]) - 1, L"%.2f", r*100.0f);
		txt = buf;
		txt += L"%";
	}
	SetDlgItemText(IDC_CASE_CACHE_HR, txt.c_str());
	r = m_info.lfnCacheHitRatio;
	if (r < 0.0f) {
		txt = L"N/A";
	} else {
		_snwprintf_s(buf, sizeof(buf) / sizeof(buf[0]) - 1, L"%.2f", r*100.0f);
		txt = buf;
		txt += L"%";
	}
	SetDlgItemText(IDC_LFN_CACHE_HR, txt.c_str());
	r = m_info.dirIvCacheHitRatio;
	if (r < 0.0f) {
		txt = L"N/A";
	} else {
		_snwprintf_s(buf, sizeof(buf) / sizeof(buf[0]) - 1, L"%.2f", r*100.0f);
		txt = buf;
		txt += L"%";
	}
	SetDlgItemText(IDC_DIRIV_CACHE_HR, txt.c_str());

	// TODO:  Add extra initialization here

	return TRUE;  // return TRUE unless you set the focus to a control
				  // EXCEPTION: OCX Property Pages should return FALSE
}


