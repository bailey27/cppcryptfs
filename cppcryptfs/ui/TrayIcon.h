// TrayIcon.h : header file

#ifndef TrayIconh
#define TrayIconh

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

/*
This is a suite of classes to make it easy to create Applications that minimize to the System Tray.
In CTrayIcon clicking the icon immediately restores the Application's Main Window.
CMenuTrayIcon handles a Context Menu for the icon, so Right-Clicking the Icon makes one of your Icon Resources pop up and Double-Clicking the icon performs that menu's Default Action.
CAniTrayIcon extends CTrayIcon to animate the Icon (you give it a list of Icon Resources).
CAniMenuTrayIcon has Animated Icons and a Context Menu.

Since this class cannot maintain the Title-Bar movement animation on Minimize and Restore that the operating system normally implements you may wish to use my CWndAnimator class with this class.

CTrayIcon helps you make a basic TrayIcon application.
Create a single instance of the class after your Application's m_pMainWnd variable is set.
In CMyApp::InitInstance() (this example is for a Dialog Application):

  CMyDlg dlg;
  m_pMainWnd=&dlg;
  CTrayIcon TI("My ToolTip Text", AfxGetApp()->LoadIcon(IDR_MAINFRAME));
  dlg.DoModal();

If you want your Main Window's Task Bar Button to be hidden when the window is minimized to the System Tray you will need to add the following function:
Use ClassWizard to add an OnSysCommand handler.

void CMyDlg::OnSysCommand(UINT nID, LPARAM lParam) {
  switch(nID & 0xFFF0) {
    case SC_MINIMIZE:  if(lParam) ShowWindow(SW_HIDE); else SetForegroundWindow(); return;
    case IDM_ABOUTBOX: CAboutDlg().DoModal();    return; //This line is only for a Dialog Application with an About Box.
    default: CDialog::OnSysCommand(nID, lParam); return;
} }


CMenuTrayIcon is a CTrayIcon with a Context Menu.

Your CMyApp::InitInstance() would now have a couple of extra parameters to construct the CMenuTrayIcon.
You need to create a Menu Resource, in this case called IDR_PopUps.
The first SubMenu will be used for the System Tray Icon (You can keep all your other PopUp Menus in the same Menu Resource).
The last parameter is the ID of the Default Menu Item.
The Default Menu Item will be shown in bold text in the menu and will be what happens when the user double-clicks the icon.

  CMyDlg dlg;
  m_pMainWnd=&dlg;
  CMenuTrayIcon MTI("My ToolTip Text", AfxGetApp()->LoadIcon(IDR_MAINFRAME), IDR_PopUps, ID_ShowMe);
  dlg.DoModal();

You will also have to use ClassWizard to create handlers for each of these menu items (COMMAND and, optionally, UPDATE_COMMAND_UI).
To show your application, use ShowWindow(SW_RESTORE);
To close a dialog application, use CDialog::OnCancel();


CAniTrayIcon is a CTrayIcon that handles Animated Icons.

Your Application can now set a NULL Terminated Array of Icon Resource IDs and turn Animation on and off:

  CMyDlg dlg;
  m_pMainWnd=&dlg;
  CAniTrayIcon ATI("My ToolTip Text", AfxGetApp()->LoadIcon(IDR_MAINFRAME));
  static const UINT Icons[]={IDI_ICON1,IDI_ICON2,IDI_ICON3, ... ,0};
  AMTI.SetIcons(Icons);
  ATI.Animate(100); //Show one frame every 100 milliseconds.
  dlg.DoModal();

Well, that'll show you how it works, but to allow your Application to access the CAniTrayIcon::Animate and CAniTrayIcon::StopAnimating functions,
you'll need to create an instance of the class you want to use in your Application Header file,
then use the Create function when you've got the pointer to the Main Window.
You can then access the class by using AfxGetApp().
For example:

((CMyApp*)AfxGetApp())->ATI.StopAnimating();


CAniMenuTrayIcon is a CTrayIcon that handles Animated Icons and a Context Menu.
You implement it using the methods described for the previous two classes.
*/

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> CTrayIcon <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
//A Simple and fast Tray Icon Application class.

class CTrayIcon : public CWnd {
public:
  // disallow copying
  CTrayIcon(CTrayIcon const&) = delete;
  void operator=(CTrayIcon const&) = delete;

  CTrayIcon() {}
  CTrayIcon(LPCTSTR szTip, HICON hIcon) {Create(szTip, hIcon);}
  virtual ~CTrayIcon() {
    RemoveIcon();
    DestroyWindow();
  }

  CString GetTooltipText() const {return NID.szTip;}
  BOOL SetTooltipText(LPCTSTR szTip){
    if(!OK) return FALSE;
    NID.uFlags=NIF_TIP;
	wcscpy_s(NID.szTip, sizeof(NID.szTip) / sizeof(NID.szTip[0]), szTip);
    return Shell_NotifyIcon(NIM_MODIFY, &NID);
  }

  HICON GetIcon() const {return NID.hIcon;}
  BOOL SetIcon(HICON hIcon) {
    if(!OK) return FALSE;
    NID.uFlags=NIF_ICON;
    NID.hIcon=hIcon;
    return Shell_NotifyIcon(NIM_MODIFY, &NID);
  }

protected:
  BOOL OK; // true if the operating system supports tray icons and the Icon was successfully created
  NOTIFYICONDATA NID;

// Operations
  BOOL Create(LPCTSTR szTip, HICON hIcon, UINT Menu=0) { //Menu may be used by derived classes
    //VERIFY(OK=(GetVersion() & 0xFF)>=4); // this is only for Windows 95 (or higher)
	OK = TRUE;
    if(OK) {
      ASSERT(_tcslen(szTip)<=64); // Tray only supports tooltip text up to 64 characters
    // Create this invisible window for Message passing
      CWnd::CreateEx(0, AfxRegisterWndClass(0), _T(""), WS_POPUP, 0,0,10,10, 0, 0);
      memset(&NID, 0, sizeof(NID));
      NID.cbSize=sizeof(NOTIFYICONDATA);
      NID.hWnd  =m_hWnd;//pParent->GetSafeHwnd()? pParent->GetSafeHwnd() : m_hWnd;
      NID.uID   =Menu;
      NID.hIcon =hIcon;
      NID.uFlags=NIF_MESSAGE | NIF_ICON | NIF_TIP;
      NID.uCallbackMessage=RegisterWindowMessage(L"CTrayIcon");
	  wcscpy_s(NID.szTip, sizeof(NID.szTip) / sizeof(NID.szTip[0]), szTip);
      VERIFY(OK=Shell_NotifyIcon(NIM_ADD, &NID));
    }
    if(!OK) memset(&NID, 0, sizeof(NID));
    return OK;
  }

  void RemoveIcon() {
    if(!OK) return;
    NID.uFlags=0;
    Shell_NotifyIcon(NIM_DELETE, &NID);
    OK=false;
  }

// Overrides
  virtual LRESULT WindowProc(UINT Message, WPARAM wParam, LPARAM lParam) {
    if(Message==NID.uCallbackMessage
    && wParam==NID.uID
    && (lParam==WM_LBUTTONDOWN
     || lParam==WM_LBUTTONDBLCLK
     || lParam==WM_RBUTTONDOWN
     || lParam==WM_RBUTTONDBLCLK)) {
      AfxGetMainWnd()->PostMessage(WM_SYSCOMMAND, SC_RESTORE, 0);
      return TRUE;
    }
    return CWnd::WindowProc(Message, wParam, lParam);
  }
};

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> CMenuTrayIcon <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
//A Tray Icon Application class that handles Context Menus.

class CMenuTrayIcon : public CTrayIcon {
public:
  CMenuTrayIcon() : DoubleClicked(false) {}
  CMenuTrayIcon(LPCTSTR szTip, HICON hIcon, UINT Menu=0, UINT Default=0, BOOL ByPos=FALSE) : DoubleClicked(false) {Create(szTip, hIcon, Menu, Default, ByPos);}
  void Create(LPCTSTR szTip, HICON hIcon, UINT Menu=0, UINT Default=0, BOOL ByPos=FALSE) {
    CTrayIcon::Create(szTip, hIcon, Menu);
    SetMenuDefaultItem(Default, ByPos);
  }
  virtual ~CMenuTrayIcon() {}

// Attributes
protected:
  UINT  DefaultMenuItemID;
  BOOL  DefaultMenuItemByPos;
  bool  DoubleClicked;

// Operations
public:
  bool SetMenuDefaultItem(UINT MenuItemID, BOOL ByPos) {
    if((DefaultMenuItemID==MenuItemID) && (DefaultMenuItemByPos==ByPos)) return TRUE;
    DefaultMenuItemID   =MenuItemID;
    DefaultMenuItemByPos=ByPos;   
    CMenu Menu, *pSubMenu;
    if(!Menu.LoadMenu(NID.uID)
    || !(pSubMenu=Menu.GetSubMenu(0))) return false;
    ::SetMenuDefaultItem(pSubMenu->m_hMenu, DefaultMenuItemID, DefaultMenuItemByPos);
    return true;
  }

// Overrides
  virtual LRESULT WindowProc(UINT Message, WPARAM wParam, LPARAM lParam) {
    if(Message==NID.uCallbackMessage
     && wParam==NID.uID) {
      CMenu Menu, *pSubMenu;
      CWnd* pMainWnd=AfxGetMainWnd();
      switch(LOWORD(lParam)) {
        case WM_RBUTTONUP: { // Clicking with right button brings up a context Menu
          if(!Menu.LoadMenu(NID.uID)
          || !(pSubMenu=Menu.GetSubMenu(0))) return false;
      // Make chosen Menu item the default (bold font)
          ::SetMenuDefaultItem(pSubMenu->m_hMenu, DefaultMenuItemID, DefaultMenuItemByPos);
      // Display and track the popup Menu
          CPoint Mouse;
          GetCursorPos(&Mouse);
          pMainWnd->SetForegroundWindow();      // See MSDN Knowledge Base article "PRB: Menus for Notification Icons Don't Work Correctly"
          pSubMenu->TrackPopupMenu(TPM_LEFTALIGN, Mouse.x, Mouse.y, pMainWnd, 0);
          pMainWnd->PostMessage(WM_NULL, 0, 0); // See MSDN Knowledge Base article "PRB: Menus for Notification Icons Don't Work Correctly"
          Menu.DestroyMenu();
          return true;
        }
        case WM_LBUTTONDBLCLK: return DoubleClicked=true; // double click received, do the default Menu item
        case WM_LBUTTONUP: {
          if(DoubleClicked) { // Make sure that if the default deletes the icon, that the next icon doesn't get our WM_LBUTTONUP notification (some icons use it).
            DoubleClicked=false;
            pMainWnd->SetForegroundWindow();  
            UINT uItem;
            if(DefaultMenuItemByPos) {
              if(!Menu.LoadMenu(NID.uID)
              || !(pSubMenu=Menu.GetSubMenu(0))) return false;
              uItem=pSubMenu->GetMenuItemID(DefaultMenuItemID);
            }else uItem=DefaultMenuItemID;
            pMainWnd->PostMessage(WM_COMMAND, uItem, 0);
            Menu.DestroyMenu();
            return true;
    } } } }
    return CWnd::WindowProc(Message, wParam, lParam);
  }
};

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> CAniIcon <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
//An Abstract Class that handles Animated Icons for the following two classes.

class CAniIcon {
// Construction
public:
  CAniIcon() : Icons(0), hIcon(0) {} //Needed for derived classes
  virtual ~CAniIcon() {if(Icons) delete Icons;}

// Attributes
private:
  CTime  StartTime;
  int    Duration; // Stop animating after Duration milliseconds
  UINT_PTR   TimerID;
  HICON* Icons;    // NULL Terminated Array of Icons to animate
  HICON* it;       // Frame Iterator
  HICON  hIcon;    // A copy of the original (non-animated) Icon.

// Operations
public:
  virtual HICON GetIcon() const      =0;
  virtual BOOL  SetIcon(HICON hIcon) =0;

  virtual UINT_PTR SetTimer(UINT nIDEvent, UINT nElapse, void (CALLBACK* lpfnTimer)(HWND, UINT, UINT_PTR, DWORD)) =0;
  virtual BOOL KillTimer(INT_PTR nIDEvent) =0;

  void SetIcons(const UINT IconIDs[]) { // NULL Terminated Array of Icon Recource IDs to animate
    const UINT* ptr=IconIDs;
	int i;
    for(i=1; *ptr++; ++i); //Count them
    if(Icons) delete Icons;
    it=Icons=new HICON[i];     //Prepare storage for their HICONs
    const CWinApp* App=AfxGetApp();
    ASSERT(App);
    for(ptr=IconIDs; i=*ptr++; *it++=App->LoadIcon(i)); //Store the HICONs
    *it=0; //NULL Terminate the list
  }

#define TrayIconTimer 1032

  BOOL Animate(UINT nDelayMilliSeconds, int nNumSeconds=-1) {
    if(!Icons) return FALSE;
    StopAnimating();
    it=Icons;
    StartTime=CTime::GetCurrentTime();
    Duration=nNumSeconds;
    hIcon=GetIcon();
    TimerID=SetTimer(TrayIconTimer, nDelayMilliSeconds, 0);
    return TimerID != 0;
  }

  void StopAnimating() {
    if(TimerID) KillTimer(TimerID);
    TimerID=0;
    if(hIcon) SetIcon(hIcon);
    hIcon=0;
  }

  virtual LRESULT WindowProc(UINT Message, WPARAM wParam, LPARAM lParam) {
    if(Message!=WM_TIMER || wParam!=TrayIconTimer) return false;
    CTime CurrentTime=CTime::GetCurrentTime();
    CTimeSpan period=CurrentTime-StartTime;
    if(Duration>0 && Duration<period.GetTotalSeconds()) StopAnimating();
    else if(Icons) {
      HICON Icon=*it++;
      if(!Icon) {
        it=Icons;
        Icon=*it++;
      }
      if(Icon) SetIcon(Icon);
      else StopAnimating();
    }
    return true;
  }
};

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> CAniTrayIcon <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
//A Tray Icon Application class that handles Animated Icons.

class CAniTrayIcon : public CTrayIcon, public CAniIcon {
// Construction
public:
  CAniTrayIcon() {}
  CAniTrayIcon(LPCTSTR szTip, HICON hIcon) {Create(szTip, hIcon);}
  virtual ~CAniTrayIcon() {StopAnimating();}

  HICON GetIcon() const      {return CTrayIcon::GetIcon();}
  BOOL  SetIcon(HICON hIcon) {return CTrayIcon::SetIcon(hIcon);}

  UINT_PTR SetTimer(UINT nIDEvent, UINT nElapse, void (CALLBACK* lpfnTimer)(HWND, UINT, UINT_PTR, DWORD)) {return CTrayIcon::SetTimer(nIDEvent, nElapse, lpfnTimer);}
  BOOL KillTimer(INT_PTR nIDEvent) {return CTrayIcon::KillTimer(nIDEvent);}

  virtual LRESULT WindowProc(UINT Message, WPARAM wParam, LPARAM lParam) {
    if(CAniIcon::WindowProc(Message,wParam,lParam)) return true;
    return CTrayIcon::WindowProc(Message,wParam,lParam);
  }
};

//>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> CAniMenuTrayIcon <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
//A Tray Icon Application class that handles Animated Icons and Context Menus.

class CAniMenuTrayIcon : public CMenuTrayIcon, public CAniIcon {
// Construction
public:
  CAniMenuTrayIcon() {}
  CAniMenuTrayIcon(LPCTSTR szTip, HICON hIcon, UINT Menu=0, UINT Default=0, BOOL ByPos=FALSE) : CMenuTrayIcon(szTip, hIcon, Menu, Default, ByPos) {}
  virtual ~CAniMenuTrayIcon() {StopAnimating();}

  HICON GetIcon() const      {return CMenuTrayIcon::GetIcon();}
  BOOL  SetIcon(HICON hIcon) {return CMenuTrayIcon::SetIcon(hIcon);}

  UINT_PTR SetTimer(UINT nIDEvent, UINT nElapse, void (CALLBACK* lpfnTimer)(HWND, UINT, UINT_PTR, DWORD)) {return CMenuTrayIcon::SetTimer(nIDEvent, nElapse, lpfnTimer);}
  BOOL KillTimer(INT_PTR nIDEvent) {return CMenuTrayIcon::KillTimer(nIDEvent);}

  virtual LRESULT WindowProc(UINT Message, WPARAM wParam, LPARAM lParam) {
    if(CAniIcon::WindowProc(Message,wParam,lParam)) return true;
    return CMenuTrayIcon::WindowProc(Message,wParam,lParam);
  }
};

#endif //ndef TrayIconh
