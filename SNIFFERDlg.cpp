
// SNIFFERDlg.cpp : implementation file
//

#include "stdafx.h"
#include "SNIFFER.h"
#include "SNIFFERDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CSnifferDlg dialog



CSnifferDlg::CSnifferDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_SNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, mListView);
	DDX_Control(pDX, IDC_CBCARDS, mComboCards);
	DDX_Control(pDX, IDC_BTNSTART, mBtnStart);
	DDX_Control(pDX, IDC_BTNSTOP, mBtnStop);
}


BEGIN_MESSAGE_MAP(CSnifferDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//自定义消息映射
	ON_MESSAGE(WM_ADDITEM, OnAddItem)
	ON_MESSAGE(WM_ADDCARD, OnAddCard)
	ON_BN_CLICKED(IDC_BTNSTART, &CSnifferDlg::OnBnClickedBtnstart)
	ON_BN_CLICKED(IDC_BTNSTOP, &CSnifferDlg::OnBnClickedBtnstop)
	ON_NOTIFY(NM_RCLICK, IDC_LIST1, &CSnifferDlg::OnNMRClickList1)
	ON_COMMAND(ID_LISTMENU_32772, &CSnifferDlg::OnListmenuClearList)
	ON_COMMAND(ID_LISTMENU_32773, &CSnifferDlg::OnListmenuCopyIP)
	ON_COMMAND(ID_LISTMENU_32774, &CSnifferDlg::OnListmenuCopyUrl)
	ON_COMMAND(ID_LISTMENU_32776, &CSnifferDlg::OnListmenuExit)
END_MESSAGE_MAP()


// CSnifferDlg message handlers

BOOL CSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	//create list view
	initListView();
	
	//disable stop btn
	mBtnStop.EnableWindow(false);

	//prepare net handler
	utility = new Utility(this->m_hWnd);
	return TRUE;  // return TRUE  unless you set the focus to a control
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;
		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);

	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

LRESULT CSnifferDlg::OnAddItem(WPARAM wParam, LPARAM lParam)
{
	//获取消息
	Pocket *pocketRecved = reinterpret_cast<Pocket *>(wParam);
	
	//更新list control
	addLine(pocketRecved->szProtocol, pocketRecved->szSrcIP, pocketRecved->szSrcPort, \
			pocketRecved->szDestIP, pocketRecved->szDestPort, \
			pocketRecved->lSize, pocketRecved->szMethod, pocketRecved->szUrl);
	
	//释放堆
	//if (pocketRecved)
	//	delete pocketRecved;

	return LRESULT();
}

LRESULT CSnifferDlg::OnAddCard(WPARAM wParam, LPARAM lParam) {
	
	mComboCards.AddString(L"------请选择一张网卡进行抓包------");
	mComboCards.SetCurSel(0);
	std::vector<CString> *cards = reinterpret_cast<std::vector<CString> *>(wParam);
	
	//填充combox
	int size = cards->size();
	if (size > 0) {
		for (int i = 0; i < size; ++i)
			mComboCards.AddString(cards->at(i));
	}

	return LRESULT();
}

void CSnifferDlg::initListView()
{
	//get the width of Dlg
	CRect rect;
	mListView.GetClientRect(&rect);

	//set some properties
	mListView.SetExtendedStyle(mListView.GetExtendedStyle() | LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	mListView.InsertColumn(0, _T("#"), LVS_ALIGNLEFT, 20, 0);
	mListView.InsertColumn(1, _T("时间"), UDS_ALIGNLEFT, 60, 0);
	mListView.InsertColumn(2, _T("协议"), UDS_ALIGNLEFT, 40, 0);
	mListView.InsertColumn(3, _T("源IP"), UDS_ALIGNLEFT, 120, 0);
	mListView.InsertColumn(4, _T("源端口"), UDS_ALIGNLEFT, 60, 0);

	mListView.InsertColumn(5, _T("目标IP"), UDS_ALIGNLEFT, 120, 0);
	mListView.InsertColumn(6, _T("目标端口"), UDS_ALIGNLEFT, 60, 0);
	mListView.InsertColumn(7, _T("方法"), UDS_ALIGNLEFT, 40, 0);
	mListView.InsertColumn(8, _T("网址"), UDS_ALIGNLEFT, rect.Width() - 540, 0);

}

void CSnifferDlg::addLine(CString szProtocol, CString szSrcIP, CString szSrcPort, \
						  CString szDestIP, CString szDestPort, \
						  unsigned int pocket_size, CString szMethod, CString url)
{
	int line = mListView.GetItemCount();
	CString num;
	num.Format(L"%d", line == 0 ? 1 : line + 1);
	//size.Format(L"%d", pocket_size);

	mListView.InsertItem(line, num);
	mListView.SetItemText(line, 1, GetTime());
	mListView.SetItemText(line, 2, szProtocol);
	mListView.SetItemText(line, 3, szSrcIP);
	mListView.SetItemText(line, 4, szSrcPort);
	mListView.SetItemText(line, 5, szDestIP);
	mListView.SetItemText(line, 6, szDestPort);
	mListView.SetItemText(line, 7, szMethod);
	mListView.SetItemText(line, 8, url);

}

inline CString CSnifferDlg::GetTime()
{
	SYSTEMTIME time;
	GetLocalTime(&time);

	CString szTime;
	szTime.Format(_T("%ld:%ld:%ld"), time.wHour, time.wMinute, time.wSecond);

//	TCHAR buf[32];
//	wsprintf(buf, _T("%ld:%ld:%ld"), time.wHour, time.wMinute, time.wSecond);
//	szTime.Append(buf);

	return szTime;
}

void CSnifferDlg::OnBnClickedBtnstart()
{
	// TODO: 在此添加控件通知处理程序代码
	if (mComboCards.GetCurSel() == 0)
		return;

	mComboCards.EnableWindow(false);
	mListView.DeleteAllItems();
	mBtnStart.EnableWindow(false);
	mBtnStop.EnableWindow(true);

	//根据当前选中网卡, 开始抓包任务
	utility->startCapture(mComboCards.GetCurSel() - 1);
}


void CSnifferDlg::OnBnClickedBtnstop()
{
	//禁止操作,除非停止
	utility->stopCapture();
	mComboCards.EnableWindow(true);
	mBtnStart.EnableWindow(true);
	mBtnStop.EnableWindow(false);

	//
}


void CSnifferDlg::OnNMRClickList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	CMenu menu;
	menu.LoadMenuW(IDR_MENU1);//加载菜单
	CMenu *pContextMenu = menu.GetSubMenu(0); //获取第一个弹出菜单

	if (mListView.GetSelectedCount() == 0) {
	
		pContextMenu->EnableMenuItem(ID_LISTMENU_32772, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
		pContextMenu->EnableMenuItem(ID_LISTMENU_32773, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
		pContextMenu->EnableMenuItem(ID_LISTMENU_32774, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
		pContextMenu->EnableMenuItem(ID_LISTMENU_32775, MF_BYCOMMAND | MF_DISABLED | MF_GRAYED);
	}
	else {
		//MF_BYCOMMAND | MF_ENABLED
		pContextMenu->EnableMenuItem(ID_LISTMENU_32772, MF_BYCOMMAND | MF_ENABLED);
		pContextMenu->EnableMenuItem(ID_LISTMENU_32773, MF_BYCOMMAND | MF_ENABLED);
		pContextMenu->EnableMenuItem(ID_LISTMENU_32774, MF_BYCOMMAND | MF_ENABLED);
		pContextMenu->EnableMenuItem(ID_LISTMENU_32775, MF_BYCOMMAND | MF_ENABLED);
	}

	CPoint cursorPoint;
	GetCursorPos(&cursorPoint);
	pContextMenu->TrackPopupMenu(TPM_LEFTALIGN | TPM_RIGHTBUTTON, \
								 cursorPoint.x, cursorPoint.y, this);


	*pResult = 0;
}


void CSnifferDlg::OnListmenuClearList()
{
	// TODO: 在此添加命令处理程序代码
	if (mListView.GetItemCount() == 0) {
		return;
	}

	mListView.DeleteAllItems();
}


void CSnifferDlg::OnListmenuCopyIP()
{
	// TODO: 在此添加命令处理程序代码
	copyListItem(5);

}

void CSnifferDlg::OnListmenuCopyUrl()
{
	// TODO: 在此添加命令处理程序代码
	copyListItem(8);

}

void CSnifferDlg::copyListItem(int cloumn)
{
	if (mListView.GetSelectedCount() == 0)
		return;

	CString itemText;
	int nRowID;

	POSITION pos = mListView.GetFirstSelectedItemPosition();
	if (pos == NULL)
		return;

	nRowID = mListView.GetNextSelectedItem(pos);
	itemText = mListView.GetItemText(nRowID, cloumn);

	this->copyToClipbrd(itemText);
}
void CSnifferDlg::copyToClipbrd(const CString& data)
{
	//打开剪贴板
	if (!OpenClipboard())
		return;

	HGLOBAL hClip;

#ifdef _UNICODE
	USES_CONVERSION;
	string s(W2A(data));
#else
	string s(data.GetBuffer(0));
#endif

	char *buffer;
	try {

		EmptyClipboard();

		int buff_len = s.length() + 1;
		//开辟内存用于存放数据
		hClip = GlobalAlloc(GMEM_DDESHARE, buff_len);

		//获取指向该内存区的指针
		buffer = (char*)GlobalLock(hClip);

		//StrCpy(buffer, data);
		//StrNCpy();
		memcpy(buffer, s.c_str(), buff_len);
		GlobalUnlock(hClip);
		SetClipboardData(CF_TEXT, hClip);
		CloseClipboard();
	}
	catch (exception& err) {
		MessageBox(CString(err.what()));
	}

#ifndef _UNICODE
	s.ReleaseBuffer();
#endif

}

void CSnifferDlg::OnListmenuExit()
{
	//先停止抓包, 再退出
	if (utility && mBtnStop.IsWindowEnabled())
		utility->stopCapture();

	ExitProcess(0);
}
