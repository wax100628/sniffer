
// SNIFFERDlg.h : header file
//

#pragma once
#include "common.h"
#include "Utility.h"
#include <string>
#include <vector>
#include "afxwin.h"


// CSnifferDlg dialog
class CSnifferDlg : public CDialogEx
{
// Construction
public:
	CSnifferDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFER_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	//自定义消息声明
	afx_msg LRESULT OnAddItem(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnAddCard(WPARAM wParam, LPARAM lParam);
	DECLARE_MESSAGE_MAP()

private:
	void initListView();
	void addLine(CString szProtocol, CString szSrcIP, CString szSrcPort, \
				 CString szDestIP, CString szDestPort, \
				 unsigned int pocket_size, CString szMethod, CString url);
	inline CString GetTime();
	//void initCBBtn();

public:
	Utility *utility;
	CListCtrl mListView;

	CComboBox mComboCards;
	CButton mBtnStart;
	CButton mBtnStop;
	afx_msg void OnBnClickedBtnstart();
	afx_msg void OnBnClickedBtnstop();
	afx_msg void OnNMRClickList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnListmenuClearList();
	afx_msg void OnListmenuCopyIP();
	afx_msg void OnListmenuCopyUrl();
	void copyToClipbrd(const CString& data);
	void copyListItem(int cloumn);
	afx_msg void OnListmenuExit();
};

