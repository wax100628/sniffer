#pragma once
#include "stdafx.h"
#define WM_ADDITEM		WM_USER+1001
#define WM_ADDCARD		WM_USER+1003
#define MPROTO_ICMP		1  
#define MPROTO_TCP		6                   
#define MPROTO_UDP		17
#define MPROTO_ICMPV6	0x3a
#define MPROTO_IP		0x0800
#define MPROTO_ARP		0x0806
#define MPROTO_IPV6		0x86dd

typedef struct _pocket
{
	CString szProtocol;		//protocol
	unsigned int lSize;				//pocket size
	CString szSrcIP;		//the source IP
	CString szSrcPort;		//source port
	CString szDestIP;		//destination
	CString szDestPort;		//destinate port
	CString szMethod;		//method
	CString szUrl;			//url
}Pocket;