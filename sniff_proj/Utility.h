#pragma once
#include "common.h"
#include "stdafx.h"
#include <string>
#include <stdexcept>
#include <vector>
#include <boost/regex.hpp>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/sniffer.h>
#include <tins/network_interface.h>
#include <tins/ip.h>
#include <vector>
#include <WinSock2.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
//#pragma comment(lib, "E:\\Microsoft SDKs\\WpdPack_4_1_2\\WpdPack\\Lib\\wpcap.lib")

#ifndef TINS_STATIC
#define TINS_STATIC
#endif

#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

using std::string;
using std::exception;
using std::vector;
using boost::regex;
using boost::match_results;

using Tins::PDU;
using Tins::NetworkInterface;
using Tins::SnifferConfiguration;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

const size_t MAX_PAYLOAD = 3 * 1024;

class Utility
{
public:
	explicit Utility(HWND hWnd);
	
	~Utility();

public:
	bool initPcap();
	void startCapture(int cardIndex);
	void stopCapture();

private:
	std::vector<CString> cards;

public:
	HWND hTagWnd;
	HANDLE capThreadHandle;
	Pocket mPocket;
	vector<NetworkInterface> mNetCards;
	vector<CString> szCardsName;
	Tins::Sniffer *mSniffer;
	
	string mCurCard;
	static bool capped;
};