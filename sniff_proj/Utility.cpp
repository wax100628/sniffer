#include "Utility.h"

DWORD WINAPI capData(LPVOID param);
void on_server_data(Stream& stream);
void on_client_data(Stream& stream);
void on_new_connection(Stream& stream);

Utility *utility;
StreamFollower follower;
regex request_regex("([\\w]+) ([^ ]+).+\r\nHost: ([\\d\\w\\.-]+)\r\n");
regex response_regex("HTTP/[^ ]+ ([\\d]+)");

bool Utility::capped = true;

Utility::Utility(HWND hWnd)
{
	if (!hWnd)
		return;
	mNetCards = NetworkInterface::all();
	this->hTagWnd = hWnd;
	utility = this;
	if (!initPcap())
		return;
}

Utility::~Utility()
{

}

bool Utility::initPcap()
{
	int size = mNetCards.size();
	if (size <= 0)
		return false;
  
  //list all Netcards
  for (int i = 0; i < size; ++i) {
		std::wstring name = mNetCards.at(i).friendly_name();
		szCardsName.push_back(name.c_str());
	}

	if (!szCardsName.empty())
		SendMessage(this->hTagWnd, WM_ADDCARD, (WPARAM)&szCardsName, 0);

	return true;
}

void Utility::startCapture(int cardIndex)
{
	capThreadHandle = NULL;
	Utility::capped = true;
	if (mNetCards.at(cardIndex).is_loopback())
		return;

	LPDWORD capThread = NULL;
	mCurCard = mNetCards.at(cardIndex).name();
	
	//use new thread to handle cap
	capThreadHandle = CreateThread(NULL, 0, capData, this, 0, capThread);
}

void Utility::stopCapture()
{
	try {
		Utility::capped = false;
		if (capThreadHandle) {
			CloseHandle(capThreadHandle);
		}
	}
	catch (exception& err) {
		CString error = CString(err.what());
		AfxMessageBox(L"sth. wrong..." + error + L"\r\nbut no matter.");
	}
}

DWORD WINAPI capData(LPVOID lpParameter)
{
	//Utility *pthis = (Utility*)lpParameter;
	try {
		SnifferConfiguration conf;
		conf.set_promisc_mode(true);
		conf.set_immediate_mode(true);
		conf.set_filter("tcp or udp");

		Tins::Sniffer curSniffer(utility->mCurCard, conf);

		follower.new_stream_callback(&on_new_connection);

		curSniffer.sniff_loop([&](PDU& packet) {
			try {
				Tins::IP &ip = packet.rfind_pdu<Tins::IP>();
				//get packet len
				(utility->mPocket).lSize = ip.tot_len();
				//get protocol type
				CString proto;
				//proto.Format(L"%d", ip.protocol());

				switch (ip.protocol()) {
				case MPROTO_ICMP:
					proto = L"ICMP";
					break;
				case MPROTO_TCP:
					proto = L"TCP";
					break;
				case MPROTO_UDP:
					proto = L"UDP";
					break;
				case MPROTO_ICMPV6:
					proto = L"ICMPv6";
					break;
				case MPROTO_IP:
					proto = L"IP";
					break;
				case MPROTO_ARP:
					proto = L"ARP";
					break;
				case MPROTO_IPV6:
					proto = L"IPv6";
					break;
				default:
					proto = L"0";
					break;
				}

				(utility->mPocket).szProtocol = proto;
			}
			catch (Tins::pdu_not_found& err) {
				//AfxMessageBox(L"IP PDU not found...\r\n" + CString(err.what()));
			}
			
			follower.process_packet(packet);
			return Utility::capped;
		});
	}
	catch (exception& err) {
		//std::cerr << "error: " << err.what() << std::endl;
		return -1;
	}

	return 1;
}


//relative callback
void on_server_data(Stream& stream) {

	match_results<Stream::payload_type::const_iterator> client_match; 
	match_results<Stream::payload_type::const_iterator> server_match; 
	const Stream::payload_type& client_payload = stream.client_payload(); 
	const Stream::payload_type& server_payload = stream.server_payload(); 
	
	// Run the regexes on client/server payloads
	bool both_valid = regex_search(server_payload.begin(), \
							  server_payload.end(), \
							  server_match, response_regex) && \
							  regex_search(client_payload.begin(), \
								  client_payload.end(), \
								  client_match, \
								  request_regex); 
	
	
	// If we matched both the client and the server regexes	
	if (both_valid) { 
		
		// Extract all fields
		string method = string(client_match[1].first, client_match[1].second); 
		string url = string(client_match[2].first, client_match[2].second); 
		string host = string(client_match[3].first, client_match[3].second); 
		//string response_code = string(server_match[1].first, server_match[1].second); 
		// Now print them
		//std::cout << method << " http://" << host << url << " -> " << response_code << std::endl;
		
		//construct msg to send
		CString szSrcPort, szDestPort, szUrl, szProtocol;

		(utility->mPocket).szMethod = CString(method.c_str());

		szUrl = L"http://";
		szUrl += CString(host.c_str());
		szUrl += CString(url.c_str());
		
		(utility->mPocket).szUrl = szUrl;
		//(utility->mPocket).szProtocol = L"nul";
	}
	else {
		(utility->mPocket).szUrl = L"nul";
		//(utility->mPocket).szProtocol = L"nul";
		(utility->mPocket).szMethod = L"nul";
	}

	CString szSrcPort, szDestPort;
	szSrcPort.Format(L"%d", stream.client_port());
	szDestPort.Format(L"%d", stream.server_port());

	(utility->mPocket).szSrcIP = CString(stream.client_addr_v4().to_string().c_str());
	(utility->mPocket).szDestIP = CString(stream.server_addr_v4().to_string().c_str());
	(utility->mPocket).szSrcPort = szSrcPort;
	(utility->mPocket).szDestPort = szDestPort;
	
	SendMessage(utility->hTagWnd, WM_ADDITEM, (WPARAM)(&(utility->mPocket)), 0);

	// Once we've seen the first request on this stream, ignore it
	stream.ignore_client_data();
	stream.ignore_server_data();
	
	// Just in case the server returns invalid data, stop at 3kb
	if (stream.server_payload().size() > MAX_PAYLOAD) {
		stream.ignore_server_data(); 
	}


} 


void on_client_data(Stream& stream) {
	
	// Don't hold more than 3kb of data from the client's flow
	if (stream.client_payload().size() > MAX_PAYLOAD) { 
		stream.ignore_client_data(); 
	}

} 



void on_new_connection(Stream& stream) {

	stream.client_data_callback(&on_client_data); 
	stream.server_data_callback(&on_server_data);
	stream.auto_cleanup_payloads(false);

}