#pragma once
#include"library.h"
#include"message.h"

/*根据TCP端口识别协议*/
void checkTCPdel(TCPHeader* pTCPHdr) {
	switch (pTCPHdr->destinationPort)
	{
	case 21:
		cout << "协议类型:" << "ftp" << endl;
		break;
	case 23:
		cout << "协议类型:" << "telnet" << endl;
		break;
	case 25:
		cout << "协议类型:" << "smtp" << endl;
		break;
	case 53:
		cout << "协议类型:" << "DNS" << endl;
		break;
	case 69:
		cout << "协议类型:" << "tftp" << endl;
		break;
	case 80:
		cout << "协议类型:" << "HTTP" << endl;
		break;
	case 109:
		cout << "协议类型:" << "POP2" << endl;
		break;
	case 110:
		cout << "协议类型:" << "POP3" << endl;
		break;
	case 443:
		cout << "协议类型:" << "HTTPS" << endl;
		break;
	default:
		break;
	}
}

/*根据UDP端口识别协议*/
void checkUDPdel(UDPHeader* pUDPHdr) {
	switch (pUDPHdr->destinationPort)
	{
	case 21:
		cout << "协议类型:" << "ftp" << endl;
		break;
	case 23:
		cout << "协议类型:" << "telnet" << endl;
		break;
	case 25:
		cout << "协议类型:" << "smtp" << endl;
		break;
	case 69:
		cout << "协议类型:" << "tftp" << endl;
		break;
	case 80:
		cout << "协议类型:" << "HTTP" << endl;
		break;
	case 109:
		cout << "协议类型:" << "POP2" << endl;
		break;
	case 110:
		cout << "协议类型:" << "POP3" << endl;
		break;
	case 443:
		cout << "协议类型:" << "HTTPS" << endl;
		break;
	default:
		break;
	}
}


/*TCP包解析函数*/
void DecodeTCPPacket(const u_char* pData)
{
	TCPHeader* pTCPHdr = (TCPHeader*)pData;
	cout << "协议:TCP" << endl;
	checkTCPdel(pTCPHdr);
	cout << "TCP源端口:" << ntohs(pTCPHdr->sourcePort) << endl;
	cout << "TCP目的端口:" << ntohs(pTCPHdr->destinationPort) << endl;
}

/*UDP包解析函数*/
void DecodeUDPPacket(const u_char* pData)
{
	UDPHeader* pUDPHdr = (UDPHeader*)pData;
	cout << "协议:UDP" << endl;
	checkUDPdel(pUDPHdr);
	cout << "UDP源端口:" << ntohs(pUDPHdr->sourcePort) << endl;
	cout << "UDP目的端口:" << ntohs(pUDPHdr->destinationPort) << endl;

}

/*ICMP包解析函数*/
void DecodeICMPPacket(const u_char* pData)
{
	cout << "协议:IMCP" << endl;
	ICMPHeader* pICMPHdr = (ICMPHeader*)pData;
	switch (pICMPHdr->i_type)
	{
	case 0:
		cout << "Echo Response .\n"; break;
	case 8:
		cout << "Echo Request. \n"; break;
	case 3:
		cout << "Destination Unreachable .\n"; break;
	case 11:
		cout << "Datagram Timeout(TTL=0).\n"; break;
	}
}

void printon() {
	cout << "|";
	cout << setw(5) << setiosflags(ios::right) << "编号";
	cout << setw(13) << setiosflags(ios::right) << "日期";
	cout << setw(13) << setiosflags(ios::right) << "时间";
	cout << setw(18) << setiosflags(ios::right) << "目的ip";
	cout << setw(17) << setiosflags(ios::right) << "源ip";
	cout << "|";
	cout << endl;
}

/*pcap_loop回调函数*/
void packet_callback(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	if (KEY_DOWN('Z')) down = 0;

	cout << "|" << setw(5) << setiosflags(ios::right) << num + 1 << ' ';
	mac_header* mh;//MAC头
	ip_header* ih;//IP头
	time_t local_tv_sec;
	struct tm time;
	char timestr[16];
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));

	/* 将时间戳转换成可识别的格式 */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&time, &local_tv_sec);
	printf("%6d/%2d/%2d ", time.tm_year + 1900, time.tm_mon + 1, time.tm_mday);
	printf("%6d:%2d:%2d ", time.tm_hour, time.tm_min, time.tm_sec);

	cout << ' ' << ' ';
	for (int i = 0; i < 3; i++) {
		printf("%3d.", ih->daddr[i]);
	}
	printf("%3d", ih->daddr[3]);
	cout << ' ' << ' ';
	for (int i = 0; i < 3; i++) {
		printf("%3d.", ih->saddr[i]);
	}
	printf("%3d|", ih->saddr[3]);

	pkt[num] = pkt_data;
	num++;
	cout << endl;
	if (KEY_DOWN('Z')) down = 0;
}

/*分析数据包函数*/
void packet_handler(const u_char* pkt_data)
{
	mac_header* mh;//MAC头
	ip_header* ih;//IP头
	time_t local_tv_sec;
	struct tm time;
	char timestr[16];

	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));

	cout << "*链路层数据" << endl;
	cout << "目的MAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02X-", mh->dest_addr[i]);
	}
	printf("%02X\n", mh->dest_addr[5]);
	cout << "源MAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02X-", mh->src_addr[i]);
	}
	printf("%02X\n", mh->src_addr[5]);

	cout << endl << "*网络层数据" << endl;
	cout << "协议:IP" << endl;
	cout << "IP长度:";
	cout << ih->tlen << endl;
	cout << "IP标识位:";
	cout << ih->identification << endl;
	cout << "IP偏移量:";
	cout << ih->flags_fo << endl;
	cout << "IP首部校验和:";
	cout << ih->crc << endl;
	cout << "目的IP:";
	for (int i = 0; i < 3; i++) {
		printf("%d.", ih->daddr[i]);
	}
	printf("%d\n", ih->daddr[3]);
	cout << "源IP:";
	for (int i = 0; i < 3; i++) {
		printf("%d.", ih->saddr[i]);
	}
	printf("%d\n", ih->saddr[3]);

	cout << endl << "*传输层数据" << endl;
	int nHeaderLen = (ih->ver_ihl & 0xf) * sizeof(ULONG);

	switch ((int)ih->proto)
	{
	case 0:
		cout << "协议: HOPOPT ";
		break;
	case 1:
		DecodeICMPPacket(pkt_data + sizeof(mac_header) + nHeaderLen);
		break;
	case 2:
		cout << "协议:IGMP";
		break;
	case 3:
		cout << "协议:GGP";
		break;
	case 4:
		cout << "协议:IP";
		break;
	case 6:
		DecodeTCPPacket(pkt_data + sizeof(mac_header) + nHeaderLen);
		break;
	case 17:
		DecodeUDPPacket(pkt_data + sizeof(mac_header) + nHeaderLen);
		break;
	case 30:
		cout << "协议:NETBLT";
		break;
	case 37:
		cout << "协议:DDP";
		break;
	case 41:
		cout << "协议:IPv6";
		break;
	case 56:
		cout << "协议:TLSP";
		break;
	case 62:
		cout << "协议:CFTP";
		break;
	case 75:
		cout << "协议:PVP";
		break;
	case 84:
		cout << "协议:TTP";
		break;
	case 101:
		cout << "协议:IFMP";
		break;
	default:
		cout << "协议号:" << (int)ih->proto << endl;
	}

	printf("\n");
}