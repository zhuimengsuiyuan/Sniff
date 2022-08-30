#pragma once
#include"library.h"
#include"message.h"

/*����TCP�˿�ʶ��Э��*/
void checkTCPdel(TCPHeader* pTCPHdr) {
	switch (pTCPHdr->destinationPort)
	{
	case 21:
		cout << "Э������:" << "ftp" << endl;
		break;
	case 23:
		cout << "Э������:" << "telnet" << endl;
		break;
	case 25:
		cout << "Э������:" << "smtp" << endl;
		break;
	case 53:
		cout << "Э������:" << "DNS" << endl;
		break;
	case 69:
		cout << "Э������:" << "tftp" << endl;
		break;
	case 80:
		cout << "Э������:" << "HTTP" << endl;
		break;
	case 109:
		cout << "Э������:" << "POP2" << endl;
		break;
	case 110:
		cout << "Э������:" << "POP3" << endl;
		break;
	case 443:
		cout << "Э������:" << "HTTPS" << endl;
		break;
	default:
		break;
	}
}

/*����UDP�˿�ʶ��Э��*/
void checkUDPdel(UDPHeader* pUDPHdr) {
	switch (pUDPHdr->destinationPort)
	{
	case 21:
		cout << "Э������:" << "ftp" << endl;
		break;
	case 23:
		cout << "Э������:" << "telnet" << endl;
		break;
	case 25:
		cout << "Э������:" << "smtp" << endl;
		break;
	case 69:
		cout << "Э������:" << "tftp" << endl;
		break;
	case 80:
		cout << "Э������:" << "HTTP" << endl;
		break;
	case 109:
		cout << "Э������:" << "POP2" << endl;
		break;
	case 110:
		cout << "Э������:" << "POP3" << endl;
		break;
	case 443:
		cout << "Э������:" << "HTTPS" << endl;
		break;
	default:
		break;
	}
}


/*TCP����������*/
void DecodeTCPPacket(const u_char* pData)
{
	TCPHeader* pTCPHdr = (TCPHeader*)pData;
	cout << "Э��:TCP" << endl;
	checkTCPdel(pTCPHdr);
	cout << "TCPԴ�˿�:" << ntohs(pTCPHdr->sourcePort) << endl;
	cout << "TCPĿ�Ķ˿�:" << ntohs(pTCPHdr->destinationPort) << endl;
}

/*UDP����������*/
void DecodeUDPPacket(const u_char* pData)
{
	UDPHeader* pUDPHdr = (UDPHeader*)pData;
	cout << "Э��:UDP" << endl;
	checkUDPdel(pUDPHdr);
	cout << "UDPԴ�˿�:" << ntohs(pUDPHdr->sourcePort) << endl;
	cout << "UDPĿ�Ķ˿�:" << ntohs(pUDPHdr->destinationPort) << endl;

}

/*ICMP����������*/
void DecodeICMPPacket(const u_char* pData)
{
	cout << "Э��:IMCP" << endl;
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
	cout << setw(5) << setiosflags(ios::right) << "���";
	cout << setw(13) << setiosflags(ios::right) << "����";
	cout << setw(13) << setiosflags(ios::right) << "ʱ��";
	cout << setw(18) << setiosflags(ios::right) << "Ŀ��ip";
	cout << setw(17) << setiosflags(ios::right) << "Դip";
	cout << "|";
	cout << endl;
}

/*pcap_loop�ص�����*/
void packet_callback(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
	if (KEY_DOWN('Z')) down = 0;

	cout << "|" << setw(5) << setiosflags(ios::right) << num + 1 << ' ';
	mac_header* mh;//MACͷ
	ip_header* ih;//IPͷ
	time_t local_tv_sec;
	struct tm time;
	char timestr[16];
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));

	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
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

/*�������ݰ�����*/
void packet_handler(const u_char* pkt_data)
{
	mac_header* mh;//MACͷ
	ip_header* ih;//IPͷ
	time_t local_tv_sec;
	struct tm time;
	char timestr[16];

	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));

	cout << "*��·������" << endl;
	cout << "Ŀ��MAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02X-", mh->dest_addr[i]);
	}
	printf("%02X\n", mh->dest_addr[5]);
	cout << "ԴMAC:";
	for (int i = 0; i < 5; i++) {
		printf("%02X-", mh->src_addr[i]);
	}
	printf("%02X\n", mh->src_addr[5]);

	cout << endl << "*���������" << endl;
	cout << "Э��:IP" << endl;
	cout << "IP����:";
	cout << ih->tlen << endl;
	cout << "IP��ʶλ:";
	cout << ih->identification << endl;
	cout << "IPƫ����:";
	cout << ih->flags_fo << endl;
	cout << "IP�ײ�У���:";
	cout << ih->crc << endl;
	cout << "Ŀ��IP:";
	for (int i = 0; i < 3; i++) {
		printf("%d.", ih->daddr[i]);
	}
	printf("%d\n", ih->daddr[3]);
	cout << "ԴIP:";
	for (int i = 0; i < 3; i++) {
		printf("%d.", ih->saddr[i]);
	}
	printf("%d\n", ih->saddr[3]);

	cout << endl << "*���������" << endl;
	int nHeaderLen = (ih->ver_ihl & 0xf) * sizeof(ULONG);

	switch ((int)ih->proto)
	{
	case 0:
		cout << "Э��: HOPOPT ";
		break;
	case 1:
		DecodeICMPPacket(pkt_data + sizeof(mac_header) + nHeaderLen);
		break;
	case 2:
		cout << "Э��:IGMP";
		break;
	case 3:
		cout << "Э��:GGP";
		break;
	case 4:
		cout << "Э��:IP";
		break;
	case 6:
		DecodeTCPPacket(pkt_data + sizeof(mac_header) + nHeaderLen);
		break;
	case 17:
		DecodeUDPPacket(pkt_data + sizeof(mac_header) + nHeaderLen);
		break;
	case 30:
		cout << "Э��:NETBLT";
		break;
	case 37:
		cout << "Э��:DDP";
		break;
	case 41:
		cout << "Э��:IPv6";
		break;
	case 56:
		cout << "Э��:TLSP";
		break;
	case 62:
		cout << "Э��:CFTP";
		break;
	case 75:
		cout << "Э��:PVP";
		break;
	case 84:
		cout << "Э��:TTP";
		break;
	case 101:
		cout << "Э��:IFMP";
		break;
	default:
		cout << "Э���:" << (int)ih->proto << endl;
	}

	printf("\n");
}