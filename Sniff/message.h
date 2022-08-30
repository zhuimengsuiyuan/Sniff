#include"library.h"
/*IP分组首部结构*/
typedef struct ip_header
{
	u_char ver_ihl;//版本号
	u_char tos; //服务类型TOS
	u_short tlen; //总长度
	u_short identification; //标识
	u_short flags_fo; //偏移量、标志位
	u_char ttl; //生存时间TTL
	u_char proto; //8位协议
	u_short crc;//首部校验和
	u_char saddr[4]; //源IP
	u_char daddr[4]; //目的IP
	u_int op_pad; // Option
}ip_header;

/*ICMP包头结构*/
typedef struct icmphdr
{
	char i_type;
	char i_code;
	unsigned short i_cksum;
	unsigned short i_id;
	unsigned short i_seq;
	unsigned long timestamp;
}ICMPHeader;

/*UDP包头结构*/
typedef struct _UDPHeader
{
	unsigned short sourcePort;
	unsigned short destinationPort;
	unsigned short len;
	unsigned short checksum;
}UDPHeader;

/*TCP包头结构*/
typedef struct _TCPHeader
{
	unsigned short sourcePort;// 源端口号
	unsigned short destinationPort; // 目的端口号
	unsigned long sequenceNumber;// 序列号
	unsigned long acknowledgeNumber;// 确认号
	char dataoffset;//数据偏移
	char flags;//标志位
	unsigned short window;// 窗口大小
	unsigned short checksum; // 校验和
	unsigned short urgentPointer;//紧急数据偏移量
}TCPHeader;

/*MAC包头结构*/
typedef struct mac_header {
	u_char dest_addr[6];//目的MAC
	u_char src_addr[6];//源MAC
	u_char type[2];
} mac_header;