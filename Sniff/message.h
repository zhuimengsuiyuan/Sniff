#include"library.h"
/*IP�����ײ��ṹ*/
typedef struct ip_header
{
	u_char ver_ihl;//�汾��
	u_char tos; //��������TOS
	u_short tlen; //�ܳ���
	u_short identification; //��ʶ
	u_short flags_fo; //ƫ��������־λ
	u_char ttl; //����ʱ��TTL
	u_char proto; //8λЭ��
	u_short crc;//�ײ�У���
	u_char saddr[4]; //ԴIP
	u_char daddr[4]; //Ŀ��IP
	u_int op_pad; // Option
}ip_header;

/*ICMP��ͷ�ṹ*/
typedef struct icmphdr
{
	char i_type;
	char i_code;
	unsigned short i_cksum;
	unsigned short i_id;
	unsigned short i_seq;
	unsigned long timestamp;
}ICMPHeader;

/*UDP��ͷ�ṹ*/
typedef struct _UDPHeader
{
	unsigned short sourcePort;
	unsigned short destinationPort;
	unsigned short len;
	unsigned short checksum;
}UDPHeader;

/*TCP��ͷ�ṹ*/
typedef struct _TCPHeader
{
	unsigned short sourcePort;// Դ�˿ں�
	unsigned short destinationPort; // Ŀ�Ķ˿ں�
	unsigned long sequenceNumber;// ���к�
	unsigned long acknowledgeNumber;// ȷ�Ϻ�
	char dataoffset;//����ƫ��
	char flags;//��־λ
	unsigned short window;// ���ڴ�С
	unsigned short checksum; // У���
	unsigned short urgentPointer;//��������ƫ����
}TCPHeader;

/*MAC��ͷ�ṹ*/
typedef struct mac_header {
	u_char dest_addr[6];//Ŀ��MAC
	u_char src_addr[6];//ԴMAC
	u_char type[2];
} mac_header;