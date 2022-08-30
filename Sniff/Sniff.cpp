#include"Decode.h"
#define IPTOSBUFFERS    12
/* 2019117055 朱周洁 */
char* iptos(u_long in)   //用来显示网卡的IP地址
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;
	p = (u_char*)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
int main()
{
	pcap_if_t* alldevs;  //用于检索网卡设备
	pcap_if_t* d;  //当前所用网卡
	pcap_if_t* card[65535];  //保存可用网卡
	int inum;  //存放输入的数字
	int i; //记录网卡个数
	pcap_t* adhandle;  //网卡的指针
	u_int netmask;  //子网掩码
	struct bpf_program fcode;  //格式过滤
	char errbuf[PCAP_ERRBUF_SIZE];  //存放获取的网卡信息
	pcap_addr_t* a;
	int op, ii;  //选项
	char* p;  //设置的过滤表达式
loop:  //在此处返回（初始界面）
	//设置各种过滤表达式
	char bf1[1010] = "src port ";
	char bf2[1010] = "dst port ";
	char bf3[1010] = "src host ";
	char bf4[1010] = "dst host ";
	char bf5[1010];
	//对下列变量初始化
	i = 0;  //可用网卡个数
	inum = 0;  //
	num = 0;
	p = "";
	cout << "网络嗅探器 by 2019117055 朱周洁" << endl;
	cout << "设备网卡列表如下:\n";
	/* 检索设备列表 */
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		fprintf(stderr, "获取网卡列表出错 %s\n", errbuf);
		exit(1);
	}
	/* 打印列表 */
	for (d = alldevs; d; d = d->next) {
		if (d->description) {
			for (a = d->addresses; a; a = a->next)
				if (a->addr && a->addr->sa_family == AF_INET) {
					//如果是有效的IPv4地址
					printf("%d. %s", ++i, d->name);
					printf(" (%s)\n", d->description);
					printf("\tIP地址: %s\n", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
					card[i] = d;
				}
		}
		else   //未获取到网卡，显示无网卡
			printf(" (无网卡)\n");
	}
	if (i == 0) {  //找不到可用网卡
		printf("\n找不到接口，请确保安装了WinPcap\n");
		return -1;
	}
	printf("输入网卡标号选择网卡 (1-%d)\n请输入:", i);
	//选择设备
	scanf("%d", &inum);
	if (inum < 1 || inum > i) {
		printf("\n输入的接口号无意义\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	while (1) {
		printf("是否设置过滤条件？\n1.是\n2.否\n请输入：", ii);
		//如果不设置过滤条件，则网络嗅探器会自动设定过滤IP协议
		scanf("%d", &ii);
		if (ii < 1 || ii>2) {
			printf("\n无效输入！\n");
		}
		else
			break;
	}
	if (ii == 1) {
		char port[1010];
		//根据选项设置相应的过滤表达式
		printf("·1.设置源端口\n·2.设置目的端口\n·3.设置源IP地址\n·4.设置目的IP地址\n·5.设置协议类型\n·6.自定义过滤表达式\n请输入：");
		scanf("%d", &op);
		if (op == 1) {
			printf("输入源端口：");
			scanf("%s", port);
			p = bf1;
			p = strcat(p, port);
		}
		else if (op == 2) {
			printf("输入目的端口：");
			scanf("%s", port);
			p = bf2;
			p = strcat(p, port);
		}
		else if (op == 3) {
			printf("输入源IP地址：");
			scanf("%s", port);
			p = bf3;
			p = strcat(p, port);
		}
		else if (op == 4) {
			printf("输入目的IP地址：");
			scanf("%s", port);
			p = bf4;
			p = strcat(p, port);
		}
		else if (op == 5) {
			while (1) {
				printf("·1.TCP协议\n·2.UDP协议\n·3.ARP协议\n·4.RARP协议\n·5.ICMP协议\n·6.IP协议\n·7.自定义\n请输入：");
				scanf("%d", &op);
				if (op == 1) {
					p = "tcp";
				}
				else if (op == 2) {
					p = "udp";
				}
				else if (op == 3) {
					p = "arp";
				}
				else if (op == 4) {
					p = "rarp";
				}
				else if (op == 5) {
					p = "icmp";
				}
				else if (op == 6) {
					p = "ip";
				}
				else if (op == 7) {
					getchar();
					cin.getline(port, 1010);
					strcpy(bf5, port);
					p = bf5;
				}
				else {
					printf("\n输入有误！\n");
					continue;
				}
				break;
			}
		}
		else if (op == 6) {
			printf("请输入过滤表达式：\n");
			getchar();
			cin.getline(port, 1010);
			//cout << "port-->" << port << endl;
			strcpy(bf5, port);
			p = bf5;
		}

	}


	/*跳到选定的适配器 */
	d = card[inum];

	/* 打开适配器 */
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL) {
		fprintf(stderr, "\n无法打开适配器%s is not supported by WinPcap\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		fprintf(stderr, "\n该程序仅适用于以太网\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	//netmask是子网掩码
	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	if (ii == 1) {    //添加了过滤条件
		/*编辑过滤器*/
		const char* buff = p;
		if (pcap_compile(adhandle, &fcode, buff, 1, netmask) < 0) {
			fprintf(stderr, "\n无法编译数据包筛选器。检查语法\n");
			pcap_freealldevs(alldevs);
			return -1;
		}
		/*设置过滤器*/
		if (pcap_setfilter(adhandle, &fcode) < 0) {
			fprintf(stderr, "\n设置过滤器时出错\n");
			pcap_freealldevs(alldevs);
			return -1;
		}
		cout << endl;
	}
	/* 释放设备列表 */
	pcap_freealldevs(alldevs);

	while (1) {
		cout << "要求捕获报文数目:";
		cin >> inum;
		cout << "开始捕获报文......" << endl;
		while (1) {
			if (cin.good() && 1 <= inum && inum <= 10000) break;//	输入类型匹配
			else
			{
				cin.clear();				//	清除当前输入缓冲区中的内容。
				cin.ignore();
				if (inum > 10000)	cout << "数目过大,请重新输入:";
				else	cout << "输入的报文标号有误,请重新输入:" << endl;
				cin >> inum;
			}
		}
		printf("--------------------------------------------------------------------\n");
		printon();
		/* 开始捕获 */
		while (down) {
			pcap_loop(adhandle, 1, packet_callback, NULL);
			if (num >= inum) break;
		}
		printf("--------------------------------------------------------------------\n");
		cout << "捕获报文结束！" << endl;

		while (1) {
			cout << "输入\n·-1：退出\n·0：再次捕获报文\n·1-" << num << "：选择一个数据报文分析\n" << "·" << num + 1 << "：返回\n";
			cout << "请输入:";
			cin >> i;
			cout << endl;
			if (i == num + 1) {   //跳转到之前的网卡设置界面
				goto loop;
			}
			while (1) {
				if (cin.good() && -1 <= i && i <= num) break;//	输入类型匹配
				else
				{
					cin.clear();				//	清除当前输入缓冲区中的内容。
					cin.ignore();
					cout << "输入的报文标号有误,请重新输入:" << endl;
					cin >> i;
				}
			}
			if (i == -1) {   //退出
				return 0;
			}
			if (i == 0) {    //初始化，准备再次捕获报文
				num = 0;
				down = 1;
				cout << endl;
				break;
			}
			packet_handler(pkt[i - 1]);  //解析数据报文
		}
	}

	system("pause");
	return 0;
}