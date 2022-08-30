#pragma once
#define HAVE_REMOTE
#include <iostream>
#include <winsock2.h>
#include <windows.h>
#include <string.h>
#include<string>
#include <mstcpip.h>
#include <stdlib.h>
#include "pcap.h"
#include<tchar.h>
#include"pcap.h"
#include <iomanip>
#include<stdio.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "packet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4996)

#define KEY_DOWN(VK_NONAME) ((GetAsyncKeyState(VK_NONAME) & 0x8000) ? 1:0) 
using namespace std;

const u_char* pkt[10000];
int cnt = 10000;//捕获包数目
int num = 0;
bool down = 1;
