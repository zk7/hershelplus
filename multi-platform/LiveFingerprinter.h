/*
 * Class definition for LiveFingerprinter
 *
 */

#define __STDC_WANT_LIB_EXT1__ 
#define _CRT_SECURE_NO_DEPRECATE
#define _WINSOCK_DEPRECATED_NO_WARNINGS



using namespace std;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vector>
#include <unordered_map>
#include <random>
#include <cstring>
#include <cfloat>
#include "structures.h"
#ifdef _WIN32
#include <WinSock2.h>
#include <IPHlpApi.h>

#pragma comment(lib,"ws2_32.lib") //For winsock
#pragma comment(lib,"iphlpapi.lib") //For iphlpapi
#pragma comment(lib,"wpcap.lib") //For pcap


//Define gettimeofday - Windows version
//from https://gist.github.com/ugovaretto/5875385
static int gettimeofday(struct timeval *tv, struct timezone *tz)
{
	// This magic number is the number of 100 nanosecond intervals since January 1, 1601 (UTC)
	// until 00:00:00 January 1, 1970 
	static const uint64_t EPOCH = ((uint64_t)116444736000000000ULL);

	SYSTEMTIME  system_time;
	FILETIME    file_time;
	uint64_t    time;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);
	time = ((uint64_t)file_time.dwLowDateTime);
	time += ((uint64_t)file_time.dwHighDateTime) << 32;

	tv->tv_sec = (long)((time - EPOCH) / 10000000L);
	tv->tv_usec = (long)(system_time.wMilliseconds * 1000);
	return 0;
}

#else
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <net/if_arp.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

struct route_info {
	u_int dstAddr;
	u_int srcAddr;
	u_int gateway;
	char ifName[IF_NAMESIZE];
};

#endif

#include <pcap.h>


 
class LiveFingerprinter{

public:
	int setupPcapAdapter();
	int getFingerprint(char* target, unsigned short port, Signature& sig);
	~LiveFingerprinter();
	
private:
	unsigned short in_checksum(unsigned short *ptr,int nbytes);
	int createPacket(char *target, int target_port, int* srcPort, unsigned char *packet);
	int timeval_subtract(timeval *result, timeval *x, timeval *y);

	pcap_t* adapterHandle;
	char* adapterName;
};
