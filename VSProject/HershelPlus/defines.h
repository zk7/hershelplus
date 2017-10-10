
#ifndef CLASSES_H
#define CLASSES_H

#define OPT_MSS 1 // max segment size
#define OPT_WIN 2 // window scaling
#define OPT_TS 3 // timestamps
#define OPT_SACK 4 // SACK allowed
#define OPT_EOL 5 // end of list (another type of padding?)
#define OPT_NOP 6 // padding

#define REAL_DATA true

#ifdef _DEBUG
#define NUM_THREADS 1
#else
#define NUM_THREADS GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)
#endif

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <stdlib.h>

#pragma comment(lib, "Ws2_32.lib")

using namespace std;

extern vector<bool> features_enabled; //booleans describing which features are enabled (RTO, WIN, TTL, DF, OPT, MSS, RST)
extern map<int, string> id_to_label_map;

class Signature{
public:
	u_int id_classified;
	u_int id_int;
	int win;
	int ttl;
	int df;
	int rst;
	int rst_ack;
	int rst_win;
	int rst_seq;
	int rst_nonzero;
	int mss;
	char options_str[25];
	unsigned long long options_int;
	vector<double> packet_arrival_time;
	vector<double> rto;
	double secondprob_norm;
	double maxprob_norm;
	//double T;
	//vector<double> owd;

	Signature(){
		win = 0;
		ttl = 0;
		df = 0;
		mss = 0;
		rst = 0;
		rst_ack = 0;
		rst_win = 0;
		rst_seq = 0;
		rst_nonzero = 0;
		options_int = 0;
	}
};


static int factorial(int n){
	return (n == 1 || n == 0) ? 1 : factorial(n - 1) * n;
}


void HershelPlusOptimized_ST(map <u_int, vector<Signature>> database_sigs, vector<Signature> observations);
void HershelPlusOptimized_MT(map <u_int, vector<Signature>> database_sigs, vector<Signature> observations);
void HershelPlus_ST(map <u_int, vector<Signature>> database_sigs, vector<Signature> observations);
void HershelPlus_MT(map<u_int, vector<Signature>> database_sigs, vector<Signature> observations);
double MatchConstantFeatures(Signature& target, Signature& dbsig);

#endif /* CLASSES_H */