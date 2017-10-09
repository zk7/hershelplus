//    Copyright © 2014 IRL at Texas A&M University (http://irl.cse.tamu.edu)
//
//    This file is part of Hershel+.
//
//    Hershel+ is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Lesser General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    Hershel+ is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Lesser General Public License for more details
//    http://www.gnu.org/licenses/lgpl.txt.
//
//	  Author: Zain Shamsi
//
//    Data and signatures:
//    http://irl.cse.tamu.edu/projects/osf
//
//    Publication:
//	  Z. Shamsi, D. Loguinov, "Unsupervised Clustering Under Temporal Feature 
//	  Volatility in Network Stack Fingerprinting, " ACM SIGMETRICS, June 2016.
//


#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "LiveFingerprinter.h"


#define OPT_MSS 1 // max segment size
#define OPT_WIN 2 // window scaling
#define OPT_TS 3 // timestamps
#define OPT_SACK 4 // SACK allowed
#define OPT_EOL 5 // end of list (another type of padding?)
#define OPT_NOP 6 // padding

//parameters for Hershel Plus matching
#define HP_JITTER_LOSS_THRESHOLD 4 //how many seconds of jitter we can tolerate when figuring out loss combinations

#define HP_JITTER_MEAN 0.5
#define HP_JITTER_LAMBDA (1 / HP_JITTER_MEAN)
#define HP_GAMMA_SHAPE 2.0
#define HP_GAMMA_MEAN 0.5
#define HP_GAMMA_SCALE (1 / (HP_GAMMA_SHAPE / HP_GAMMA_MEAN))
#define HP_GAMMA_NU (HP_GAMMA_SHAPE / HP_GAMMA_MEAN)
#define HP_LOSS_PROB 0.038
#define HP_FEATURE_PROB_PI_RST_OPT 0.01
#define HP_FEATURE_PROB_PI 0.1

#define T_GUESS_LIMIT_IN_SECS 4.0
#define T_NUM_BINS 100
#define Q_GUESS_LIMIT_IN_SECS 4.0
#define Q_NUM_BINS 100

using namespace std;

int factorial(int n) {
	return (n == 1 || n == 0) ? 1 : factorial(n - 1) * n;
}

//Hershel RTO Estimator
class HershelPlusEstimator{
public:
public:
	int y_nPkts;
	int x_nPkts;
	double subOS_prob;
	double t_step_size = T_GUESS_LIMIT_IN_SECS / T_NUM_BINS;
	double owd_step_size = Q_GUESS_LIMIT_IN_SECS / Q_NUM_BINS;
	vector<double>& x_timestamps;
	vector<double>& y_timestamps;
	vector<double>& t_prob_array;
	vector<double>& owd_prob_array;
	vector<int> accumulator;

	HershelPlusEstimator(vector<double>& sample, vector<double>& signature, vector<double>& tarray, vector<double>& owdarray)
		:subOS_prob(0), x_timestamps(sample), y_timestamps(signature), t_prob_array(tarray), owd_prob_array(owdarray)
	{
		y_nPkts = signature.size();
		x_nPkts = sample.size();
		accumulator.resize(x_nPkts);
	}

	void ExamineCombination(vector<int>& gamma) {
		double gamma_prob = 0;
		double t_limit = T_GUESS_LIMIT_IN_SECS;

		//but T has to be less than the smallest distance between any x and y
		for (int t = 0; t < x_nPkts; t++) {
			double d = x_timestamps[t] - y_timestamps[gamma[t]];
			if (d < t_limit) t_limit = d;
		}


		for (double t_guess = 0; t_guess <= t_limit; t_guess += t_step_size) {
			double probQ = 1;

			int t_index = t_guess / t_step_size;
			double probT = t_prob_array[t_index];

			//for each received packet, determine the OWD (Q) and calculate \prod p(Q)
			for (int t = 0; t < x_nPkts; t++) {
				double Q = (x_timestamps[t] - y_timestamps[gamma[t]] - t_guess);
				if (Q < 0) {
					probQ = 0;
					break;
				}
				else {
					int owd_index = Q / owd_step_size;
					if (owd_index > owd_prob_array.size() - 1) owd_index = owd_prob_array.size() - 1;
					double p = owd_prob_array[owd_index];
					probQ *= p;
				}
			}

			//the prob of this gamma with this T is p(T) * \prod p(Q)
			gamma_prob += probQ * probT;
		}

		subOS_prob += gamma_prob;
	}

	void ProduceLossPatterns(int remaining, int start, int accumulatorSize) {
		if (remaining > 0) {
			for (int i = start; i < y_nPkts - remaining + 1; i++) {
				bool possible = false;
				double diff = x_timestamps[accumulatorSize] - y_timestamps[i];
				if (diff >= 0) { // must arrive after the signature's timestamp		
					if (accumulatorSize == 0) // first packet being matched: allow it since the RTT can be anything
						possible = true;
					else {// non-first packet: do a test on jitter
						double jitt = x_timestamps[accumulatorSize] - x_timestamps[accumulatorSize - 1] -
							(y_timestamps[i] - y_timestamps[accumulator[accumulatorSize - 1]]);
						// TODO: automatically determine the value of jitter for this cutoff 
						// need the jitter PMF and some threshold: CDF sum above the threshold should be less than some small number
						if (abs(jitt) < HP_JITTER_LOSS_THRESHOLD) // only if less than "JITTER_THRESHOLD" OWD
							possible = true;
					}
				}
				if (possible) {
					accumulator[accumulatorSize] = i;
					ProduceLossPatterns(remaining - 1, i + 1, accumulatorSize + 1);
				}
			}
		}
		else {
			//if (produced == 0) // emulates always taking the first x[i].nPkts packets of the signature
			ExamineCombination(accumulator);
			//produced ++;
		}
	}
};

/*********************CONSTANT FEATURE MATCHING***********************/

//match int64 options, intersection of both tar and sig should be ordered the same
int options_match_int64(unsigned long long tar_opts, unsigned long long sig_opts) {
	if (tar_opts == sig_opts) return 2;

	//keep track of where we found our last option in sig list
	int last_found_position = -1;
	unsigned long long sig_it;

	while (tar_opts > 0) {
		int opt = -1;
		while (opt != OPT_MSS && opt != OPT_WIN && opt != OPT_SACK && opt != OPT_TS) { //skip unimportant bits
			if (tar_opts == 0) return 1; //we've matched so far and reached 0 without another option
										 //get last 3 bits from target
			opt = tar_opts & 0x7; //AND by 3 bits to get value
								  //move to next option
			tar_opts = tar_opts >> 3;
		}

		sig_it = sig_opts; //reset iterator to beginning
		int position = 0;
		bool found = false;
		while (sig_it > 0) { //go through sig_opt list
			int sopt = sig_it & 0x7;
			if (sopt == opt) { //if found
				if (position < last_found_position) return 0; //found it before the last one, doesnt match ordering
				else last_found_position = position;
				found = true;
				break;
			}
			sig_it = sig_it >> 3;
			position++;
		}
		if (!found) {
			//not found in list, was probably enabled by user - do nothing here
		}
	}

	//all there
	return 1;
}

//calculate likeliest class by adding FEATURE_CHANGE_PROBABILITY onto candidates
double MatchConstantFeatures(Signature& target, Signature& dbsig) {
	double prob = 1;

	if (target.win == dbsig.win) prob *= (1 - HP_FEATURE_PROB_PI);
	else prob *= HP_FEATURE_PROB_PI;

	if (target.ttl == dbsig.ttl) prob *= (1 - HP_FEATURE_PROB_PI);
	else prob *= HP_FEATURE_PROB_PI;

	if (target.df == dbsig.df) prob *= (1 - HP_FEATURE_PROB_PI);
	else prob *= HP_FEATURE_PROB_PI;

	int oval = options_match_int64(target.options_int, dbsig.options_int);
	if (oval < 1) prob *= HP_FEATURE_PROB_PI_RST_OPT;
	else if (oval == 1) prob *= HP_FEATURE_PROB_PI;
	else if (oval > 1) prob *= (1 - HP_FEATURE_PROB_PI);

	if (target.mss == dbsig.mss) prob *= (1 - HP_FEATURE_PROB_PI);
	else prob *= HP_FEATURE_PROB_PI;

	if (target.rst) {
		//rst_seq not used as it does not provide any new information. nonzero is a better feature in all regards
		if (target.rst == dbsig.rst && target.rst_ack == dbsig.rst_ack	&& target.rst_win == dbsig.rst_win && target.rst_nonzero == dbsig.rst_nonzero) prob *= (1 - HP_FEATURE_PROB_PI_RST_OPT);
		else prob *= HP_FEATURE_PROB_PI_RST_OPT;
	}
	return prob;
}

/***********************************************************************/

void HershelPlus(unordered_map<unsigned int, vector<Signature>>& database, vector<Signature>& observations){
	printf("\n---Starting Hershel+ Classification---\n");

	//set up T probabilities as Erlang2
	vector<double> t_prob_array;
	double sum = 0;
	double common = pow(HP_GAMMA_NU, HP_GAMMA_SHAPE) / factorial(HP_GAMMA_SHAPE - 1);
	for (int s = 0; s < T_NUM_BINS; s++) {
		double x = (s + 1) * T_GUESS_LIMIT_IN_SECS / T_NUM_BINS;
		double prob = common * pow(x, HP_GAMMA_SHAPE - 1) * exp(-HP_GAMMA_NU * x);
		t_prob_array.push_back(prob);
		sum += prob;
	}
	//normalize array
	for (int i = 0; i < t_prob_array.size(); i++) {
		t_prob_array[i] = t_prob_array[i] / sum;
	}

	//set up OWD probabilities as exponential
	vector<double> owd_prob_array;	
	sum = 0;
	for (int s = 0; s < Q_NUM_BINS; s++) {
		double x = (s + 1) * Q_GUESS_LIMIT_IN_SECS / Q_NUM_BINS;
		double prob = exp(-HP_JITTER_LAMBDA * x);
		owd_prob_array.push_back(prob);
		sum += prob;
	}
	//normalize array
	for (int i = 0; i < owd_prob_array.size(); i++){
		owd_prob_array[i] = owd_prob_array[i] / sum;
	}

	int unclassified = 0;

	//run through all observations and classify
	for (int i = 0; i < observations.size(); i++){
		//get next host
		Signature target = observations[i];
		double highest_prob = 0;
		unsigned int highest_id = 0;

		for (auto it = database.begin(); it != database.end(); it++){
			double os_prob = 0;

			//get difference in lengths
			int lost_packets = it->second[0].packet_arrival_time.size() - target.packet_arrival_time.size();

			//apply loss filter, cant receive more packets than signature
			if (lost_packets >= 0){

				//for each subOS
				for (int r = 0; r < it->second.size(); r++){

					//get the probability of this subOS rto vs. target using estimator
					HershelPlusEstimator e(target.packet_arrival_time, it->second[r].packet_arrival_time, t_prob_array, owd_prob_array);
					e.ProduceLossPatterns(target.packet_arrival_time.size(), 0, 0);

					os_prob += e.subOS_prob; //for all subOS prob
				}

				//multiply by lost packet prob
				os_prob *= pow(HP_LOSS_PROB, lost_packets) * pow(1 - HP_LOSS_PROB, target.packet_arrival_time.size());

				//match constants			
				os_prob *= MatchConstantFeatures(target, it->second[0]);
			}

			//track highest prob
			if (os_prob > highest_prob){
				highest_prob = os_prob;
				highest_id = it->first;
			}
		}

		if (highest_id == 0) unclassified++;
		observations[i].id_classified = highest_id;

	}

}

vector<Signature> readSigList(char *filename){
	//read signatures into vector
	vector<Signature> retvec;
	int sig_count = 0;
	int BUFFER_SIZE = (1 << 12); //4MB

	FILE* fin = fopen(filename, "r");
	if (fin == NULL){
		printf("Error opening file %s!\n", filename);
		exit(-1);
	}
	else printf("\nReading from %s...\n", filename);
	char* buffer = new char[BUFFER_SIZE];
	int count;
	double timestamp = 0;
	vector<double> rtos;

	while (!feof(fin)){
		Signature sig;

		//read next line
		fgets(buffer, BUFFER_SIZE, fin);
		char* bufferptr = buffer;

		sscanf(bufferptr, "%u,%d,%d,%d,%[^,],%lld,%d,%d,%d,%d,%d%n",
			&sig.id, &sig.win, &sig.ttl, &sig.df, sig.options_str, &sig.options_int, &sig.mss, &sig.rst, &sig.rst_ack, &sig.rst_win, &sig.rst_nonzero, &count);

		bufferptr += count;

		while (strcmp(bufferptr, "\n") != 0 && strlen(bufferptr) > 0){
			sscanf(bufferptr, ",%lf%n", &timestamp, &count);
			sig.packet_arrival_time.push_back(timestamp);

			bufferptr += count;
		}

		retvec.push_back(sig);
		sig_count++;
		if (sig_count % 10000 == 0) printf("Read %d signatures...\r", sig_count);
	}

	fclose(fin);
	printf("Stored %zu signatures in map\n", retvec.size());
	return retvec;
}

int main(int argc, char* argv[]){
	if (argc < 4){
		printf("%s can be run in two modes: Live and Offline.\n", argv[0]);
		printf("To run in live mode: %s <database_file> <label_mapping_file> <IP> <port>\n", argv[0]);
		printf("To run in offline mode: %s <database_file> <label_mapping_file> <observations_file>\n", argv[0]);
		return 0;
	}

	//read database signatures	
	vector<Signature> database_sigs = readSigList(argv[1]);
	//combine them into a hashmap for easier organization
	unordered_map<unsigned int, vector<Signature>> database;
	for (Signature s : database_sigs) database[s.id].push_back(s);

	//read class to OS label mapping
	FILE *fin = fopen(argv[2], "r");	
	if (fin == NULL){
		printf("Error opening file %s!\n", argv[3]);
		exit(-1);
	}
	unordered_map<int, string> os_mapping;
	char buffer[512];
	while (!feof(fin)){
		int id;
		char osname[512];

		fgets(buffer, 512, fin);
		sscanf(buffer, "%d,%[^\n]", &id, osname);
		os_mapping[id] = string(osname);
	}
	
	//determine if next argument is an IP	
	unsigned short port;
	vector<Signature> observations;
	unsigned int ip = inet_addr(argv[3]);
	if (ip != INADDR_NONE){
		//it was an ip
		if (argc < 5) {
			printf("Port argument missing\n");
			exit(-1);
		}
		port = atoi(argv[4]);
		
		//set up for live fingerprinting
		printf("Starting Live fingerprinting of %s:%d...\n", argv[3], port);
		LiveFingerprinter lf;
		if (lf.setupPcapAdapter() < 0){
			printf("Error setting up pcap!\n");
			exit(-1);
		}
		
		Signature s; 		
		if (lf.getFingerprint(argv[3], port, s) < 0){
			printf("Error getting fingerprint\n");
			exit(-1);
		}
		
		printf("\rSignature being classified: %d,%d,%d,%s,%d,%d,%d,%d,%d,%d", s.win, s.ttl, s.df, s.options_str, s.mss, s.rst, s.rst_ack, s.rst_win, s.rst_seq, s.rst_nonzero);
		for (u_int r = 0; r < s.packet_arrival_time.size(); r++) printf(",%lf", s.packet_arrival_time[r]);	
		printf("\n");
		observations.push_back(s);
	}
	else {
		//it was not an IP, read observations
		vector<Signature> observations = readSigList(argv[3]);
	}
	
	//run Hershel on observations	
	HershelPlus(database, observations);
		
	//print out observation results
	for (Signature o : observations) printf("Observation %u classified as id %d (%s)\n", o.id, o.id_classified, os_mapping[o.id_classified].c_str());
	
}
