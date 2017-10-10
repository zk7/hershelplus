/*
Hershel Plus "Optimized" uses closed form of Hershel Plus equation, as opposed to calculating the integral numerically

*/

#include "defines.h"

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

vector<double> owd_prob_array;

class HPlusOptimizedEstimator{
public:
	int y_nPkts;
	int x_nPkts;
	double subOS_prob;
	vector<double>& x_timestamps;
	vector<double>& y_timestamps;
	vector<int> accumulator;

	HPlusOptimizedEstimator(vector<double>& sample, vector<double>& signature)
		:subOS_prob(0), x_timestamps(sample), y_timestamps(signature)
	{
		y_nPkts = signature.size();
		x_nPkts = sample.size();
		accumulator.resize(x_nPkts);
	}

	void ExamineCombination(vector<int>& gamma){
		double gamma_prob = 1;
		double s = DBL_MAX; //keep track of the min e_m seen
				
		//for each received packet, determine the OWD (Q) and calculate \prod p(Q)
		for (int m = 0; m < x_nPkts; m++){
			double em = x_timestamps[m] - y_timestamps[gamma[m]];
			if (em < 0){
				gamma_prob = 0;
			}
			else {
				int owd_index = em / (Q_GUESS_LIMIT_IN_SECS / Q_NUM_BINS);
				if (owd_index > owd_prob_array.size() - 1) owd_index = owd_prob_array.size() - 1;
				gamma_prob *= owd_prob_array[owd_index];

				//gamma_prob *= exp(-HP_JITTER_LAMBDA * em);

				if (em < s) s = em;
			}
		}

		if (gamma_prob > 0){
			//have case for denom = 0
			if (x_nPkts == HP_GAMMA_NU / HP_JITTER_LAMBDA) gamma_prob *= (s * s) / 2;
			//else gamma_prob *= (exp(-HP_GAMMA_NU * s) * (exp(HP_JITTER_LAMBDA * s * x_nPkts) * (HP_JITTER_LAMBDA * s * x_nPkts - HP_GAMMA_NU * s - 1) + exp(HP_GAMMA_NU * s))) / pow((HP_GAMMA_NU - HP_JITTER_LAMBDA * x_nPkts), 2); //result from Wolfram
			else gamma_prob *= (1 - exp(s * (-HP_GAMMA_NU * HP_JITTER_LAMBDA * x_nPkts)) * (1 + s * (HP_GAMMA_NU - HP_JITTER_LAMBDA * x_nPkts))) / pow((HP_GAMMA_NU - HP_JITTER_LAMBDA * x_nPkts), 2); // to match paper (16)
			
			//multiply by the constant for completeness
			//gamma_prob *= HP_JITTER_LAMBDA * pow(HP_GAMMA_NU, 2);
			gamma_prob *= pow(HP_JITTER_LAMBDA, x_nPkts) * pow(HP_GAMMA_NU, 2); //to match paper (16)

		}

		subOS_prob += gamma_prob;
	}

	void ProduceLossPatterns(int remaining, int start, int accumulatorSize){
		if (remaining > 0){
			for (int i = start; i < y_nPkts - remaining + 1; i++){
				bool possible = false;
				double diff = x_timestamps[accumulatorSize] - y_timestamps[i];
				if (diff >= 0){ // must arrive after the signature's timestamp		
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
				if (possible){
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

struct HPOThreadVars{
	HANDLE mutex;
	int correct;
	int wrong;
	int thread_id;
	map<u_int, vector<Signature>> training_data;
	vector<Signature> observations;
	map<u_int, int> classcounts;
};

/*********************CONSTANT FEATURE MATCHING***********************/

//match int64 options, intersection of both tar and sig should be ordered the same
int options_match_int64(unsigned long long tar_opts, unsigned long long sig_opts){
	if (tar_opts == sig_opts) return 2;

	int count = 0;

	//keep track of where we found our last option in sig list
	int last_found_position = -1;
	unsigned long long sig_it;

	while (tar_opts > 0){
		int opt = -1;
		while (opt != OPT_MSS && opt != OPT_WIN && opt != OPT_SACK && opt != OPT_TS){ //skip unimportant bits
			if (tar_opts == 0) return 1; //we've matched so far and reached 0 without another option
			//get last 3 bits from target
			opt = tar_opts & 0x7; //AND by 3 bits to get value
			//move to next option
			tar_opts = tar_opts >> 3;
		}

		sig_it = sig_opts; //reset iterator to beginning
		int position = 0;
		bool found = false;
		while (sig_it > 0){ //go through sig_opt list
			int sopt = sig_it & 0x7;
			if (sopt == opt){ //if found
				if (position < last_found_position) return 0; //found it before the last one, doesnt match ordering
				else last_found_position = position;
				found = true;
				break;
			}
			sig_it = sig_it >> 3;
			position++;
		}
		if (!found){
			//not found in list, was probably enabled by user - do nothing here
		}
	}

	//all there
	return 1;
}

//calculate likeliest class by adding FEATURE_CHANGE_PROBABILITY onto candidates
double MatchConstantFeatures(Signature& target, Signature& dbsig){
	double total_prob;

	if (!features_enabled[0]){
		total_prob = 0;
		//if not using RTO, do a constant score match for simplicity and to avoid probability rounding errors
		if (features_enabled[1]){
			if (target.win == dbsig.win) total_prob++;
		}
		if (features_enabled[2]){
			if (target.ttl == dbsig.ttl) total_prob++;
		}
		if (features_enabled[3]){
			if (target.df == dbsig.df) total_prob++;
		}
		if (features_enabled[4]){
			int oval = options_match_int64(target.options_int, dbsig.options_int);
			if (oval >= 1) total_prob++;
		}
		if (features_enabled[5]){
			if (target.mss == dbsig.mss) total_prob++;
		}
		if (target.rst){
			if (features_enabled[6]){
				if (target.rst == dbsig.rst && target.rst_ack == dbsig.rst_ack	&& target.rst_win == dbsig.rst_win && target.rst_nonzero == dbsig.rst_nonzero) total_prob++;
			}
		}
		
	}
	else{
		//start with total prob = 1
		total_prob = 1;

		if (features_enabled[1]){
			if (target.win == dbsig.win) total_prob *= (1 - HP_FEATURE_PROB_PI);
			else total_prob *= HP_FEATURE_PROB_PI;
		}
		if (features_enabled[2]){
			if (target.ttl == dbsig.ttl) total_prob *= (1 - HP_FEATURE_PROB_PI);
			else total_prob *= HP_FEATURE_PROB_PI;
		}
		if (features_enabled[3]){
			if (target.df == dbsig.df) total_prob *= (1 - HP_FEATURE_PROB_PI);
			else total_prob *= HP_FEATURE_PROB_PI;
		}
		if (features_enabled[4]){
			int oval = options_match_int64(target.options_int, dbsig.options_int);
			if (oval <= 1) total_prob *= HP_FEATURE_PROB_PI_RST_OPT;
			else if (oval > 1) total_prob *= (1 - HP_FEATURE_PROB_PI_RST_OPT);
		}
		if (features_enabled[5]){
			if (target.mss == dbsig.mss) total_prob *= (1 - HP_FEATURE_PROB_PI);
			else total_prob *= HP_FEATURE_PROB_PI;
		}
		if (features_enabled[6]){
			if (target.rst == dbsig.rst && target.rst_ack == dbsig.rst_ack	&& target.rst_win == dbsig.rst_win && target.rst_nonzero == dbsig.rst_nonzero) total_prob *= (1 - HP_FEATURE_PROB_PI_RST_OPT);
			else total_prob *= HP_FEATURE_PROB_PI_RST_OPT;

			//treat rst win differently
			//if (target.rst_win == candidates[i].rst_win) candidates[i].prob *= (1 - FEATURE_PROB_PI);
			//else candidates[i].prob *= FEATURE_PROB_PI;			
		}
	}

	return total_prob;
}

/***********************************************************************/

//Thread function for Hershel+ Optimized MT
void HershelPlusOptimized_Thread(LPVOID thread_variables){
	HPOThreadVars* hpt = (HPOThreadVars*)thread_variables;

	WaitForSingleObject(hpt->mutex, INFINITE); //LOCK Mutex to give self an id

	int thread_id = hpt->thread_id;
	hpt->thread_id++;

	ReleaseMutex(hpt->mutex); // RELEASE Mutex

	map<u_int, vector<Signature>>::iterator it;
	for (int i = thread_id; i < hpt->observations.size(); i += NUM_THREADS){
		u_int chosenOS = 0;		
		double probsum = 0; 
		double maxprob = 0; //keep track of max prob
		double secondprob = 0; //keep track of second highest prob

		for (it = hpt->training_data.begin(); it != hpt->training_data.end(); it++){
			double osprob = 0;

			if (features_enabled[0]) {
				//training data RTO vector must be >= size of sample, due to loss
				int lost_packets = it->second[0].packet_arrival_time.size() - hpt->observations[i].packet_arrival_time.size();
				if (lost_packets >= 0) {

					double totalsum = 0;
					//for each subOS tj of dbsig
					for (int tj = 0; tj < it->second.size(); tj++) {

						//calculate jitter probability using Estimator
						HPlusOptimizedEstimator e(hpt->observations[i].packet_arrival_time, it->second[tj].packet_arrival_time);
						e.ProduceLossPatterns(hpt->observations[i].packet_arrival_time.size(), 0, 0);
						totalsum += e.subOS_prob;

					}

					//get average over all subOS
					osprob = totalsum / it->second.size();

					//add loss probability
					osprob *= pow(HP_LOSS_PROB, lost_packets) * pow(1 - HP_LOSS_PROB, hpt->observations[i].packet_arrival_time.size());
				}
			}
			osprob *= MatchConstantFeatures(hpt->observations[i], it->second[0]);

			if (osprob > maxprob){				
				secondprob = maxprob;
				maxprob = osprob;					
				chosenOS = it->first;
			}
			else {
				if (osprob > secondprob) secondprob = osprob;
			}

			probsum += osprob;			
		}

		//track the normalized probability matched for the best and second-best match
		hpt->observations[i].maxprob_norm = maxprob / probsum;
		hpt->observations[i].secondprob_norm = secondprob / probsum;

		WaitForSingleObject(hpt->mutex, INFINITE); //LOCK Mutex to write correct or wrong
		
		if (!REAL_DATA){
			if (chosenOS == hpt->observations[i].id_int) hpt->correct++;
			else {
				hpt->wrong++;
			}
		}
		else {
			hpt->classcounts[chosenOS]++;
			hpt->observations[i].id_classified = chosenOS;
			hpt->correct++;
		}

		ReleaseMutex(hpt->mutex); // RELEASE Mutex
	}
}

//Multi threaded Hershel+ Optimized
void HershelPlusOptimized_MT(map <u_int, vector<Signature>> database_sigs, vector<Signature> observations){
	printf("\n---Starting H+ Classification (Using closed form)--\n");

	//set up OWD probabilities
	double sum = 0;

	for (DWORD s = 0; s < Q_NUM_BINS; s++) {
		double x = (s + 1) * Q_GUESS_LIMIT_IN_SECS / Q_NUM_BINS;
		double prob = exp(-HP_JITTER_LAMBDA * x);
		owd_prob_array.push_back(prob);
		sum += prob;
	}
	//normalize array
	for (int i = 0; i < owd_prob_array.size(); i++){
		owd_prob_array[i] = owd_prob_array[i] / sum;
	}

	HPOThreadVars hpt;
	hpt.mutex = CreateMutex(NULL, 0, NULL);
	hpt.correct = 0;
	hpt.wrong = 0;
	hpt.thread_id = 0;
	hpt.observations = observations;
	hpt.training_data = database_sigs;

	HANDLE *handles = new HANDLE[NUM_THREADS];
	//Split Threads
	for (int i = 0; i < NUM_THREADS; i++){
		handles[i] = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)HershelPlusOptimized_Thread, &hpt, 0, NULL);
		SetThreadPriority(handles[i], THREAD_PRIORITY_LOWEST);
	}

	//Print info every 5 secs until no more active threads
	printf("Started %d threads...\n\n", NUM_THREADS);

	int sleep_interval = 5000;
	int remaining, done_count, old_done_count = 0, step = 0;
	double avg_rate = 0, sum_rate = 0;
	while (true){
		//calculate done and remaining
		done_count = hpt.correct + hpt.wrong;
		remaining = hpt.observations.size() - done_count;

		double rate = (done_count - old_done_count) / (double)(sleep_interval / 1000);

		sum_rate += rate;
		step++;
		avg_rate = sum_rate / step;
		double time_remaining = (remaining / avg_rate) / 60;

		if (!REAL_DATA) printf("IPs left: %d, Correct: %.2lf, Done: %d at %f per sec. %f min to go\r", remaining, (double)hpt.correct / done_count, done_count, rate, time_remaining);
		else printf("IPs left: %d, Done: %d at %f per sec. %f min to go\r", remaining, done_count, rate, time_remaining);

		old_done_count = done_count;
		if (remaining <= 0) break;
		Sleep(sleep_interval);
	}

	//Wait for threads to return
	printf("\n--->Quit Condition Reached!<---\nWaiting for all threads to end..\n");
	WaitForMultipleObjects(NUM_THREADS, handles, TRUE, INFINITE);

	// Close handles
	for (int i = 0; i < NUM_THREADS; i++) CloseHandle(handles[i]);
	CloseHandle(hpt.mutex);

	if (!REAL_DATA)	printf("--------->Correct: %d, Accuracy: %f\n", hpt.correct, (double)hpt.correct / hpt.observations.size());
	else {
		//print out the results
		FILE* fout;
		fopen_s(&fout, "internet_classcounts.txt", "w");
		for (auto cc : hpt.classcounts) fprintf(fout, "%s, %d\n", id_to_label_map[cc.first].c_str(), cc.second);
		fclose(fout);

		fopen_s(&fout, "internet_results.txt", "w");
		fprintf(fout, "Internet ID, Classified ID, Label, MaxProb, SecondMaxProb\n");
		for (int i = 0; i < hpt.observations.size(); i++){
			fprintf(fout, "%u, %u, %s, %lf, %lf\n", hpt.observations[i].id_int, hpt.observations[i].id_classified, id_to_label_map[hpt.observations[i].id_classified].c_str(), hpt.observations[i].maxprob_norm, hpt.observations[i].secondprob_norm);
		}
		fclose(fout);

		printf("Result files written.\n");
	}
	
}

//Single threaded Hershel+ Optimized
void HershelPlusOptimized_ST(map <u_int, vector<Signature>> database_sigs, vector<Signature> observations){
	//use the closed form equation to get probability

	int correct = 0, wrong = 0;
	int total = 0;

	//classify each observed vector (tau)
	for (int t = 0; t < observations.size(); t++){

		double highest_prob = 0;
		u_int highest_matching_ip = UINT_MAX;

		//for each database sig
		for (auto dbsig : database_sigs){

			int lost_packets = dbsig.second[0].packet_arrival_time.size() - observations[t].packet_arrival_time.size();

			double total_prob = 0;

			if (lost_packets >= 0){

				//for each subOS tj of dbsig
				for (int tj = 0; tj < dbsig.second.size(); tj++){

					//calculate jitter probability using Estimator
					HPlusOptimizedEstimator e(observations[t].packet_arrival_time, dbsig.second[tj].packet_arrival_time);
					e.ProduceLossPatterns(observations[t].packet_arrival_time.size(), 0, 0);
					total_prob += e.subOS_prob;

				}

				//get average over all subOS
				total_prob /= dbsig.second.size();
				
				//add loss probability
				total_prob *= pow(HP_LOSS_PROB, lost_packets) * pow(1 - HP_LOSS_PROB, observations[t].packet_arrival_time.size());
			}

			if (total_prob > highest_prob){
				highest_prob = total_prob;
				highest_matching_ip = dbsig.first;
			}
		}

		//mark correct or incorrect
		if (highest_matching_ip == observations[t].id_int) correct++;
		else wrong++;

		total++;

		if (total % 100 == 0) printf("Finished: %d, Correct: %lf\r", total, (double)correct / total);
		
	}

	printf("\nCorrect: %lf\n", (double)correct / total);

}