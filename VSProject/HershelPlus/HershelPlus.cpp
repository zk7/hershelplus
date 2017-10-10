
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

struct HPThreadVar{
	HANDLE mutex;
	int correct;
	int wrong;
	int thread_id;
	map<u_int, vector<Signature>> training_data;
	vector<Signature> observations;
	vector<double> t_prob_array;
	vector<double> owd_prob_array;
	map<u_int, int> classcounts;
};

class Estimator{
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

	Estimator(vector<double>& sample, vector<double>& signature, vector<double>& rttarray, vector<double>& owdarray)
		:subOS_prob(0), x_timestamps(sample), y_timestamps(signature), t_prob_array(rttarray), owd_prob_array(owdarray)
	{
		y_nPkts = signature.size();
		x_nPkts = sample.size();
		accumulator.resize(x_nPkts);
	}

	void ExamineCombination(vector<int>& gamma){
		double gamma_prob = 0;
		double t_limit = T_GUESS_LIMIT_IN_SECS;
		
		//but T has to be less than the smallest distance between any x and y
		for (int t = 0; t < x_nPkts; t++){
			double d = x_timestamps[t] - y_timestamps[gamma[t]];
			if (d < t_limit) t_limit = d;
		}

		
		for (double t_guess = 0; t_guess <= t_limit; t_guess += t_step_size){
			double probQ = 1;

			int t_index = t_guess / t_step_size;
			double probT = t_prob_array[t_index];

			//for each received packet, determine the OWD (Q) and calculate \prod p(Q)
			for (int t = 0; t < x_nPkts; t++){
				double Q = (x_timestamps[t] - y_timestamps[gamma[t]] - t_guess);
				if (Q < 0){
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

//Thread function for Hershel+ MT
void HershelPlus_Thread(LPVOID thread_variables){
	HPThreadVar* hpt = (HPThreadVar*)thread_variables;
	
	WaitForSingleObject(hpt->mutex, INFINITE); //LOCK Mutex to give self an id

	int thread_id = hpt->thread_id;
	hpt->thread_id++;

	ReleaseMutex(hpt->mutex); // RELEASE Mutex

	map<u_int, vector<Signature>>::iterator it;
	for (int i = thread_id; i < hpt->observations.size(); i += NUM_THREADS){
		Signature obs = hpt->observations[i];
		int chosenOS = 0;
		double probsum = 0;
		double maxprob = 0; //keep track of max prob
		double secondprob = 0; //keep track of second highest prob

		for (it = hpt->training_data.begin(); it != hpt->training_data.end(); it++){
			double osprob = 0;

			if (features_enabled[0]) { //if RTO enabled
			//training data RTO vector must be >= size of sample, due to loss
				int lost_packets = it->second[0].packet_arrival_time.size() - obs.packet_arrival_time.size();
				if (lost_packets >= 0) {

					double totalsum = 0;

					for (int s = 0; s < it->second.size(); s++) {
						Estimator e(obs.packet_arrival_time, it->second[s].packet_arrival_time, hpt->t_prob_array, hpt->owd_prob_array);
						//Estimator e(target.rto_cumulative, candidates[j].rep_rto); //this is when using the 50-subOS average only
						e.ProduceLossPatterns(obs.packet_arrival_time.size(), 0, 0);
						totalsum += e.subOS_prob;
					}

					osprob = totalsum / it->second.size(); //average sum over all subOS

					//multiply by loss probability
					osprob *= pow(HP_LOSS_PROB, lost_packets) * pow(1 - HP_LOSS_PROB, obs.packet_arrival_time.size());
				}
			}
			osprob *= MatchConstantFeatures(hpt->observations[i], it->second[0]);

			if (osprob > maxprob) {
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

		if (!REAL_DATA) {
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

//Hershel+ multi threaded version
void HershelPlus_MT(map <u_int, vector<Signature>> database_sigs, vector<Signature> observations){

	//declare vars for numerical integration using rectangles
	//double w = T_GUESS_LIMIT_IN_SECS / T_NUM_BINS; //width of the rect
	//thus area of each rectangle is width(w) * height(f(i*w)), where f is the distribution function

	//build array of probabilities
	
	vector<double> parray;
	double sum = 0;
	
	double meanT = 0.5;
	// now the T model: erlang(k); mean = k / lambda 
	int erlang_k = 2; 
	double erlang_lambda = (double) erlang_k / meanT; 
	double common = pow (erlang_lambda, erlang_k) / factorial(erlang_k - 1); 
	for (DWORD s = 0; s < T_NUM_BINS; s++) {
		double x = (s + 1) * T_GUESS_LIMIT_IN_SECS / T_NUM_BINS;
		double prob = common * pow(x, erlang_k - 1) * exp(-erlang_lambda * x);
		parray.push_back(prob);
		sum += prob;
	}
	//normalize array
	for (int i = 0; i < parray.size(); i++){
		parray[i] = parray[i] / sum;
	}
	/***********************************************/

	HPThreadVar hpt;
	hpt.mutex = CreateMutex(NULL, 0, NULL);
	hpt.correct = 0;
	hpt.wrong = 0;
	hpt.thread_id = 0;
	hpt.observations = observations;
	hpt.t_prob_array = parray;
	hpt.owd_prob_array = parray;
	hpt.training_data = database_sigs;

	HANDLE *handles = new HANDLE[NUM_THREADS];
	//Split Threads
	for (int i = 0; i < NUM_THREADS; i++){
		handles[i] = CreateThread(NULL, 4096, (LPTHREAD_START_ROUTINE)HershelPlus_Thread, &hpt, 0, NULL);
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
		for (int i = 0; i < hpt.observations.size(); i++) {
			fprintf(fout, "%u, %u, %s, %lf, %lf\n", hpt.observations[i].id_int, hpt.observations[i].id_classified, id_to_label_map[hpt.observations[i].id_classified].c_str(), hpt.observations[i].maxprob_norm, hpt.observations[i].secondprob_norm);
		}
		fclose(fout);

		printf("Result files written.\n");
	}


}

//Hershel+ single threaded version. Likely outdated
void HershelPlus_ST(map <u_int, vector<Signature>> database_sigs, vector<Signature> observations){
	
	FILE* file;
	fopen_s(&file, "err.txt", "w");
	map<u_int, vector<Signature>>::iterator it;


	//declare vars for numerical integration using rectangles
	double w = T_GUESS_LIMIT_IN_SECS / T_NUM_BINS; //number of rectangles	
	//thus area of each rectangle is width(h) * height(f(i*h)), where f is the distribution function

	//build array of probabilities
	double max = DBL_MIN;
	vector<double> parray;
	double sum = 0;

	double meanT = 0.5;
	// now the T model: erlang(k); mean = k / lambda 
	int erlang_k = 2;
	double erlang_lambda = (double)erlang_k / meanT;
	double common = pow(erlang_lambda, erlang_k) / factorial(erlang_k - 1);
	for (DWORD s = 0; s < T_NUM_BINS; s++) {
		double x = (s + 1) * T_GUESS_LIMIT_IN_SECS / T_NUM_BINS;
		double prob = common * pow(x, erlang_k - 1) * exp(-erlang_lambda * x);
		parray.push_back(prob);
		sum += prob;
	}
	//normalize array
	for (int i = 0; i < parray.size(); i++) {
		parray[i] = parray[i] / sum;
	}

	//match each disturbedOS
	int correct = 0, wrong = 0;
	vector<double> finalprobs;

	for (Signature dos : observations){
		int chosenOS;
		double maxprob = -1;
		finalprobs.clear();
		for (it = database_sigs.begin(); it != database_sigs.end(); it++){

			//check if RTO vector size is the same 
			if (it->second[0].packet_arrival_time.size() == dos.packet_arrival_time.size()){

				double totalsum = 0;

				for (int s = 0; s < it->second.size(); s++){
					//match DOS to host_i
					double subOS_sum = 0;

					//for each rtt guess
					for (int i = 0; i < parray.size(); i++){
						double rtt_guess = (i + 1) * w;
						double subos_prob = 1;

						//for each tau
						for (int t = 1; t < dos.packet_arrival_time.size(); t++){ //skip (0)
							double Q = (dos.packet_arrival_time[t] - it->second[s].packet_arrival_time[t] - rtt_guess);
							if (Q < 0) subos_prob = 0;
							else {
								double p = exp(-HP_JITTER_LAMBDA * Q);
								double q = parray[i];
								subos_prob *= (p * q);
							}
						}
						subOS_sum += subos_prob;
					}

					totalsum += subOS_sum;
					//printf("sum: %lf\n", sum);

				}

				double osprob = totalsum / it->second.size(); //average sum over all subOS
				//printf("Average sum: %lf\n", osprob); 
				finalprobs.push_back(totalsum);

				if (osprob > maxprob){
					maxprob = osprob;
					chosenOS = it->first;
				}
			}
			else{
				//printf("SIZE MISMATCH!");
				finalprobs.push_back(0);
			}
		}

		if (chosenOS == dos.id_int) correct++;
		else{
			/*fprintf(file, "Correct: %d, Picked: %d", dos.correct_class, chosenOS);
			for (double r : dos.rto){
				fprintf(file, ",%lf", r);
			}
			fprintf(file, "\t");
			for (double p : finalprobs){
				fprintf(file, "%lf   ", p);
			}
			fprintf(file, "\n");*/
			wrong++;
		}
			

		printf("Working on: %d, Correct: %d, Wrong: %d, %.0f%% done.\r", dos.id_int, correct, wrong, ((double)(correct + wrong) / observations.size()) * 100);
	}

	printf("Correct: %d, Accuracy: %f\n", correct, (double)correct / observations.size());

	_fcloseall();
}
