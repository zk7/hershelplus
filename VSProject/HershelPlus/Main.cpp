//Hershel+ Parallel
//Written by Zain Shamsi

#include "defines.h"
#include "SimpleRNG.h"


//simulation parameters for sample generation
#if _DEBUG
#define TOTAL_NUM_DISTORTIONS (1 << 5)
#else
#define TOTAL_NUM_DISTORTIONS (1 << 18)
#endif

vector<bool> features_enabled = { 1, 1, 1, 1, 1, 1, 1 }; //booleans describing which features are enabled (RTO, WIN, TTL, DF, OPT, MSS, RST)
map<int, string> id_to_label_map;

vector<double> getRTOs(vector<double> absolutes){

	if (absolutes.size() > 1){
		vector<double> return_vector;
		double rto = 0;
		return_vector.push_back(absolutes[0]); //push back first packet right away
		for (int i = 1; i < absolutes.size(); i++){
			rto = absolutes[i] - absolutes[i - 1]; //now calculate diff between this and last
			return_vector.push_back(rto);
		}
		return return_vector;
	}
	else return absolutes;
}

void printSignature(FILE* fout, Signature s){
	fprintf(fout, "%u,%d,%d,%d,%llu,%d,%d,%d,%d,%d", s.id_int,
		s.win, s.ttl, s.df, s.options_int, s.mss,
		s.rst, s.rst_ack, s.rst_win, s.rst_nonzero);
	for (int m = 0; m < s.packet_arrival_time.size(); m++){
		fprintf(fout, ",%f", s.packet_arrival_time[m]);
	}
	fprintf(fout, "\n");
}

vector<Signature> createDisturbedUniform(map <u_int, vector<Signature>>& database_sigs){
	//creates samples uniformly distributed across OS and subOS
	map<u_int, vector<Signature>>::iterator it;
	vector<Signature> disturbed_vectors;
	SimpleRNG srng;
	srng.SetState(time(NULL) % 7427, time(NULL));

	for (int i = 0; i < TOTAL_NUM_DISTORTIONS; i++){

		//pick subOS based on distribution
		int chosenOS = rand() % database_sigs.size();

		it = database_sigs.begin();
		advance(it, chosenOS);
		Signature randsubOS = it->second[rand() % it->second.size()];

		Signature dos;
		dos.id_int = it->first;

		double qi = srng.GetUniform();
		double T = srng.GetUniform();

		dos.packet_arrival_time.push_back(T + qi); //RTT

		//create distortions of this sig's rto and add to array, start at 1 to skip first (0)
		for (int t = 1; t < randsubOS.packet_arrival_time.size(); t++){
			qi = srng.GetExponential(0.5);			

			double tau = max(T + randsubOS.packet_arrival_time[t] + qi, dos.packet_arrival_time.back()); //new arrival time = max(T + RTO-C + Q, last arrival)
			dos.packet_arrival_time.push_back(tau);

		}
		disturbed_vectors.push_back(dos);
	}


	printf("Created %d disturbed vectors\n", disturbed_vectors.size());
	return disturbed_vectors;
}

vector<Signature> createDisturbedZipf(map<u_int, vector<Signature>>& database_sigs, double T_mean, double owd_mean, double loss_prob){
	//build sample observation data by disturbing database signatures. Only disturbs RTO
	//first build Zipf pmf
	vector<double> ratios;
	double sum = 0;
	for (int j = 0; j < database_sigs.size(); j++){
		ratios.push_back(1.0 / pow((j + 1), 1.2));
		sum += ratios[j];
	}

	//normalize ratio
	for (int i = 0; i < database_sigs.size(); i++){
		ratios[i] /= sum;
	}

	vector<Signature> ret_list;
	int loss_counter = 0;
	SimpleRNG srng;
	srng.SetState(time(NULL) % 7427, time(NULL));
	//srng.SetState(5, 5); //seed set to same for testing

	//start backwards and generate samples
	map<u_int, vector<Signature>>::iterator it = database_sigs.begin();
	for (int j = 0; it != database_sigs.end(); ++it, ++j){

		int totalsamplesj = TOTAL_NUM_DISTORTIONS * ratios[j];

		//cycle through subOSes until reached totalsamples
		for (int s = 0, i = 0; i < totalsamplesj; s = ((s + 1) % it->second.size()), i++){

			bool loss_happened = false;
			Signature sig(it->second[s]);
			sig.packet_arrival_time.clear();
			sig.maxprob_norm = 0;
			sig.id_classified = 0;
			
			//double T = srng.GetUniform(0.0, T_mean * 2);
			double T = srng.GetExponential(T_mean);
			//double T = srng.GetPareto(3, T_mean);
			
			//sig.T = T;
						
			for (int m = 0; m < it->second[s].packet_arrival_time.size(); m++){
				double loss = srng.GetUniform();
				double qi;
				qi = srng.GetExponential(owd_mean); //from http://tcp-reassembly-project.googlecode.com/files/jitter_model.pdf 		
				//qi = srng.GetPareto(3, owd_mean);
				//qi = srng.GetUniform(0.0, owd_mean * 2);				
								

				if (loss >= loss_prob){

					double departure = T + it->second[s].packet_arrival_time[m]; //departure of packet from server
					double arrival = departure + qi; //arrival of packet at client with OWD

					if (sig.packet_arrival_time.empty()){
						//if no packets till now, push this one back as first packet
						sig.packet_arrival_time.push_back(arrival);
					}
					else { //check for FIFO ordering
						double last_arrival = sig.packet_arrival_time.back();
						//if new packet arrived after arrival of last packet, add like normal
						//else, new packet arrived at same time or before arrival of last one, make arrival equal to last_arrival to preserve order
						//this effectively pushes 0 as the RTO
						if (arrival > last_arrival) sig.packet_arrival_time.push_back(arrival);
						else sig.packet_arrival_time.push_back(last_arrival);
					}
				}
				else {
					loss_happened = true;
				}
			}
			if (loss_happened) loss_counter++;

			//add signature if we have packets, if all were lost then dont add
			if (!sig.packet_arrival_time.empty())
				ret_list.push_back(sig);
			else i--;
		}
	}

	printf("%d signatures created, %d with loss\n", ret_list.size(), loss_counter);

	return ret_list;
}

map<u_int, vector<Signature>> readDatabaseSigs(char *filename){
	map<u_int, vector<Signature>> retmap;
	int sig_count = 0;
	int BUFFER_SIZE = (1 << 27); //128MB

	FILE* fin;

	int ret = fopen_s(&fin, filename, "r");
	if (ret != 0){
		printf("Error opening file %s!\n", filename);
		return retmap;
	}
	char* buffer = new char[BUFFER_SIZE];
	int count, count_discard = 0;
	double ts = 0;
	u_int old_ip = 0;
	vector<double> rtos;

	while (!feof(fin)){
		Signature sig;

		//read next line
		fgets(buffer, BUFFER_SIZE, fin);
		char* bufferptr = buffer;
		
		sscanf_s(bufferptr, "%u,%d,%d,%d,%[^,],%llu,%d,%d,%d,%d,%d,%d%n",
			&sig.id_int, &sig.win, &sig.ttl, &sig.df, sig.options_str, _countof(sig.options_str), &sig.options_int, &sig.mss, &sig.rst, &sig.rst_ack, &sig.rst_win, &sig.rst_seq, &sig.rst_nonzero, &count);
		

		bufferptr += count;

		while (strcmp(bufferptr, "\n") != 0 && strlen(bufferptr) > 0){
			sscanf_s(bufferptr, ",%lf%n", &ts, &count);
			sig.packet_arrival_time.push_back(ts);

			if (sig.packet_arrival_time.size() == 20) break; //limit to 20 packets

			bufferptr += count;
		}

		retmap[sig.id_int].push_back(sig);
		sig_count++;

		if (sig_count % 10000 == 0) printf("Read %d signatures...\r", sig_count);
	}

	fclose(fin);
	printf("\nStored %d database signatures\n", retmap.size());
	return retmap;
}

map<int, string> readLabels(char* filename){
	map<int, string> retmap;	
	FILE* fin;
	int ret = fopen_s(&fin, filename, "r");
	if (ret != 0){
		printf("Error opening file %s!\n", filename);
		return retmap;
	}
	char* buffer = new char[1500];
	
	while (!feof(fin)){
		int id;
		char label[1500];		

		//read next line
		fgets(buffer, 1500, fin);
		sscanf_s(buffer, "%d,%[^\n]", &id, label, _countof(label));

		retmap[id] = label;
	}

	printf("Stored %d ip->banner mappings\n", retmap.size());
	return retmap;
}

vector<Signature> readTestData(char* filename){
	vector<Signature> return_vector;
	int sig_count = 0;
	int BUFFER_SIZE = (1 << 27); //128MB

	FILE* fin;

	int ret = fopen_s(&fin, filename, "r");
	if (ret != 0){
		printf("Error opening file %s!\n", filename);
		return return_vector;
	}
	char* buffer = new char[BUFFER_SIZE];
	int count, count_discard = 0;
	double ts = 0;
	u_int old_ip = 0;
	vector<double> rtos;

	while (!feof(fin)){
		Signature sig;

		//read next line
		fgets(buffer, BUFFER_SIZE, fin);
		char* bufferptr = buffer;

		//sscanf_s(bufferptr, "%[^,]", sig.options, _countof(sig.options)
		sscanf_s(bufferptr, "%u,%d,%d,%d,%[^,],%llu,%d,%d,%d,%d,%d%n",
			&sig.id_int, &sig.win, &sig.ttl, &sig.df, sig.options_str, _countof(sig.options_str), &sig.options_int, &sig.mss, &sig.rst, &sig.rst_ack, &sig.rst_win, &sig.rst_nonzero, &count);
		

		bufferptr += count;

		while (strcmp(bufferptr, "\n") != 0 && strlen(bufferptr) > 0){
			sscanf_s(bufferptr, ",%lf%n", &ts, &count);
			sig.packet_arrival_time.push_back(ts);

			if (sig.packet_arrival_time.size() == 20) break; //limit to 20 packets

			bufferptr += count;
		}

		return_vector.push_back(sig);
		sig_count++;

		if (sig_count % 10000 == 0) printf("Read %d signatures...\r", sig_count);
	}

	fclose(fin);
	printf("\nStored %d observations stored\n", return_vector.size());
	return return_vector;
}

int main(int argc, char* argv[]){
	
	DWORD start_time = clock();

	printf("REAL_DATA variable is set to %d.\n", REAL_DATA);
	printf("Features Enabled: \n");
	vector<string> features = { "RTO", "WIN", "TTL", "DF", "OPT", "MSS", "RST" };
	for (int i = 0; i < features_enabled.size(); i++){
		if (features_enabled[i] == 1) printf("%s ", features[i].c_str());
	}
	printf("\n");
	//getchar();

	/**********Load database signatures*********************************/

	char* database_filename;
	if (argc > 1) database_filename = argv[1];
	else {
		database_filename = "420OS_db.txt";
	}
	map<u_int, vector<Signature>> sigmap = readDatabaseSigs(database_filename);	

	/**********Load observations********************************************/

	char* test_filename;
	if (argc > 2) test_filename = argv[2];
	else {
		test_filename = "test_observations.txt";
	}

	vector<Signature> observations;
	if (REAL_DATA){ 
		//read observations and load database labels
		observations = readTestData(test_filename);
		id_to_label_map = readLabels("420OS_mapping.txt");
	}
	else{
		//generate simulated observations
		observations = createDisturbedZipf(sigmap, 0.5, 0.5, 0);
	}

	if (sigmap.empty()) {
		printf("No signatures loaded!\n");
		exit(0);
	}
	if (observations.empty()) {
		printf("No observations to classify!\n");
		exit(0);
	}

	/*******************CHOOSE H+ VERSION**********************/
	
	HershelPlusOptimized_MT(sigmap, observations);
	//HershelPlus_MT(sigmap, observations);
	

	/**********************************************************/
	
	printf("__Took %lf minutes___\n", ((double)(clock() - start_time) / CLOCKS_PER_SEC) / 60);
}