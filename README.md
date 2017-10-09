# Hershel+

Hershel+ is an improved version of [Hershel](https://github.com/zk7/hershel), which is an OS fingerprinting algorithm that determines the OS of a remote host using a single outbound TCP SYN packet. To accomplish OS classification, Hershel+ uses several features from the IP/TCP headers as well as TCP retransmission timeouts (RTOs). The improvements of Hershel+ mainly revolve around the handling of the RTO feature, and experiments in our paper show it has superior accuracy to Hershel by up to 10% in just RTO classification. Similar to Hershel, this algorithm also allows standard header fields (e.g., TCP Window size, IP TTL, IP DF etc.) to exhibit volatility, i.e., a probability that a user changes these features. 

# Project files

Hershel+ is written in C++.

This repository includes two versions of Hershel+. The multi-platform version contains the main Hershel+ algorithm and should work on most systems. This version can be run in "live mode" or "offline mode".
 + Live Mode: Sends a TCP SYN packet to the target host/port, gathers a signature, and attempts to classify it.  
 + Offline Mode: Reads an existing observations file and classifies all signatures using Hershel+.
 
Compiling: 
 - On Linux, Hershel+ was compiled on Ubuntu 17.04 using: 
 
      `g++ HershelPlus.cpp LiveFingerprinter.cpp -lpcap -pthread`      
      
 - On Windows, Hershel+ was compiled using VS2015.
 
 libpcap/Winpcap is required. The HershelPlusOptimized.cpp can be substituted for HershelPlus.cpp to run the optimized algorithm, but should not matter for a single observation in live mode or a small observation set in offline mode.
 
Running:
 - Live Mode: `HershelPlus.exe database_file mapping_file IP port`  
   **NOTE:** Running in Live mode requires your machine to allow half-open TCP connections. This means kernel generated RSTs need to be suppressed. 	
	- On Windows, the Windows firewall should do this by default. If not, create a custom rule to drop unsolicited SYN/ACKs
	- On Linux, inserting the following iptables rules should take care of this:  
		`sudo iptables -t filter -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT`  
		`sudo iptables -t filter -A INPUT -p icmp -j ACCEPT`  
		`sudo iptables -t filter -A INPUT -i lo -j ACCEPT`  
		`sudo iptables -t filter -A INPUT -j DROP`  
	This accepts anything from established connections, icmp pings, and all traffic on the loopback interface. Everything else is dropped. 
 - Offline Mode: `HershelPlus.exe database_file mapping_file observations_file` 

The Visual Studio project files use the Windows library for multi-threading and hence compile in Win32/64. It also includes the Hershel+ database and example signatures. This is likely the version you want to run if you have a large dataset.

### File structure

The data files containing the OS and Internet signatures have mostly the same text format. For the files in the multi-platform folder, this is format:

	int id
	int tcp_window
	int ip_ttl
	int ip_df
	string tcp_options
	longlong tcp_options_encoded
	int mss
	int rst_present
	int rst_ack flag
	int rst_window
	int rst_nonzero
	double RTT (0 value for database)
	double RTO1_timestamp
	double RTO2_timestamp
	double RTO3_timestamp
	...

420OS_db.txt contains the database signatures, 420OS_mapping.txt maps plain text labels to signature data in the database, and observations.txt contains sample observed signatures that are to be classified using the Hershel+ algorithm. 


# Publication
### Conference
Z. Shamsi and D. Loguinov, "Unsupervised Clustering Under Temporal Feature Volatility in Network Stack Fingerprinting,", ACM SIGMETRICS, June 2016.

	@inproceedings{shamsi2016,
		title={Unsupervised Clustering Under Temporal Feature Volatility in Network Stack Fingerprinting},
		author={Zain Shamsi and Dmitri Loguinov},
		booktitle={ACM SIGMETRICS},
		year={2016},
		organization={ACM}
		location = {Antibes Juan-les-Pins, France},
		pages = {127--138},
		doi = {10.1145/2896377.2901449},
		keywords = {internet measurement, os classification, device fingerprinting},
 	} 
  
[ACM Portal](http://dl.acm.org/citation.cfm?id=2901449) 

[Direct Paper Link](http://irl.cs.tamu.edu/people/zain/papers/sigmetrics2016.pdf)

### Journal
Z. Shamsi and D. Loguinov, "Unsupervised Clustering Under Temporal Feature Volatility in Network Stack Fingerprinting,"  IEEE/ACM Transactions on Networking, vol. 25, no. 4, August 2017.
	
	@ARTICLE{shamsi2016, 
		author={Zain Shamsi and Dmitri Loguinov}, 
		journal={IEEE/ACM Transactions on Networking}, 
		title={Unsupervised Clustering Under Temporal Feature Volatility in Network Stack Fingerprinting}, 
		year={2017}, 
		month={Aug},
		volume={25}, 
		number={4}, 
		pages={2430-2443}, 
		doi={10.1109/TNET.2017.2690641}, 
		ISSN={1063-6692}, 	
	}

[IEEE Xplore](http://ieeexplore.ieee.org/document/7902193/) 

[Direct Paper Link](http://irl.cs.tamu.edu/people/zain/papers/ton2017.pdf)



