/*
 * Code for using pcap for active fingerprinting
 *
 */

#include "LiveFingerprinter.h"

unsigned short in_checksum(unsigned short *ptr,int nbytes);
int CreatePacket(int adapterCount, char *adapterName, char *dest, unsigned char *packet);

char  errorBuffer[ PCAP_ERRBUF_SIZE ];
const int TIMEOUT = 120; //2 mins

int LiveFingerprinter::setupPcapAdapter(){

    pcap_if_t* allAdapters;
    int crtAdapter;
    int adapterNumber;	
    pcap_if_t* adapter;
    vector<char*> adapterReadableNames;

    // retrieve the adapters from the computer
    if( pcap_findalldevs(&allAdapters, errorBuffer ) == -1 )
    {
        printf( "Error in pcap_findalldevs_ex function: %s\n", errorBuffer );
        return -1;
    }

    // if there are no adapters, print an error
    if( allAdapters == NULL )
    {
		printf( "\nNo adapters found! Make sure pcap is installed.\n" );
        return -1;
    }
	
    // print the list of adapters along with basic information about an adapter
    printf("Listing system adapters:\n");
    crtAdapter = 0;
    for( adapter = allAdapters; adapter != NULL; adapter = adapter->next){		
		pcap_addr* addresses = adapter->addresses;
		while (addresses != NULL && addresses->addr->sa_family != AF_INET) addresses = addresses->next;
		
		if (addresses != NULL){
			sockaddr_in * sa = (sockaddr_in *)(addresses->addr);
			char* ip = inet_ntoa(sa->sin_addr);
			
			#ifdef _WIN32
			adapterReadableNames.push_back(adapter->description);
			#else 
			adapterReadableNames.push_back(adapter->name);
			#endif			
			
			printf("\n%d. %s at %s\n", ++crtAdapter, adapterReadableNames.back(), ip);
			
		}
		
    }
    printf( "\n" );

	if (crtAdapter > 1){
		printf( "Enter the adapter number between 1 and %d: ", crtAdapter );
		scanf( "%d", &adapterNumber );
	}
	else adapterNumber = 1;
	

	printf("\n-----------------------------------------------\n");
    
    if( adapterNumber < 1 || adapterNumber > crtAdapter )
    {
        printf( "\nAdapter number out of range.\n" );
        // Free the adapter list
        pcap_freealldevs( allAdapters );
        return -1;
    }
    
    // parse the list until we reach the desired adapter
    adapter = allAdapters;
    for( crtAdapter = 0; crtAdapter < adapterNumber - 1; crtAdapter++ ){
        adapter = adapter->next;
	}

	//open the adapter
	printf("Opening device %s\n", adapterReadableNames[adapterNumber-1]);
	adapterHandle = pcap_open_live( adapter->name, // name of the adapter
                               65536,         // portion of the packet to capture
                                              // 65536 guarantees that the whole 
                                              // packet will be captured
                               1, // promiscuous mode
                               TIMEOUT,             // read timeout - 2 mins
                               errorBuffer    // error buffer
                              );
	if( adapterHandle == NULL ){
        printf( "\nUnable to open the adapter %s\n", adapterReadableNames[adapterNumber-1]);
        return -1;
    }	    
    else printf("Adapter %s opened successfully\n", adapterReadableNames[adapterNumber-1]);
           
    //store the adapter name for future pcap calls
    adapterName = new char[strlen(adapter->name) + 1];
    strcpy(adapterName, adapter->name);

	// Free the adapter list
    pcap_freealldevs( allAdapters );
	return 0;
}

int LiveFingerprinter::getFingerprint(char* target, unsigned short port, Signature& sig){
	
	unsigned char packet[65535];
	int retValue;
	int srcPort;
	struct pcap_pkthdr* packetHeader;
    const unsigned char* packetData;

	if (createPacket(target, port, &srcPort, packet) < 0){
		printf("Creation of Send Packet failed\n"); 
		return -1;
	}

	//open output file and set pcap filter
	const char* output_file = "fingerprints.txt";
	FILE* ofile = fopen(output_file, "a");

	struct bpf_program fp;		/* The compiled filter expression */
	char filter_exp[100];	/* The filter expression */
	snprintf(filter_exp, sizeof(filter_exp), "ip and tcp and src host %s and src port %d and dst port %d", target, port, srcPort);	
	//bpf_u_int32 netmask = 0xffffff; /* The netmask of our sniffing device */
	if (pcap_compile(adapterHandle, &fp, filter_exp, 1, -1) < 0){
        printf("\nUnable to compile the packet filter. Check the syntax.\n");
        return -1;
    }    
    
    if (pcap_setfilter(adapterHandle, &fp) < 0){
        printf("\nError setting the filter.\n");
        return -1;
    }
    
    //if (pcap_setnonblock(adapterHandle, 1, errorBuffer) < 0){
	//	printf("\nError setting pcap to nonblocking\n");
	//	return -1;
	//}
    
	//timeval lastTS = {0, 0};
	timeval timeSent;
	bool first_packet = true;

	/********************************************************************************************************/
	// send the packet	
	gettimeofday(&timeSent, NULL);
	printf("\nSending a SYN packet to %s on port %d...\n", target, port);
	if( pcap_sendpacket(adapterHandle, packet, sizeof(ETHERHeader) + sizeof(IPHeader) + sizeof(TCPHeader)) != 0) //adapter, packet, length of packet
	{
		printf("\nError sending the packet: %s\n", pcap_geterr(adapterHandle));
		return -1;
	}

	//PACKET SENT
	/************************************************************************************************************************/
	//NOW RECEIVING

	printf("Listening for responses for 2 minutes (TCP Maximum Segment Life)...\n\n");
		
	int remaining_time = TIMEOUT;
	time_t start;
	time(&start);
	

	fd_set rfds;
	struct timeval tv;
	int fd = pcap_fileno(adapterHandle);
	if (fd == -1){
		printf("Error getting pcap file handle: %s\n", pcap_geterr(adapterHandle)); 
		return -1;
	}
	
	while (remaining_time > 0){
		
		//calculate remaining time to wait
		time_t elapsed;
		time(&elapsed);
		double elapsed_seconds = difftime(elapsed, start);
		remaining_time = TIMEOUT - elapsed_seconds;


		//have to split Win and linux here because of inconsistensies in how pcap_next_ex works
		//and pcap_fileno not providing a selectable handle for Windows
#ifdef _WIN32	
		retValue = pcap_next_ex(adapterHandle, &packetHeader, &packetData);
		if (retValue > 0) {
#else
		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);
		
		tv.tv_sec = remaining_time;
		tv.tv_usec = 0;
		
		//printf("Listening for %d more secs\n", remaining_time);
		retValue = select(fd+1, &rfds, NULL, NULL, &tv);				
		
		if (retValue == -1){
			printf("select() on pcap file handle failed!\n");
			return -1;
		}
		else if (retValue == 0){
			//printf("Timeout reached\n");
			break;
		}
		else {
			pcap_next_ex(adapterHandle, &packetHeader, &packetData);
#endif		
			//get characteristics
			IPHeader *iph = (IPHeader *)(packetData + sizeof(ETHER_HDR));
			u_int srcip = ntohl(iph->ip_srcaddr);		
			TCPHeader* tcph = (TCPHeader*)(packetData + sizeof(ETHERHeader) + sizeof(IPHeader));
			int len = tcph->data_offset;
			int syn = tcph->syn;
			int rst = tcph->rst;
			int ack = tcph->ack;		
			u_int seq_val = ntohl(tcph->sequence);		
			u_int ack_val = ntohl(tcph->acknowledge);

			if (rst){	
				if (first_packet){
					printf("Connection was reset without SYN/ACK response! Does %s have port %d open?\n", target, port);
					return -1;
				}
					
				if (ack){ sig.rst_ack = 1; sig.rst = 0; }
				else sig.rst = 1;
				sig.rst_win = tcph->window;
				if ( seq_val - srcip > 0 ) sig.rst_seq = 1;
				if (ack_val > 0) sig.rst_nonzero = 1;
				
				//calculate timestamp since the first SYN packet
				timeval diff;
				timeval_subtract(&diff, &packetHeader->ts, &timeSent);		
				double ts = (diff.tv_sec * 1000000.0 + diff.tv_usec) / 1000000.0;
				sig.packet_arrival_time.push_back(ts); 				
					
			}	

			if (syn && ack){				
				if (first_packet){
					sig.win = ntohs(tcph->window);
					sig.ttl = iph->ip_ttl;
					sig.df = iph->ip_dont_fragment;
					
					//Read Options
					//Options:
					//		M: MSS
					//		W: Window Scale
					//		N: NOP
					//		T: Timestamp
					//		E: EOL
					//		S: SACK Permitted
					//		X: No option
					

					char options[25] = "\0";
					u_short mss = 0;
					//u_short wscale = 0;
					int options_bytes_size = len*4 - 20;
					if (options_bytes_size > 0){
						struct Option {
							unsigned char kind;
							unsigned char length;
						};

						int options_read = 0;
						int len;
						unsigned char* opt_ptr = (unsigned char*)(packetData + sizeof(ETHERHeader) + sizeof(IPHeader) + 20);				
						while (options_read < options_bytes_size){
							Option* opt = (Option*)opt_ptr;
							int kind = opt->kind;

							if (strlen(options) > 20){ 
								break;
							}

							//read kind
							switch(kind){
							case 0: //EOL
								strcat(options, "E");
								opt_ptr += 1; 
								options_read += 1;
								break;
							case 1: //NO-Op
								strcat(options, "N");
								opt_ptr += 1; 
								options_read += 1;
								break;
							case 2:	//MSS	
								len = opt->length; //get length
								strcat(options, "M"); //add to string
								opt_ptr += sizeof(Option); //skip past option
								mss = ntohs(*((u_short*)opt_ptr)); //get data
								opt_ptr += (len - sizeof(Option)); //skip past data
								options_read += len; //add to bytes read
								break;
							case 3: //Window Scale
								len = opt->length; //get length
								strcat(options, "W"); //add to string
								opt_ptr += sizeof(Option);
								//wscale = *opt_ptr;
								opt_ptr += (len - sizeof(Option)); //skip past data
								options_read += len; //add to bytes read
								break;
							case 4: //SACK
								len = opt->length; //get length
								strcat(options, "S"); //add to string
								opt_ptr += len; //skip forward
								options_read += len; //add to bytes read
								break;
							case 8: //Timestamp
								len = opt->length; //get length
								strcat(options, "T"); //add to string
								opt_ptr += len; //skip forward
								options_read += len; //add to bytes read
								break;
							default:
								len = opt->length; //get length
								if (len == 0) len = 1;
								opt_ptr += len; //skip forward
								options_read += len; //add to bytes read
								break;
							}
						}
					}
					else strcat(options, "X");

					strcpy(sig.options_str, options);
					sig.mss = mss;

					first_packet = false;
				}
				
				// calculate RTO
				//if (lastTS.tv_sec != 0){
				//	timeval diff;
				//	diff.tv_sec = packetHeader->ts.tv_sec - lastTS.tv_sec;
				//	diff.tv_usec = packetHeader->ts.tv_usec - lastTS.tv_usec;
				//	while(diff.tv_usec<0){
				//		diff.tv_usec += 1000000;
				//		diff.tv_sec -= 1;
				//	}				
				//	double rto = (diff.tv_sec * 1000000.0 + diff.tv_usec) / 1000000.0;
				//	sig.rto.push_back(rto);
				//}			
				//lastTS = packetHeader->ts;	
			
			
				//calculate timestamp since the first SYN packet
				timeval diff;
				timeval_subtract(&diff, &packetHeader->ts, &timeSent);		
				double ts = (diff.tv_sec * 1000000.0 + diff.tv_usec) / 1000000.0;
				if (ts < 0) ts *= -1; //make sure ts is positive. This was occurring because of drift in Windows version of gettimeofday. Needs better timing fix
				sig.packet_arrival_time.push_back(ts); 
							
			}
			
			//print running output
			printf("\rSignature so far: %d,%d,%d,%s,%d,%d,%d,%d,%d,%d", sig.win, sig.ttl, sig.df, sig.options_str, sig.mss, sig.rst, sig.rst_ack, sig.rst_win, sig.rst_seq, sig.rst_nonzero);
			for (u_int r = 0; r < sig.packet_arrival_time.size(); r++) printf(",%lf", sig.packet_arrival_time[r]);	
			//printf("\n");
		}
	}
		
	if( retValue == -1 ){
		printf("Error reading the packets: %s\n", pcap_geterr(adapterHandle));
		return -1;
	}	

	//output signature to file
	fprintf(ofile, "%s,%d,%d,%d,%s,%lld,%d,%d,%d,%d,%d,%d", target, sig.win, sig.ttl, sig.df, sig.options_str, sig.options_int, sig.mss, sig.rst, sig.rst_ack, sig.rst_win, sig.rst_seq, sig.rst_nonzero);
	for (u_int r = 0; r < sig.packet_arrival_time.size(); r++) fprintf(ofile, ",%lf", sig.packet_arrival_time[r]);
	fprintf(ofile, "\n");
	fclose(ofile);
	printf("\nResults appended to file %s\n", output_file);

	return 0;
}

int LiveFingerprinter::timeval_subtract(timeval *result, timeval *x, timeval *y){
	//Taken from www.gnu.org/software/libc/manual/html_node/Elapsed-Time.html
	
	/* Perform the carry for the later subtraction by updating y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}


unsigned short LiveFingerprinter::in_checksum(unsigned short *ptr,int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((unsigned char*)&oddbyte)=*(unsigned char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

int LiveFingerprinter::createPacket(char *target, int target_port, int* srcPort, unsigned char *packet){ 
	
	char src[16];
	ETHER_HDR *ehdr;
	IP_HDR *iphdr;
	TCP_HDR *tcphdr;
	PSEUDO_HDR pseudo_header;	
	unsigned char seudo[sizeof(PSEUDO_HDR)];
	u_long MACADDRLEN = 6;

	

	//create headers
	// *******************  Ethernet Header *****************
	
	ehdr = (ETHER_HDR*)packet;
	
	//long long test_mac = 0x0000db28a9721300; //reverse of 0x001372a928db0000
	//long long test_mac = 0x0000dfb181270008; ; //reverse of 0x08002781b1df0000	
	//memcpy(ehdr->dest, &test_mac, 6);	//Destination MAC address

	ehdr->type = htons(0x0800); //IP Frames

#ifdef _WIN32
	//fill Ethernet header on Windows and getsource IP

	//get source mac and IP
	unsigned long size = 15000; //15k buffer according to MSDN
	char* AdapterAddresses = new char[size];

	//try and get network adapter information from the OS
	int ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, (IP_ADAPTER_ADDRESSES *)AdapterAddresses, &size);
	if (ret != NO_ERROR){
		if (ret == ERROR_BUFFER_OVERFLOW) printf("Error, could not return adapter addresses\n");
		return -1;
	}

	IP_ADAPTER_ADDRESSES* pCurrAddresses = (IP_ADAPTER_ADDRESSES *)AdapterAddresses;
	while (pCurrAddresses) {
		if (strstr(adapterName, pCurrAddresses->AdapterName) != NULL){
			unsigned char *MAC = (unsigned char*)pCurrAddresses->PhysicalAddress;
			printf("Local MAC Address Is: %02X-%02X-%02X-%02X-%02X-%02X\n", MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
			memcpy_s(ehdr->source, MACADDRLEN, MAC, MACADDRLEN);
			SOCKADDR_IN* sa = (SOCKADDR_IN *)(pCurrAddresses->FirstUnicastAddress->Address.lpSockaddr);
			strcpy_s(src, inet_ntoa(sa->sin_addr));
			printf("Source IP set to: %s\n", src);
			break;
		}
		pCurrAddresses = pCurrAddresses->Next;
    } 

	delete AdapterAddresses;

	//then get dest mac
	IPAddr destip;
	IPAddr srcip;
	destip = inet_addr(target);
	srcip = inet_addr(src);
	ULONG MAC[2];
	
	ret = SendARP(destip, srcip, MAC, &MACADDRLEN);
	if (ret == NO_ERROR){
		memcpy_s(ehdr->dest, MACADDRLEN, MAC, MACADDRLEN);
	}
	else { 
		printf("SendARP failed with error %d. Could not figure out destination MAC addr\n", ret);
		return -1;
	}
#else
	//fill Ethernet header on *nix
	
	//using getifaddrs
	//struct ifaddrs *ifap, *ifa;	
	//getifaddrs(&ifap);
	//for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		//if (ifa->ifa_addr != NULL && strcmp(ifa->ifa_name, adapterName) == 0){
			
			////if adapter name matches and family PF_PACKET, get MAC address
			//int family = ifa->ifa_addr->sa_family;			
			//if (family == PF_PACKET){
				//sockaddr* sa = (struct sockaddr*) ifa->ifa_addr;		
				//unsigned char* mac = (unsigned char*) sa->sa_data;
				//mac += 10;
				//printf("Local MAC Address Is: %02X-%02X-%02X-%02X-%02X-%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);		
				//memcpy(ehdr->source, mac, MACADDRLEN);					
			//}
			
			////if adapter name matches and family INET, get IP addresses
			//if (family == AF_INET){
				////get src IP
				//char host[NI_MAXHOST];
				//int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
				//if (s != 0) {
					//printf("getnameinfo() failed: %s\n", gai_strerror(s));
					//return -1;
				//}
				//printf("Local IP: %s\n", host);
				//strcpy(src, host);
				
			//}
		//}	
	//}						
	//freeifaddrs(ifap);
	
	//using ioctl and netlink sockets
	struct ifconf ifc;
	char buf[1024];
	
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0){
		printf("Could not open socket\n");
		return -1;
	}
	
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(fd, SIOCGIFCONF, &ifc) == -1){
		printf("ioctl SIOCGIFCONF failed! errno: %d\n", errno);
		return -1;
	}
	
	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(ifreq));
	
	while (it != end){
		if (strcmp(it->ifr_name, adapterName) == 0){
			struct ifreq ifr;
			strcpy(ifr.ifr_name, it->ifr_name);
			
			//fire ioctl for local MAC
			if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1){
				printf("ioctl SIOCGIFHWADDR failed! errno: %d\n", errno);
				return -1;
			}
			char* mac = ifr.ifr_hwaddr.sa_data;
			//printf("Local MAC Address Is: %02X-%02X-%02X-%02X-%02X-%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);		
			memcpy(ehdr->source, mac, MACADDRLEN);	
			
			//fire ioctl for local IP
			if (ioctl(fd, SIOCGIFADDR, &ifr) == -1){
				printf("ioctl SIOCGIFADDR failed! errno: %d\n", errno);
				return -1;
			}
			//get src IP
			char host[NI_MAXHOST];
			int s = getnameinfo(&ifr.ifr_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			if (s != 0) {
				printf("getnameinfo() failed: %s\n", gai_strerror(s));
				return -1;
			}
			printf("Local IP: %s\n", host);
			strcpy(src, host);
		}		
		it++;
	}	
	
	//read destination MAC from system ARP table using ioctl
	//assumes your system cache stores the MAC of your gateway. 
	
	//first get gateway IP using Netlink Socket to read system route table
	//Netlink documentation: http://smacked.org/docs/netlink.pdf
	//code below taken from https://stackoverflow.com/questions/3288065/
	//why is this process so complicated in linux?
	
	u_int gatewayIP = 0;
	struct nlmsghdr *nlMsg;
	struct nlmsghdr *nlHdr;
	struct rtmsg *rtMsg;
	struct route_info *rtInfo;
	char msgBuf[8192];
	
	int sock, readLen = 0, msgLen = 0, msgSeq=0, pid = getpid();
	
	if ((sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)) < 0){
		printf("Netlink socket creation failed: %d\n", errno);
		return -1;
	}
	
	//create request
	memset(msgBuf, 0, 8192);
	nlMsg = (struct nlmsghdr *)msgBuf;
	rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);
	
	nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlMsg->nlmsg_type = RTM_GETROUTE;
	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlMsg->nlmsg_seq = msgSeq++;
	nlMsg->nlmsg_pid = pid;
	
	//send request
	if (send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0){
		printf("Write to netlink socket failed: %d\n", errno);
		return -1;
	}
	
	//recv response			
	memset(msgBuf, 0, 8192);
	char* bufptr = msgBuf;
	do {
		if ((readLen = recv(sock, bufptr, 8192 - msgLen, 0)) < 0){
			printf("Error in receiving Netlink response: %d\n", errno);
			return -1;
		}
		
		nlHdr = (struct nlmsghdr *)bufptr;			
		
		//check if error
		if ((NLMSG_OK(nlHdr, readLen) == 0) || (nlHdr->nlmsg_type == NLMSG_ERROR)){
			printf("Error in Netlink response packet: %d\n", errno);
			return -1;
		}
		
		//if last message, break
		if (nlHdr->nlmsg_type == NLMSG_DONE) break;
		else {
			bufptr += readLen;
			msgLen += readLen;
		}
		
		//if not multipart message, break
		if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) break;
		
	}while((nlHdr->nlmsg_seq != msgSeq) || (nlHdr->nlmsg_pid != pid));
	
	//parse response			
	for (; NLMSG_OK(nlMsg,msgLen); nlMsg = NLMSG_NEXT(nlMsg,msgLen)){						
		route_info rtinfo;
		struct rtattr *rtAttr;
		
		rtMsg = (struct rtmsg *)NLMSG_DATA(nlMsg);
		
		//if not AF_INET or not main routing table, skip
		if ((rtMsg->rtm_family != AF_INET) || (rtMsg->rtm_table != RT_TABLE_MAIN)) continue;
	
		//get attributes
		rtAttr = (struct rtattr *)RTM_RTA(rtMsg);
		int rtLen = RTM_PAYLOAD(nlMsg);				
		for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)){					
			switch(rtAttr->rta_type){
				case RTA_OIF: 
					if_indextoname(*(int*)RTA_DATA(rtAttr), rtinfo.ifName);
					break;
				case RTA_GATEWAY:
					rtinfo.gateway = *(u_int *)RTA_DATA(rtAttr);
					break;
				case RTA_PREFSRC:
					rtinfo.srcAddr = *(u_int *)RTA_DATA(rtAttr);
					break;
				case RTA_DST:
					rtinfo.dstAddr = *(u_int *)RTA_DATA(rtAttr);
					break;
			}
		}
		
		//print info
		//printf("Interface: %s \n Src: %u \n Dst: %u \n Gateway: %u \n\n", rtinfo.ifName, rtinfo.srcAddr, rtinfo.dstAddr, rtinfo.gateway);
		
		//if this is for the chosen adapter
		if (strcmp(adapterName, rtinfo.ifName) == 0){
			gatewayIP = rtinfo.gateway;
			printf("Gateway IP: %s\n", inet_ntoa(*(struct in_addr*) &gatewayIP));
			break; 
			//Now there could be multiple gateways for this interface, though not common
			//We are being lazy and taking the first one we see
			//A more correct way would be to do a prefix match against our target and pick that gateway
		}		
	}
	
	// fire ioctl for ARP table	
	if (gatewayIP > 0){
		struct arpreq areq;
		memset(&areq, 0, sizeof(areq));
		
		sockaddr_in* sa;
		sa = (sockaddr_in*)&areq.arp_pa;
		sa->sin_family = AF_INET;
		//inet_aton(target, &sa->sin_addr);
		sa->sin_addr = *(struct in_addr*) &gatewayIP;
		sa = (sockaddr_in*)&areq.arp_ha;
		sa->sin_family = ARPHRD_ETHER;
		
		strcpy(areq.arp_dev, adapterName);
		
		if (ioctl(fd, SIOCGARP, (caddr_t) &areq) == -1){
			printf("ioctl SIOCGARP failed! errno: %d\n", errno);
			return -1;
		}
		char* mac = areq.arp_ha.sa_data;
		
		//printf("Dest MAC Address Is: %02X-%02X-%02X-%02X-%02X-%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);		
		memcpy(ehdr->dest, mac, MACADDRLEN);	
	}
	else {			
		//did not get a gateway IP, set dest MAC to 0 and cross our fingers
		memset(ehdr->dest, 0, MACADDRLEN);				
	}
	
	
#endif
	
	// *******************  IP Header *****************

	//generate a random number between 1024 and 65535 for the source port
	srand ( time(NULL) );
	*srcPort = (rand() % (65535 - 1024)) + 1024;

	iphdr = (IP_HDR*)(packet + sizeof(ETHER_HDR));
	
	iphdr->ip_version = 4;
	iphdr->ip_header_len = 5;	//In double words thats 4 bytes
	iphdr->ip_tos = 0;
	iphdr->ip_total_length = htons (sizeof(IP_HDR) + sizeof(TCP_HDR));
	iphdr->ip_id = htons(*srcPort); //encode port in IP_ID
	iphdr->ip_frag_offset = 0;
	iphdr->ip_reserved_zero=0;
	iphdr->ip_dont_fragment=1;
	iphdr->ip_more_fragment=0;
	iphdr->ip_frag_offset1 = 0;
	iphdr->ip_ttl    = 64;
	iphdr->ip_protocol = 6; //tcp
	iphdr->ip_srcaddr  = inet_addr(src);   //srcip.s_addr;
	iphdr->ip_destaddr = inet_addr(target);
	iphdr->ip_checksum =0;
	iphdr->ip_checksum = in_checksum((unsigned short*)iphdr, sizeof(IP_HDR));
	
	// *******************  TCP Header *****************
	tcphdr = (TCP_HDR*)(packet + sizeof(ETHER_HDR) + sizeof(IP_HDR));
	
	

	tcphdr->source_port = htons(*srcPort);
	tcphdr->dest_port = htons(target_port);
	tcphdr->sequence=inet_addr(target);
	tcphdr->acknowledge=0;
	tcphdr->reserved_part1=0;
	tcphdr->data_offset=10;
	tcphdr->fin=0;
	tcphdr->syn=1;
	tcphdr->rst=0;
	tcphdr->psh=0;
	tcphdr->ack=0;
	tcphdr->urg=0;
	tcphdr->ecn=0;
	tcphdr->cwr=0;
	tcphdr->window = htons(8192); //8K window size
	tcphdr->checksum=0;
	tcphdr->urgent_pointer = 0;
	tcphdr->opt1 = ntohl(0x020405b4); //M
	tcphdr->opt2 = ntohl(0x01030308); //NW
	//tcphdr->opt3 = ntohl(0x01010402); //NNS
	tcphdr->opt3 = ntohl(0x0402080a); //ST
	tcphdr->opt4 = ntohl(0x00000001); //TSval
	tcphdr->opt5 = ntohl(0x00000000); //TSecr
	
	// *******************  Checksum calculation *****************
	pseudo_header.source_address = inet_addr(src); 
	pseudo_header.dest_address = inet_addr(target);
	pseudo_header.placeholder = 0;
	pseudo_header.protocol = IPPROTO_TCP;
	pseudo_header.tcp_length = htons(sizeof(TCP_HDR));
	memcpy(&pseudo_header.tcp , tcphdr , sizeof(TCP_HDR));

	memcpy(seudo, &pseudo_header, sizeof(PSEUDO_HDR));
	
	tcphdr->checksum = in_checksum((unsigned short*)seudo, sizeof(PSEUDO_HDR));
	
	// ***************************************************************

	return 0;
} 

LiveFingerprinter::~LiveFingerprinter(){
	
	//clean vars
	pcap_close(adapterHandle);
	delete[] adapterName;
}
	
