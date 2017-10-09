/*
structures.h 
- Contains the structures for the IP TCP UDP version 4  headers for raw sockets
can be used with IP_HDRINCL option with setsockopt
*/

class Signature{
public:
	unsigned int id_classified;
	unsigned int id;
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
	
	Signature(){
		id = 0; win = 0; ttl = 0; df = 0; rst = 0; rst_ack = 0; rst_win = 0; rst_seq = 0; rst_nonzero = 0; mss = 0; options_int = 0;
	}
};

// Set the packing to a 1 byte boundary
// #include "pshpack1.h"

//Ethernet Header
typedef struct ethernet_header
{
	unsigned char dest[6];
	unsigned char source[6];
	unsigned short type;
}   ETHER_HDR, ETHERHeader;

/*
 Define the IPv4 header. Make the version and length field one
 character since we can't declare two 4 bit fields without
 the compiler aligning them on at least a 1 byte boundary.
*/

typedef struct ip_hdr
{
    unsigned char  ip_header_len:4;  // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
    unsigned char  ip_version   :4;  // 4-bit IPv4 version
    unsigned char  ip_tos;           // IP type of service
    unsigned short ip_total_length;  // Total length
    unsigned short ip_id;            // Unique identifier 
    
	unsigned char  ip_frag_offset   :5;        // Fragment offset field
	
	unsigned char  ip_more_fragment :1;
	unsigned char  ip_dont_fragment :1;
	unsigned char  ip_reserved_zero :1;
	
    unsigned char  ip_frag_offset1;    //fragment offset
	
	unsigned char  ip_ttl;           // Time to live
    unsigned char  ip_protocol;      // Protocol(TCP,UDP etc)
    unsigned short ip_checksum;      // IP checksum
    unsigned int   ip_srcaddr;       // Source address
    unsigned int   ip_destaddr;      // Source address
}   IP_HDR, IP_HEADER, IPHeader;


//UDP header
typedef struct udp_hdr
{
	unsigned short source_port;     // Source port no.
	unsigned short dest_port;       // Dest. port no.
	unsigned short udp_length;      // Udp packet length
	unsigned short udp_checksum;    // Udp checksum (optional)
}   UDP_HDR, UDP_HEADER, UDPHeader;


// TCP header
typedef struct tcp_header
{
	unsigned short source_port;  // source port 
	unsigned short dest_port;    // destination port 
	unsigned int   sequence;     // sequence number - 32 bits 
	unsigned int   acknowledge;  // acknowledgement number - 32 bits 

	unsigned char  ns : 1;          //Nonce Sum Flag Added in RFC 3540.
	unsigned char  reserved_part1 : 3; //according to rfc
	unsigned char  data_offset : 4;    /*The number of 32-bit words in the TCP header.
									   This indicates where the data begins.
									   The length of the TCP header is always a multiple
									   of 32 bits.*/

	unsigned char  fin : 1;      //Finish Flag
	unsigned char  syn : 1;      //Synchronise Flag
	unsigned char  rst : 1;      //Reset Flag
	unsigned char  psh : 1;      //Push Flag 
	unsigned char  ack : 1;      //Acknowledgement Flag 
	unsigned char  urg : 1;      //Urgent Flag

	unsigned char  ecn : 1;      //ECN-Echo Flag
	unsigned char  cwr : 1;      //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window;  // window 
	unsigned short checksum;  // checksum 
	unsigned short urgent_pointer;  // urgent pointer 

	//Options
	unsigned int opt1;
	unsigned int opt2;
	unsigned int opt3;
	unsigned int opt4;
	unsigned int opt5;
}   TCP_HDR, TCP_HEADER, TCPHeader;

typedef struct pseudo_header    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	//char tcp[28];
	TCP_HDR tcp;
}   PSEUDO_HDR , PSEUDO_HEADER, PseudoHeader;

// Restore the byte boundary back to the previous value
// #include <poppack.h>
