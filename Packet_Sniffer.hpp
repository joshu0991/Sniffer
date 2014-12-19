/*
 * Packet_Sniffer.hpp
 *
 *  Created on: Dec 7, 2014
 *      Author: Josh
 */

#ifndef PACKET_SNIFFER_HPP_
#define PACKET_SNIFFER_HPP_

#include <iostream>
#include <cstdio>
#include<cstdlib>
#include <cstring>
#include<netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>

class Packet_Sniffer{

	unsigned char *buffer;
	FILE* logfile;
	int total, tcp, udp;

public:
	Packet_Sniffer();
	Packet_Sniffer(int);
	~Packet_Sniffer();
	int sniff_packets();
	int process_TCP(unsigned char*);
	int process_packet(unsigned char*);
	int print_ip_headers(unsigned char*);
};

#endif /* PACKET_SNIFFER_HPP_ */
