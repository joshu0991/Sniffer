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
#include <string>
#include<netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>

class Packet_Sniffer{

	struct sockaddr_in source,dest;
	unsigned char *buffer;
	socklen_t saddr_size;
	struct sockaddr saddr;
	struct in_addr in;
	int raw_socket;
	int data_size;

public:
	Packet_Sniffer();
	Packet_Sniffer(int);
	~Packet_Sniffer();
	int sniff_packets();
	int process_packet(unsigned char*);
};

#endif /* PACKET_SNIFFER_HPP_ */
