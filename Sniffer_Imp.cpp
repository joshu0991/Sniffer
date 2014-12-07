/*
 * Sniffer_Imp.cpp
 *
 *  Created on: Dec 7, 2014
 *      Author: Josh
 */

#include "Packet_Sniffer.hpp"

Packet_Sniffer::Packet_Sniffer()
{
	std::cout << "Setting buffer..." << std::endl;
	buffer = (unsigned char *)malloc(65536);
}

Packet_Sniffer::~Packet_Sniffer()
{
	std::cout << "Buffer Deleted" << std::endl;
	free (buffer);
}

int Packet_Sniffer::sniff_packets()
{
	raw_socket = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	if(raw_socket < 0)
	{
		std::cerr << "Could not open socket" << std::endl;
		return 1;
	}
	std::cout << "Succefully created socket" <<std::endl;
	int i = 0;
	while(i < 100)
		{
			saddr_size = sizeof saddr;
			data_size = recvfrom(raw_socket , buffer , 65536 , 0 , &saddr , &saddr_size);
			if(data_size < 0)
			{
				std::cerr << "Receive from error" << std::endl;
			}
			i++;
		}
	process_packet(buffer);
	return 0;
}

int Packet_Sniffer::process_packet(unsigned char* buf)
{
	struct iphdr *iph = (struct iphdr*)buffer;
	std::cout << buf << std::endl;
	return 0;
}
