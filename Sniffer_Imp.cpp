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
	logfile=fopen("log.txt","w");
}

Packet_Sniffer::~Packet_Sniffer()
{
	std::cout << "Buffer Deleted" << std::endl;
	free (buffer);
}

int Packet_Sniffer::sniff_packets()
{
	total = 0;
	tcp = 0;
	udp = 0;
	struct sockaddr saddr;
	socklen_t saddr_size;
	int data_size, raw_socket;
	raw_socket = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	if(raw_socket < 0)
	{
		std::cerr << "Could not open socket" << std::endl;
		return 1;
	}
	std::cout << "Succefully created socket" <<std::endl;
	int i = 0;
	while(i < 10)
		{
			saddr_size = sizeof saddr;
			data_size = recvfrom(raw_socket , buffer , 65536 , 0 , &saddr , &saddr_size);
			if(data_size < 0)
			{
				std::cerr << "Receive from error" << std::endl;
				return 2;
			}
			i++;
		}
	process_packet(buffer);
	return 0;
}

int Packet_Sniffer::process_packet(unsigned char* buf)
{
	total++;
	struct iphdr *iph = (struct iphdr*)buf;
	switch(iph->protocol)
	{
	//Print TCP packets
	case 6:
		tcp++;
		print_ip_headers(buf);
		//process_TCP(buf);
		break;
	//print UDP packets
	case 17:
		udp++;
		break;

	}
	std::cout << "Total: " << total << " TCP: " << tcp << " UDP: " << udp << std::endl;
	return 0;
}

int Packet_Sniffer::print_ip_headers(unsigned char* buf)
{
	std::cout << "Made it into printing ip headers" << std::endl;
	struct sockaddr_in source,dest;
	std::cout << "Made it into printing ip headers IIII" << std::endl;
	unsigned short iphdrlen;
	struct iphdr *iph = (struct iphdr*)buf;
	iphdrlen = iph->ihl*4;
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

		fprintf(logfile,"\n");
	    fprintf(logfile,"IP Header\n");
	    fprintf(logfile,"   |-IP Version        : %d\n",(unsigned int)iph->version);
	    fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	    fprintf(logfile,"   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
	    fprintf(logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
	    fprintf(logfile,"   |-Identification    : %d\n",ntohs(iph->id));
	    //fprintf(logfile,"   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
	    //fprintf(logfile,"   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
	    //fprintf(logfile,"   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
	    fprintf(logfile,"   |-TTL      : %d\n",(unsigned int)iph->ttl);
	    fprintf(logfile,"   |-Protocol : %d\n",(unsigned int)iph->protocol);
	    fprintf(logfile,"   |-Checksum : %d\n",ntohs(iph->check));
	    fprintf(logfile,"   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
	    fprintf(logfile,"   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
	    return 0;
}

int Packet_Sniffer::process_TCP(unsigned char* buf)
{

	return 0;
}
