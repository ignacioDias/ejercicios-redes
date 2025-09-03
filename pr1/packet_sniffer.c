/* Note: run this program as root user
 * Author:Subodh Saxena 
 */
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/if_packet.h>
#include <netinet/in.h>		 
#include <netinet/if_ether.h>   // ethernet header
#include <netinet/ip.h>		    // ip header
#include <netinet/udp.h>		// udp header
#include <netinet/tcp.h>        // tcp header
#include <arpa/inet.h>          // inet_ntoa(), ...

#define BUF_SIZE 65536          // buffer size: 64KB

static volatile int sock_r;

FILE* log_txt;
int total, tcp, udp, icmp, igmp, other, iphdrlen;

struct sockaddr saddr;
struct sockaddr_in source, dest;

// Ctrl-C signal handler
void ctrl_c_handler(int _)
{
    close(sock_r);
    exit(1);
}

/* shows payload */
void payload(unsigned char* buffer, int buflen, int offset)
{
	int i=0;
	fprintf(log_txt,"\nData\n");
    while (offset < buflen) {
		if(i!=0 && i%16==0)
			fprintf(log_txt,"\n");
		fprintf(log_txt," %.2X ", *(buffer + offset));
        offset++;
        i++;
	}
	fprintf(log_txt,"\n");
}

void ethernet_header(unsigned char* buffer, int buflen)
{
	struct ethhdr *eth = (struct ethhdr *)(buffer);
	fprintf(log_txt,"\nEthernet Header\n");
	fprintf(log_txt,"\t|-Source Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
	fprintf(log_txt,"\t|-Destination Address	: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
	fprintf(log_txt,"\t|-Protocol		: 0x%04x\n", (unsigned int) eth->h_proto);
    if (ntohs(eth->h_proto) != 0x0800) {
        payload(buffer, buflen, sizeof(struct ethhdr));
    }
}

void ip_header(unsigned char* buffer,int buflen)
{
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	iphdrlen = ip->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip->saddr;
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip->daddr;   

	fprintf(log_txt , "\nIP Header\n");

	fprintf(log_txt , "\t|-Version              : %d\n",(unsigned int)ip->version);
	fprintf(log_txt , "\t|-Internet Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)ip->ihl,((unsigned int)(ip->ihl))*4);
	fprintf(log_txt , "\t|-Type Of Service   : %d\n",(unsigned int)ip->tos);
	fprintf(log_txt , "\t|-Total Length      : %d  Bytes\n",ntohs(ip->tot_len));
	fprintf(log_txt , "\t|-Identification    : %d\n",ntohs(ip->id));
	fprintf(log_txt , "\t|-Time To Live	    : %d\n",(unsigned int)ip->ttl);
	fprintf(log_txt , "\t|-Protocol 	    : %d\n",(unsigned int)ip->protocol);
	fprintf(log_txt , "\t|-Header Checksum   : %d\n",ntohs(ip->check));
	fprintf(log_txt , "\t|-Source IP         : %s\n", inet_ntoa(source.sin_addr));
	fprintf(log_txt , "\t|-Destination IP    : %s\n",inet_ntoa(dest.sin_addr));
    if (ip->protocol != 6 && ip->protocol != 17) {
        /* not UDP or TCP, show as payload */
        payload(buffer, buflen, sizeof(struct ethhdr) + iphdrlen);
    }
}

void tcp_header(unsigned char* buffer,int buflen)
{
	fprintf(log_txt,"\n*********************TCP Packet**************************");
   	ethernet_header(buffer,buflen);
  	ip_header(buffer,buflen);

   	struct tcphdr *tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
   	fprintf(log_txt , "\nTCP Header\n");
   	fprintf(log_txt , "\t|-Source Port          : %u\n",ntohs(tcp->source));
   	fprintf(log_txt , "\t|-Destination Port     : %u\n",ntohs(tcp->dest));
   	fprintf(log_txt , "\t|-Sequence Number      : %u\n",ntohl(tcp->seq));
   	fprintf(log_txt , "\t|-Acknowledge Number   : %u\n",ntohl(tcp->ack_seq));
   	fprintf(log_txt , "\t|-Header Length        : %d DWORDS or %d BYTES\n" ,(unsigned int)tcp->doff,(unsigned int)tcp->doff*4);
	fprintf(log_txt , "\t|----------Flags-----------\n");
	fprintf(log_txt , "\t\t|-Urgent Flag          : %d\n",(unsigned int)tcp->urg);
	fprintf(log_txt , "\t\t|-Acknowledgement Flag : %d\n",(unsigned int)tcp->ack);
	fprintf(log_txt , "\t\t|-Push Flag            : %d\n",(unsigned int)tcp->psh);
	fprintf(log_txt , "\t\t|-Reset Flag           : %d\n",(unsigned int)tcp->rst);
	fprintf(log_txt , "\t\t|-Synchronise Flag     : %d\n",(unsigned int)tcp->syn);
	fprintf(log_txt , "\t\t|-Finish Flag          : %d\n",(unsigned int)tcp->fin);
	fprintf(log_txt , "\t|-Window size          : %d\n",ntohs(tcp->window));
	fprintf(log_txt , "\t|-Checksum             : %d\n",ntohs(tcp->check));
	fprintf(log_txt , "\t|-Urgent Pointer       : %d\n",tcp->urg_ptr);
	payload(buffer, buflen, sizeof(struct ethhdr) + iphdrlen + 
                            sizeof(struct tcphdr));
    fprintf(log_txt,"*****************************************************\n\n\n");
}

void udp_header(unsigned char* buffer, int buflen)
{
	fprintf(log_txt,"\n********************UDP Packet************************");
	ethernet_header(buffer, buflen);
	ip_header(buffer, buflen);
	fprintf(log_txt,"\nUDP Header\n");

	struct udphdr *udp = (struct udphdr*)(buffer + iphdrlen + 
                                                   sizeof(struct ethhdr));
	fprintf(log_txt , "\t|-Source Port    	: %d\n" , ntohs(udp->source));
	fprintf(log_txt , "\t|-Destination Port	: %d\n" , ntohs(udp->dest));
	fprintf(log_txt , "\t|-UDP Length      	: %d\n" , ntohs(udp->len));
	fprintf(log_txt , "\t|-UDP Checksum   	: %d\n" , ntohs(udp->check));

	payload(buffer, buflen, sizeof(struct ethhdr) + iphdrlen + 
                            sizeof(struct udphdr));
	fprintf(log_txt,"*****************************************************\n\n\n");
}

void data_process(unsigned char* buffer,int buflen)
{
    struct ethhdr *ethernet = (struct ethhdr*) buffer;
	struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));

    ++total;

    if (ntohs(ethernet->h_proto) != 0x0800) {
        ethernet_header(buffer, buflen);
    } else {
        /* we will se UDP Protocol only*/ 
        switch (ip->protocol)    //see /etc/protocols file 
        {

            case 6:
                ++tcp;
                tcp_header(buffer, buflen);
                break;

            case 17:
                ++udp;
                udp_header(buffer, buflen);
                break;

            default:
                ip_header(buffer, buflen);
                ++other;
        }
        printf("TCP: %d  UDP: %d  Other: %d  Total: %d\r", 
               tcp ,     udp,     other,     total);
    }
}

int main()
{
    unsigned char buffer[BUF_SIZE];
	int saddr_len, buflen;

    // set Ctrl-C signal handler
    signal(SIGINT, ctrl_c_handler);

	memset(buffer, 0, BUF_SIZE);

	log_txt=fopen("log.txt","w");
	if (!log_txt) {
		printf("unable to open log.txt\n");
		return -1;
	}

	printf("starting .... \n");

	sock_r=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); 
	if(sock_r < 0)
	{
		printf("error in socket\n");
		return -1;
	}

	while(1)
	{
		saddr_len = sizeof saddr;
		buflen = recvfrom(sock_r,buffer,BUF_SIZE,0,&saddr,(socklen_t *)&saddr_len);
		if(buflen < 0)
		{
			printf("error in reading recvfrom function\n");
			return -1;
		}
		fflush(log_txt);
		data_process(buffer, buflen);
	}
}
