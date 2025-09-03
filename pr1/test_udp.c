#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#include "udp.h"


#define MAX_DATA_SIZE 1024


void hexdump(unsigned char *data, unsigned int data_bytes)
{
    int bin_p, ascii_p;

    bin_p = ascii_p = 0;

    while(bin_p < data_bytes){
        int j;
        int whitespaces;
        for(j = 0; j < 8 && bin_p < data_bytes; j++){
            printf("%02x ", data[bin_p++]);
        }

        whitespaces = (8 - j) * 3;
        for(j = 0; j < whitespaces; j++){
            printf(" ");
        }

        for(j = 0; j < 8 && ascii_p < data_bytes; j++){
            if(isprint(data[ascii_p])){
                printf("%c", data[ascii_p++]);
            }else{
                printf(".");
                ascii_p++;
            }
        }

        printf("\n");
    }
}


int main(void)
{
    int raw_sock;
    uint8_t packet[ETH_DATA_LEN];
    uint8_t udp_packet[ETH_DATA_LEN];
    uint8_t data[MAX_DATA_SIZE];
    char *sending_data = "AAAAAAAA";
    char *localhost = "127.0.0.1";
    char *srchost = "192.168.0.1";
    unsigned int packet_size;
    unsigned int data_size;
    struct sockaddr_in src_addr;
    struct sockaddr_in dst_addr;

    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(2048);
    inet_aton(srchost, &src_addr.sin_addr);

    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(4086);
    inet_aton(localhost, &dst_addr.sin_addr);

    strcpy((char *)data, sending_data);
    data_size = strlen(sending_data);

    printf("[+] Build UDP packet...\n\n");
    packet_size = build_udp_packet(src_addr, dst_addr, udp_packet, data, data_size);
    hexdump(udp_packet, packet_size);
    printf("\n\n");

    printf("[+] Build IP packet...\n\n");
    packet_size = build_ip_packet(src_addr.sin_addr, dst_addr.sin_addr, IPPROTO_UDP, packet, udp_packet, packet_size);
    hexdump(packet, packet_size);
    printf("\n\n");

    printf("[+] Send UDP packet...\n");
    if((raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
        perror("socket");
        exit(1);
    }
    send_udp_packet(raw_sock, src_addr, dst_addr, data, data_size);

    return 0;
}

