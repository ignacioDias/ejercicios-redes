/*
 * compile as send_eth and give the following capabilities:
 * sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' ./send_eth
 * This program send a broadcast package. You can see it in other LAN machine
 * by using: sudo tcpdump -i <net-interface> ether host <sender-mac>
 * Example: sudo tcpdump -i eth0 ether host d0:37:45:d5:79:d1
 * Also, we can filter this packet by its protocol (type field) with
 * sudo tcpdump -i eth0 ether proto 0x6100
 */

#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

/* Ethernet packet structure */
struct eth_packet {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t type;
    uint8_t  data[1500];
} __attribute__((packed));

int main(int argc, char* argv[])
{
    unsigned char bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    char *data = "Hello from Ethernet";
    const int data_length = strlen(data);
    int s;
    struct eth_packet packet;
    struct ifreq req;

    if (argc < 2) {
        printf("Usage: ./send_eth interface");
        return -1;
    }

    s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    /* get interface infoe */
    memset(&req, 0, sizeof(req));
    strcpy((char*)req.ifr_name, argv[1]);

    if (ioctl(s, SIOCGIFINDEX, &req) < 0)
    {
        perror("init: ioctl");
        close(s);
        return -1;
    }

    /* socket address link layer struct */
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = PF_PACKET;
    addr.sll_protocol = 0;
    addr.sll_ifindex  = req.ifr_ifindex;

    /* bind socket to interface */
    if (bind(s, (const struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        perror("init: bind fails");
        close(s);
        return -1;
    }

    /* get interface MAC address */
    if (ioctl(s, SIOCGIFHWADDR, &req) < 0)
    {
        perror( "init: ioctl SIOCGIFHWADDR" );
        close(s);
        return -1;
    }
 
    /* set packet fields */
    memset(&packet, 0, sizeof(packet));
    memcpy(packet.dst, bcast, 6);
    memcpy(packet.src, (unsigned char*)req.ifr_hwaddr.sa_data, ETH_ALEN);
    packet.type = htons(0x6100);    // unused value
    memcpy(packet.data, data, data_length);

    /* send packet */
    if (write(s, &packet, sizeof(packet)) < 0) {
        perror("write error");
    }

    close(s);
}
