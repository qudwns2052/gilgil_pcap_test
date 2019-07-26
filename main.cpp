#include <pcap.h>
#include <stdio.h>
#include "packet_structure.h"
#include <arpa/inet.h>
#include <iostream>

#define ETHER_HEADER_SIZE   14
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

using namespace std;

void print_info(Ethernet * e, Ip * ip, Tcp * tcp)
{
    printf("d_mac = %02X:%02X:%02X:%02X:%02X:%02X\n", e->d_mac[0],e->d_mac[1],e->d_mac[2],e->d_mac[3],e->d_mac[4],e->d_mac[5]);
    printf("s_mac = %02X:%02X:%02X:%02X:%02X:%02X\n", e->s_mac[0],e->s_mac[1],e->s_mac[2],e->s_mac[3],e->s_mac[4],e->s_mac[5]);
    printf("s_ip = %u.%u.%u.%u\n", ip->s_ip[0], ip->s_ip[1], ip->s_ip[2], ip->s_ip[3]);
    printf("d_ip = %u.%u.%u.%u\n", ip->d_ip[0], ip->d_ip[1], ip->d_ip[2], ip->d_ip[3]);
    cout << "s_port = " << htons(tcp->s_port) << endl;
    cout << "d_port = " << htons(tcp->d_port) << endl;
    printf("----------------TCP Packet--------------\n");
}


int main(int argc, char* argv[])
{

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }


    int ethernet_SIZE;
    int ip_SIZE;
    int tcp_SIZE;
    int payload_SIZE;

    while (true)
    {
        printf("\n\n--------------Packet Capture-------------\n");
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        Ethernet * ethernet_header = (Ethernet *)packet;
        ethernet_SIZE = 14;

        if(ntohs(ethernet_header->type) != 0x0800)
            continue;

        Ip * ip_header = (Ip *)(packet + ethernet_SIZE);
        ip_SIZE = (ip_header->VHL & 0x0F) * 4;

        if(ip_header->protocol != 0x06)
            continue;
        Tcp * tcp_header = (Tcp *)(packet + ethernet_SIZE + ip_SIZE);
        tcp_SIZE = ((tcp_header->HLR & 0xF0) >> 4) * 4;

        u_char * payload = (u_char *)(packet + ethernet_SIZE + ip_SIZE + tcp_SIZE);
        payload_SIZE = ntohs(ip_header->Total_LEN) - (ip_SIZE + tcp_SIZE);

        cout << "\n----------------Filtering---------------\n" << endl;
        //











        //
        print_info(ethernet_header, ip_header, tcp_header);
        printf("----------------TCP Packet--------------\n");
    }

    pcap_close(handle);
    return 0;
}
