#include <pcap.h>
#include <stdio.h>
#include "packet_structure.h"
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_d_Mac(Ethernet * e)
{
    printf("d_mac = %02X:%02X:%02X:%02X:%02X:%02X\n", e->d_mac[0],e->d_mac[1],e->d_mac[2],e->d_mac[3],e->d_mac[4],e->d_mac[5]);
}

void print_s_Mac(Ethernet * e)
{
    printf("s_mac = %02X:%02X:%02X:%02X:%02X:%02X\n", e->s_mac[0],e->s_mac[1],e->s_mac[2],e->s_mac[3],e->s_mac[4],e->s_mac[5]);
}

void print_s_ip(Ip * ip)
{
    printf("s_ip = %u.%u.%u.%u\n", ip->s_ip[0], ip->s_ip[1], ip->s_ip[2], ip->s_ip[3]);
}

void print_d_ip(Ip * ip)
{
    printf("d_ip = %u.%u.%u.%u\n", ip->d_ip[0], ip->d_ip[1], ip->d_ip[2], ip->d_ip[3]);
}

void print_s_port(Tcp * tcp)
{
    printf("s_port = %d\n", ntohs(tcp->s_port));
}

void print_d_port(Tcp * tcp)
{
    printf("d_port = %d\n", ntohs(tcp->d_port));
}

/*void print_payload(Tcp * tcp)
{
    printf("payload : % %c %c %c %c %c %c %c %c %c\n", tcp->payload[0], tcp->payload[1], tcp->payload[2], tcp->payload[3],
            tcp->payload[4], tcp->payload[5], tcp->payload[6], tcp->payload[7], tcp->payload[8], tcp->payload[9]);
}
*/


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

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

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    Ethernet * ethernet_header = (Ethernet *)packet;
    ethernet_SIZE = 14;

    Ip * ip_header = (Ip *)(packet + ethernet_SIZE);
    ip_SIZE = (ip_header->VHL & 0x0F) * 4;

    Tcp * tcp_header = (Tcp *)(packet + ethernet_SIZE + ip_SIZE);
    tcp_SIZE = ((tcp_header->HLR & 0xF0) >> 4) * 4;

    u_char * payload = (u_char *)(packet + ethernet_SIZE + ip_SIZE + tcp_SIZE);
    payload_SIZE = ntohs(ip_header->Total_LEN) - (ip_SIZE + tcp_SIZE);

    if(ethernet_header->type == ntohs(0x0800) &&
            ip_header->protocol == 0x06)
    {
        printf("\n------------------------------------\n\n");

        print_d_Mac(ethernet_header);
        print_s_Mac(ethernet_header);
        print_s_ip(ip_header);
        print_d_ip(ip_header);
        print_s_port(tcp_header);
        print_d_port(tcp_header);

        if(payload_SIZE == 0)   printf("payload data : X\n");
        else
        {
            printf("payload data : ");
            for(int i=0; i<payload_SIZE;i++)
            {
                if(i >= 10)
                    break;
                printf("%02X ", payload[i]);
            }
            printf("\n");
        }

        printf("%u bytes captured\n", header->caplen);
        printf("\n------------------------------------\n");
    }


  }

  pcap_close(handle);
  return 0;
}
