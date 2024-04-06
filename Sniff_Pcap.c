#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

#define DATA_LEN 20

/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
 
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
  u_char             data[DATA_LEN];        // Packet data

};

/* TCP Header */
struct tcpheader {
  u_short tcph_srcport; // Source port
  u_short tcph_destport; // Destination port
  unsigned int tcph_seqnum; // Sequence Number
  unsigned int tcph_acknum; // Acknowledgment Number
  unsigned char tcph_offset:4, // Data offset
                tcph_reserved:4; // Reserved
  unsigned char tcph_flags; // Flags
  unsigned short tcph_win; // Window
  unsigned short tcph_chksum; // Checksum
  unsigned short tcph_urgptr; // Urgent Pointer
};


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{

  struct ethheader *eth = (struct ethheader *)packet;

  /* Print MAC Address */
  printf("Source MAC  : %02X:%02X:%02X:%02X:%02X:%02X\n",
       eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
       eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
  printf("Dest MAC    : %02X:%02X:%02X:%02X:%02X:%02X\n",
       eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
       eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
  /* IP Address */
  if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
    
    /* Print IP Address */
    printf("Source IP   : %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("Dest   IP   : %s\n", inet_ntoa(ip->iph_destip));
     
    /* Print Protocol */
    char *pt_protocol;
    switch(ip->iph_protocol){
        case 1: pt_protocol="ICMP"; break;
        case 2: pt_protocol="IGMP"; break;
        case 6: pt_protocol="TCP"; break;
        case 17:pt_protocol="UDP"; break;
        case 41:pt_protocol="IPv6"; break;
    }
    printf("IP Protocol : %s\n",pt_protocol);
    
    /* Port */
    if (ip->iph_protocol == IPPROTO_TCP) {
      struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) +  ip->iph_ihl * 4); 
      
      /* Print Port*/
      printf("Source Port : %d\n", ntohs(tcp->tcph_srcport));
      printf("Dest Port   : %d\n", ntohs(tcp->tcph_destport));
    }
   
    /* Print DATA[~DATA_LEN] */ 
    printf("Data        : ");
    for (int i = 0; i < DATA_LEN; i++) {
        printf("%02X ", ip->data[i]);
    }
    printf("\n===============================================================================\n");
  
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle); 
  return 0;
}


