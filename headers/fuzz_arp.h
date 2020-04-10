

/*
 *  $Id: fuzz.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  fuzz_arp.h - Network fuzzing library header file for ARP protocol
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */




struct arp_header {
    u_int16_t hw_type;
    u_int16_t protocol;
    u_int8_t hw_size;
    u_int8_t p_size;
    u_int16_t opcode;
    char smac[6];
    u_int32_t sip;
    char tmac[6];
    u_int32_t tip;
};

bool mac_set;

void fuzz_arp(u_char *pkt_ptr);

void fuzz_arp_multid(u_char *pkt_ptr);

void rand_mac_gen(u_char *rand_str, size_t length);

void build_arp_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet);

void parse_arp_pack(u_char *pkt_ptr, struct arp_header *arph);
