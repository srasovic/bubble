

/*
 *  $Id: fuzz.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  fuzz_ipv6.h - Network fuzzing library header file for IPv6 protocol
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */




struct ipv6_header {
    u_int32_t version_class;
    u_int16_t len;
    u_int8_t next;
    u_int8_t hop;
    unsigned char source[16];
    unsigned char destination[16];
};


void fuzz_ipv6(u_char *pkt_ptr);

void build_ipv6_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet);
