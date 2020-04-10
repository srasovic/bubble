

/*
 *  $Id: fuzz.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  fuzz_ipv4.h - Network fuzzing library header file for IPv4 protocol
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */



struct ip_header {
    u_int8_t version;
    u_int8_t len;
    u_int8_t tos;
    u_int16_t id;
    u_int8_t flags;
    u_int16_t offset;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t checksum;
    u_int32_t source;
    u_int32_t destination;
};



void fuzz_ipv4(u_char *pkt_ptr);

void build_ipv4_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet);
