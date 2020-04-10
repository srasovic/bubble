
/*
 ##########################################################################################
 Revision #      1.0
 Name:               :  build_session.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Session builder routines for non-session fuzzing.
 ##########################################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_bgp.h"
#include "../headers/fuzz_dhcp.h"
#include "../headers/fuzz_dns.h"
#include "../headers/fuzz_msdp.h"




void build_session(struct tuple * tuple) {

    type_of_packet = (struct type_of_packet *) calloc(1, sizeof(struct type_of_packet));

    char protocol;

    u_int32_t src_ip;
    libnet_t *libt = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];

    libt = libnet_init(LIBNET_LINK_ADV, tuple->intf, errbuf);

    if (tuple->source)
        src_ip = libnet_name2addr4(libt, tuple->source, LIBNET_DONT_RESOLVE);
    else
        src_ip = libnet_get_ipaddr4(libt);

    if (libnet_get_ipaddr4(libt) != src_ip) {
        fprintf(stderr, "Spoofing isn't supported for sessions in non-proxy mode.\n");
        exit(-1);
    }

    libnet_destroy(libt);

    // Except for IKEv2, which is a temporary hack, all 'session-mode' protocols need to be called from build_session().

    if (strncmp(tuple->protocol, "ike", 3)==0)
        protocol = 'i';
    else if (strncmp(tuple->protocol, "bgp", 3)==0)
        protocol = 'b';
    else if (strncmp(tuple->protocol, "dhcpv4", 6)==0)
        protocol = 'd';
    else if (strncmp(tuple->protocol, "dns", 3)==0)
        protocol = 'n';
    else if (strncmp(tuple->protocol, "msdp", 4)==0)
        protocol = 'm';


    switch (protocol) {
         case 'i':
            build_pack(tuple);
            break;
        case 'b':
            strncpy(type_of_packet->l3_type, "ipv4", 4);
            strncpy(type_of_packet->l4_type, "tcp", 3);
            build_bgp_session(tuple);
            break;
        case 'd':
            strncpy(type_of_packet->l3_type, "ipv4", 4);
            strncpy(type_of_packet->l4_type, "udp", 3);
            build_dhcpv4_session(tuple);
            break;
        case 'n':
            strncpy(type_of_packet->l3_type, "ipv4", 4);
            strncpy(type_of_packet->l4_type, "udp", 3);
            build_dns_session(tuple);
            break;
        case 'm':
            strncpy(type_of_packet->l3_type, "ipv4", 4);
            strncpy(type_of_packet->l4_type, "tcp", 3);
            build_msdp_session(tuple);
            break;
        default:
            break;
    }

}
