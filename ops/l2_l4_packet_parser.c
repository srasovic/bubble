

/*
 ##############################################################################
 Revision #      1.0
 Name:               :  l2_l4_packet_parser.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Packet parsing routines for fuzzing over protocol data.
 ##############################################################################
 */


#include "../headers/fuzz.h"



void parse_l3_info (const u_char *pkt_ptr) {

    const u_char *pkt = pkt_ptr;
    u_int16_t l3_prot;

    memcpy(&l3_prot, &pkt[L2HDR_LEN-2], sizeof(u_int16_t));

	if (ntohs(l3_prot) == 0x0806) {
        strncpy(type_of_packet->l3_type, "ipv4", 4);
    }

    else {
        fprintf(stderr, "Currently unsupported L3 type.\n");
        exit(-1);
    }


}

void parse_l3_l4_info(const u_char *pkt_ptr) {

	const u_char *pkt = pkt_ptr;
    u_int16_t l3_prot;
    u_int8_t l4_prot;

    bool is_valid_ipv4, is_valid_ipv6;

    memcpy(&l3_prot, &pkt[L2HDR_LEN-2], sizeof(u_int16_t));

	if (ntohs(l3_prot) == 0x86dd) {
        if (tuple.source) {
            if (!(is_valid_ipv6 = check_ipv6_addr(tuple.source))) {
                fprintf(stderr, "Unsupported IPv6 source address format!\n");
                exit(-1);
            }
        }
        if (!(is_valid_ipv6 = check_ipv6_addr(tuple.destination))) {
        	fprintf(stderr, "Unsupported IPv6 destination address format!\n");
        	exit(-1);
        }
		strncpy(type_of_packet->l3_type, "ipv6", 4);
        memcpy(&l4_prot, &pkt[20], sizeof(u_int8_t));
        strncpy(type_of_packet->l4_type, parse_ipv6_hdrs(l4_prot), 3);
	}

	else if (ntohs(l3_prot) == 0x0800) {

        if (tuple.source) {
            if (!(is_valid_ipv4 = check_ipv4_addr(tuple.source))) {
                fprintf(stderr, "Unsupported IPv4 source address format!\n");
                exit(-1);
            }
        }
        if (!(is_valid_ipv4 = check_ipv4_addr(tuple.destination))) {
        	fprintf(stderr, "Unsupported IPv4 destination address format!\n");
        	exit(-1);
        }
		strncpy(type_of_packet->l3_type, "ipv4", 4);
        memcpy(&l4_prot, &pkt[23], sizeof(u_int8_t));

        if (l4_prot == 0x06) {
            strncpy(type_of_packet->l4_type,"tcp", 3);
        }
        else if (l4_prot== 0x11) {
            strncpy(type_of_packet->l4_type,"udp", 3);
        }
        else if (l4_prot== 0x01) {
            strncpy(type_of_packet->l4_type,"icmp", 4);
        }
        else {
            fprintf(stderr, "Unsupported L4 protocol type: 0x%02x", l4_prot);
        }

	}

	else {
		printf("Unsupported L3 protocol type: 0x%04X\n\n", ntohs(l3_prot));
		exit(-1);
	}

}

u_char * parse_ipv6_hdrs(int8_t l4_prot) {

    if (l4_prot == 6)
        return "tcp";

    else if (l4_prot == 17)
        return "udp";

    else if (l4_prot == 58)
        return "icmpv6";

    else {
        fprintf(stderr, "Currently unsupported packet format.\n");
        exit(-1);
    }
}

/*
u_char * parse_ipv6_hdrs(u_char *pkt, u_int8_t l4_prot) {

    u_char *pkt_ptr = pkt;
    static int initial_pass = 1;

    if (l4_prot == 6)
        return "tcp";

    else if (l4_prot == 17)
        return "udp";

    else {
        while (l4_prot == 0) {
            if (initial_pass) {
                pkt_ptr = &pkt_ptr[18 + (8*(pkt_ptr[1]+1))];
                initial_pass =0;
                parse_ipv6_hdrs(pkt_ptr, l4_prot);
            }
            else {
                pkt_ptr = &pkt_ptr[(8*(pkt_ptr[1]+1))];
                parse_ipv6_hdrs(pkt_ptr, l4_prot);
            }
        }

    }
}
*/
