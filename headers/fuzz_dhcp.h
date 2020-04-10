

/*
 *  $Id: fuzz.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  fuzz_dhcp.h - Network fuzzing library header file for DHCP protocol
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */


#define DHCP_SPORT    67
#define DHCP_CPORT    68
#define DHCP_CLIENT   1
#define DHCP_SERVER   2

#define DHCP_MAX_OPT    255

#define DHCPDISCOVER			1
#define DHCPOFFER				2
#define DHCPREQUEST				3
#define DHCPDECLINE				4
#define DHCPACK					5
#define DHCPNAK					6
#define DHCPRELEASE				7
#define DHCPINFORM				8
#define DHCPFORCERENEW			9
#define DHCPLEASEQUERY			10
#define DHCPLEASEUNASSIGNED		11
#define DHCPLEASEUNKNOWN		12
#define DHCPLEASEACTIVE			13
#define DHCPBULKLEASEQUERY		14
#define DHCPLEASEQUERYDONE		15
#define DHCPACTIVELEASEQUERY	16
#define DHCPLEASEQUERYSTATUS	17
#define DHCPTLS					18

#define MAX_TYPES               18

u_int32_t dhcp_sim_mode;

/*

#define DHCP_MSG_TYPE       53
#define DHCP_CID            61
#define DHCP_RIP            50
#define DHCP_PARAM_RLIST    55
#define DHCP_END            255
#define DHCP_SUB_MASK       1
#define DHCP_RENEWAL_TIME   58
#define DHCP_REBIND_TIME    59
#define DHCP_LEASE_TIME     51
#define DHCP_SID            54

 */


struct client_packs {

    u_char discovery_packet[REG_PACK_SIZE];
    u_char request_packet[REG_PACK_SIZE];
    u_char inform_packet[REG_PACK_SIZE];
    u_char release_packet[REG_PACK_SIZE];
    u_char decline_packet[REG_PACK_SIZE];
    u_char query_packet[REG_PACK_SIZE];
};

struct server_packs {

    u_char offer_packet[REG_PACK_SIZE];
    u_char ack_packet[REG_PACK_SIZE];
    u_char nak_packet[REG_PACK_SIZE];

};


struct dhcpv4_header {

    u_int8_t op;
    u_int8_t htype;
    u_int8_t hlen;
    u_int8_t hops;
    u_int32_t xid;
    u_int16_t secs;
    u_int16_t flags;
    u_int32_t ciaddr;
    u_int32_t yiaddr;
    u_int32_t siaddr;
    u_int32_t giaddr;
    u_char chaddr[16];
    u_char sname[64];
    u_char file[128];
    u_int32_t cookie;

};


enum client_msg_types {
    discover=1, request, decline, release, inform, query
};

enum server_msg_types {
    offer, ack, nak
};


void build_dummy_client_packs(struct dhcpv4_header *dheader, struct client_packs *cpacks);

void build_dummy_server_packs(struct dhcpv4_header *dheader, struct server_packs *spacks);

void build_dhcpv4_session(struct tuple * tuple);

int gen_pack_matrix(int pack_matrix[]);


void fuzz_dhcpv4_pack(int type, u_char *packet, int *plen);




