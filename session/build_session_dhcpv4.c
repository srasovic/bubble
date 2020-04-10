
/*
 ##########################################################################################
 Revision #      1.0
 Name:               :  build_session_dhcpv4.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Packet builder routines for session fuzzing over DHCPv4 protocol data.
 ##########################################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_dhcp.h"
#include "../headers/instrumentation.h"
#include "../headers/database.h"
#include "../headers/socket_ops.h"


#define UDP_PROTO   17
#define TCP_PROTO   6
#define IP_PROTO   4

#define TTL 64
#define MACLEN  6
#define IP4LEN  4

u_char protocol[64];
struct libnet_ether_addr *my_mac;

static u_int32_t xid;
int nlen, hlen, rlen, dlen, ilen, rllen, qlen;
int mlen;
int tries = 1;


struct dhcpv4_header *dheader;
struct client_packs *cpacks;
struct client_packs *cppacks;
struct server_packs *spacks;

static struct packet_tuple *packet_tuple;


void build_dhcpv4_session(struct tuple * tuple) {


    u_char *init_packet = calloc(1, MAX_PACK_SIZE);
    u_char *pass_packet = calloc(1, MAX_PACK_SIZE);

    spacks = calloc(1, sizeof(struct server_packs));
    cpacks = calloc(1, sizeof (struct client_packs));
    cppacks = calloc(1, sizeof (struct client_packs));
    dheader = calloc(1, sizeof(struct dhcpv4_header));

    pcap_t *pc;
    struct pcap_pkthdr *pkt;
    char perr[256];
    struct bpf_program filter;
    bpf_u_int32 maskp=0;

    u_int8_t *pkt_ptr = NULL;
    u_int32_t packet_size;
    int servlen, n, i, ping_result, num_packs;
    int count = 1;

    int pack_matrix[MAX_TYPES];
    memset(pack_matrix, '\0', MAX_TYPES);

    char filter_exp[150];
    u_char *tport = "udp port ";
    u_char *filter_ext = " && src host ";
    u_char port[5];

    u_char xids[4];

    memset(filter_exp, '\0', 150);

    u_char broadcast_str[INET_ADDRSTRLEN];
    memset(broadcast_str, '\0', INET_ADDRSTRLEN);
    u_char search_str[INET_ADDRSTRLEN];
    memset(search_str, '\0', INET_ADDRSTRLEN);

    u_char caddress[IP4LEN];
    u_char saddress[IP4LEN];
    memset(caddress, '\0', IP4LEN);
    memset(saddress, '\0', IP4LEN);

    strncpy(search_str, tuple->destination, strlen(tuple->destination));

    char dot[2] = ".";
    char *token;
    char *allnet = "255";
    int toklen;


    token = strtok(search_str, dot);
    toklen = strlen(token);
    for (i=1;i<3;i++) {
        token = strtok(NULL, dot);
        toklen++;
        toklen = toklen+strlen(token);
    }
    toklen++;

    strncpy(broadcast_str, tuple->destination, toklen);
    strncat(broadcast_str, allnet, 3);


    libnet_t *libt = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];

    libt = libnet_init(LIBNET_LINK_ADV, tuple->intf, errbuf);

    my_mac = libnet_get_hwaddr (libt);

    libnet_destroy(libt);

    if (dhcp_sim_mode == DHCP_CLIENT) {
        xid = rand();
        build_dummy_client_packs(dheader, cpacks);
    }
    else
        build_dummy_server_packs(dheader, spacks);



    packet_tuple = calloc(1, sizeof(struct packet_tuple));
    packet_tuple->tcp_dp = DHCP_SPORT;
    packet_tuple->tcp_sp = DHCP_CPORT;


    get_udp_socket("0.0.0.0", broadcast_str, packet_tuple);

    servlen = sizeof(struct sockaddr_in);

    sprintf(port, "%d", packet_tuple->tcp_sp);
    strncat(filter_exp, tport, strlen(tport));
    strncat(filter_exp, port, strlen(port));
    strncat(filter_exp, filter_ext, strlen(filter_ext));
    strncat(filter_exp, tuple->destination, strlen(tuple->destination));

    pc = pcap_open_live(tuple->intf, 1520, 1, 1000, perr);

    int f = pcap_compile(pc, &filter, filter_exp, 1, maskp);
    if (f<0) {
        fprintf(stderr, "Filter compilation failed. Exiting.\n");
        exit(-1);
    }

    int s = pcap_setfilter(pc, &filter);
    if (s<0) {
        fprintf(stderr, "Filter failed. Exiting.\n");
        exit(-1);
    }



    memcpy(cppacks, cpacks, sizeof (struct client_packs));


    while (1) {

        memcpy(cpacks, cppacks, sizeof (struct client_packs));

        rand_str_gen(xids, 4);

        memcpy(&cpacks->discovery_packet[4], xids, 4);
        memcpy(&cpacks->request_packet[4], xids, 4);
        memcpy(&cpacks->decline_packet[4], xids, 4);
        memcpy(&cpacks->inform_packet[4], xids, 4);
        memcpy(&cpacks->release_packet[4], xids, 4);
        memcpy(&cpacks->query_packet[4], xids, 4);

        do {
            tries++;
            if (n = sendto(packet_tuple->sockfd, cpacks->discovery_packet, hlen, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen) == -1) {
                fprintf(stderr, "Error writing packet.\n");
                close(packet_tuple->sockfd);
                exit(-1);

            }

            else {
                pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);
                packet_size = pkt->len;
                ping_result = ping_to_uut(tuple->destination);
            }

            if (tries > 3) {
                fprintf(stderr, "Server not responding\n");
                exit(-1);
            }
        }
        while (!pkt->len);

        tries = 1;

        memcpy(&(cpacks->request_packet[nlen+14]), &pkt_ptr[L2HDR_LEN+16], IP4LEN);
        memcpy(&(cpacks->request_packet[nlen+20]), &pkt_ptr[L2HDR_LEN+12], IP4LEN);

        memcpy(caddress, &pkt_ptr[L2HDR_LEN+16], IP4LEN);
        memcpy(saddress, &pkt_ptr[L2HDR_LEN+12], IP4LEN);


        num_packs = gen_pack_matrix(pack_matrix);


        fprintf(stderr, "\nSending test batch #%d with %d packets in a sequence:\n", count, num_packs);

        for (i=0;i<num_packs; i++) {

            switch (pack_matrix[i]) {

                case discover:
                    mlen = hlen;
                    fuzz_dhcpv4_pack(discover, cpacks->discovery_packet, &mlen);
                    fprintf(stderr, "\tDHCPDISCOVER - %d bytes.\n", mlen);
                    if (n = sendto(packet_tuple->sockfd, cpacks->discovery_packet, mlen, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen) == -1) {
                        fprintf(stderr, "Error writing DHCPDISCOVER packet.\n");
                        close(packet_tuple->sockfd);
                        exit(-1);
                    }

                    else {
                        pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);
                        packet_size = pkt->len;

                        memcpy(&(cpacks->request_packet[nlen+14]), &pkt_ptr[L2HDR_LEN+16], IP4LEN);
                        memcpy(&(cpacks->request_packet[nlen+20]), &pkt_ptr[L2HDR_LEN+12], IP4LEN);

                        memcpy(caddress, &pkt_ptr[L2HDR_LEN+16], IP4LEN);
                        memcpy(saddress, &pkt_ptr[L2HDR_LEN+12], IP4LEN);

                        ping_result = ping_to_uut(tuple->destination);
                    }
                    break;

                case request:
                    mlen = rlen;
                    fuzz_dhcpv4_pack(request, cpacks->request_packet, &mlen);
                    fprintf(stderr, "\tDHCPREQUEST - %d bytes.\n", mlen);
                    if (n = sendto(packet_tuple->sockfd, cpacks->request_packet, mlen, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen) == -1) {
                        fprintf(stderr, "Error writing DHCPREQUEST packet.\n");
                        close(packet_tuple->sockfd);
                        exit(-1);
                    }

                    else {
                        pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);
                        packet_size = pkt->len;
                        ping_result = ping_to_uut(tuple->destination);
                    }
                    break;

                case decline:
                    mlen = dlen;
                    fuzz_dhcpv4_pack(decline, cpacks->decline_packet, &mlen);
                    fprintf(stderr, "\tDHCPDECLINE - %d bytes.\n", mlen);
                    if (n = sendto(packet_tuple->sockfd, cpacks->decline_packet, mlen, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen) == -1) {
                        fprintf(stderr, "Error writing DHCPDECLINE packet.\n");
                        close(packet_tuple->sockfd);
                        exit(-1);
                    }

                    else {
                        pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);
                        packet_size = pkt->len;
                        ping_result = ping_to_uut(tuple->destination);
                    }
                  break;


                case inform:
                    mlen = ilen;
                    fuzz_dhcpv4_pack(inform, cpacks->inform_packet, &mlen);
                    memcpy(&(cpacks->inform_packet[12]), caddress, IP4LEN);
                    fprintf(stderr, "\tDHCPINFORM - %d bytes.\n", mlen);
                    if (n = sendto(packet_tuple->sockfd, cpacks->inform_packet, mlen, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen) == -1) {
                        fprintf(stderr, "Error writing DHCPINFORM packet.\n");
                        close(packet_tuple->sockfd);
                        exit(-1);
                    }

                    else {
                        pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);
                        packet_size = pkt->len;
                        ping_result = ping_to_uut(tuple->destination);
                    }
                    break;

                case release:
                    mlen = rllen;
                    fuzz_dhcpv4_pack(release, cpacks->release_packet, &mlen);
                    memcpy(&(cpacks->release_packet[12]), caddress, IP4LEN);
                    fprintf(stderr, "\tDHCPRELEASE - %d bytes.\n", mlen);
                    if (n = sendto(packet_tuple->sockfd, cpacks->release_packet, mlen, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen) == -1) {
                        fprintf(stderr, "Error writing DHCPRELEASE packet.\n");
                        close(packet_tuple->sockfd);
                        exit(-1);
                    }

                    else {
                        pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);
                        packet_size = pkt->len;
                        ping_result = ping_to_uut(tuple->destination);
                    }
                    break;

                case query:
                    mlen = qlen;
                    fuzz_dhcpv4_pack(query, cpacks->query_packet, &mlen);
                    memcpy(&(cpacks->query_packet[12]), caddress, IP4LEN);
                    fprintf(stderr, "\tDHCPQUERY - %d bytes.\n", mlen);
                    if (n = sendto(packet_tuple->sockfd, cpacks->query_packet, mlen, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen) == -1) {
                        fprintf(stderr, "Error writing DHCPRELEASE packet.\n");
                        close(packet_tuple->sockfd);
                        exit(-1);
                    }

                    else {
                        pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);
                        packet_size = pkt->len;
                        ping_result = ping_to_uut(tuple->destination);
                    }
                    break;

                default:
                    fprintf(stderr, "Shouldn't be here.\n");
                    exit(-1);
            }
        }

        count++;
        usleep(tuple->timer);

    }



   // close(packet_tuple->sockfd);



}



void build_dummy_client_packs(struct dhcpv4_header *dheader, struct client_packs *cpacks) {

    u_char *dptr = (u_char *)dheader;

    dheader->op = 0x01;
    dheader->htype = 0x01;
    dheader->hlen = 0x06;
    dheader->hops = 0;
    dheader->xid =  xid;
    dheader->secs = 0;
    dheader->flags = 0x0000;
    dheader->ciaddr = 0x00000000;
    dheader->yiaddr = 0x00000000;
    dheader->siaddr = 0x00000000;
    dheader->giaddr = 0x00000000;
    dheader->cookie = htonl(0x63825363);

    memcpy(dheader->chaddr, my_mac->ether_addr_octet, MACLEN);
    memset(dheader->sname, '\0', sizeof(dheader->sname));
    memset(dheader->file, '\0', sizeof(dheader->file));

    nlen = sizeof(struct dhcpv4_header);
    memcpy(cpacks->discovery_packet, dptr, nlen);

    cpacks->discovery_packet[nlen] = 0x35;
    cpacks->discovery_packet[nlen+1] = 0x01;
    cpacks->discovery_packet[nlen+2] = 0x01;

    cpacks->discovery_packet[nlen+3] = 0x39;
    cpacks->discovery_packet[nlen+4] = 0x02;
    cpacks->discovery_packet[nlen+5] = 0x02;
    cpacks->discovery_packet[nlen+6] = 0x4e;

    cpacks->discovery_packet[nlen+7] = 0x37;
    cpacks->discovery_packet[nlen+8] = 0x06;
    cpacks->discovery_packet[nlen+9] = 0x01;
    cpacks->discovery_packet[nlen+10] = 0x1c;
    cpacks->discovery_packet[nlen+11] = 0x03;
    cpacks->discovery_packet[nlen+12] = 0x06;
    cpacks->discovery_packet[nlen+13] = 0x2a;
    cpacks->discovery_packet[nlen+14] = 0x2b;

    cpacks->discovery_packet[nlen+15] = 0x33;
    cpacks->discovery_packet[nlen+16] = 0x04;
    cpacks->discovery_packet[nlen+17] = 0x00;
    cpacks->discovery_packet[nlen+18] = 0x00;
    cpacks->discovery_packet[nlen+19] = 0x0e;
    cpacks->discovery_packet[nlen+20] = 0x10;

    cpacks->discovery_packet[nlen+21] = 0x34;
    cpacks->discovery_packet[nlen+22] = 0x01;
    cpacks->discovery_packet[nlen+23] = 0x03;

    cpacks->discovery_packet[nlen+24] = 0x38;
    cpacks->discovery_packet[nlen+25] = 0x07;
    cpacks->discovery_packet[nlen+26] = 0x50;
    cpacks->discovery_packet[nlen+27] = 0x61;
    cpacks->discovery_packet[nlen+28] = 0x64;
    cpacks->discovery_packet[nlen+29] = 0x64;
    cpacks->discovery_packet[nlen+30] = 0x69;
    cpacks->discovery_packet[nlen+31] = 0x6e;
    cpacks->discovery_packet[nlen+32] = 0x67;
    cpacks->discovery_packet[nlen+33] = 0x00;
    cpacks->discovery_packet[nlen+34] = 0x3d;
    cpacks->discovery_packet[nlen+35] = 0x07;
    cpacks->discovery_packet[nlen+36] = 0x01;
    memcpy(&(cpacks->discovery_packet[nlen+37]), my_mac->ether_addr_octet, MACLEN);
    cpacks->discovery_packet[nlen+43] = 0xff;

    hlen = nlen+44;


    memcpy(cpacks->request_packet, dptr, nlen);

    cpacks->request_packet[nlen] = 0x35;
    cpacks->request_packet[nlen+1] = 0x01;
    cpacks->request_packet[nlen+2] = 0x03;

    cpacks->request_packet[nlen+3] = 0x3d;
    cpacks->request_packet[nlen+4] = 0x07;
    cpacks->request_packet[nlen+5] = 0x01;
    memcpy(&(cpacks->request_packet[nlen+6]), my_mac->ether_addr_octet, MACLEN);

    cpacks->request_packet[nlen+12] = 0x32;
    cpacks->request_packet[nlen+13] = 0x04;
    memset(&(cpacks->request_packet[nlen+14]), '\0', IP4LEN);

    cpacks->request_packet[nlen+18] = 0x36;
    cpacks->request_packet[nlen+19] = 0x04;
    memset(&(cpacks->request_packet[nlen+20]), '\0', IP4LEN);

    cpacks->request_packet[nlen+24] = 0x37;
    cpacks->request_packet[nlen+25] = 0x06;
    cpacks->request_packet[nlen+26] = 0x01;
    cpacks->request_packet[nlen+27] = 0x1c;
    cpacks->request_packet[nlen+28] = 0x03;
    cpacks->request_packet[nlen+29] = 0x06;
    cpacks->request_packet[nlen+30] = 0x2a;
    cpacks->request_packet[nlen+31] = 0x2b;

    cpacks->request_packet[nlen+32] = 0xff;

    rlen = nlen+33;


    memcpy(cpacks->decline_packet, dptr, nlen);

    cpacks->decline_packet[nlen] = 0x35;
    cpacks->decline_packet[nlen+1] = 0x01;
    cpacks->decline_packet[nlen+2] = 0x04;

    cpacks->decline_packet[nlen+3] = 0x39;
    cpacks->decline_packet[nlen+4] = 0x02;
    cpacks->decline_packet[nlen+5] = 0x02;
    cpacks->decline_packet[nlen+6] = 0x4e;

    cpacks->decline_packet[nlen+7] = 0x37;
    cpacks->decline_packet[nlen+8] = 0x06;
    cpacks->decline_packet[nlen+9] = 0x01;
    cpacks->decline_packet[nlen+10] = 0x1c;
    cpacks->decline_packet[nlen+11] = 0x03;
    cpacks->decline_packet[nlen+12] = 0x06;
    cpacks->decline_packet[nlen+13] = 0x2a;
    cpacks->decline_packet[nlen+14] = 0x2b;

    cpacks->decline_packet[nlen+15] = 0x33;
    cpacks->decline_packet[nlen+16] = 0x04;
    cpacks->decline_packet[nlen+17] = 0x00;
    cpacks->decline_packet[nlen+18] = 0x00;
    cpacks->decline_packet[nlen+19] = 0x0e;
    cpacks->decline_packet[nlen+20] = 0x10;

    cpacks->decline_packet[nlen+21] = 0x34;
    cpacks->decline_packet[nlen+22] = 0x01;
    cpacks->decline_packet[nlen+23] = 0x03;

    cpacks->decline_packet[nlen+24] = 0x38;
    cpacks->decline_packet[nlen+25] = 0x07;
    cpacks->decline_packet[nlen+26] = 0x50;
    cpacks->decline_packet[nlen+27] = 0x61;
    cpacks->decline_packet[nlen+28] = 0x64;
    cpacks->decline_packet[nlen+29] = 0x64;
    cpacks->decline_packet[nlen+30] = 0x69;
    cpacks->decline_packet[nlen+31] = 0x6e;
    cpacks->decline_packet[nlen+32] = 0x67;
    cpacks->decline_packet[nlen+33] = 0x00;
    cpacks->decline_packet[nlen+34] = 0x3d;
    cpacks->decline_packet[nlen+35] = 0x07;
    cpacks->decline_packet[nlen+36] = 0x01;
    memcpy(&(cpacks->decline_packet[nlen+37]), my_mac->ether_addr_octet, MACLEN);
    cpacks->decline_packet[nlen+43] = 0xff;

    dlen = nlen+44;


    memcpy(cpacks->inform_packet, dptr, nlen);

    cpacks->inform_packet[nlen] = 0x35;
    cpacks->inform_packet[nlen+1] = 0x01;
    cpacks->inform_packet[nlen+2] = 0x08;

    cpacks->inform_packet[nlen+3] = 0x39;
    cpacks->inform_packet[nlen+4] = 0x02;
    cpacks->inform_packet[nlen+5] = 0x02;
    cpacks->inform_packet[nlen+6] = 0x4e;

    cpacks->inform_packet[nlen+7] = 0x37;
    cpacks->inform_packet[nlen+8] = 0x06;
    cpacks->inform_packet[nlen+9] = 0x01;
    cpacks->inform_packet[nlen+10] = 0x1c;
    cpacks->inform_packet[nlen+11] = 0x03;
    cpacks->inform_packet[nlen+12] = 0x06;
    cpacks->inform_packet[nlen+13] = 0x2a;
    cpacks->inform_packet[nlen+14] = 0x2b;

    cpacks->inform_packet[nlen+15] = 0x34;
    cpacks->inform_packet[nlen+16] = 0x01;
    cpacks->inform_packet[nlen+17] = 0x03;

    cpacks->inform_packet[nlen+18] = 0x38;
    cpacks->inform_packet[nlen+19] = 0x07;
    cpacks->inform_packet[nlen+19] = 0x50;
    cpacks->inform_packet[nlen+20] = 0x61;
    cpacks->inform_packet[nlen+21] = 0x64;
    cpacks->inform_packet[nlen+22] = 0x64;
    cpacks->inform_packet[nlen+23] = 0x69;
    cpacks->inform_packet[nlen+24] = 0x6e;
    cpacks->inform_packet[nlen+25] = 0x67;
    cpacks->inform_packet[nlen+26] = 0x00;
    cpacks->inform_packet[nlen+27] = 0x3d;
    cpacks->inform_packet[nlen+28] = 0x07;
    cpacks->inform_packet[nlen+29] = 0x01;
    memcpy(&(cpacks->inform_packet[nlen+30]), my_mac->ether_addr_octet, MACLEN);
    cpacks->inform_packet[nlen+36] = 0xff;

    ilen = nlen+37;


    memcpy(cpacks->release_packet, dptr, nlen);

    cpacks->release_packet[nlen] = 0x35;
    cpacks->release_packet[nlen+1] = 0x01;
    cpacks->release_packet[nlen+2] = 0x07;

    cpacks->release_packet[nlen+3] = 0x39;
    cpacks->release_packet[nlen+4] = 0x02;
    cpacks->release_packet[nlen+5] = 0x02;
    cpacks->release_packet[nlen+6] = 0x4e;

    cpacks->release_packet[nlen+7] = 0x37;
    cpacks->release_packet[nlen+8] = 0x06;
    cpacks->release_packet[nlen+9] = 0x01;
    cpacks->release_packet[nlen+10] = 0x1c;
    cpacks->release_packet[nlen+11] = 0x03;
    cpacks->release_packet[nlen+12] = 0x06;
    cpacks->release_packet[nlen+13] = 0x2a;
    cpacks->release_packet[nlen+14] = 0x2b;

    cpacks->release_packet[nlen+15] = 0x34;
    cpacks->release_packet[nlen+16] = 0x01;
    cpacks->release_packet[nlen+17] = 0x03;

    cpacks->release_packet[nlen+18] = 0x38;
    cpacks->release_packet[nlen+19] = 0x07;
    cpacks->release_packet[nlen+19] = 0x50;
    cpacks->release_packet[nlen+20] = 0x61;
    cpacks->release_packet[nlen+21] = 0x64;
    cpacks->release_packet[nlen+22] = 0x64;
    cpacks->release_packet[nlen+23] = 0x69;
    cpacks->release_packet[nlen+24] = 0x6e;
    cpacks->release_packet[nlen+25] = 0x67;
    cpacks->release_packet[nlen+26] = 0x00;
    cpacks->release_packet[nlen+27] = 0x3d;
    cpacks->release_packet[nlen+28] = 0x07;
    cpacks->release_packet[nlen+29] = 0x01;
    memcpy(&(cpacks->release_packet[nlen+30]), my_mac->ether_addr_octet, MACLEN);
    cpacks->release_packet[nlen+36] = 0xff;

    rllen = nlen+37;


    memcpy(cpacks->query_packet, dptr, nlen);

    cpacks->query_packet[nlen] = 0x37;
    cpacks->query_packet[nlen+1] = 0x04;
    cpacks->query_packet[nlen+2] = 0x33;
    cpacks->query_packet[nlen+3] = 0x36;
    cpacks->query_packet[nlen+4] = 0x3d;
    cpacks->query_packet[nlen+5] = 0x52;

    cpacks->query_packet[nlen+6] = 0x35;
    cpacks->query_packet[nlen+7] = 0x01;
    cpacks->query_packet[nlen+8] = 0x0a;

    cpacks->query_packet[nlen+9] = 0xff;

    qlen = nlen + 10;


}




void build_dummy_server_packs(struct dhcpv4_header *dheader, struct server_packs *spacks) {
}


int gen_pack_matrix(int pack_matrix[]) {

    int a, b, c, i;

    if (dhcp_sim_mode == DHCP_CLIENT) {

        a = 1 + rand() / (RAND_MAX / (6 - 1 + 1) + 1);

        for (i =0; i<a; i++) {

            b = 1 + rand() / (RAND_MAX / (6 - 1 + 1) + 1);
            pack_matrix[i] = b;
        }
    }

    else {

        a = 1 + rand() / (RAND_MAX / (3 - 1 + 1) + 1);

        for (i =0; i<a; i++) {

            b = 1 + rand() / (RAND_MAX / (3 - 1 + 1) + 1);
            pack_matrix[i] = b;
        }

    }

    return a;



}




