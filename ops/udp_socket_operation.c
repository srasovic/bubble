
/*
 ##############################################################################
 Revision #      1.0
 Name:               :  tcp_socket_operation.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  TCP socket ops routines for fuzzing over protocol data.
 ##############################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/socket_ops.h"


void get_udp_socket(u_char *source, u_char *destination, struct packet_tuple *packet_tuple) {

    int sockfd;
    struct sockaddr_in servaddr, myaddr;
    int sa_len = sizeof(myaddr);
    int ret;
    int broadcastEnable=1;

    char str[INET_ADDRSTRLEN];

    bzero(&servaddr, sizeof(servaddr));
    bzero(&myaddr, sizeof(myaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(packet_tuple->tcp_dp);

    if (packet_tuple->tcp_sp)
        myaddr.sin_port = htons(packet_tuple->tcp_sp);
    myaddr.sin_family = AF_INET;

    inet_pton(AF_INET, destination, &servaddr.sin_addr);
    inet_pton(AF_INET, source, &myaddr.sin_addr);


    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    ret=setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
    if (ret == -1) {
        fprintf(stderr, "Unable to set SO_BROADCAST option on socket. Exiting.\n");
        exit(-1);
    }

    ret=setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &broadcastEnable, sizeof(broadcastEnable));
    if (ret == -1) {
        fprintf(stderr, "Unable to set SO_REUSEADDR option on socket. Exiting.\n");
        exit(-1);
    }


    ret = bind(sockfd, (const struct sockaddr *)&myaddr, sa_len);
    if (ret == -1) {
        fprintf(stderr, "Unable to bind a socket. Exiting.\n");
        exit(-1);
    }

    packet_tuple->sockfd = sockfd;
    packet_tuple->serveraddr = servaddr;
    packet_tuple->myaddr = myaddr;


    if (packet_tuple->tcp_sp == 0) {

        if (getsockname(packet_tuple->sockfd,(struct sockaddr *)&myaddr,(socklen_t *)&sa_len) == 0) {
            packet_tuple->tcp_sp = ntohs(myaddr.sin_port);
            packet_tuple->src_ip = ntohl(myaddr.sin_addr.s_addr);
            inet_ntop(AF_INET, &myaddr.sin_addr, str, INET_ADDRSTRLEN);

        }
        else {
            fprintf(stderr, "Unable to determine source port for the socket.\n");
            exit(-1);
        }
    }

    else {

        if (getsockname(packet_tuple->sockfd,(struct sockaddr *)&myaddr,(socklen_t *)&sa_len) == 0) {
            packet_tuple->src_ip = ntohl(myaddr.sin_addr.s_addr);
            inet_ntop(AF_INET, &myaddr.sin_addr, str, INET_ADDRSTRLEN);

        }
        else {
            fprintf(stderr, "Unable to determine source port for the socket.\n");
            exit(-1);
        }

    }


}
