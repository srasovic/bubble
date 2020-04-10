

/*
 *  $Id: fuzz.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  socket_ops.h - Network fuzzing library header file for socket operations
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */


struct packet_tuple {

    int sockfd;
    u_int32_t tcp_seq;
    u_int32_t tcp_ack;
    u_int32_t src_ip;
    u_int32_t dst_ip;
    u_int16_t tcp_sp;
    u_int16_t tcp_dp;
    u_int16_t ip_id;
    u_int8_t src_mac[ETH_ADDR_LEN];
    u_int8_t dst_mac[ETH_ADDR_LEN];
    struct sockaddr_in serveraddr;
    struct sockaddr_in myaddr;
    bool mac_set;

};


struct packet_tuple* establish_tcp_sess_row(libnet_t *libt, struct packet_tuple *packet_tuple, struct tuple *tuple);

void close_tcp_sess_row(libnet_t *libt, struct packet_tuple *packet_tuple, struct tuple *tuple);

u_int16_t compute_tcp_checksum(u_char *packet, int len, struct tuple *tuple);

void establish_tcp_session(struct tuple *tuple, struct packet_tuple *packet_tuple);

void close_tcp_session(int sockfd);

void db_l3_src_packet_mangle(u_char *packet, struct packet_tuple *packet_tuple);

void db_l3_dst_packet_mangle(u_char *packet, struct packet_tuple *packet_tuple);

void db_l4_packet_mangle(u_char *packet, struct packet_tuple *packet_tuple, int len, struct tuple *tuple);

void get_udp_socket(u_char *source, u_char *destination, struct packet_tuple *packet_tuple);

