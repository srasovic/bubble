

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


struct packet_tuple* establish_tcp_sess_row(libnet_t *libt, struct packet_tuple *packet_tuple, struct tuple *tuple) {


    u_char *iptables_rst_drop = "sudo iptables -A OUTPUT -p tcp --dport 43440 --tcp-flags RST RST -j DROP > /dev/null 2>&1";

    libt = build_libnet_link_adv(tuple);
    libnet_seed_prand(libt);

    struct libnet_in6_addr ip6_dst_addr, ip6_src_addr, ip6_my_addr;
    libnet_ptag_t ip, ipv6, udp, tcp, tcp_opt, eth;
    ip = ipv6 = udp = tcp = eth = LIBNET_PTAG_INITIALIZER;
    struct libnet_ether_addr *my_mac;

    char errbuf[LIBNET_ERRBUF_SIZE];

    u_int32_t src_ip, dst_ip;
    u_int8_t dst_mac[ETH_ADDR_LEN];
    u_int8_t *mac_addr;
    u_char mac_addr_str[MAC_ADDR_STR_LEN];
    memset(mac_addr_str, '\0', MAC_ADDR_STR_LEN);

    u_int16_t tcp_sp = libnet_get_prand(LIBNET_PR16), tcp_dp = packet_tuple->tcp_dp;
    u_int32_t tcp_seq, tcp_ack = 0;
    tcp_seq = libnet_get_prand(LIBNET_PR32);
    u_int16_t tcp_win = 14600;
    u_int8_t tcp_flags = TH_SYN;

    u_int16_t ip_id = libnet_get_prand(LIBNET_PR16);

    pcap_t *pc;
    struct pcap_pkthdr *pkt;
    char perr[256];
    int res;
    struct bpf_program filter;
    bpf_u_int32 maskp=0;
    char filter_exp[150] = "tcp port ";
    u_char *filter_ext = " && dst host ";

    u_char port[5];
    u_int8_t flags;
    u_int32_t ack_num;
    int maclen = 0, i = 0, n = 0;

    u_char *rec_packet = NULL;

    get_mac_address(tuple->destination, mac_addr_str);
    mac_addr = libnet_hex_aton(mac_addr_str, &maclen);

    for (i=0; i < maclen; i++)
        dst_mac[i] = mac_addr[i];

    my_mac = libnet_get_hwaddr (libt);


    if (!tuple->source)
        src_ip = libnet_get_ipaddr4(libt);
    else
        src_ip = libnet_name2addr4(libt, tuple->source, LIBNET_DONT_RESOLVE);

    if (libnet_get_ipaddr4(libt) != src_ip) {
        fprintf(stderr, "Spoofing isn't supported for TCP sessions in non-proxy mode.\n");
        exit(-1);
    }

    dst_ip = libnet_name2addr4(libt, tuple->destination, LIBNET_DONT_RESOLVE);


    if (tcp_opt = libnet_build_tcp_options("\003\003\012\001\002\004\001\040\010\012\077\077\077\077\000\000\000\000\000\000", 20, libt, 0) == -1)
        fprintf(stderr, "Error building TCP options header: %s\n", libnet_geterror(libt));

    if (tcp = libnet_build_tcp(tcp_sp, tcp_dp, tcp_seq, tcp_ack, tcp_flags, tcp_win, 0, 0, TCPSYNHDR_SIZE, NULL, 0, libt, 0) == -1)
        fprintf(stderr, "Error building TCP header: %s\n", libnet_geterror(libt));

    if ((ip = libnet_build_ipv4((IPHDR_SIZE+TCPSYNHDR_SIZE), 0, ip_id, 0, 64, IPPROTO_TCP, 0, src_ip, dst_ip, 0, 0, libt, 0))==-1)
        fprintf(stderr, "Error building IP header: %s\n", libnet_geterror(libt));
    if ((eth =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_IP, NULL, 0, libt, 0))==-1)
        fprintf(stderr, "Error building ETHERNET header: %s\n", libnet_geterror(libt));


    sprintf(port, "%d", tcp_sp);

    strncat(filter_exp, port, strlen(port));
    strncat(filter_exp, filter_ext, strlen(filter_ext));
    strncat(filter_exp, tuple->source, strlen(tuple->source));

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

    system(iptables_rst_drop);

    // send SYN packet:

    if ((n =libnet_write(libt))==-1) {
        fprintf(stderr, "Error writing packet: %s\n",libnet_geterror(libt));
        exit(-1);
    }


    int getout = 0, j;
    static int sendagain = 1;

    u_int16_t tt = 0;

    while (1) {

        j = 1;

        if (getout ==1)
            break;

        while (1) {

            if (sendagain >= 3) {
                fprintf(stderr, "The host is not responding. Port may be closed or filtered. Exiting.\n");
                exit(-1);
            }

            if (j>=3) {
                sendagain++;
                j = 1;
                continue;
            }

            if (getout ==1)
                break;

            while ((res = pcap_next_ex(pc, &pkt, (const u_char **)&rec_packet))<=0) {

                if (j>=3) {
                    sendagain++;
                    getout = 1;
                    break;
                }

                if ((n =libnet_write(libt))==-1) {
                    fprintf(stderr, "Error writing packet: %s\n",libnet_geterror(libt));
                    exit(-1);
                }
                j++;

            }

            memcpy(&tt, &rec_packet[36], sizeof(u_int16_t));

            if (ntohs(tt) == atoi(port)) {

                flags = rec_packet[47];

                if (flags == 0x012) {
                    memcpy((void *)&ack_num, &rec_packet[38], sizeof(u_int32_t));
                    ack_num = ntohl(ack_num);
                    getout = 1;
                    break;
                }

                else {
                    j++;
                    sendagain++;
                    continue;
                }

            }

        }

        libnet_clear_packet(libt);

        tcp_seq++;
        ack_num++;
        tcp_ack = ack_num;
        tcp_flags = TH_ACK;

        if (tcp = libnet_build_tcp(tcp_sp, tcp_dp, tcp_seq, tcp_ack, tcp_flags, tcp_win, 0, 0, TCPHDR_SIZE, NULL, 0, libt, 0) == -1)
            fprintf(stderr, "Error building TCP header: %s\n", libnet_geterror(libt));
        if ((ip = libnet_build_ipv4((IPHDR_SIZE+TCPHDR_SIZE), 0, ++ip_id, 0, 64, IPPROTO_TCP, 0, src_ip, dst_ip, 0, 0, libt, 0))==-1)
            fprintf(stderr, "Error building IP header: %s\n", libnet_geterror(libt));
        if ((eth =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_IP, NULL, 0, libt, 0))==-1)
            fprintf(stderr, "Error building ETHERNET header: %s\n", libnet_geterror(libt));


        // send ACK packet and complete the 3-way handshake:

        if ((n =libnet_write(libt))==-1) {
            fprintf(stderr, "Error writing packet: %s\n",libnet_geterror(libt));
            exit(-1);
        }

        libnet_clear_packet(libt);

    }

    packet_tuple->tcp_sp = tcp_sp;
    packet_tuple->tcp_seq = tcp_seq;
    packet_tuple->tcp_ack = tcp_ack;
    packet_tuple->ip_id = ip_id++;
    packet_tuple->src_ip = src_ip;
    packet_tuple->dst_ip = dst_ip;
    memcpy(packet_tuple->src_mac, my_mac->ether_addr_octet, maclen);
    memcpy(packet_tuple->dst_mac, dst_mac, maclen);
    packet_tuple->mac_set = true;

    return packet_tuple;
}


void close_tcp_sess_row(libnet_t *libt, struct packet_tuple *packet_tuple, struct tuple *tuple) {

    u_char *iptables_entry_del = "iptables -D OUTPUT -p tcp --dport 43440 --tcp-flags RST RST -j DROP > /dev/null 2>&1";

    libt = build_libnet_link_adv(tuple);

    libnet_ptag_t ip, ipv6, udp, tcp, tcp_opt, eth;
    ip = ipv6 = udp = tcp = eth = LIBNET_PTAG_INITIALIZER;
    struct libnet_ether_addr *my_mac;
    int maclen = 6, i;

    u_int8_t tcp_flags = TH_RST;
    u_int16_t tcp_sp = packet_tuple->tcp_sp, tcp_dp = packet_tuple->tcp_dp;
    u_int32_t tcp_seq = packet_tuple->tcp_seq, tcp_ack = packet_tuple->tcp_ack;
    u_int16_t tcp_win = 14600;

    u_int32_t src_ip = packet_tuple->src_ip, dst_ip = packet_tuple->dst_ip;
    u_int16_t ip_id = packet_tuple->ip_id;

    u_int8_t *mac_addr;
    u_char mac_addr_str[MAC_ADDR_STR_LEN];
    u_int8_t dst_mac[ETH_ADDR_LEN];

    memset(mac_addr_str, '\0', MAC_ADDR_STR_LEN);

    get_mac_address(tuple->destination, mac_addr_str);
    mac_addr = libnet_hex_aton(mac_addr_str, &maclen);

    for (i=0; i < maclen; i++)
        dst_mac[i] = mac_addr[i];

//    strncpy(dst_mac, packet_tuple->dst_mac, strlen(packet_tuple->src_mac));

    my_mac = libnet_get_hwaddr (libt);


    double rst_timer = 500000;
    int n = 0;

    if (tcp = libnet_build_tcp(tcp_sp, tcp_dp, tcp_seq, 0, tcp_flags, 0, 0, 0, TCPHDR_SIZE, NULL, 0, libt, 0) == -1)
        fprintf(stderr, "Error building TCP header: %s\n", libnet_geterror(libt));
    if ((ip = libnet_build_ipv4((IPHDR_SIZE+TCPHDR_SIZE), 0, ip_id, IP_DF, 64, IPPROTO_TCP, 0, src_ip, dst_ip, 0, 0, libt, 0))==-1)
        fprintf(stderr, "Error building IP header: %s\n", libnet_geterror(libt));
    if ((eth =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_IP, NULL, 0, libt, 0))==-1)
        fprintf(stderr, "Error building ETHERNET header: %s\n", libnet_geterror(libt));


    // send RST packet and close this connection. If ignored, kernel will send RST after iptables entry is removed upon test completion.

    usleep(rst_timer);
    if ((n =libnet_write(libt))==-1) {
        fprintf(stderr, "Error writing packet: %s\n",libnet_geterror(libt));
        exit(-1);
    }

    libnet_destroy(libt);
    system(iptables_entry_del);

}


uint16_t compute_tcp_checksum(u_char *packet, int len, struct tuple *tuple) {
    const uint16_t *buf=(void *)&packet[IPSEG_LEN];

    u_int32_t src_addr, dst_addr;
    src_addr = inet_addr(tuple->source);
    dst_addr = inet_addr(tuple->destination);

    uint16_t *ip_src=(uint16_t *)&src_addr;
    uint16_t *ip_dst=(uint16_t *)&dst_addr;

    uint32_t sum;
    size_t length= len - IPSEG_LEN;

    sum = 0;

    while (len > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if ( len & 1 )
        sum += *((uint8_t *)buf);

    sum += *(ip_src++);
    sum += *(ip_dst++);
    sum += htons(IPPROTO_TCP);
    sum += htons(length);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    sum = htons(~sum);

    //Ugly hack, need to understand where is 0xc34 coming from, but it seems a stable value
    sum = ntohs(sum + 0xc34);

    return (u_int16_t)sum;

}


void establish_tcp_session(struct tuple *tuple, struct packet_tuple *packet_tuple) {

    int sockfd = 0;
    struct sockaddr_in serv;
    struct sockaddr_in myaddr;
    struct sockaddr_in readaddr;

    int sa_len = sizeof(readaddr);
    int n, er;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&serv, sizeof(serv));
    serv.sin_family = AF_INET;
    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin_family = AF_INET;

    serv.sin_port = htons(packet_tuple->tcp_dp);
    inet_pton(AF_INET, tuple->destination, &(serv.sin_addr));
    inet_pton(AF_INET, tuple->source, &(myaddr.sin_addr));

    bind(sockfd, (const struct sockaddr *)&myaddr, sizeof(myaddr));

    for (n = 0, er = 1; n<3; n++) {

        sleep(1);

        if (er>=3 && er<=5) {
            fprintf(stderr, "Peer is not responding. Waiting and trying again.\n");
            sleep(3);
        }

        else if (er>=6 && er<9) {
            fprintf(stderr, "Peer is not responding. Waiting and trying again.\n");
            sleep(6);
        }

        else if (er == 9) {
            fprintf(stderr, "Unable to establish connection. Exiting.\n");
            exit(-1);
        }

        if (connect(sockfd, (struct sockaddr *) &serv, sizeof(serv)) !=0) {

            if (errno == ETIMEDOUT) {
                fprintf(stderr, "Connection timed out. Attempt number %d\n", er);
                er++;
            }
            else if (errno == ECONNREFUSED){
                fprintf(stderr, "RST received. Attempt number %d\n", er);
                er++;
            }
            else if (errno == EHOSTUNREACH || errno == ENETUNREACH) {
                fprintf(stderr, "Destination unreachable. Exiting.\n");
                exit(-1);
            }
            else {
                fprintf(stderr, "Unspecified error occured during socket establishment.\n");
                exit(-1);
            }

        }

        else {
            //return sockfd;

            if (er>2)
                fprintf(stderr, "\nConnection established successfully. Continuing.\n");
            packet_tuple->sockfd = sockfd;
            if (getsockname(sockfd,(struct sockaddr *)&readaddr,(socklen_t *)&sa_len) == 0) {
                packet_tuple->tcp_sp = ntohs(readaddr.sin_port);
                packet_tuple->src_ip = readaddr.sin_addr.s_addr;
                break;
            }
            else {
                fprintf(stderr, "Unable to determine source port for the socket.\n");
                exit(-1);
            }
        }

    }

}


void close_tcp_session(int sockfd) {

    int n;

    if (close(sockfd) !=0) {
        fprintf(stderr, "Error occured while closing the socket. Exiting.\n");
        exit(-1);
    }

}


