

/*
 #########################################################################################################
 Revision #      1.0
 Name:               :  build_session_bgp.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Packet builder routines for session fuzzing over BGP protocol data. - FIRST RUN!!!
 #########################################################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_bgp.h"

#include "../headers/instrumentation.h"
#include "../headers/database.h"
#include "../headers/socket_ops.h"

#define TCP_PROTO   6
#define IP_PROTO   4
#define IPv6_PROTO   6

#define TTL 64

#define MAX_HDRS    20
#define MAX_PATH_ATTRS  21

u_char protocol[64];


static u_char *packet;
static u_char *r_packet;

struct bgp_hdr *bgp_hdr;
struct bgp_hdr *keepalive;
struct bgp_open *bgp_open;
struct bgp_update *bgp_update;
struct bgp_notification *bgp_notify;

static struct packet_tuple *packet_tuple;

static u_int32_t marker1 = 0xFFFFFFFF;
static u_int32_t marker2 = 0xFFFFFFFF;
static u_int32_t marker3 = 0xFFFFFFFF;
static u_int32_t marker4 = 0xFFFFFFFF;

u_int32_t packet_size;
int init;

int bgp_update_offsets[MAX_HDRS];
int bgp_update_path_offsets[MAX_HDRS][MAX_HDRS];
int bgp_update_nlri_offsets[MAX_HDRS][5];



void build_bgp_session(struct tuple * tuple) {

    packet = calloc(1, MAX_PACK_SIZE);
    r_packet = calloc(1, MAX_PACK_SIZE);

    u_char *init_packet = calloc(1, MAX_PACK_SIZE);
    u_char *pass_packet = calloc(1, MAX_PACK_SIZE);

    u_int8_t *pkt_ptr = NULL;

    static int fail_count = 0;
    static int run_count = 0;

    int max_hdr_fields = 8;

    fd_set readfds;
    int max_sock;

    time_t rawtime;
    struct timeval timeout, tv;
    struct tm * timeinfo;
    char time_buffer[80];

    pthread_t *ctid = tuple->ssh_tid;

    strncpy(protocol, "bgp ", 3);
    char *pack_delimiter = "***";

    u_char test_id[10];
    memset(test_id, '\0', 10);

    pcap_t *pc;
    struct pcap_pkthdr *pkt;
    char perr[256];

    int res, pack_num = 0, move_size = 0;
    int i, n, ping_result, open_no_param_len, packet_count, rv, recvd_msg, num_msgs;
    init = packet_count = i = 0;

    struct bpf_program filter;
    bpf_u_int32 maskp=0;

    char filter_exp[150];
    u_char *tport = "tcp port ";
    u_char *filter_ext = " && dst host ";
    u_char port[5];

    memset(filter_exp, '\0', 150);
    memset(port, '\0', 5);

    char *pqueue[7];
    for (i=0;i<7;i++){
        pqueue[i] = calloc(1, MAX_PACK_SIZE);
    }


    struct db_table_entry *new_entry = (struct db_table_entry *) calloc(1, sizeof(struct db_table_entry));

    strncpy(new_entry->protocol, protocol, strlen(protocol));
    strncpy(new_entry->packet_type, type_of_packet->l4_type, 3);
    strncat(new_entry->packet_type, " over ", 6);
    strncat(new_entry->packet_type, type_of_packet->l3_type, 4);

    PGconn *conn = create_db_conn(tuple->db_pass);

    os_data = (char *)calloc(1, 34);
    char *os = "Unknown";

    if (tuple->os_data){
        tuple->os_data[34] = '\0';
        strncpy(os_data, tuple->os_data, 34);
    }
    else
        strncpy(os_data, os, strlen(os));

    strncpy(new_entry->os_version_device, os_data, 34);

    strncpy(new_entry->problem_type, "crash", 5);

    if (tuple->comment) {
        tuple->comment[28] = '\0';
        strncpy(new_entry->comment, tuple->comment, 28);
    }
    else
        memset(new_entry->comment, '\0', sizeof(new_entry->comment));


    packet_tuple = calloc(1, sizeof(struct packet_tuple));

    packet_tuple->tcp_dp = BGP_PORT;


    bgp_hdr = calloc(MAX_HDRS, sizeof(struct bgp_hdr));
    bgp_update = calloc(MAX_HDRS, sizeof(struct bgp_update));
    bgp_open = calloc(1, sizeof(struct bgp_open));
    keepalive = calloc(1, sizeof(struct bgp_open));
    bgp_notify = calloc(1, sizeof(struct bgp_notification));

    /*
    for (i=0; i<MAX_HDRS; i++) {

        bgp_update[i].path_list = calloc(1, sizeof(struct bgp_path_attribute));
//        bgp_update[i].path_list->data = calloc(1, 124);
        bgp_update[i].path_list->next = calloc(1, sizeof(struct bgp_path_attribute));

        bgp_update[i].nlri_list = calloc(1, sizeof(struct bgp_nlri));
//        bgp_update[i].nlri_list->data = calloc(1, 4);
        bgp_update[i].nlri_list->next = calloc(1, sizeof(struct bgp_nlri));


    }
*/


    establish_tcp_session(tuple, packet_tuple);

    sprintf(port, "%d", packet_tuple->tcp_sp);
    strncat(filter_exp, tport, strlen(tport));
    strncat(filter_exp, port, strlen(port));
    strncat(filter_exp, filter_ext, strlen(filter_ext));
    strncat(filter_exp, tuple->destination, strlen(tuple->destination));

    tv.tv_sec = 2;

    FD_ZERO(&readfds);
    FD_SET(packet_tuple->sockfd, &readfds);

    max_sock = packet_tuple->sockfd+1;


    while (1) {


        // this first level is to establish whether OPEN should be fuzzed:

        int msg_rand = rand() % 10;

        //debugging:
        msg_rand = UPDATE;

        if (msg_rand == 0)
            bgp_msg_type = OPEN;
        else if (msg_rand == 1)
            bgp_msg_type == KEEPALIVE;
        else if (msg_rand == 9)
            bgp_msg_type == NOTIFICATION;
        else
            bgp_msg_type = UPDATE;


        build_dummy_bgp_open(bgp_open);
        bgp_hdr->next = &bgp_hdr[1];

        bgp_hdr->len = bgp_data_len;

        if (bgp_msg_type == OPEN) {
            packet_size = fuzz_bgp_open(packet, bgp_hdr);
            fprintf(stderr, "Initial Open fuzzed.\n");
        }

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

        packet_size = htons(bgp_hdr->len) + IP_TCPSEG_LEN;


        if (tuple->instrumentation) {
            db_packet_save(packet, packet_size, pqueue[pack_num]);

            if (pack_num == 0) {
                memset(ssh_entry->binary_pack_data, '\0', strlen(pqueue[pack_num]));
                strncpy(&(ssh_entry->binary_pack_data[0]), pqueue[pack_num], strlen(pqueue[pack_num]));
                strncpy(&ssh_entry->binary_pack_data[strlen(pqueue[pack_num])], pack_delimiter, strlen(pack_delimiter));
            }
            else {
                move_size = (strlen(pqueue[pack_num])+3)*pack_num;
                strncpy(&(ssh_entry->binary_pack_data[move_size]), pqueue[pack_num], strlen(pqueue[pack_num]));
                strncpy(&ssh_entry->binary_pack_data[move_size+strlen(pqueue[pack_num])], pack_delimiter, strlen(pack_delimiter));
            }

            pack_num++;
            if (pack_num==7)
                pack_num=0;


            if (ssh_alert) {
                //do_stuff here: insert entry in db.
                pthread_join(*ctid, NULL);
                insert_new_db_entry(conn, ssh_entry->protocol, ssh_entry);
                free(ssh_entry);
                exit(1);
            }
        }


        if ((n =write(packet_tuple->sockfd, packet, htons(bgp_hdr->len)))==-1) {
            fprintf(stderr, "Error writing packet.\n");
            close_tcp_session(packet_tuple->sockfd);
            exit(-1);
        }


        else if (bgp_msg_type == OPEN) {

            pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);
            packet_size = pkt->len;

        }


        FD_ZERO(&readfds);
        FD_SET(packet_tuple->sockfd, &readfds);

        max_sock = packet_tuple->sockfd+1;

        tv.tv_sec = 2;

        rv = select(max_sock, &readfds, NULL, NULL, &tv);

        if (rv) {

            n = recv(packet_tuple->sockfd, r_packet, MAX_PACK_SIZE, 0);
            recvd_msg = parse_recvd_bgp_packet(packet_tuple->sockfd, r_packet, n);

            if (recvd_msg != OPEN) {

                if (recvd_msg != -1)
                    close_tcp_session(packet_tuple->sockfd);

                pkt_ptr = NULL;

                pcap_freecode(&filter);
                //pcap_close(pc);
                memset(packet_tuple, '\0', sizeof(packet_tuple));
                memset(filter_exp, '\0', 150);

                fprintf(stderr, "Didn't receive Open in time. Trying again.\n");

                    establish_tcp_session(tuple, packet_tuple);

                continue;

            }

        }

        else {

            pkt_ptr = NULL;

            pcap_freecode(&filter);
            //pcap_close(pc);
            memset(packet_tuple, '\0', sizeof(packet_tuple));
            memset(filter_exp, '\0', 150);

            fprintf(stderr, "Didn't receive any response to our Open in time. Trying again.\n");

            close_tcp_session(packet_tuple->sockfd);
            sleep(2);
            establish_tcp_session(tuple, packet_tuple);

            continue;

        }


        build_dummy_bgp_keepalive(keepalive);

        if ((n =write(packet_tuple->sockfd, packet, BGP_HDR_SIZE))==-1) {
            fprintf(stderr, "Error writing packet.\n");
            close_tcp_session(packet_tuple->sockfd);
            exit(-1);
        }


        // Do we really care what the peer sends at this point?:


        FD_ZERO(&readfds);
        FD_SET(packet_tuple->sockfd, &readfds);

        max_sock = packet_tuple->sockfd+1;

        tv.tv_sec = 2;

        rv = select(max_sock, &readfds, NULL, NULL, &tv);

        if (rv) {

            n = recv(packet_tuple->sockfd, r_packet, MAX_PACK_SIZE, 0);
            recvd_msg = parse_recvd_bgp_packet(packet_tuple->sockfd, r_packet, n);

            if (recvd_msg==-1) {

                pkt_ptr = NULL;

                pcap_freecode(&filter);
                //pcap_close(pc);
                memset(packet_tuple, '\0', sizeof(packet_tuple));
                memset(filter_exp, '\0', 150);

                establish_tcp_session(tuple, packet_tuple);

                continue;

            }

        }

        else {

            pkt_ptr = NULL;

            pcap_freecode(&filter);
            //pcap_close(pc);
            memset(packet_tuple, '\0', sizeof(packet_tuple));
            memset(filter_exp, '\0', 150);

            fprintf(stderr, "Didn't receive any response to our keepalive in time. Trying again.\n");

            close_tcp_session(packet_tuple->sockfd);
            establish_tcp_session(tuple, packet_tuple);

            continue;

        }



        num_msgs = rand() %5 + 1;


        for (i=0;i<num_msgs;i++) {


            msg_rand = rand() % 10;

            if (i==0) {
                run_count++;
                init = 0;
                fprintf(stderr, "\n### Fuzzing run #%d - number of messages: %d ###\n", run_count, num_msgs);
                fprintf(stderr, "---------------------------------------------------\n");

                msg_rand = 0;
            }


            if (msg_rand >= 2 && msg_rand <= 4) {
                bgp_msg_type = NOTIFICATION;
                run_bgp_notify(pc, pkt, pkt_ptr);
            }
            else if (msg_rand == 9) {
                bgp_msg_type = OPEN;
                run_bgp_open(pc, pkt, pkt_ptr);
            }
            else {
                bgp_msg_type = UPDATE;
                run_bgp_update(pc, pkt, pkt_ptr);
            }


            if (tuple->instrumentation) {
                db_packet_save(packet, packet_size, pqueue[pack_num]);

                if (pack_num == 0) {
                    memset(ssh_entry->binary_pack_data, '\0', strlen(pqueue[pack_num]));
                    strncpy(&(ssh_entry->binary_pack_data[0]), pqueue[pack_num], strlen(pqueue[pack_num]));
                    strncpy(&ssh_entry->binary_pack_data[strlen(pqueue[pack_num])], pack_delimiter, strlen(pack_delimiter));
                }
                else {
                    move_size = (strlen(pqueue[pack_num])+3)*pack_num;
                    strncpy(&(ssh_entry->binary_pack_data[move_size]), pqueue[pack_num], strlen(pqueue[pack_num]));
                    strncpy(&ssh_entry->binary_pack_data[move_size+strlen(pqueue[pack_num])], pack_delimiter, strlen(pack_delimiter));
                }

                pack_num++;
                if (pack_num==7)
                    pack_num=0;


                if (ssh_alert) {
                    //do_stuff here: insert entry in db.
                    pthread_join(*ctid, NULL);
                    insert_new_db_entry(conn, ssh_entry->protocol, ssh_entry);
                    free(ssh_entry);
                    exit(1);
                }
            }

            if ((n =write(packet_tuple->sockfd, packet, packet_size))==-1) {
                fprintf(stderr, "Error writing packet.\n");
                close_tcp_session(packet_tuple->sockfd);
                exit(-1);
            }

            else
                pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);



            FD_ZERO(&readfds);
            FD_SET(packet_tuple->sockfd, &readfds);

            max_sock = packet_tuple->sockfd+1;

            tv.tv_sec = 2;

            rv = select(max_sock, &readfds, NULL, NULL, &tv);

            if (rv) {

                n = recv(packet_tuple->sockfd, r_packet, MAX_PACK_SIZE, 0);

                //this is just to print notification. We don't need to check any further messages:

                if (n==0) {
                    fprintf(stderr, "\t---> Remote host closed connection\n");
                    recvd_msg = -1;
                }

                else
                    recvd_msg = parse_recvd_bgp_packet(packet_tuple->sockfd, r_packet, n);


                if (recvd_msg==OPEN)
                    fprintf(stderr, "\t---> Received OPEN from peer\n");
                if (recvd_msg==KEEPALIVE)
                    fprintf(stderr, "\t---> Received KEEPALIVE from peer\n");
                if (recvd_msg==UPDATE)

                    fprintf(stderr, "\t---> Received UPDATE from peer\n");

                if (recvd_msg==-1) {

                    if (init<num_msgs)
                        fprintf(stderr, "Skipping remaining messages in this run.\n");

                    sleep(2);
                    memset(filter_exp, '\0', 150);
                    pkt_ptr = NULL;

                    pcap_freecode(&filter);
                    //pcap_close(pc);
                    memset(packet_tuple, '\0', sizeof(packet_tuple));
                    memset(filter_exp, '\0', 150);
                    usleep(tuple->timer);

                    establish_tcp_session(tuple, packet_tuple);

                    sprintf(port, "%d", packet_tuple->tcp_sp);
                    strncat(filter_exp, tport, strlen(tport));
                    strncat(filter_exp, port, strlen(port));
                    strncat(filter_exp, filter_ext, strlen(filter_ext));
                    strncat(filter_exp, tuple->destination, strlen(tuple->destination));

                    break;

                }

            }


            ping_result = ping_to_uut(tuple->destination);

            packet_count++;

            usleep(tuple->timer);


            if (ping_result==FAIL) {

                fprintf(stderr, "----- Test failed - saving to database.\n");

                time(&rawtime);
                timeinfo = localtime (&rawtime);
                strftime (time_buffer, 80, "%X",timeinfo);

                db_packet_save(pkt_ptr, packet_size, pass_packet);
                strncpy(new_entry->binary_pack_data, pass_packet, strlen(pass_packet));
                //This needs to change:

                if (type_of_packet) {

                    if (strncmp(type_of_packet->l4_type, "tcp", 3)==0)
                        strncpy(new_entry->misc_description, "bgp", 3);
                    else
                        strncpy(new_entry->misc_description, "\0\0\0", 3);

                }

                insert_new_db_entry(conn, new_entry->protocol, new_entry);
                get_db_current_test_id(tuple->protocol, test_id);
                //                save_pkt_desc_html(type_of_packet, o_packet, pkt_ptr, packet_size, ew_fdata, test_id);


                if (tuple->verbose) {
                    fprintf(stderr, "-- %s -- Test failed. Saving the following packet to packet.pcap: \n", time_buffer);
                    packet_save(pkt_ptr, packet_size);
                }


                memset(time_buffer, '\0', strlen(time_buffer));

                if (tuple->quit){
                    exit(1);
                }
                fail_count++;

                usleep(tuple->timer);
                close_tcp_session(packet_tuple->sockfd);
                memset(filter_exp, '\0', 150);

                pkt_ptr = NULL;

                pcap_freecode(&filter);
                pcap_close(pc);
                memset(packet_tuple, '\0', sizeof(packet_tuple));

                usleep(tuple->timer);

                establish_tcp_session(tuple, packet_tuple);

                sprintf(port, "%d", packet_tuple->tcp_sp);
                strncat(filter_exp, tport, strlen(tport));
                strncat(filter_exp, port, strlen(port));
                strncat(filter_exp, filter_ext, strlen(filter_ext));
                strncat(filter_exp, tuple->destination, strlen(tuple->destination));

                break;

            }


            usleep(tuple->timer);

            //memcpy(init_packet, packet, MAX_PACK_SIZE);

        }

        if (recvd_msg!=-1) {

            sleep(2);
            close_tcp_session(packet_tuple->sockfd);
            memset(filter_exp, '\0', 150);
            pkt_ptr = NULL;

            pcap_freecode(&filter);
            //pcap_close(pc);
            memset(packet_tuple, '\0', sizeof(packet_tuple));
            memset(filter_exp, '\0', 150);
            usleep(tuple->timer);

            establish_tcp_session(tuple, packet_tuple);

            sprintf(port, "%d", packet_tuple->tcp_sp);
            strncat(filter_exp, tport, strlen(tport));
            strncat(filter_exp, port, strlen(port));
            strncat(filter_exp, filter_ext, strlen(filter_ext));
            strncat(filter_exp, tuple->destination, strlen(tuple->destination));

        }

     }

    free(bgp_open);
    free(bgp_update);
    free(keepalive);
    free(bgp_notify);
    free(bgp_hdr);


}



void build_dummy_bgp_open(struct bgp_open *open) {

    memset(packet, 0, MAX_PACK_SIZE);

    int i, param_size, param_list_size, pl=0;

    struct bgp_opt_param_capabilities *params[5];

    for (i =0;i<5;i++) {
        params[i] = calloc(1, sizeof(struct bgp_opt_param_capabilities));
    }


    /*

     Default Dummy BGP OPEN packet, carrying 5 parameters:

     */

    params[0]->type = 0x02;
    params[0]->len = 0x06;
    params[0]->ctype = 0x01;
    params[0]->clen = 0x04;

    params[1]->type = 0x02;
    params[1]->len = 0x02;
    params[1]->ctype = 0x80;
    params[1]->clen = 0x00;
    params[1]->value =  NULL;

    params[2]->type = 0x02;
    params[2]->len = 0x02;
    params[2]->ctype = 0x02;
    params[2]->clen = 0x00;
    params[2]->value = NULL;

    params[3]->type = 0x02;
    params[3]->len = 0x03;
    params[3]->ctype = 0x83;
    params[3]->clen = 0x01;
    params[3]->value = calloc(1, 1);
    params[3]->value[0] = 0x00;

    params[4]->type = 0x02;
    params[4]->len = 0x06;
    params[4]->ctype = 0x41;
    params[4]->clen = 0x04;

    param_list_size = i*sizeof(u_int32_t) + 9;
    param_size = 4;

    bgp_hdr->marker1 = marker1;
    bgp_hdr->marker2 = marker2;
    bgp_hdr->marker3 = marker3;
    bgp_hdr->marker4 = marker4;
    bgp_hdr->type = OPEN;
    bgp_data_len = htons(BGP_HDR_SIZE + BGP_OPEN_SIZE + param_list_size);
    bgp_hdr->len = bgp_data_len;
    open->holdtime = 0x00b4;
    open->version = 0x04;
    open->my_as[0] = (bgp_my_as >> 8);
    open->my_as[1] = (bgp_my_as);


    open->identifier[0] = (packet_tuple->src_ip);
    open->identifier[1] = (packet_tuple->src_ip >> 8);
    open->identifier[2] = (packet_tuple->src_ip >> 16);
    open->identifier[3] = (packet_tuple->src_ip >> 24);

    unsigned int asn_num = asdot_convert(tuple.source, strlen(tuple.source));

    open->params = params[0];
    open->param_len = param_list_size;


    memcpy(packet, bgp_hdr, BGP_HDR_SIZE);
    memcpy(&packet[BGP_HDR_SIZE], open, 5);
    memcpy(&packet[BGP_HDR_SIZE+5], open->identifier, 4);
    packet[BGP_HDR_SIZE+9] = open->param_len;

    for (i = 0;i<5;i++) {

        memcpy(&packet[BGP_HDR_SIZE+10+pl], params[i], params[i]->len+2);
        pl = pl + params[i]->len +2;

    }

    packet[BGP_HDR_SIZE+10 + param_size] = 0;
    packet[BGP_HDR_SIZE+10 + param_size + 1] = 1;
    packet[BGP_HDR_SIZE+10 + param_size + 2] = 0;
    packet[BGP_HDR_SIZE+10 + param_size + 3] = 1;


    packet[BGP_HDR_SIZE+10 + pl - 1] = asn_num;
    packet[BGP_HDR_SIZE+10 + pl - 2] = (asn_num >> 8);
    packet[BGP_HDR_SIZE+10 + pl - 3] = (asn_num >> 16);
    packet[BGP_HDR_SIZE+10 + pl - 4] = (asn_num >> 24);

    free(params[3]->value);
    for (i =0;i<5;i++) {
        free(params[i]);
    }

    parse_bgp_params(&packet[BGP_HDR_SIZE + BGP_OPEN_SIZE], param_list_size);

}



size_t build_dummy_bgp_update(struct bgp_update *bgp_update, struct bgp_hdr *bgp_hdr, int num_hdrs) {


    int bgp_hdr_ext_size = BGP_HDR_SIZE + 4;

    int pack_slider[124] = {0};
    int i, n, c, x = 0, y = 0, j = 0, dlen, prefix_len, clen, l;
    size_t size = 0, r_size = 0;

    memset(packet, 0, MAX_PACK_SIZE);

    struct bgp_hdr *dummy_bgp_hdr = bgp_hdr;


    struct bgp_path_attribute *path_ptr;
    struct bgp_path_attribute **p_path_ptr;

    struct bgp_nlri *nlri_ptr;

    struct bgp_path_attribute *head_path_ptr;
    struct bgp_nlri *head_nlri_ptr;


    const unsigned char path_attr_list[MAX_PATH_ATTRS][124] = {
        {0x40, 0x01, 0x01, 0x01},                                           /* ORIGIN */
        {0x40, 0x02, 0x0e, 0x02, 0x03, (bgp_my_as >> 24),                   /* AS_PATH */
         (bgp_my_as >> 16), (bgp_my_as >> 8), bgp_my_as,
         0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
         0x03},
        {0x40, 0x03, 0x04, packet_tuple->src_ip,                            /* NEXT_HOP */
         (packet_tuple->src_ip >>8), (packet_tuple->src_ip >>16),
         (packet_tuple->src_ip >>24)},
        {0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00},                         /* MULTI_EXIT_DISC */
        {0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64},                         /* LOCAL_PREF */
        {0x40, 0x06, 0x00},                                                 /* ATOMIC_AGGREGATE */
        {0xc0, 0x07, 0x08, (bgp_my_as >> 8), bgp_my_as,                     /* AGGREGATOR */
         packet_tuple->src_ip, (packet_tuple->src_ip >>8),
         (packet_tuple->src_ip >>16), (packet_tuple->src_ip >>24)},
        {0xc0, 0x08, 0x08, 0x02, 0x40, 0x02, 0x00,                          /* COMMUNITY */
         0x80, 0x04, 0x004, 0x00},
        {0x80, 0x09, 0x04, 0x4b, 0x01, 0x01, 0x02},                         /* ORIGINATOR_ID */
        {0x80, 0x0a, 0x04, 0x4b, 0x00, 0x01, 0x01},                         /* CLUSTER_LIST */
        {0x80, 0x0e, 0x31, 0x00, 0x01, 0x80, 0x0c,                          /* MP_REACH_NLRI */
         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x4b, 0x01, 0x01, 0x02, 0x00, 0x78,
         0x00, 0x02, 0xd1, 0x00, 0x00, 0x02, 0xda,
         0x00, 0x00, 0x02, 0xef, 0x4b, 0x01, 0x02,
         0x01, 0x76, 0x00, 0x02, 0xc1, 0x00, 0x00,
         0x02, 0xda, 0x00, 0x00, 0x02, 0xef, 0x14,
         0x01, 0x01, 0x08},
        {0x80, 0x0f, 0x23, 0x00, 0x01, 0x80, 0x78,                          /* MP_UNREACH_NLRI */
         0x00, 0x02, 0xd1, 0x00, 0x00, 0x02, 0xda,
         0x00, 0x00, 0x02, 0xef, 0x4b, 0x01, 0x02,
         0x01, 0x76, 0x00, 0x02, 0xc1, 0x00, 0x00,
         0x02, 0xda, 0x00, 0x00, 0x02, 0xef, 0x14,
         0x01, 0x01, 0x08},
        {0x90, 0x0e, 0x00, 0x15, 0x00, 0x01, 0x85,                          /* FLOWSPEC - MP_REACH_NLRI */
         0x00, 0x00, 0x0f, 0x01, 0x20, 0xc0, 0xa8,
         0x6e, 0xfe, 0x03, 0x81, 0x01, 0x07, 0x81,
         0x03, 0x08, 0x81, 0x03},
        {0xc0, 0x10, 0x20, 0x00, 0x02, 0x1c, 0x84,                          /* EXTENDED_COMMUNITIES */
         0x00, 0x00, 0x02, 0xda, 0x00, 0x05, 0x00,
         0x00, 0x02, 0xda, 0x02, 0x00, 0x80, 0x00,
         0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x80,
         0x01, 0x0a, 0x53, 0x01, 0x02, 0x02, 0x00},
        {0x80, 0x11, 0x28, 0x01, 0x01, 0x80, 0x78,                          /* AS4_PATH */
         0x00, 0x02, 0x02, 0x00, 0x03, 0x02, 0xda,
         0x00, 0x00, 0x02, 0xef, 0x4b, 0x01, 0x02,
         0x04, 0x05, 0x00, 0x02, 0xc1, 0x00, 0x00,
         0x02, 0xda, 0x00, 0x00, 0x02, 0xef, 0x14,
         0x01, 0x01, 0x08},
        {0x80, 0x12, 0x08, 0x4b, 0x01, 0x01, 0x02,                          /* AS4_AGGREGATOR */
         0x00, 0x00, 0x00, 0x00},
        {0xc0, 0x16, 0x10, 0x01, 0x01, 0x01, 0x01,                          /* PMSI_TUNNEL */
         0x80, 0x11, 0x23, 0x01, 0x01, 0x80, 0x78,
         0x00, 0x02, 0x02, 0x00, 0x03},
        {0x80, 0x17, 0x23, 0x00, 0x01, 0x00, 0x06,                          /* TUNNEL_ENCAP */
         0x04, 0x04, 0x23, 0x01, 0x01, 0x80, 0x00,
         0x02, 0x00, 0x09, 0x01, 0x03, 0x02, 0xda,
         0x00, 0x02, 0x02, 0xef, 0x4b, 0x00, 0x07,
         0x00, 0x08, 0x04, 0x02, 0xc1, 0x00, 0x02,
         0x02, 0x02, 0x00},
        {0x80, 0x1a, 0x0b, 0x01, 0x00, 0x01, 0x00,                          /* AIGP */
         0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
        {0x80, 0x1d, 0x1c, 0x04, 0x06, 0x00, 0x04,                          /* BGP_LINK_STATE */
         0x00, 0x00, 0x00, 0x00, 0x04, 0x07, 0x00,
         0x10, 0x00, 0x08, 0x01, 0x03, 0x02, 0xda,
         0x00, 0x02, 0x02, 0xef, 0x4b, 0x00, 0x07,
         0x00, 0x08, 0x04},
        {0x80, 0x80, 0x20, 0x04, 0x06, 0x00, 0x04,                          /* ATTR_SET */
         0xc0, 0x10, 0x08, 0x00, 0x04, 0x07, 0x00,
         0x10, 0x00, 0x08, 0x01, 0x40, 0x02, 0x00,
         0x40, 0x05, 0x04, 0xef, 0x4b, 0x00, 0x07,
         0x00, 0x08, 0x04, 0x02, 0xc1, 0x00, 0x02}
    };


    const unsigned char nlri_list[24][124] = {
        {0x18, 0x0a, 0x1e, 0x01},
        {0x18, 0x0a, 0x1e, 0x02},
        {0x18, 0x0a, 0x1e, 0x03},
        {0x18, 0x0a, 0x1e, 0x00},
        {0x1e, 0xac, 0x10, 0x00, 0x0c},
        0,
        0,
        0
    };


    for (i = 0; i<num_hdrs; i++) {


        dummy_bgp_hdr[i].marker1 = marker1;
        dummy_bgp_hdr[i].marker2 = marker2;
        dummy_bgp_hdr[i].marker3 = marker3;
        dummy_bgp_hdr[i].marker4 = marker4;

        dummy_bgp_hdr[i].type = 0x02;

        if (i == num_hdrs-1)
            dummy_bgp_hdr[i].next = NULL;
        else
            dummy_bgp_hdr[i].next = &dummy_bgp_hdr[i+1];
    }


    c = rand() %MAX_PATH_ATTRS/2 +3;         // this needs to be %MAX_PATH_ATTRS (num of attributes)
    while (!c)
        c = rand() %MAX_PATH_ATTRS/2 +3;


    for (i=0;i<num_hdrs;i++) {

        size = 0;

        bgp_update[i].wr_len = 0;
        bgp_update[i].tpa_len = 0;          // temporary setting

        bgp_update_path_offsets[i][0] = bgp_hdr_ext_size;
        bgp_update_offsets[0] = 0;

        for (n = 0;n<c;n++) {

            // taking care of the mandatory attributes:

            if (n==0) {
                x = n;
                bgp_update[i].path_list = calloc(1, sizeof(struct bgp_path_attribute));
                head_path_ptr = &bgp_update[i].path_list[0];
            }
            else if (n==1)
                x = n;
            else if (n==2)
                x = n;

            else {
                x = rand() % MAX_PATH_ATTRS;
                while (x==y)
                    x = rand() % MAX_PATH_ATTRS;
            }

            bgp_update[i].path_list->flags = path_attr_list[x][0];
            bgp_update[i].path_list->code = path_attr_list[x][1];
            bgp_update[i].path_list->len = path_attr_list[x][2];
            dlen = bgp_update[i].path_list->len;
            if (dlen) {
                bgp_update[i].path_list->data = calloc(1, dlen);
                memcpy(bgp_update[i].path_list->data, &path_attr_list[x][3], dlen);
            }

            y = x;

            memcpy(&packet[BGP_HDR_SIZE+size+4+j], bgp_update[i].path_list, 3);
            memcpy(&packet[BGP_HDR_SIZE+size+4+3+j], bgp_update[i].path_list->data, dlen);

            size+=(dlen+3);
            bgp_update_path_offsets[i][n+1] = size+bgp_hdr_ext_size;

            if (n<c-1) {
                bgp_update[i].path_list->next = calloc(1, sizeof(struct bgp_path_attribute));
                bgp_update[i].path_list = bgp_update[i].path_list->next;
            }

        }

        bgp_update_path_offsets[i][n+1] = 0;
        bgp_update_path_offsets[i][n] = 0;

        bgp_update[i].tpa_len = htons(size);

        memcpy(&packet[BGP_HDR_SIZE+j], &bgp_update[i], 4);

        bgp_update[i].path_list = head_path_ptr;


        c = rand() % 5;
        while (!c)
            c = rand() %5;

        for (n = 0; n<c;n++) {

            x = rand() % 5;
            while (x==y)
                x = rand() % 5;

            if (n==0) {
                bgp_update[i].nlri_list = calloc(1, sizeof(struct bgp_nlri));
                head_nlri_ptr = &bgp_update[i].nlri_list[0];
            }

            bgp_update[i].nlri_list->prefix_len = nlri_list[x][0];
            prefix_len = bgp_update[i].nlri_list->prefix_len;
            if (prefix_len>=0 && prefix_len<=8)
                prefix_len = 1;
            else if (prefix_len>=9 && prefix_len<=16)
                prefix_len = 2;
            else if (prefix_len>=17 && prefix_len<=24)
                prefix_len = 3;
            else if (prefix_len>=25 && prefix_len<=32)
                prefix_len = 4;

            if (prefix_len) {
                bgp_update[i].nlri_list->data = calloc(1, prefix_len);
                memcpy(bgp_update[i].nlri_list->data, &nlri_list[x][1], prefix_len);
            }

            memcpy(&packet[BGP_HDR_SIZE+4+size+j], bgp_update[i].nlri_list, 1);
            memcpy(&packet[BGP_HDR_SIZE+size+4+1+j], bgp_update[i].nlri_list->data, prefix_len);

            bgp_update_nlri_offsets[i][n] = BGP_HDR_SIZE+4+size;

            size+=(1+prefix_len);

            y = x;

            if (n<c-1) {

                bgp_update[i].nlri_list->next = calloc(1, sizeof(struct bgp_nlri));
                bgp_update[i].nlri_list = bgp_update[i].nlri_list->next;
            }


        }


        bgp_update[i].nlri_list = head_nlri_ptr;


        size += bgp_hdr_ext_size;
        dummy_bgp_hdr[i].len = htons(size);
        r_size += size;

        bgp_update_offsets[i+1] = size+bgp_update_offsets[i];

        memcpy(&packet[j], &dummy_bgp_hdr[i], BGP_HDR_SIZE);
        j +=size;


    }

    bgp_update_offsets[i] = 0;

    return r_size;



}



size_t build_dummy_bgp_notify(struct bgp_notification *bgp_notify) {


    int f_field = rand() % 10;
    int dlen = 3;

    memset(packet, 0, MAX_PACK_SIZE);

    struct bgp_hdr *dummy_bgp_hdr = calloc(1, sizeof(struct bgp_hdr));

    dummy_bgp_hdr->marker1 = marker1;
    dummy_bgp_hdr->marker2 = marker2;
    dummy_bgp_hdr->marker3 = marker3;
    dummy_bgp_hdr->marker4 = marker4;

    dummy_bgp_hdr->type = NOTIFICATION;

    bgp_notify->maj_err_code = 0x02;
    bgp_notify->min_err_code = 0x08;

    if (f_field < 3)
        bgp_notify->maj_err_code = rand() %8;

    else if (f_field < 6)
        bgp_notify->maj_err_code = rand() %14;

    else
        dlen = rand() % 124;

    dummy_bgp_hdr->len = htons(BGP_HDR_SIZE+2+dlen);

    bgp_notify->data = calloc(1, dlen);

    rand_str_gen(bgp_notify->data, dlen);

    memcpy(packet, dummy_bgp_hdr, sizeof(struct bgp_hdr));
    packet[BGP_HDR_SIZE] = bgp_notify->maj_err_code;
    packet[BGP_HDR_SIZE+1] = bgp_notify->min_err_code;
    memcpy(&packet[BGP_HDR_SIZE+2], bgp_notify->data, dlen);

    dlen = htons(dummy_bgp_hdr->len);
    free(dummy_bgp_hdr);
    return dlen;


}



void build_dummy_bgp_keepalive(struct bgp_hdr *keepalive) {

    memset(packet, 0, MAX_PACK_SIZE);

    keepalive->marker1 = marker1;
    keepalive->marker2 = marker2;
    keepalive->marker3 = marker3;
    keepalive->marker4 = marker4;
    keepalive->type = KEEPALIVE;
    keepalive->len = htons(19);

    memcpy(packet, keepalive, BGP_HDR_SIZE);
}



void run_bgp_update(pcap_t *pc, struct pcap_pkthdr *pkt, u_int8_t *pkt_ptr) {

    int i, n;

    int num_hdrs = rand() % MAX_HDRS/2;
    while (num_hdrs == 0)
        num_hdrs = rand() % MAX_HDRS/2;


    packet_size = build_dummy_bgp_update(bgp_update, &bgp_hdr[1], num_hdrs);

    //need to put some logic to switch to MODE_MULTIPLE:

    packet_size = fuzz_bgp_update(packet, bgp_update, num_hdrs, MODE_SINGLE);

    deallocate_bgp_update_data(bgp_update, num_hdrs);

    for (i=0;i<num_hdrs;i++) {
        bgp_update_offsets[i] = 0;
        for (n=0;n<num_hdrs;n++)
            bgp_update_path_offsets[i][n] = 0;
        for (n=0;n<5;n++)
            bgp_update_nlri_offsets[i][n];

    }

}



void run_bgp_open(pcap_t *pc, struct pcap_pkthdr *pkt, u_int8_t *pkt_ptr) {

    int n;

    build_dummy_bgp_open(bgp_open);
    packet_size = fuzz_bgp_open(packet, bgp_hdr);

    if ((n =write(packet_tuple->sockfd, packet, packet_size))==-1) {
        fprintf(stderr, "Error writing packet.\n");
        close_tcp_session(packet_tuple->sockfd);
        exit(-1);
    }

    else
        pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);



}



void run_bgp_notify(pcap_t *pc, struct pcap_pkthdr *pkt, u_int8_t *pkt_ptr) {

    int n, i;

    packet_size = build_dummy_bgp_notify(bgp_notify);
    fuzz_bgp_notify(packet, bgp_hdr);

    if ((n =write(packet_tuple->sockfd, packet, packet_size))==-1) {
        fprintf(stderr, "Error writing packet.\n");
        close_tcp_session(packet_tuple->sockfd);
        exit(-1);
    }

    else
        pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);


}



unsigned int asdot_convert(u_char * asn_s, int len) {

    char asn[len];
    strncpy(asn, asn_s, len);
    char dot = '.';
    char *asdot = strchr(asn, dot);
    unsigned int asn_int = atoi(asn);

    *asdot = '\0';
    unsigned int asn_low = asn_int;
    unsigned int asn_high = atoi(asdot+1);
    return ((asn_low<<16)+asn_high);

}



void parse_bgp_params(u_char *params, size_t param_list_size) {

    int plen = 0, param_size = 0, rem_size = 0;
    int i, pkt_bit;

    bgp_params_offsets[0] = BGP_HDR_SIZE + BGP_OPEN_SIZE;

    plen = params[1];

    if (plen > 2) {

        param_size = plen + 2;
        bgp_params_offsets[1] = bgp_params_offsets[0] + param_size;
        param_list_size = param_list_size - param_size;
        pkt_bit = param_size;

        for (i = 2; i< param_list_size; i++) {
            plen = params[pkt_bit + 1];
            param_size = plen + 2;
            bgp_params_offsets[i] = bgp_params_offsets[i-1] + param_size;
            param_list_size = param_list_size - param_size;
            pkt_bit = pkt_bit + param_size;
        }

        bgp_param_list_size = param_list_size;

    }

    else {
        bgp_params_offsets[0] = 0;
        bgp_param_list_size = 0;
    }


}



void deallocate_bgp_update_data(struct bgp_update *bgp_update, int num_hdrs) {

    int i, c, x;
    struct bgp_path_attribute *path_ptr;
    struct bgp_nlri *nlri_ptr;
    u_char *data_ptr;

    for (i=0;i<num_hdrs;i++) {

        while (bgp_update[i].path_list) {
            path_ptr = bgp_update[i].path_list;
            data_ptr = bgp_update[i].path_list->data;
            bgp_update[i].path_list = bgp_update[i].path_list->next;
            free(data_ptr);
            free(path_ptr);
        }

    }

    for (i=0;i<num_hdrs;i++) {

        while (bgp_update[i].nlri_list) {
            nlri_ptr = bgp_update[i].nlri_list;
            data_ptr = bgp_update[i].nlri_list->data;
            bgp_update[i].nlri_list = bgp_update[i].nlri_list->next;
            free(data_ptr);
            free(nlri_ptr);
        }

    }



}



