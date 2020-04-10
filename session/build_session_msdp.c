


/*
 #####################################################################################################
 Revision #      1.0
 Name:               :  build_session_msdp.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Packet builder routines for session fuzzing over MSDP protocol data.
 #####################################################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_msdp.h"

#include "../headers/instrumentation.h"
#include "../headers/database.h"
#include "../headers/socket_ops.h"


#define TCP_PROTO   6
#define IP_PROTO   4

#define TTL 64

u_char protocol[64];


static u_char *packet;

static u_char encap_data[] = {0x45, 0xc0, 0x00, 0x36, 0x00, 0x8b, 0x00, 0x00, 0x01, 0x67, 0xd9, 0xc4, 0x0a, 0x00, 0x00, 0x0e, 0xe0, 0x00, 0x00, 0x0d, 0x23, 0x00, 0x5a, 0xe5, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x0d, 0x00, 0x01, 0x00, 0xd2, 0x01, 0x00, 0x00, 0x20, 0xe0, 0x00, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x07, 0x20, 0x01, 0x01, 0x01, 0x01 };

struct msdp_header *msdp_hdr;

static struct packet_tuple *packet_tuple;


void build_msdp_session(struct tuple * tuple) {

    packet = calloc(1, MAX_PACK_SIZE);

    u_char *init_packet = calloc(1, MAX_PACK_SIZE);
    u_char *pass_packet = calloc(1, MAX_PACK_SIZE);

    u_int8_t *pkt_ptr = NULL;

    u_int32_t packet_size;

    static int fail_count = 0;

    time_t rawtime;
    struct timeval timeout;
    struct tm * timeinfo;
    char time_buffer[80];

    pthread_t *ctid = tuple->ssh_tid;

    strncpy(protocol, "msdp ", 4);
    char *pack_delimiter = "***";

    u_char test_id[10];
    memset(test_id, '\0', 10);

    pcap_t *pc;
    struct pcap_pkthdr *pkt;
    char perr[256];

    int res, pack_num = 0, move_size = 0;
    int i, n, ping_result, init, packet_count;
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

    msdp_hdr = calloc(1, sizeof(msdp_hdr));


    packet_tuple->tcp_dp = MSDP_PORT;
    establish_tcp_session(tuple, packet_tuple);

    sprintf(port, "%d", packet_tuple->tcp_sp);
    strncat(filter_exp, tport, strlen(tport));
    strncat(filter_exp, port, strlen(port));
    strncat(filter_exp, filter_ext, strlen(filter_ext));
    strncat(filter_exp, tuple->destination, strlen(tuple->destination));

    build_dummy_msdp_pack(msdp_hdr);

    memcpy(init_packet, packet, MAX_PACK_SIZE);

    i =0;

    while (i<3) {
        if ((n =write(packet_tuple->sockfd, packet, htons(msdp_hdr->len)))==-1) {
            fprintf(stderr, "Error writing packet.\n");
            close_tcp_session(packet_tuple->sockfd);
            exit(-1);
        }
        i++;
    }

/*
    close_tcp_session(packet_tuple->sockfd);

    establish_tcp_session(tuple, packet_tuple);

    memset(filter_exp, '\0', 150);

    sprintf(port, "%d", packet_tuple->tcp_sp);
    strncat(filter_exp, tport, strlen(tport));
    strncat(filter_exp, port, strlen(port));
    strncat(filter_exp, filter_ext, strlen(filter_ext));
    strncat(filter_exp, tuple->destination, strlen(tuple->destination));
*/
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

        while (1) {

            memcpy(packet, init_packet, MAX_PACK_SIZE);

            //fuzz_msdp(packet, msdp_hdr);

            /*

             Needs to be implemented:

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
                    fprintf(stderr, "Cought ssh_alert\n");
                    //do_stuff here: insert entry in db.
                    pthread_join(*ctid, NULL);
                    insert_new_db_entry(conn, ssh_entry->protocol, ssh_entry);
                    free(ssh_entry);
                    exit(1);
                }
            }

             */


            if ((n =write(packet_tuple->sockfd, packet, htons(msdp_hdr->len)))==-1) {

                close_tcp_session(packet_tuple->sockfd);

                if (errno == ECONNRESET) {

                    fprintf(stderr, "Recieved connection reset from peer. Trying to restart.\n");
                    sleep (10);
                    establish_tcp_session(tuple, packet_tuple);

                    memset(filter_exp, '\0', 150);

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
                    continue;
                }

                else {
                    fprintf(stderr, "Error writing packet.\n");
                    exit(-1);
                }
            }

            else {
                pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);
                packet_size = pkt->len;
                ping_result = ping_to_uut(tuple->destination);
            }

            usleep(tuple->timer);

            /*
            close_tcp_session(packet_tuple->sockfd);
            memset(filter_exp, '\0', 150);
             */

            fprintf(stderr, "%d.Fuzzing %d bytes of %s data\n", init+1, packet_size, tuple->protocol);
            init++;
            packet_count++;

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
                        strncpy(new_entry->misc_description, "msdp", 3);
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

            }

            pkt_ptr = NULL;

            /*
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
            */

        }


}


void build_dummy_msdp_pack(struct msdp_header *msdp_hdr) {

    u_char *ll_group = "224.2.127.254";
    u_char *saddress = tuple.source;

    struct sockaddr_in group, sadr;
    bzero(&group, sizeof(group));
    bzero(&sadr, sizeof(sadr));

    inet_pton(AF_INET, ll_group, &(group.sin_addr));
    inet_pton(AF_INET, saddress, &(sadr.sin_addr));

    msdp_hdr->type = 0x01;
    msdp_hdr->len = htons(0x004a);
    msdp_hdr->count = 0x01;
    msdp_hdr->rp[0] = (packet_tuple->src_ip);
    msdp_hdr->rp[1] = (packet_tuple->src_ip >> 8);
    msdp_hdr->rp[2] = (packet_tuple->src_ip >> 16);
    msdp_hdr->rp[3] = (packet_tuple->src_ip >> 24);
    msdp_hdr->start.res1 = 0x00;
    msdp_hdr->start.res2 = htons(0x0020);
    msdp_hdr->start.len = 0x20;

    msdp_hdr->start.group[0] = (group.sin_addr.s_addr);
    msdp_hdr->start.group[1] = (group.sin_addr.s_addr >> 8);
    msdp_hdr->start.group[2] = (group.sin_addr.s_addr >> 16);
    msdp_hdr->start.group[3] = (group.sin_addr.s_addr >> 24);

    msdp_hdr->start.source[0] = (sadr.sin_addr.s_addr);
    msdp_hdr->start.source[1] = (sadr.sin_addr.s_addr >> 8);
    msdp_hdr->start.source[2] = (sadr.sin_addr.s_addr >> 16);
    msdp_hdr->start.source[3] = (sadr.sin_addr.s_addr >> 24);

//    msdp_hdr->start.source[0] = (packet_tuple->src_ip);
//    msdp_hdr->start.source[1] = (packet_tuple->src_ip >> 8);
//    msdp_hdr->start.source[2] = (packet_tuple->src_ip >> 16);
//    msdp_hdr->start.source[3] = rand() % 254;

    encap_data[12] = msdp_hdr->start.source[0];
    encap_data[13] = msdp_hdr->start.source[1];
    encap_data[14] = msdp_hdr->start.source[2];
    encap_data[15] = msdp_hdr->start.source[3];
    encap_data[16] = msdp_hdr->start.group[0];
    encap_data[17] = msdp_hdr->start.group[1];
    encap_data[18] = msdp_hdr->start.group[2];
    encap_data[19] = msdp_hdr->start.group[3];

    packet[0] = msdp_hdr->type;
    packet[1] = msdp_hdr->len;
    packet[2] = (msdp_hdr->len >> 8);
    packet[3] = msdp_hdr->count;
    memcpy(&packet[4], msdp_hdr->rp, 4);
    packet[8] = msdp_hdr->start.res1;
    packet[9] = msdp_hdr->start.res2;
    packet[10] = (msdp_hdr->start.res2 >> 8);
    packet[11] = msdp_hdr->start.len;
    memcpy(&packet[12], msdp_hdr->start.group, 4);
    memcpy(&packet[16], msdp_hdr->start.source, 4);

    memcpy(&packet[20], encap_data, sizeof(encap_data));

}




