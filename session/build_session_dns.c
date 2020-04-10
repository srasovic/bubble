

/*
 ##########################################################################################
 Revision #      1.0
 Name:               :  build_session_dns.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Packet builder routines for session fuzzing over DNS protocol data.
 ##########################################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_dns.h"
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
int nlen, alen, hlen, attlen=0;
int plen[13];

int socktest_result=1;

struct dns_header *dheader;
struct queries qrs[13];
struct addrecords *addrcds;

u_char cpack[REG_PACK_SIZE];

static struct packet_tuple *packet_tuple;


void build_dns_session(struct tuple * tuple) {

    int i, res;
    u_char *pass_packet = calloc(1, MAX_PACK_SIZE);

    memset(cpack, '\0', REG_PACK_SIZE);

    dheader = calloc(1, sizeof(struct dns_header));

    /*for (i=0; i<8; i++)
            qrs[i] = calloc(1, sizeof(struct queries));*/

    addrcds = calloc(1, sizeof(struct addrecords));

    addrcds->name = 0;
    addrcds->type=41;
    addrcds->psize = 4096;
    addrcds->hbits = 0;
    addrcds->z = 0x8000;
    addrcds->dlen = 0x0000;

    pcap_t *pc, *pcd;
    struct pcap_pkthdr *pkt, *pktd;
    char perr[256], perrd[256];
    struct bpf_program filter, filterd;
    bpf_u_int32 maskp=0;

    u_int8_t *pkt_ptr, *o_pkt_ptr = NULL;
    u_int32_t packet_size;
    int servlen, n, ping_result, num_packs;
    int count = 1;
    static int fail_count = 0;

    time_t rawtime;
    struct timeval timeout, tv;
    struct tm * timeinfo;
    char time_buffer[80];
    char filter_exp[150], filterd_exp[150];

    u_char *tport = "udp port ";
   // u_char *filter_ext = " && src host ";
    u_char *filter_ext = "src host ";
    u_char port[5];

    strncpy(protocol, "dns ", 3);

    u_char test_id[10];
    memset(test_id, '\0', 10);

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
    strncpy(new_entry->problem_type, "daemon crash", 12);

    if (tuple->comment) {
        tuple->comment[28] = '\0';
        strncpy(new_entry->comment, tuple->comment, 28);
    }
    else
        memset(new_entry->comment, '\0', sizeof(new_entry->comment));


    memset(filter_exp, '\0', 150);
    memset(filterd_exp, '\0', 150);

    libnet_t *libt = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];

    libt = libnet_init(LIBNET_LINK_ADV, tuple->intf, errbuf);

    my_mac = libnet_get_hwaddr (libt);

    libnet_destroy(libt);

    packet_tuple = calloc(1, sizeof(struct packet_tuple));

    //packet_tuple->tcp_dp = DNS_SPORT;
    if (tuple->dport)
        packet_tuple->tcp_dp = atoi(tuple->dport);
    else
        packet_tuple->tcp_dp = 53;

    get_udp_socket(tuple->source, tuple->destination, packet_tuple);

    servlen = sizeof(struct sockaddr_in);

    sprintf(port, "%d", packet_tuple->tcp_sp);
    //strncat(filter_exp, tport, strlen(tport));
    //strncat(filter_exp, port, strlen(port));
    //strncat(filter_exp, filter_ext, strlen(filter_ext));
    //strncat(filter_exp, tuple->destination, strlen(tuple->destination));

    strcat(filter_exp, "icmp[icmptype]=icmp-unreach");

    strncpy(filterd_exp, tport, strlen(tport));
    strncat(filterd_exp, port, strlen(port));
//    strncat(filterd_exp, filter_ext, strlen(filter_ext));
//    strncat(filterd_exp, tuple->destination, strlen(tuple->destination));
    strcat(filterd_exp, "");

    pc = pcap_open_live(tuple->intf, 1520, 1, 1000, perr);
    pcd = pcap_open_live(tuple->intf, 1520, 1, 500, perrd);

    int f = pcap_compile(pc, &filter, filter_exp, 1, maskp);
    if (f<0) {
        fprintf(stderr, "Filter compilation failed. Exiting.\n");
        exit(-1);
    }

    f = pcap_compile(pcd, &filterd, filterd_exp, 1, maskp);
    if (f<0) {
        fprintf(stderr, "Filter compilation failed. Exiting.\n");
        exit(-1);
    }

    int s = pcap_setfilter(pc, &filter);
    if (s<0) {
        fprintf(stderr, "Filter failed. Exiting.\n");
        exit(-1);
    }

    s = pcap_setfilter(pcd, &filterd);
    if (s<0) {
        fprintf(stderr, "Filter failed. Exiting.\n");
        exit(-1);
    }

    //Check whether the port is open first:

    i=3;

    if (n = sendto(packet_tuple->sockfd, "X", 1, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen) == -1) {
        fprintf(stderr, "Error writing packet - unable to get a socket.\n");
        close(packet_tuple->sockfd);
        exit(-1);
    }

    else {

        while(i){

            res = pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);

            //run it 3 times for the sake of safety:

            if (pkt->len ==0) {
                i--;
                continue;
            }

            else {
                run_socktest((u_char *)pkt_ptr);

                if (!socktest_result) {
                    fprintf(stderr, "Port is not opened. Please check if the service is up and try again.\n");
                    exit(-1);
                }
            }

        }

    }

    pkt_ptr = NULL;
    o_pkt_ptr = NULL;


    while (1) {

        build_dns_client_pack(dheader, qrs, addrcds);

        fuzz_dns_client_pack(cpack, qrs, alen);

        if (n = sendto(packet_tuple->sockfd, cpack, hlen, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen) == -1) {
            fprintf(stderr, "Error writing packet - unable to get a socket.\n");
            close(packet_tuple->sockfd);
            exit(-1);
        }

        else {

            pcap_next_ex(pcd, &pktd, (const u_char **)&o_pkt_ptr);
            hlen = pktd->len;

            //n = sendto(packet_tuple->sockfd, "X", 1, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen);
            pcap_next_ex(pc, &pkt, (const u_char **)&pkt_ptr);

            if (pkt->len)
                run_socktest((u_char *)pkt_ptr);

            if (!socktest_result) {

                fprintf(stderr, "----- Test failed - saving to database.\n");

                time(&rawtime);
                timeinfo = localtime (&rawtime);
                strftime (time_buffer, 80, "%X",timeinfo);

                //db_packet_save(cpack, hlen, pass_packet);
                db_packet_save(o_pkt_ptr, hlen, pass_packet);
                strncpy(new_entry->binary_pack_data, pass_packet, strlen(pass_packet));

                if (type_of_packet) {

                    if (strncmp(type_of_packet->l4_type, "udp", 3)==0)
                        strncpy(new_entry->misc_description, "dns", 3);
                    else
                        strncpy(new_entry->misc_description, "\0\0\0", 3);

                }

                insert_new_db_entry(conn, new_entry->protocol, new_entry);
                get_db_current_test_id(tuple->protocol, test_id);


                if (tuple->verbose) {
                    fprintf(stderr, "-- %s -- Test failed. Saving the following packet to packet.pcap: \n", time_buffer);
                    packet_save(o_pkt_ptr, hlen);
                }


                memset(time_buffer, '\0', strlen(time_buffer));

                if (tuple->quit){
                    exit(1);
                }
                fail_count++;

                usleep(tuple->timer);
                memset(filter_exp, '\0', 150);
                memset(filterd_exp, '\0', 150);

                memset(pkt_ptr, '\0', pkt->len);
                memset(o_pkt_ptr, '\0', pktd->len);

  /*
                pcap_freecode(&filter);
                pcap_close(pc);

                sprintf(port, "%d", packet_tuple->tcp_sp);
                strncat(filter_exp, tport, strlen(tport));
                strncat(filter_exp, port, strlen(port));
                strncat(filter_exp, filter_ext, strlen(filter_ext));
                strncat(filter_exp, tuple->destination, strlen(tuple->destination));
*/

                usleep(tuple->timer);

            }

        }

        fprintf(stderr, "Sending a DNS packet size of %d bytes, shipping %d attributes:\n", hlen, alen);

        /*
        for (i = 0; i<alen; i++) {
            fprintf(stderr, "attribute %d: %s-->%04x-->%04x\n", i+1, qrs[i].name, qrs[i].type, qrs[i].clas);
        }
        */

    }


   // close(packet_tuple->sockfd);



}



void build_dns_client_pack(struct dns_header *dheader, struct queries *qrs, struct addrecords *addrcds) {

    dheader->xid = htons(rand()%0xffff);
    dheader->flags = htons(0x0100);
    alen = rand()%13;
    //debug:
    alen = 1;
    dheader->questions = htons(alen);
    while (!alen) {
        alen = rand()%13;
        //debug:
        alen = 1;
        dheader->questions = htons(alen);
    }
    dheader->answers = 0;
    dheader->authrr = 0;
    dheader->addrr = 0;

    nlen = sizeof(struct dns_header);

    memcpy(cpack, dheader, nlen);

    hlen = nlen;
    plen[0] = 12;

    int i, var=0;

    for (i=0;i<13;i++) {
            memset(qrs[i].name, '\0', 124);
    }

    get_dummy_dns_queries(qrs, alen);

    for (i=0; i<alen; i++) {


        attlen = strlen(qrs[i].name);
        memcpy(&cpack[nlen+var], &qrs[i].name, attlen);
        var += attlen;
        cpack[nlen+var] = 0x00;
        var++;
        memcpy(&cpack[nlen+var], &qrs[i].type, 2);
        var += 2;
        memcpy(&cpack[nlen+var], &qrs[i].clas, 2);
        var += 2;
        plen[i+1] = plen[i]+attlen+5;

    }

    hlen += var;

  /*  memcpy(&cpack[nlen+var], addrcds, 11);

    hlen +=11;
*/
}


void get_dummy_dns_queries(struct queries *qrs, int num_qrs) {


    struct queries qdata[13] = {

        {"\x06google\x03\x63om", htons(0x0001), htons(0x0001)},
        {"\x06google\x03\x63om", htons(16), htons(0x0001)},
        {"\x07rasovic\x03net", htons(2), htons(0x0001)},
        {"\x07rasovic\x03net", htons(15), htons(0x0001)},
        {"\x03www\x06netbsd\x03org", htons(0x0001), htons(0x0001)},
        {"\x05pr0xy\x03\x63om", htons(0x0001), htons(0x0001)},
        {"\x05pr0xy\x03\x63om", htons(15), htons(0x0001)},
        {"\x03\x31\x30\x34\x01\x39\x03\x31\x39\x32\x02\x36\x36\x07in-addr\x04\x61rpa", htons(0x0001), htons(0x0001)},
        {"\x03\x31\x30\x34\x01\x39\x03\x31\x39\x32\x02\x36\x36\x07in-addr\x04\x61rpa", htons(12), htons(0x0001)},
        {"\x03www\x03isc\x03org", htons(28), htons(0x0001)},
        {"\x05\x5f\x6c\x64\x61\x70\x04\x5f\x74\x63\x70\x17\x44\x65\x66\x61\x75\x6c\x74\x2d\x46\x69\x72\x73\x74\x2d\x53\x69\x74\x65\x2d\x4e\x61\x6d\x65\x06\x5f\x73\x69\x74\x65\x73\x02\x64\x63\x06\x5f\x6d\x73\x64\x63\x73\x0b\x75\x74\x65\x6c\x73\x79\x73\x74\x65\x6d\x73\x05\x6c\x6f\x63\x61\x6c\x00", htons(33), htons(0x0001)},
        {"\x03www\x0awallpapers\x03org", htons(0x0001), htons(0x0001)},
        {"\x03www\x0awallpapers\x03org", htons(0x0002), htons(0x0001)}

    };

    int i, r;

    int arr[13] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

    shuffle(arr, 13);

    for (i=0; i<num_qrs; i++)
        qrs[i] = qdata[arr[i]];

}


void shuffle(int *array, size_t n){

    if (n > 1) {
        size_t i;
	for (i = 0; i < n - 1; i++) {
	  size_t j = i + rand() / (RAND_MAX / (n - i) + 1);
	  int t = array[j];
	  array[j] = array[i];
	  array[i] = t;
	}
    }
}


void run_socktest(u_char *pkt_ptr) {

    if ((int)pkt_ptr[23] == 1)
        socktest_result = 0;
    else
        socktest_result = 1;

}
