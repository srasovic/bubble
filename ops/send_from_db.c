
/*
 ##############################################################################
 Revision #      1.0
 Name:               :  send_from_db.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Routines for sending packets directly from a database.
 ##############################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/socket_ops.h"
#include "../headers/database.h"

extern int table_rows;

#define ETH_PROT_POS    12
#define ETH_PROT_POS    12
#define ETH_PROT_POS    12

#define IPv4_SRC_POS    26
#define IPv4_DST_POS    30

#define TCP_SP_POS      34
#define TCP_DP_POS      36
#define TCP_SEQ_POS     38
#define TCP_ACK_POS     42
#define TCP_SUM_POS     50

FILE * fp;
int fd;


void send_packet_from_db(u_char *db_pass, u_char *protocol) {

    int i=0, j=0, k=0, tid, num_packs = 1;
    char test_id[tuple.test_num][20];
    int misc_desc_num = 1;
    int pack_type[misc_desc_num];

    if(!tuple.source || !tuple.destination) {
        fprintf(stderr, "Sending from database requires specifing source and destination address. Try again.\n");
        exit(-1);
    }

    for (i=0;i<tuple.test_num;i++)
        memset(test_id[i], '\0', 20);


    for (i =0; i<tuple.test_num; i++)
        strncpy(test_id[i], tuple.test_id[i], strlen(tuple.test_id[i]));

    fd = open("temp.pcap", O_WRONLY| O_APPEND| O_CREAT);

    if (fd==-1) {
        fprintf(stderr, "Unable to open temp.pcap\n");
        exit(-1);
    }

    fp = fdopen(fd, "a");

    db_pack = calloc(1, MAX_PACK_ARRAY_SIZE);
    //    pass_packet = calloc(1, MAX_PACK_SIZE);

    PGconn *conn = create_db_conn(db_pass);
    PGresult *res[tuple.test_num];

    if (tuple.test_num) {

        for (i=0; i<tuple.test_num;i++) {
            res[i] = get_db_table_entry(conn, test_id[i], protocol);

            if (!table_rows) {
                fprintf(stderr, "Test ID %d is not present in the database\n", atoi(test_id[i]));
                j--;
            }

            else {
                misc_desc_num = table_rows;
                get_db_data(conn, res[i], db_pack);
                num_packs = get_num_db_packs(db_pack);
                get_db_packet_type(conn, res[i], pack_type);

                if (num_packs==1)
                    db_packet_convert(db_pack, fd, fp);
                else
                    split_db_data(num_packs);
                j++;
            }
        }
        j = j+num_packs;
    }

    else {
        res[0] = get_db_table_entry_all(conn, protocol);
        misc_desc_num = table_rows;

        while (i<table_rows) {
            get_db_data_all(conn, res[0], db_pack);
            num_packs = get_num_db_packs(db_pack);
            get_db_packet_type(conn, res[0], pack_type);

            if (num_packs==1)
                db_packet_convert(db_pack, fd, fp);
            else
                split_db_data(num_packs);
            i++;
        }
        j = i+num_packs;
    }

    //    PQfinish(conn);

    if(j) {
        close(fd);
        db_packet_inject((j-1), pack_type);
    }

    else {
        fprintf(stderr, "No tests present in the database for table %s\n", tuple.db_protocol);
        close(fd);
        remove("temp.pcap");
        exit(1);
    }

    fprintf(stderr, "Test completed.\n");

    //    free(db_pack);
    //    free(pass_packet);

    exit(1);

}


int get_num_db_packs(u_char *db_pack) {

	int i=0;
    char *token;
	char *pack_delimiter = "***";

    token = strtok(db_pack, pack_delimiter);

    while(token!=NULL) {
        token = strtok(NULL, pack_delimiter);
        i++;
    }

    return i;
}


void split_db_data(int num_packs) {

    u_char *temp_pack = NULL;
    u_char*pkt_ptr;
	char *pack_delimiter = "***";

    int i =1;

    temp_pack = strtok(db_pack, pack_delimiter);
    int pack_size = strlen(temp_pack);
    db_packet_convert(temp_pack, fd, fp);

    while(i<num_packs) {
        pkt_ptr = &temp_pack[pack_size+3];
        temp_pack = pkt_ptr;
        temp_pack = strtok(temp_pack, pack_delimiter);
        pack_size = strlen(temp_pack);

        db_packet_convert(temp_pack, fd, fp);
        i++;
    }
}


void split_db_data_to_console(int num_packs) {

    u_char *temp_pack = NULL;
    u_char*pkt_ptr;
	char *pack_delimiter = "***";

    int i =1;

    temp_pack = strtok(db_pack, pack_delimiter);
    int pack_size = strlen(temp_pack);
	fprintf(stderr, "%s\n\n", temp_pack);


    while(i<num_packs) {
        pkt_ptr = &temp_pack[pack_size+3];
        temp_pack = pkt_ptr;
        temp_pack = strtok(temp_pack, pack_delimiter);
        pack_size = strlen(temp_pack);

		fprintf(stderr, "%s\n\n", temp_pack);
        i++;
    }
}


PGresult * get_db_table_entry(PGconn *conn, u_char *test_id, u_char *protocol) {


	PGresult *res=NULL;
	char *sql_query = calloc(1, 1024);
    char *select = "select * from ";
    char *where = " where test_id=";

    strncpy(sql_query, select, strlen(select));
    strncat(sql_query, protocol, strlen(protocol));
    strncat(sql_query, where, strlen(where));
    strncat(sql_query, test_id, strlen(test_id));

	res = PQexec(conn, sql_query);
    table_rows = PQntuples(res);

    free(sql_query);
	return res;
}


PGresult * get_db_table_entry_all(PGconn *conn, u_char *protocol) {


	PGresult *res=NULL;
	char *sql_query = calloc(1, 1024);
    char *select = "select * from ";

    strncpy(sql_query, select, strlen(select));
    strncat(sql_query, protocol, strlen(protocol));

	res = PQexec(conn, sql_query);
    table_rows = PQntuples(res);

    if (!table_rows) {
        fprintf(stderr, "No entries present in the table %s\n", protocol);
        exit(-1);
    }

    free(sql_query);
	return res;
}


void get_db_data(PGconn *conn, PGresult *res, u_char *pass_pack) {

    //
    pass_packet=NULL;

	int row = 0;
	int col = 5;

    pass_packet = PQgetvalue(res, row, col);
    memset(pass_pack, '\0', strlen(pass_pack));

    strncpy(pass_pack, pass_packet, MAX_PACK_ARRAY_SIZE);

}


void get_db_data_all(PGconn *conn, PGresult *res, u_char *pass_pack) {

    //
    pass_packet=NULL;

	static int row = 0;
	int col = 5;

    if (row<table_rows) {

        pass_packet = PQgetvalue(res, row, col);
        memset(pass_pack, '\0', strlen(pass_pack));
        strncpy(pass_pack, pass_packet, MAX_PACK_ARRAY_SIZE);
    }
    row++;
}


void get_db_packet_type(PGconn *conn, PGresult *res, int pack_type[]) {

    //
    u_char *db_pack_type;

    int row = 0;
    static int count = 0;
    int type = 7;

    if (tuple.test_num) {
        db_pack_type = PQgetvalue(res, row, type);
    }
    else
        db_pack_type = PQgetvalue(res, count

                                  , type);

    if (strncmp(db_pack_type, "udp", 3)==0)
        pack_type[count] = 17;
    else if (strncmp(db_pack_type, "dns", 3)==0)
        pack_type[count] = 17;
    else if (strncmp(db_pack_type, "tcp", 3)==0)
        pack_type[count] = 6;
    else
        pack_type[count] = 0;

    count++;
}


void get_db_entry_data(PGconn *conn, PGresult *res, int test_id) {

	int row = test_id;
	int col = 5;

	db_pack = PQgetvalue(res, row, col);

}


void db_packet_convert(u_char *packet, int fd, FILE *fp) {

    int j;
    time_t rawtime;
    struct tm * timeinfo;
    time(&rawtime);
    char time_buffer_pcap[80], time_buffer_log[80];

    const u_char * pcap_hdr_string = "+---------+---------------+----------+\n";
    const u_char *pcap_hdr_ethernet = "   ETHER\n";
    const u_char *pcap_hdr_pad = "|0   |";

    // Packet size may need to be modified:

    u_char pcap_packet[2048];
    memset(pcap_packet, '\0', 2048);

    timeinfo = localtime (&rawtime);

    /*
     I have no clue what do those 2 numbers after HH:MM:SS stand for. (111,111) - should check wireshark code for that.
     Apparently, changing them to some other value makes no difference to the .pcap file readability.
     But they both have to be present as 3-digit numbers other than 000.
     Guess those are needed for milisecond resolution or so - will fix this part in the future if needed.
     */

    strftime (time_buffer_pcap, 80, "%X,111,111",timeinfo);
    strftime (time_buffer_log, 80, "%X",timeinfo);
    strncpy(pcap_packet, pcap_hdr_string, strlen(pcap_hdr_string));
    strncat(pcap_packet, time_buffer_pcap, strlen(time_buffer_pcap));
    strncat(pcap_packet, pcap_hdr_ethernet, strlen(pcap_hdr_ethernet));
    strncat(pcap_packet, pcap_hdr_pad, strlen(pcap_hdr_pad));


    j = write(fd, pcap_packet, strlen(pcap_packet));

    j = fprintf(fp, "%s", packet);

    j = fprintf(fp, "\n\n");

    fflush(fp);

    memset(pcap_packet, '\0', strlen(pcap_packet));

    //    fclose(fp);
    //    close(fd);

}


void db_l3_src_packet_mangle(u_char *packet, struct packet_tuple *packet_tuple) {


    libnet_t *libt;
    char errbuf[LIBNET_ERRBUF_SIZE];
    u_int32_t src_ip;

    int j = 0, maclen = 6, i = 0;

    u_int8_t src_mac[ETH_ADDR_LEN];
    struct libnet_ether_addr *my_mac;

    libt = build_libnet_link_adv(&tuple);

    if (packet_tuple->mac_set) {

        for (i=0; i < sizeof(packet_tuple->src_mac); i++) {
            packet[i+6] = packet_tuple->src_mac[i];
        }

    }

    else {

        my_mac = libnet_get_hwaddr(libt);

        for (i=0; i < maclen; i++) {
            packet[i+6] = my_mac->ether_addr_octet[i];

        }
    }

    u_char first[3], second[3], third[3], forth[3];
    int a, b, c, d;
    a = b = c = d = 0;

    for (i =0; i<4; i++, j++) {
        if (tuple.source[i] == '.') {
            j++;
            break;
        }
        first[i] = tuple.source[j];
    }

    for (i=0; i<4; j++, i++) {
        if (tuple.source[j] == '.') {
            j++;
            break;
        }
        second[i] = tuple.source[j];
    }

    for (i=0; i<4; j++, i++) {
        if (tuple.source[j] == '.') {
            j++;
            break;
        }
        third[i] = tuple.source[j];
    }

    for (i=0; i<4; j++, i++) {
        if (tuple.source[j] == '.') {
            j++;
            break;
        }
        forth[i] = tuple.source[j];
    }

    a = atoi(first);
    b = atoi(second);
    c = atoi(third);
    d = atoi(forth);

    packet[IPv4_SRC_POS] = a;
    packet[IPv4_SRC_POS+1] = b;
    packet[IPv4_SRC_POS+2] = c;

    packet[IPv4_SRC_POS+3] = d;

    libnet_destroy(libt);

}


void db_l3_dst_packet_mangle(u_char *packet, struct packet_tuple *packet_tuple) {


    libnet_t *libt;
    char errbuf[LIBNET_ERRBUF_SIZE];
    u_int32_t dst_ip;

    int j = 0, maclen = 6, i = 0;

    u_char *mac_addr_str_dst, *mac_addr_dst;

    libt = build_libnet_link_adv(&tuple);

    if (packet_tuple->mac_set) {

        for (i=0; i < sizeof(packet_tuple->dst_mac); i++) {
            packet[i] = packet_tuple->dst_mac[i];
        }

    }

    else {

        get_mac_address(tuple.destination, mac_addr_str_dst);

        mac_addr_dst = libnet_hex_aton(mac_addr_str_dst, &maclen);

        for (i=0; i < maclen; i++) {
            packet[i] = mac_addr_dst[i];
        }

    }

    u_char first[3], second[3], third[3], forth[3];
    int a, b, c, d;
    a = b = c = d = 0;

    for (i =0; i<4; i++, j++) {
        if (tuple.destination[i] == '.') {
            j++;
            break;
        }
        first[i] = tuple.destination[j];
    }

    for (i=0; i<4; j++, i++) {
        if (tuple.destination[j] == '.') {
            j++;
            break;
        }
        second[i] = tuple.destination[j];
    }

    for (i=0; i<4; j++, i++) {
        if (tuple.destination[j] == '.') {
            j++;
            break;
        }
        third[i] = tuple.destination[j];
    }

    for (i=0; i<4; j++, i++) {
        if (tuple.destination[j] == '.') {
            j++;
            break;
        }
        forth[i] = tuple.destination[j];
    }

    a = atoi(first);
    b = atoi(second);
    c = atoi(third);
    d = atoi(forth);

    packet[IPv4_DST_POS]= a;
    packet[IPv4_DST_POS+1] = b;
    packet[IPv4_DST_POS+2] = c;
    packet[IPv4_DST_POS+3] = d;

    //    libnet_destroy(libt);

}


void db_l4_packet_mangle(u_char *packet, struct packet_tuple *packet_tuple, int len, struct tuple *tuple) {

    u_int16_t tcp_sp = htons(packet_tuple->tcp_sp);
    u_int32_t tcp_seq = htonl(packet_tuple->tcp_seq);
    u_int32_t tcp_ack = htonl(packet_tuple->tcp_ack);

    memcpy((void *)&packet[TCP_SP_POS], &tcp_sp, sizeof(packet_tuple->tcp_sp));
    memcpy((void *)&packet[TCP_SEQ_POS], &tcp_seq, sizeof(packet_tuple->tcp_seq));
    memcpy((void *)&packet[TCP_ACK_POS], &tcp_ack, sizeof(packet_tuple->tcp_ack));

    u_int16_t sum = compute_tcp_checksum(packet, len, tuple);

    memcpy((void *)&packet[TCP_SUM_POS], &sum, sizeof(u_int16_t));

}


void db_packet_inject(int num_packs, int packet_type[]) {

    type_of_packet = (struct type_of_packet *) calloc(1, sizeof(struct type_of_packet));

    u_char *packet = NULL;
    struct pcap_pkthdr header;
    pcap_t *pc;
    char perrbuf[PCAP_ERRBUF_SIZE];
    int i, j, b, n;
    int payload_len;
    static int num =1;
    u_char dport[2], prot[2];


    u_int32_t src_ip;

    struct packet_tuple *packet_tuple = calloc(1, sizeof(struct packet_tuple));

    remove( "temp1.pcap" );

    int rc = system("editcap -T ether temp.pcap temp1.pcap");

    libnet_t *libt;
    libt = build_libnet_link_adv(&tuple);

    FILE *fp = fopen("temp1.pcap", "r");

    if (rc == -1)
        perror("packet convert failed:");

    if(remove( "temp.pcap" ) != 0)
        perror("Error deleting file");

    pc = pcap_fopen_offline(fp, perrbuf);

    if (!pc)
        fprintf(stderr, "Unable to open temp.pcap: %s\n", perrbuf);

    for (i = 0; i<num_packs; i++) {

        packet = (u_char *)pcap_next(pc, &header);

        if (!packet){
            fprintf(stderr, "No packet to read. Exiting.\n");
            exit(-1);
        }

        else {

            dport[0] = packet[TCP_DP_POS];
            dport[1] = packet[TCP_DP_POS+1];
            prot[0] = packet[ETH_PROT_POS];
            prot[1] = packet[ETH_PROT_POS+1];

            if (strncmp(prot, "0x0800", 2))
                strncpy(type_of_packet->l3_type, "ipv4", 4);
            else
                strncpy(type_of_packet->l3_type, "ipv6", 4);

            if (tuple.source && tuple.destination) {
                db_l3_src_packet_mangle(packet, packet_tuple);
                db_l3_dst_packet_mangle(packet, packet_tuple);
            }

            if (packet_type[i] == 6){

                src_ip = libnet_name2addr4(libt, tuple.source, LIBNET_DONT_RESOLVE);

                if (libnet_get_ipaddr4(libt) != src_ip) {
                    fprintf(stderr, "Spoofing isn't supported for TCP sessions in non-proxy mode.\n");
                    exit(-1);
                }

                payload_len = header.len - IP_TCPSEG_LEN;
                packet_tuple->tcp_dp = (unsigned char)dport[0] * 256 + (unsigned char)dport[1];
                strncpy(type_of_packet->l4_type, "tcp", 3);

                establish_tcp_session(&tuple, packet_tuple);

                fprintf(stderr, "Sending packet #%d\n", num);
                num++;

                if ((n =write(packet_tuple->sockfd, &packet[header.len - payload_len], (payload_len)))==-1) {
                    fprintf(stderr, "Error writing packet.\n");
                    exit(-1);
                }


                usleep(tuple.timer);
                close_tcp_session(packet_tuple->sockfd);     //

            }

            else {
                strncpy(type_of_packet->l4_type, "udp", 3);

                if (tuple.num) {
                    fprintf(stderr, "Sending batch of packets #%d\n", num);
                    for(j=0;j<tuple.num;j++) {
                        b = libnet_db_packet_inject(libt, packet, header.len);
                    }
                    num++;
                }

                else {
                    fprintf(stderr, "Sending packet #%d\n", num);
                    num++;
                    b = libnet_db_packet_inject(libt, packet, header.len);
                    if (b==-1)
                        fprintf(stderr, "%s\n", libnet_geterror(libt));
                }

            }



        }

        if (tuple.timer)
            usleep(tuple.timer);

    }

    if(remove( "temp1.pcap" ) != 0)
        perror("Error deleting file");

    libnet_destroy(libt);


}


int libnet_db_packet_inject(libnet_t* libt, u_char *packet, int len) {

    libnet_destroy(libt);
    char errbuf[LIBNET_ERRBUF_SIZE];
    int b;

    libt = build_libnet_link_adv(&tuple);
    b = libnet_adv_write_link(libt, packet, len);
    //    libnet_destroy(libt);
    return b;

}


void dump_db_packet_to_console(u_char *protocol, u_char *db_pass) {


    int i=0, j=0, tid;
    char test_id[tuple.test_num][20];
    int num_packs = 1;
    int pack_type = 0;

    if(tuple.test_num) {
        for(i=0;i<tuple.test_num;i++) {
            memset(test_id[i], '\0', 20);
            strncpy(test_id[i], tuple.test_id[i], strlen(tuple.test_id[i]));
        }
    }
    else
        memset(test_id[0], '\0', 20);

    db_pack = (u_char *)calloc(1, MAX_PACK_ARRAY_SIZE);

    PGconn *conn = create_db_conn(db_pass);
    PGresult *res[tuple.test_num];

    if (tuple.test_num) {
        for (i=0; i<tuple.test_num;i++) {
            res[i] = get_db_table_entry(conn, test_id[i], protocol);
            fprintf(stderr, "\nPacket test_id #%s:\n", test_id[i]);
            if (!table_rows) {
                fprintf(stderr, "Test ID %d is not present in the database\n", atoi(test_id[i]));
            }
            else {
                get_db_data(conn, res[i], db_pack);
                num_packs = get_num_db_packs(db_pack);
                if (num_packs==1)
                	fprintf(stderr, "%s\n\n", db_pack);
                else
                    split_db_data_to_console(num_packs);

                j++;
            }
        }
    }

    else {
        res[0] = get_db_table_entry_all(conn, protocol);
        while (i<table_rows) {
            get_db_data_all(conn, res[0], db_pack);
            num_packs = get_num_db_packs(db_pack);

            if (num_packs==1) {
				fprintf(stderr, "\nPacket test_id #%s:\n", get_db_test_id(conn, protocol));
                fprintf(stderr, "%s\n\n", db_pack);
            }
            else
                split_db_data_to_console(num_packs);
            i++;
        }
    }

    //  free(pass_packet);
    //    free(db_pack);
    //    exit_db(conn);

}


void dump_db_packet_to_capture(u_char *protocol, u_char *db_pass, u_char *file) {


    int i=0, j=0, tid;
    char test_id[tuple.test_num][20];
    int num_packs = 1;
    int pack_type = 0;

    if(tuple.test_num) {
        for(i=0;i<tuple.test_num;i++) {
            memset(test_id[i], '\0', 20);
            strncpy(test_id[i], tuple.test_id[i], strlen(tuple.test_id[i]));
        }
    }
    else
        memset(test_id[0], '\0', 20);


    remove(file);

    fd = open(file, O_WRONLY| O_APPEND| O_CREAT);

    if (fd==-1) {
        fprintf(stderr, "Unable to create a file %s\n", file);
        exit(-1);
    }

    chown(file, userid, groupid);
    chmod(file, S_IRWXU | S_IRWXG | S_IRWXO);

    setgid(groupid);
    setuid(userid);

    fp = fdopen(fd, "a");

    db_pack = (u_char *)calloc(1, MAX_PACK_ARRAY_SIZE);

    fprintf(stderr, "Saving to %s...\n", file);

    PGconn *conn = create_db_conn(db_pass);
    PGresult *res[tuple.test_num];

    if (tuple.test_num) {
        for (i=0; i<tuple.test_num;i++) {
            res[i] = get_db_table_entry(conn, test_id[i], protocol);
            if (!table_rows) {
                fprintf(stderr, "Test ID %d is not present in the database\n", atoi(test_id[i]));
            }
            else {
                get_db_data(conn, res[i], db_pack);
                num_packs = get_num_db_packs(db_pack);
                if (num_packs==1)
                	fprintf(stderr, "%s\n\n", db_pack);
                else
                    split_db_data(num_packs);
            }
        }
    }

    else {
        res[0] = get_db_table_entry_all(conn, protocol);
        while (i<table_rows) {
            get_db_data_all(conn, res[0], db_pack);
            num_packs = get_num_db_packs(db_pack);

            if (num_packs==1)
                db_packet_convert(db_pack, fd, fp);
            else
                split_db_data(num_packs);
            i++;
        }
    }

    close(fd);

    //    setgid(0);
    //    setuid(0);

    //    free(db_pack);
    //   free(pass_packet);
    //    exit_db(conn);

}


