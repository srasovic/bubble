
/*
 ####################################################################################
 Revision #      1.0
 Name:               :  send_from_db.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Routines for reading sample packets directly from a database.
 ####################################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/database.h"



void read_sample_db_pack(u_char *db_pass, u_char *protocol) {

    u_char *sample_table;
    int result = 0;

    int fd;
    FILE * fp;


    if (strncmp(protocol, "energywise", 10)==0)
        sample_table = "ew_sample";
    if (strncmp(protocol, "bgp", 3)==0)
        sample_table = "bgp_sample";
    if (strncmp(protocol, "arp", 3)==0)
        sample_table = "arp_sample";


    result = access("temp.pcap", F_OK);
    if (result!=-1)
        remove("temp.pcap");

    result = access("temp1.pcap", F_OK);
    if (result!=-1)
        remove("temp1.pcap");

    fd = open("temp.pcap", O_WRONLY| O_APPEND| O_CREAT);

    if (fd==-1) {
        fprintf(stderr, "Unable to open temp.pcap\n");
        exit(-1);
    }

    fp = fdopen(fd, "a");
    chmod("temp.pcap", S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);

    db_sample_pack = calloc(1, MAX_PACK_ARRAY_SIZE);

    PGconn *conn = create_db_conn(db_pass);
    PGresult *res;

    res = get_db_table_entry_all(conn, sample_table);
    get_db_data(conn, res, db_sample_pack);
    db_packet_convert(db_sample_pack, fd, fp);
    exit_db(conn);

    if (!res||!db_sample_pack) {
        fprintf(stderr, "No tests present in the database for table %s\n", tuple.db_protocol);
        close(fd);
        fclose(fp);
        free(db_sample_pack);
        remove("temp.pcap");
        exit(1);
    }

    else {
        int rc = system("editcap -T ether temp.pcap temp1.pcap");
        chmod("temp1.pcap", S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
        remove("temp.pcap");
        close(fd);
        fclose(fp);
        free(db_sample_pack);
    }

}
