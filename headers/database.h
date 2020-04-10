

/*
 *  $Id: fuzz.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  database.h - Network fuzzing library header file for database tasks
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */




struct db_table_entry {
	u_char protocol[48];
	u_char packet_type[48];
	u_char problem_type[48];
	u_char os_version_device[96];
    u_char comment[28];
    const u_int pad2:20;
	u_char binary_pack_data[MAX_PACK_ARRAY_SIZE];
	u_char binary_diff_data[MAX_PACK_ARRAY_SIZE];
    u_char misc_description[3];
};


struct db_table_entry *ssh_entry;

u_char *db_pack, *pass_packet, *db_sample_pack;


void db_packet_save(u_char *packet, int packet_size, u_int8_t *db_pack);

void db_packet_convert(u_char *packet, int fd, FILE *fp);

void db_packet_inject(int num_packs, int packet_type[]);

int libnet_db_packet_inject(libnet_t* libt, u_char *packet, int len);


void exit_db(PGconn *conn);

PGconn * create_db_conn(u_char *password);

void insert_new_db_entry(PGconn *conn, u_char* protocol, struct db_table_entry *new_entry);

void delete_db_entry(u_char* protocol, char *test_id);

PGresult * get_db_table_rows(PGconn *conn, u_char *protocol);

PGresult * get_db_table_entry(PGconn *conn, u_char *test_id, u_char *protocol);

PGresult * get_db_table_entry_all(PGconn *conn, u_char *protocol);

u_char * get_db_test_id(PGconn *conn, u_char *protocol);

void get_db_data(PGconn *conn, PGresult *res, u_char *pass_packet);

void get_db_data_all(PGconn *conn, PGresult *res, u_char *pass_pack);

void get_db_packet_type(PGconn *conn, PGresult *res, int pack_type[]);

void get_db_entry_data(PGconn *conn, PGresult *res, int test_id);

void get_db_current_test_id(u_char *protocol, u_char *test_id);

void send_packet_from_db(u_char *db_pass, u_char *protocol);

void display_db_table(u_char *protocol, u_char *password);

void dump_db_packet_to_console(u_char *protocol, u_char *db_pass);

void dump_db_packet_to_capture(u_char *protocol, u_char *db_pass, u_char *file);

int get_num_db_packs(u_char *db_pack);

void split_db_data(int num_packs);

void split_db_data_to_console(int num_packs);

void read_sample_db_pack(u_char *db_pass, u_char *protocol);
