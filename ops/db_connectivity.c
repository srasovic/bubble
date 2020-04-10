
/*
 ##############################################################################
 Revision #      1.0
 Name:               :  db_connectivity.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  SQL Db routines for connecting to an internal database.
 ##############################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/database.h"

int table_rows;

u_char *sql_query;

void exit_db(PGconn *conn) {

    PQfinish(conn);
}


void db_packet_save(u_char *packet, int packet_size, u_int8_t *db_pack){

    int i, j;

    memset(db_pack, '\0', MAX_PACK_SIZE);

    for (i=0; i < packet_size; i++) {

        j = sprintf(&db_pack[strlen(db_pack)], "%02x|", packet[i]);

    }

}


PGconn * create_db_conn(u_char *password){


	PGconn          *conn;
	int             rec_count;
	int             row;
	int             col;

	u_char conninfo[100];
    memset(conninfo, '\0', 100);
	u_char *db_desc = "dbname = bubble host = localhost user = postgres password = ";

	strncpy(conninfo, db_desc, strlen(db_desc));

	//sanity check:

    if (password==NULL)
        strncat(conninfo, "postgres", strlen("postgres"));
    else
        strncat(conninfo, password, strlen(password));


	conn = PQconnectdb(conninfo);

	if (PQstatus(conn) != CONNECTION_OK) {
		fprintf(stderr, "Connection to database failed: %s", PQerrorMessage(conn));
	    exit_db(conn);
    }

    return conn;
}


void insert_new_db_entry(PGconn *conn, u_char* protocol, struct db_table_entry *new_entry) {

    u_char test_id[10];
    memset(test_id, '\0', 10);

	PGresult        *res;

	sql_query = calloc(1, MAX_PACK_ARRAY_SIZE*2);   // call free

	u_char *insert = "INSERT INTO ";
//	u_char *fields = "(Type_of_Packet,Type_of_Problem,OS_Version_Device,binary_pack_data,binary_diff_data) VALUES (\'";

    u_char *fields = "(type_of_packet,type_of_problem,os_version_device,comment,binary_pack_data,binary_diff_data,misc_description) VALUES (\'";


	strncpy(sql_query, insert, strlen(insert));
	strncat(sql_query, protocol, strlen(protocol));
	strncat(sql_query, fields, strlen(fields));
	strncat(sql_query, new_entry->packet_type, strlen(new_entry->packet_type));
	strncat(sql_query, "\',\'",3);
	strncat(sql_query, new_entry->problem_type, strlen(new_entry->problem_type));
	strncat(sql_query, "\',\'",3);
	strncat(sql_query, new_entry->os_version_device, strlen(new_entry->os_version_device));
	strncat(sql_query, "\',\'",3);
	strncat(sql_query, new_entry->comment, strlen(new_entry->comment));
	strncat(sql_query, "\',\'",3);
	strncat(sql_query, new_entry->binary_pack_data, strlen(new_entry->binary_pack_data));
	strncat(sql_query, "\',\'",3);
	strncat(sql_query, new_entry->binary_diff_data, strlen(new_entry->binary_diff_data));
    strncat(sql_query, "\',\'",3);
	strncat(sql_query, new_entry->misc_description, sizeof(u_int));
	strncat(sql_query, "\')",2);
    // there should be a separate routine here that creates a XML/HTML or similar file explaining what was malformed.
    // the routine should fill in new_entry->fuzz_description.

	res = PQexec(conn, sql_query);

	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
	    fprintf(stderr, "INSERT failed: %s", PQerrorMessage(conn));
        fprintf(stderr, "Entry already exists in the database.\n\n");
	}
	else {
        get_db_current_test_id(tuple.protocol, test_id);
        fprintf(stderr, "New entry %s created in the table %s\n", test_id, new_entry->protocol);
	}


    free(sql_query);
//    memset(new_entry->problem_type, '\0', strlen(new_entry->problem_type));
    memset(new_entry->binary_pack_data, '\0', strlen(new_entry->binary_pack_data));
    memset(new_entry->binary_diff_data, '\0', strlen(new_entry->binary_diff_data));
}


void delete_db_entry(u_char* protocol, char *test_id) {


    u_char * delete = "delete from energywise where test_id=";
    u_char * delete_all = "delete from energywise";

    sql_query = calloc(1, strlen(delete)+20);

    if (strncmp(test_id, "all", 3) == 0)
        strncpy(sql_query, delete_all, strlen(delete));
    else {
        strncpy(sql_query, delete, strlen(delete));
        strncat(sql_query, test_id, strlen(test_id));
    }

    PGresult        *res;

    PGconn *conn = create_db_conn(tuple.db_pass);

    res = PQexec(conn, sql_query);                              // ned to add a check for empty result (non-error, but "DELETE 0")
    if (PQresultStatus(res) != PGRES_COMMAND_OK)
        fprintf(stderr, "DELETE failed: %s", PQerrorMessage(conn));
    else {
        if (strncmp(test_id, "all", 3) == 0)
            fprintf(stderr, "All entries deleted from the table %s\n", tuple.db_protocol);
        else
            fprintf(stderr, "Entry %d deleted from the table %s\n", atoi(test_id), tuple.db_protocol);
    }

    exit(1);
}


PGresult * get_db_table_rows(PGconn *conn, u_char *protocol) {

	PGresult *res;
	char *sql_query = calloc(1, 1024);
    char *select = "select * from ";

    strncpy(sql_query, select, strlen(select));

    strncat(sql_query, protocol, strlen(protocol));

	res = PQexec(conn, sql_query);

	table_rows = PQntuples(res);
	return res;
}


void display_db_table(u_char *protocol, u_char *password) {

    char *select = "select test_id, type_of_packet, type_of_problem, os_version_device, comment from ";
	char *sql_query = calloc(1, 1024);

	strncpy(sql_query, select, strlen(select));
	strncat(sql_query, protocol, strlen(protocol));

    PGresult        *res;

    PGconn *conn = create_db_conn(password);

	res = PQexec(conn, sql_query);
    table_rows = PQntuples(res);

	int i = 0;

    fprintf(stderr, "Tests present in table %s:\n\n", protocol);
	fprintf(stderr, " test_id |    type_of_packet    |                 type_of_problem                 |                                os_version_device                                |             comment           \n");
	fprintf(stderr, "---------+----------------------+-------------------------------------------------+---------------------------------------------------------------------------------+-------------------------------\n");

	while (i < table_rows) {
		fprintf(stderr, " %-8s", PQgetvalue(res, i, 0));
		fprintf(stderr, "|");
		fprintf(stderr, " %-21s", PQgetvalue(res, i, 1));
		fprintf(stderr, "|");
		fprintf(stderr, " %-21s", PQgetvalue(res, i, 2));
		fprintf(stderr, "|");
		fprintf(stderr, " %-.80s", PQgetvalue(res, i, 3));
        fprintf(stderr, "|");
		fprintf(stderr, " %-.28s", PQgetvalue(res, i, 4));
        fprintf(stderr, "\n");
		i++;
	}
    fprintf(stderr, "\n");

}


u_char * get_db_test_id(PGconn *conn, u_char *protocol) {

	PGresult *res;
	char *sql_query = calloc(1, 1024);
    char *select = "select test_id from ";
    u_char *test_id= NULL;

    strncpy(sql_query, select, strlen(select));
    strncat(sql_query, protocol, strlen(protocol));

	res = PQexec(conn, sql_query);
//    table_rows = PQntuples(res);

	static int row = 0;
	int col = 0;

	if (row < table_rows) {
		test_id = PQgetvalue(res, row, col);
		row++;
        return test_id;
	}
}


void get_db_current_test_id(u_char *protocol, u_char *test_id){

	PGresult *res = NULL;
	if (tuple.db_pass==NULL)
        tuple.db_pass = "postgres";
    PGconn *conn = create_db_conn(tuple.db_pass);

    u_char *select = "select max(test_id) from ";
	memset(test_id, '\0', 10);
	u_char *sql_currval = calloc(1, 124);

    u_char *tid = NULL;

	strncat(sql_currval, select, strlen(select));
	strncat(sql_currval, protocol, strlen(protocol));

	res = PQexec(conn, sql_currval);
    /*
     if (PQresultStatus(res) != PGRES_COMMAND_OK) {
     fprintf(stderr, "test_id query failed: %s", PQerrorMessage(conn));
     exit(-1);
     }
     */
	tid = PQgetvalue(res, 0, 0);
    strncpy(test_id, tid, strlen(tid));


}



