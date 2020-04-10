


/*
 *  $Id: fuzz.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  fuzz_dns.h - Network fuzzing library header file for DNS protocol
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */


#define DNS_SPORT    53
#define DNS_CLIENT   1
#define DNS_SERVER   2

#define DNS_MAX_QRS    24

#define DNS_MAX_NAME_LEN    124



struct queries {

    u_char name[DNS_MAX_NAME_LEN];
    u_int16_t type;
    u_int16_t clas;
};


struct addrecords {

    u_int8_t name;
    u_int16_t type;
    u_int16_t psize;
    u_int8_t hbits;
    u_int8_t version;
    u_int16_t z;
    u_int16_t dlen;

};


struct dns_header {

    u_int16_t xid;
    u_int16_t flags;
    u_int16_t questions;
    u_int16_t answers;
    u_int16_t authrr;
    u_int16_t addrr;

};


void build_dns_client_pack(struct dns_header *dheader, struct queries *qrs, struct addrecords *addrcds);

void build_dns_session(struct tuple *tuple);

void get_dummy_dns_queries(struct queries *qrs, int num_qrs);

void fuzz_dns_client_pack(u_char *cpack, struct queries *qrs, int alen);

void shuffle(int *array, size_t n);

void run_socktest(u_char *pkt_ptr);
