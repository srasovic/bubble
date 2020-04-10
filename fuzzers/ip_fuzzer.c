
/*
    ##############################################################################
    Revision #      1.0
    Name:               :  ip_fuzzer.c
    Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
    Description         :  Routine for fuzzing over IPv4 protocol data.
    ##############################################################################
*/


#include "../headers/fuzz.h"
#include "../headers/fuzz_ipv4.h"


int ipv4_field_offsets[] =   {
                        offsetof(struct ip_header, version), offsetof(struct ip_header, len), \
                        offsetof(struct ip_header, tos), offsetof(struct ip_header, id), \
                        offsetof(struct ip_header, flags), offsetof(struct ip_header, offset), \
                        offsetof(struct ip_header, ttl), offsetof(struct ip_header, protocol), \
                        offsetof(struct ip_header, checksum), offsetof(struct ip_header, source), \
                        offsetof(struct ip_header, destination)
                        };


char rand_str_1[8];
char rand_str_2[16];
char rand_str_4[32];


void fuzz_ipv4(u_char *pkt_ptr) {

    char saddress[16];

    char *dummy_v4_address = "1.1.1.1";

    int x, i, z =0, y;

    x = rand() % 10;        //number of fields to fuzz.
    while (x==0)
        x = rand() % 10;

    for (i=0; i<x; i++) {

        if (x==1)
        y=1;

        else {
            y = rand() %10;
            while (y==z || y==0)
                y = rand() %10;
        }

        if (y==2 || y==3 || y==5 || y==7 || y==8) {
            rand_str_gen(rand_str_1, sizeof(rand_str_1));
            memcpy((u_char *)pkt_ptr+ipv4_field_offsets[y-1], rand_str_1, sizeof(rand_str_1));
        }

        else if (y==4 || y==6 || y==9) {
            rand_str_gen(rand_str_2, sizeof(rand_str_2));
            memcpy((u_char *)pkt_ptr+ipv4_field_offsets[y-1], rand_str_2, sizeof(rand_str_2));
        }

        else if (y==10) {
            rand_ipv4_gen(dummy_v4_address, saddress);
            dest_ipv4_overwrite(saddress, (u_char *)pkt_ptr+ipv4_field_offsets[y-1]);
        }
    }

    z = y;
}

