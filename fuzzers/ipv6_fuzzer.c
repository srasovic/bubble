
/*
    ##############################################################################
    Revision #      1.0
    Name:               :  ipv6_fuzzer.c
    Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
    Description         :  Routine for fuzzing over IPv6 protocol data.
    ##############################################################################
*/


#include "../headers/fuzz.h"
#include "../headers/fuzz_ipv6.h"


int ipv6_field_offsets[] =   {
                        offsetof(struct ipv6_header, version_class), offsetof(struct ipv6_header, len), \
                        offsetof(struct ipv6_header, next), offsetof(struct ipv6_header, hop), \
                        offsetof(struct ipv6_header, source), offsetof(struct ipv6_header, destination)
                        };


char rand_str_1[8];
char rand_str_2[16];
char rand_str_4[32];


void fuzz_ipv6(u_char *pkt_ptr){
}


void dest_ipv6_overwrite(u_char* address_string, u_char * destination) {
}


