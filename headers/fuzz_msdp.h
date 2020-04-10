
/*
 *  $Id: fuzz_bgp.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  fuzz_msdp.h - Network fuzzing library header file for MSDP protocol
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */



#define MSDP_PORT        639

// BGP message types:


struct sg_block {

    u_int16_t res1;
    u_int8_t res2;
    u_int8_t len;
    u_char group[4];
    u_char source[4];

};


struct msdp_header {

    u_int8_t type;
    u_int16_t len;
    u_int8_t count;
    u_char rp[4];
    struct sg_block start;

};



void build_dummy_msdp_pack(struct msdp_header *msdp_hdr);

void build_msdp_session(struct tuple * tuple);

void fuzz_msdp(u_char *packet, struct msdp_header *msdp_hdr);
