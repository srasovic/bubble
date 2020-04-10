
/*
    ##############################################################################
    Revision #      1.0
    Name:               :  arp_fuzzer.c
    Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
    Description         :  Routines for fuzzing over ARP protocol data.
    ##############################################################################
*/


#include "../headers/fuzz.h"
#include "../headers/fuzz_arp.h"


#define RESERVED        0
#define REQUEST         1
#define REPLY           2
#define REV_REQ         3
#define REV_REP         4
#define DRARP_REQ       5
#define DRARP_REP       6
#define DRARP_ERR       7
#define INARP_REQ       8
#define INARP_REP       9
#define NAK             10

char rand_str_1[8];
char rand_str_2[16];
char rand_str_4[32];
char rand_str[48];

char *dummy_v4_address = "1.12.3.5";

extern u_int8_t *mac_addr;


int arp_field_offsets[] =   {
                        offsetof(struct arp_header, hw_type), offsetof(struct arp_header, protocol), \
                        offsetof(struct arp_header, hw_size), offsetof(struct arp_header, p_size), \
                        offsetof(struct arp_header, opcode), offsetof(struct arp_header, smac), \
                        offsetof(struct arp_header, sip)-2, offsetof(struct arp_header, tmac)-2, \
                        offsetof(struct arp_header, tip)-4
                        };


/*

 Offsetof may have different results on different platforms due to lining of char[6] in the struct. In case its not portrable, use straightforward:


 int arp_field_offsets[] =   {
                        0, 2, 4, 5, 6, 8, 14, 18, 24, 28
                        };

 */

/*
    The problem with rand() in this case, is it will never produce the same set of results between 2 runs. It is even more evident with srand().
    This, of course, is diminished by the fact that failed tests are logged/captured.
    In case static/monotonus character of testing is needed, those functions will have to be completely changed for non-random equivalents that will intruduce some "order" in fuzzing - I wanted to avoid that from the beggining, even if that means getting different packets every time its run.
 */


void fuzz_arp_multid(u_char *pkt_ptr) {


    int x, y, w, i, p;

    char saddress[16], taddress[16];

    rand_ipv4_gen(dummy_v4_address, saddress);
    dest_ipv4_overwrite(saddress, pkt_ptr+arp_field_offsets[6]);

    p = rand();

    if (p%2)
        dest_ipv4_overwrite(tuple.destination, pkt_ptr+arp_field_offsets[8]);
    else {
        rand_ipv4_gen(dummy_v4_address, taddress);
        dest_ipv4_overwrite(taddress, pkt_ptr+arp_field_offsets[8]);
    }

    char hw_type_str[2];
    char opcode_str[2];


    x = rand() % 7;                 // number of fields to fuzz - 7 is chosen as other fields are already randomized above
    while (x==0)
        x = rand() % 7;

    for (i=0; i<x; i++) {

        if (x==1)
            y=1;

        else {
            y = rand() % 9;             //the field to fuzz in this iteration
            while (y==0)
                y = rand() % 9;
        }

        //hw_type - 36 known values - the remaining 4 here are left for additional fuzz-ing:
        if (y==1) {
            w = rand() % 40;
            hw_type_str[0] = 0x00;
            hw_type_str[1] = w;
            memcpy((u_char *)pkt_ptr+arp_field_offsets[y-1], hw_type_str, 2);
        }

        // ethertype:
        else if (y==2) {
            rand_str_gen(rand_str_2, sizeof(rand_str_2));
            memcpy((u_char *)pkt_ptr+arp_field_offsets[y-1], rand_str_2, sizeof(rand_str_2));
        }

        //opcode - 25 known values - the remaining 5 here are left for additional fuzz-ing:
        else if (y==5) {
            w = rand() % 30;
            opcode_str[0] = 0x00;
            opcode_str[1] = w;
            memcpy((u_char *)pkt_ptr+arp_field_offsets[y-1], opcode_str, 2);
        }

        // hw_size and p_size:
        else if (y==3 || y==4) {
            rand_str_gen(rand_str_1, sizeof(rand_str_1));
            memcpy((u_char *)pkt_ptr+arp_field_offsets[y-1], rand_str_1, sizeof(rand_str_1));
        }

        // smac and dmac:
        else if (y==6 || y==8) {
            rand_mac_gen(rand_str, sizeof(rand_str));
            memcpy((u_char *)pkt_ptr+arp_field_offsets[y-1], rand_str, sizeof(rand_str));
        }
    }
}


void fuzz_arp(u_char *pkt_ptr) {


    int x, y, w, i, p, r, o;

    int maclen = MACSIZE;

    char saddress[16], taddress[16];
    memset(saddress, 0, 16);

    char hw_type_str[2];

    struct sockaddr_in sa;

    struct arp_header *arph = calloc(sizeof(struct arp_header), 1);

    parse_arp_pack(pkt_ptr, arph);

    p = rand() % 10;
    while (!p)
        p = rand() % 10;

    //debugging:
    p = 3;

    pkt_ptr[7] = p;

    switch (p) {

        case REQUEST:

            rand_ipv4_octet_gen(tuple.destination, 4, saddress);
            rand_mac_gen(rand_str,6);

            memcpy(&pkt_ptr[8], rand_str, 6);

            inet_pton(AF_INET, saddress, &(sa.sin_addr));
            pkt_ptr[14] = sa.sin_addr.s_addr;
            pkt_ptr[15] = sa.sin_addr.s_addr >> 8;
            pkt_ptr[16] = sa.sin_addr.s_addr >> 16;
            pkt_ptr[17] = sa.sin_addr.s_addr >> 24;

            r = rand() % 255;

            if (r%2) {
                for (i = 0;i<maclen;i++)
                    pkt_ptr[18+i] = '\0';
            }
            else {
                rand_mac_gen(rand_str, 6);
                memcpy(&pkt_ptr[18], rand_str, 6);
            }


            inet_pton(AF_INET, tuple.destination, &(sa.sin_addr));
            pkt_ptr[24] = sa.sin_addr.s_addr;
            pkt_ptr[25] = sa.sin_addr.s_addr >> 8;
            pkt_ptr[26] = sa.sin_addr.s_addr >> 16;
            pkt_ptr[27] = sa.sin_addr.s_addr >> 24;

            r = rand() % 80;
            while (!r)
                r = rand() % 80;

            if (r<5) {
                w = rand() % 40;
                hw_type_str[0] = 0x00;
                hw_type_str[1] = w;
                memcpy((u_char *)pkt_ptr, hw_type_str, 2);
            }

            else if (r>5 && r<10) {
                rand_str_gen(rand_str_2, sizeof(rand_str_2));
                memcpy((u_char *)&pkt_ptr[2], rand_str_2, 2);
            }

            else if (r>40 && r<60) {
                rand_str_gen(rand_str_1, sizeof(rand_str_1));
                memcpy((u_char *)&pkt_ptr[4], rand_str_1, 1);

            }

            else {
                rand_str_gen(rand_str_1, sizeof(rand_str_1));
                memcpy((u_char *)&pkt_ptr[5], rand_str_1, 1);

                if (pkt_ptr[5] == '\0') {

                    r = rand() % 10;

                    if (r <2 ) {
                        for (i = 0;i<maclen;i++)
                            pkt_ptr[8+i] = mac_addr[i];
                        for (i = 0;i<maclen;i++)
                            pkt_ptr[14+i] = mac_addr[i];
                    }

                }

            }

            break;

        case REPLY:

            rand_ipv4_octet_gen(tuple.source, 4, saddress);
            inet_pton(AF_INET, saddress, &(sa.sin_addr));
            pkt_ptr[14] = sa.sin_addr.s_addr;
            pkt_ptr[15] = sa.sin_addr.s_addr >> 8;
            pkt_ptr[16] = sa.sin_addr.s_addr >> 16;
            pkt_ptr[17] = sa.sin_addr.s_addr >> 24;

            inet_pton(AF_INET, tuple.destination, &(sa.sin_addr));
            pkt_ptr[24] = sa.sin_addr.s_addr;
            pkt_ptr[25] = sa.sin_addr.s_addr >> 8;
            pkt_ptr[26] = sa.sin_addr.s_addr >> 16;
            pkt_ptr[27] = sa.sin_addr.s_addr >> 24;

            rand_mac_gen(rand_str,6);
            memcpy(&pkt_ptr[8], rand_str, 6);

            r = rand() % 255;

            if (r <90) {
                for (i = 0;i<maclen;i++)
                    pkt_ptr[18+i] = '\0';
            }
            else if (r>90 && r<180) {
                rand_mac_gen(rand_str, 6);
                memcpy(&pkt_ptr[18], rand_str, 6);
            }
            else {
                for (i = 0;i<maclen;i++)
                    pkt_ptr[18+i] = mac_addr[i];
            }

            r = rand() % 80;

            while (!r)
                r = rand() % 80;


            if (r<5) {
                w = rand() % 40;
                hw_type_str[0] = 0x00;
                hw_type_str[1] = w;
                memcpy((u_char *)pkt_ptr, hw_type_str, 2);
            }

            else if (r>5 && r<10) {
                rand_str_gen(rand_str_2, sizeof(rand_str_2));
                memcpy((u_char *)&pkt_ptr[2], rand_str_2, 2);
            }

            else if (r>40 && r<60) {

                rand_str_gen(rand_str_1, sizeof(rand_str_1));
                memcpy((u_char *)&pkt_ptr[4], rand_str_1, 1);

                if (pkt_ptr[4] == '\0') {

                    o = rand() % 10;

                    if (o < 2) {

                        pkt_ptr[8] = sa.sin_addr.s_addr;
                        pkt_ptr[9] = sa.sin_addr.s_addr >> 8;
                        pkt_ptr[10] = sa.sin_addr.s_addr >> 16;
                        pkt_ptr[11] = sa.sin_addr.s_addr >> 24;

                        pkt_ptr[12] = sa.sin_addr.s_addr;
                        pkt_ptr[13] = sa.sin_addr.s_addr >> 8;
                        pkt_ptr[14] = sa.sin_addr.s_addr >> 16;
                        pkt_ptr[15] = sa.sin_addr.s_addr >> 24;

                    }

                    else if (o >= 2 && o < 4) {

                        pkt_ptr[8] = '\0';
                        pkt_ptr[9] = '\0';
                        pkt_ptr[10] = '\0';
                        pkt_ptr[11] = '\0';

                        pkt_ptr[12] = sa.sin_addr.s_addr;
                        pkt_ptr[13] = sa.sin_addr.s_addr >> 8;
                        pkt_ptr[14] = sa.sin_addr.s_addr >> 16;
                        pkt_ptr[15] = sa.sin_addr.s_addr >> 24;

                    }

                    else if (o >= 4 && o < 6) {

                        pkt_ptr[8] = '\0';
                        pkt_ptr[9] = '\0';
                        pkt_ptr[10] = '\0';
                        pkt_ptr[11] = '\0';

                        pkt_ptr[12] = '\0';
                        pkt_ptr[13] = '\0';
                        pkt_ptr[14] = '\0';
                        pkt_ptr[15] = '\0';

                    }

                    else if (o >= 6 && o < 8) {

                        memset(saddress, 0, 16);
                        rand_ipv4_octet_gen(tuple.destination, 4, saddress);
                        inet_pton(AF_INET, saddress, &(sa.sin_addr));

                        pkt_ptr[8] = sa.sin_addr.s_addr;
                        pkt_ptr[9] = sa.sin_addr.s_addr >> 8;
                        pkt_ptr[10] = sa.sin_addr.s_addr >> 16;
                        pkt_ptr[11] = sa.sin_addr.s_addr >> 24;

                        pkt_ptr[12] = sa.sin_addr.s_addr;
                        pkt_ptr[13] = sa.sin_addr.s_addr >> 8;
                        pkt_ptr[14] = sa.sin_addr.s_addr >> 16;
                        pkt_ptr[15] = sa.sin_addr.s_addr >> 24;

                    }

                    else if (o == 8) {

                        memset(saddress, 0, 16);
                        rand_ipv4_octet_gen(tuple.destination, 4, saddress);
                        inet_pton(AF_INET, saddress, &(sa.sin_addr));

                        pkt_ptr[8] = sa.sin_addr.s_addr;
                        pkt_ptr[9] = sa.sin_addr.s_addr >> 8;
                        pkt_ptr[10] = sa.sin_addr.s_addr >> 16;
                        pkt_ptr[11] = sa.sin_addr.s_addr >> 24;

                        memset(saddress, 0, 16);
                        inet_pton(AF_INET, tuple.destination, &(sa.sin_addr));

                        pkt_ptr[12] = sa.sin_addr.s_addr;
                        pkt_ptr[13] = sa.sin_addr.s_addr >> 8;
                        pkt_ptr[14] = sa.sin_addr.s_addr >> 16;
                        pkt_ptr[15] = sa.sin_addr.s_addr >> 24;

                    }

                    else {

                        memset(saddress, 0, 16);
                        inet_pton(AF_INET, tuple.destination, &(sa.sin_addr));

                        pkt_ptr[8] = sa.sin_addr.s_addr;
                        pkt_ptr[9] = sa.sin_addr.s_addr >> 8;
                        pkt_ptr[10] = sa.sin_addr.s_addr >> 16;
                        pkt_ptr[11] = sa.sin_addr.s_addr >> 24;

                        memset(saddress, 0, 16);
                        rand_ipv4_octet_gen(tuple.destination, 4, saddress);
                        inet_pton(AF_INET, saddress, &(sa.sin_addr));

                        pkt_ptr[12] = sa.sin_addr.s_addr;
                        pkt_ptr[13] = sa.sin_addr.s_addr >> 8;
                        pkt_ptr[14] = sa.sin_addr.s_addr >> 16;
                        pkt_ptr[15] = sa.sin_addr.s_addr >> 24;

                    }

                }

            }

            else {
                rand_str_gen(rand_str_1, sizeof(rand_str_1));
                memcpy((u_char *)&pkt_ptr[5], rand_str_1, 1);

                if (pkt_ptr[5] == '\0') {

                    o = rand() % 10;

                    if (o < 3 ) {
                        for (i = 0;i<maclen;i++)
                            pkt_ptr[8+i] = mac_addr[i];
                        for (i = 0;i<maclen;i++)
                            pkt_ptr[14+i] = mac_addr[i];
                    }

                    else if (o > 3 && o < 5) {
                        for (i = 0;i<maclen;i++)
                            pkt_ptr[8+i] = '\0';
                        for (i = 0;i<maclen;i++)
                            pkt_ptr[14+i] = mac_addr[i];
                    }

                    else if (o > 5 && o < 8) {
                        for (i = 0;i<maclen;i++)
                            pkt_ptr[8+i] = '\0';
                        for (i = 0;i<maclen;i++)
                            pkt_ptr[14+i] = '\0';
                    }

                }

            }

            break;

        case REV_REQ:
            break;
        case REV_REP:
            break;
        case DRARP_REQ:
            break;
        case DRARP_REP:
            break;
        case DRARP_ERR:
            break;
        case INARP_REQ:
            break;
        case INARP_REP:
            break;
        case NAK:
            break;
        default:
            break;
    }


}


void parse_arp_pack(u_char *pkt_ptr, struct arp_header *arph) {

    arph->hw_type = htons(convert_xstring_to_dec(pkt_ptr, 2));
    arph->protocol = htons(convert_xstring_to_dec(&pkt_ptr[2], 2));
    arph->hw_size = convert_xstring_to_dec(&pkt_ptr[4], 1);
    arph->p_size = convert_xstring_to_dec(&pkt_ptr[5], 1);
    arph->opcode = htons(convert_xstring_to_dec(&pkt_ptr[6], 2));

    memcpy(arph->smac, &pkt_ptr[8], 6);
    arph->sip = convert_xstring_to_dec(&pkt_ptr[14], 4);
    memcpy(arph->tmac, &pkt_ptr[18], 6);
    arph->tip = convert_xstring_to_dec(&pkt_ptr[24], 4);

}


void rand_mac_gen(u_char *rand_str, size_t length) {
    char charset[] = "0123456789"
    "ABCDEF";

    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
        *rand_str++ = charset[index];
    }
    *rand_str = '\0';
}
