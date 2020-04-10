

/*
 ##############################################################################
 Revision #      1.0
 Name:               :  dhcpv4_fuzzer.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Routines for fuzzing over DHCPv4 protocol data.
 ##############################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_dhcp.h"

#define HDR_FCOUNT  16

extern u_char *null_string;


void fuzz_dhcpv4_pack(int type, u_char *packet, int *plen) {


    u_char *pkt_ptr = packet;

    time_t t;
    srand((unsigned) time(&t));

    int top, count, field_count, md_field_count, mlen;
    int i, a, b, c, d, e;

    mlen = *plen;

    u_char xid[4];
    u_char ip[4];
    u_char cookie[4];
    u_char mac[6];
    u_char pad[10];
    u_char sname[64];
    u_char file[128];
    u_char junk[512];

    memset(xid, '\0', 4);
    memset(ip, '\0', 4);
    memset(cookie, '\0', 4);
    memset(mac, '\0', 6);
    memset(pad, '\0', 10);
    memset(sname, '\0', 64);
    memset(file, '\0', 128);
    memset(junk, '\0', 512);


    switch (type) {

        case discover:
            field_count = HDR_FCOUNT + 44 + 1;
            break;

        case request:
            field_count = HDR_FCOUNT + 33 + 1;
            break;

        case decline:
            field_count = HDR_FCOUNT + 44 + 1;
            break;

        case inform:
            field_count = HDR_FCOUNT + 37 + 1;
            break;

        case release:
            field_count = HDR_FCOUNT + 37 + 1;
            break;

        case query:
            field_count = HDR_FCOUNT + 10 + 1;
            break;

        default:
            break;
    }


    md_field_count = rand() % field_count;

    top = rand() % 6;

    if (top <= 3)
        count = 1;

    else
        count = 1 + rand() / (RAND_MAX / (md_field_count - 1 + 1) + 1);


    for (i = 0; i<count; i++) {

        a = 1 + rand() / (RAND_MAX / (field_count - 1 + 1) + 1);

        if (a == 1) {
            b = rand() % 5;
            if (b<3)
                pkt_ptr[0] = rand() % 0x03;
            else
                pkt_ptr[0] = 0x00;
        }

        if (a == 2) {
            b = rand() % 5;
            if (b<3)
                pkt_ptr[1] = rand() % 0xFF;
            else
                pkt_ptr[1] = 0x00;

        }

        if (a == 3) {
            pkt_ptr[2] = 0x00;
        }

        if (a == 4) {
            b = rand() % 5;
            if (b<3)
                pkt_ptr[3] = rand() % 0xFF;
            else
                pkt_ptr[3] = 0x00;

        }

        if (a == 5) {
/*            b = rand() % 10;
            if (b == 4) {
                rand_str_gen(xid, 4);
                memcpy(&pkt_ptr[4], xid, 4);
            }
 */
        }

        if (a == 6) {
            b = rand() % 5;
            if (b<3) {
                pkt_ptr[8] = rand() % 0xFF;
                pkt_ptr[9] = rand() % 0xFF;
            }
            else {
                pkt_ptr[8] = 0x00;
                pkt_ptr[9] = 0x00;
            }
        }

        if (a == 7) {
            b = rand() % 5;
            if (b<3) {
                pkt_ptr[10] = rand() % 0xFF;
                pkt_ptr[11] = rand() % 0xFF;
            }
            else {
                pkt_ptr[10] = 0x00;
                pkt_ptr[11] = 0x00;
            }
        }

        if (a == 8) {
            b = rand() % 5;
            if (b<3) {
                rand_str_gen(ip, 4);
                memcpy(&pkt_ptr[12], ip, 4);
            }
            else
                memcpy(&pkt_ptr[12], null_string, 4);
        }


        if (a == 9) {
            b = rand() % 5;
            if (b<3) {
                rand_str_gen(ip, 4);
                memcpy(&pkt_ptr[16], ip, 4);
            }
            else
                memcpy(&pkt_ptr[16], null_string, 4);
        }


        if (a == 10) {
            b = rand() % 5;
            if (b<3) {
                rand_str_gen(ip, 4);
                memcpy(&pkt_ptr[20], ip, 4);
            }
            else
                memcpy(&pkt_ptr[20], null_string, 4);

        }


        if (a == 11) {
            b = rand() % 5;
            if (b<3) {
                rand_str_gen(ip, 4);
                memcpy(&pkt_ptr[24], ip, 4);
            }
            else
                memcpy(&pkt_ptr[24], null_string, 4);
        }

        if (a == 12) {
            b = rand() % 5;
            if (b<3) {
                rand_str_gen(mac, 6);
                memcpy(&pkt_ptr[28], mac, 6);
            }
            else
                memcpy(&pkt_ptr[28], null_string, 6);
        }

        if (a == 13) {
            b = rand() % 5;
            if (b<3) {
                rand_str_gen(pad, 10);
                memcpy(&pkt_ptr[34], pad, 10);
            }
            else
                memcpy(&pkt_ptr[34], null_string, 10);
        }

        if (a == 14) {
            b = rand() % 5;
            if (b<3) {
                rand_str_gen(sname, 64);
                memcpy(&pkt_ptr[44], sname, 64);
            }
            else
                memcpy(&pkt_ptr[44], null_string, 64);
        }

        if (a == 15) {
            b = rand() % 5;
            if (b<3) {
                rand_str_gen(file, 128);
                memcpy(&pkt_ptr[108], file, 128);
            }
            else
                memcpy(&pkt_ptr[108], null_string, 128);
        }

        if (a == 16) {
            b = rand() % 5;
            if (b<3) {
                rand_str_gen(cookie, 4);
                memcpy(&pkt_ptr[236], cookie, 4);
            }
            else
                memcpy(&pkt_ptr[236], null_string, 4);
        }


        else {

            switch (type) {

                case discover:
                case decline:

                    if (a == 17) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[240] = rand() % 0xFF;
                        else
                            pkt_ptr[240] = 0x00;

                    }
                    if (a == 18) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[241] = rand() % 0xFF;
                        else
                            pkt_ptr[241] = 0x00;
                    }
                    if (a == 19) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[242] = rand() % 0xFF;
                        else
                            pkt_ptr[242] = 0x00;
                    }
                    if (a == 20) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[243] = rand() % 0xFF;
                        else
                            pkt_ptr[243] = 0x00;
                    }
                    if (a == 21) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[244] = rand() % 0xFF;
                        else
                            pkt_ptr[244] = 0x00;
                    }
                    if (a == 22) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[245] = rand() % 0xFF;
                        else
                            pkt_ptr[245] = 0x00;
                    }
                    if (a == 23) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[246] = rand() % 0xFF;
                        else
                            pkt_ptr[246] = 0x00;
                    }
                    if (a == 24) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[247] = rand() % 0xFF;
                        else
                            pkt_ptr[247] = 0x00;
                    }
                    if (a == 25) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[248] = rand() % 0xFF;
                        else
                            pkt_ptr[248] = 0x00;
                    }
                    if (a == 26) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[249] = rand() % 0xFF;
                        else
                            pkt_ptr[249] = 0x00;
                    }
                    if (a == 27) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[250] = rand() % 0xFF;
                        else
                            pkt_ptr[250] = 0x00;
                    }
                    if (a == 28) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[251] = rand() % 0xFF;
                        else
                            pkt_ptr[251] = 0x00;
                    }
                    if (a == 29) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[252] = rand() % 0xFF;
                        else
                            pkt_ptr[252] = 0x00;
                    }
                    if (a == 30) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[253] = rand() % 0xFF;
                        else
                            pkt_ptr[253] = 0x00;
                    }
                    if (a == 31) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[254] = rand() % 0xFF;
                        else
                            pkt_ptr[254] = 0x00;
                    }
                    if (a == 32) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[255] = rand() % 0xFF;
                        else
                            pkt_ptr[255] = 0x00;
                    }
                    if (a == 33) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[256] = rand() % 0xFF;
                        else
                            pkt_ptr[256] = 0x00;
                    }
                    if (a == 34) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[257] = rand() % 0xFF;
                        else
                            pkt_ptr[257] = 0x00;
                    }
                    if (a == 35) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[258] = rand() % 0xFF;
                        else
                            pkt_ptr[258] = 0x00;
                    }
                    if (a == 36) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[259] = rand() % 0xFF;
                        else
                            pkt_ptr[259] = 0x00;
                    }
                    if (a == 37) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[260] = rand() % 0xFF;
                        else
                            pkt_ptr[260] = 0x00;
                    }
                    if (a == 38) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[261] = rand() % 0xFF;
                        else
                            pkt_ptr[261] = 0x00;
                    }
                    if (a == 39) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[262] = rand() % 0xFF;
                        else
                            pkt_ptr[262] = 0x00;
                    }
                    if (a == 40) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[263] = rand() % 0xFF;
                        else
                            pkt_ptr[263] = 0x00;
                    }
                    if (a == 41) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[264] = rand() % 0xFF;
                        else
                            pkt_ptr[264] = 0x00;
                    }
                    if (a == 42) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[265] = rand() % 0xFF;
                        else
                            pkt_ptr[265] = 0x00;
                    }
                    if (a == 43) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[266] = rand() % 0xFF;
                        else
                            pkt_ptr[266] = 0x00;
                    }
                    if (a == 44) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[267] = rand() % 0xFF;
                        else
                            pkt_ptr[267] = 0x00;
                    }
                    if (a == 45) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[268] = rand() % 0xFF;
                        else
                            pkt_ptr[268] = 0x00;
                    }
                    if (a == 46) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[269] = rand() % 0xFF;
                        else
                            pkt_ptr[269] = 0x00;
                    }
                    if (a == 47) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[270] = rand() % 0xFF;
                        else
                            pkt_ptr[270] = 0x00;
                    }
                    if (a == 48) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[271] = rand() % 0xFF;
                        else
                            pkt_ptr[271] = 0x00;
                    }
                    if (a == 49) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[272] = rand() % 0xFF;
                        else
                            pkt_ptr[272] = 0x00;
                    }
                    if (a == 50) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[273] = rand() % 0xFF;
                        else
                            pkt_ptr[273] = 0x00;
                    }
                    if (a == 51) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[274] = rand() % 0xFF;
                        else
                            pkt_ptr[274] = 0x00;
                    }
                    if (a == 52) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[275] = rand() % 0xFF;
                        else
                            pkt_ptr[275] = 0x00;
                    }
                    if (a == 53) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[276] = rand() % 0xFF;
                        else
                            pkt_ptr[276] = 0x00;
                    }
                    if (a == 54) {
                        b = rand() % 5;
                        if (b<3) {
                            rand_str_gen(mac, 6);
                            memcpy(&pkt_ptr[277], mac, 6);
                        }
                        else
                            memcpy(&pkt_ptr[277], null_string, 6);

                    }
                    if (a == 55) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[283] = rand() % 0xFF;
                        else
                            pkt_ptr[283] = 0x00;

                    }
                    if (a==56) {
                        b= rand() % 512;
                        *plen = mlen + b;
                        if (b<128) {
                            rand_str_gen(junk, b);
                            memcpy(&pkt_ptr[283], junk, b);
                        }
                        else {
                            memcpy(&pkt_ptr[283], null_string, b);
                        }
                    }

                    break;

                case request:

                    if (a == 17) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[240] = rand() % 0xFF;
                        else
                            pkt_ptr[240] = 0x00;
                    }
                    if (a == 18) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[241] = rand() % 0xFF;
                        else
                            pkt_ptr[241] = 0x00;
                    }
                    if (a == 19) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[242] = rand() % 0xFF;
                        else
                            pkt_ptr[242] = 0x00;
                    }
                    if (a == 20) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[243] = rand() % 0xFF;
                        else
                            pkt_ptr[243] = 0x00;
                    }
                    if (a == 21) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[244] = rand() % 0xFF;
                        else
                            pkt_ptr[244] = 0x00;
                    }
                    if (a == 22) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[245] = rand() % 0xFF;
                        else
                            pkt_ptr[245] = 0x00;
                    }
                    if (a == 23) {
                        rand_str_gen(mac, 6);
                        memcpy(&pkt_ptr[246], mac, 6);
                    }
                    if (a == 24) {
                        pkt_ptr[252] = rand() % 0xFF;
                    }
                    if (a == 25) {
                        pkt_ptr[253] = rand() % 0xFF;
                    }
                    if (a == 26) {
                        b = rand() % 5;
                        if (b<3) {
                            rand_str_gen(ip, 4);
                            memcpy(&pkt_ptr[254], ip, 4);
                        }
                        else
                            memcpy(&pkt_ptr[254], null_string, 4);

                    }
                    if (a == 27) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[258] = rand() % 0xFF;
                        else
                            pkt_ptr[258] = 0x00;
                    }
                    if (a == 28) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[259] = rand() % 0xFF;
                        else
                            pkt_ptr[259] = 0x00;
                    }
                    if (a == 29) {
                        b = rand() % 5;
                        if (b<3) {
                            rand_str_gen(ip, 4);
                            memcpy(&pkt_ptr[260], ip, 4);
                        }
                        else
                            memcpy(&pkt_ptr[260], null_string, 4);

                    }
                    if (a == 30) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[264] = rand() % 0xFF;
                        else
                            pkt_ptr[264] = 0x00;
                    }
                    if (a == 31) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[264] = rand() % 0xFF;
                        else
                            pkt_ptr[265] = 0x00;
                    }
                    if (a == 32) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[266] = rand() % 0xFF;
                        else
                            pkt_ptr[266] = 0x00;
                    }
                    if (a == 33) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[267] = rand() % 0xFF;
                        else
                            pkt_ptr[267] = 0x00;
                    }
                    if (a == 34) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[268] = rand() % 0xFF;
                        else
                            pkt_ptr[268] = 0x00;
                    }
                    if (a == 35) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[269] = rand() % 0xFF;
                        else
                            pkt_ptr[269] = 0x00;
                    }
                    if (a == 36) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[270] = rand() % 0xFF;
                        else
                            pkt_ptr[270] = 0x00;
                    }
                    if (a == 37) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[271] = rand() % 0xFF;
                        else
                            pkt_ptr[271] = 0x00;
                    }
                    if (a == 38) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[272] = rand() % 0xFF;
                        else
                            pkt_ptr[272] = 0x00;
                    }
                    if (a==39) {
                        b= rand() % 512;
                        *plen = mlen + b;
                        if (b<128) {
                            rand_str_gen(junk, b);
                            memcpy(&pkt_ptr[272], junk, b);
                        }
                        else {
                            memcpy(&pkt_ptr[272], null_string, b);
                        }
                    }

                    break;

                case inform:
                case release:

                    if (a == 17) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[240] = rand() % 0xFF;
                        else
                            pkt_ptr[240] = 0x00;
                    }
                    if (a == 18) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[241] = rand() % 0xFF;
                        else
                            pkt_ptr[241] = 0x00;
                    }
                    if (a == 19) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[242] = rand() % 0xFF;
                        else
                            pkt_ptr[242] = 0x00;
                    }
                    if (a == 20) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[243] = rand() % 0xFF;
                        else
                            pkt_ptr[243] = 0x00;
                    }
                    if (a == 21) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[244] = rand() % 0xFF;
                        else
                            pkt_ptr[244] = 0x00;
                    }
                    if (a == 22) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[245] = rand() % 0xFF;
                        else
                            pkt_ptr[245] = 0x00;
                    }
                    if (a == 23) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[246] = rand() % 0xFF;
                        else
                            pkt_ptr[246] = 0x00;
                    }
                    if (a == 24) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[247] = rand() % 0xFF;
                        else
                            pkt_ptr[247] = 0x00;
                    }
                    if (a == 25) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[248] = rand() % 0xFF;
                        else
                            pkt_ptr[248] = 0x00;
                    }
                    if (a == 26) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[249] = rand() % 0xFF;
                        else
                            pkt_ptr[249] = 0x00;
                    }
                    if (a == 27) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[250] = rand() % 0xFF;
                        else
                            pkt_ptr[250] = 0x00;
                    }
                    if (a == 28) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[251] = rand() % 0xFF;
                        else
                            pkt_ptr[251] = 0x00;
                    }
                    if (a == 29) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[252] = rand() % 0xFF;
                        else
                            pkt_ptr[252] = 0x00;
                    }
                    if (a == 30) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[253] = rand() % 0xFF;
                        else
                            pkt_ptr[253] = 0x00;
                    }
                    if (a == 31) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[254] = rand() % 0xFF;
                        else
                            pkt_ptr[254] = 0x00;
                    }
                    if (a == 32) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[255] = rand() % 0xFF;
                        else
                            pkt_ptr[255] = 0x00;
                    }
                    if (a == 33) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[256] = rand() % 0xFF;
                        else
                            pkt_ptr[256] = 0x00;
                    }
                    if (a == 34) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[257] = rand() % 0xFF;
                        else
                            pkt_ptr[257] = 0x00;
                    }
                    if (a == 35) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[258] = rand() % 0xFF;
                        else
                            pkt_ptr[258] = 0x00;
                    }
                    if (a == 36) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[259] = rand() % 0xFF;
                        else
                            pkt_ptr[259] = 0x00;
                    }
                    if (a == 37) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[260] = rand() % 0xFF;
                        else
                            pkt_ptr[260] = 0x00;
                    }
                    if (a == 38) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[261] = rand() % 0xFF;
                        else
                            pkt_ptr[261] = 0x00;
                    }
                    if (a == 39) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[262] = rand() % 0xFF;
                        else
                            pkt_ptr[262] = 0x00;
                    }
                    if (a == 40) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[263] = rand() % 0xFF;
                        else
                            pkt_ptr[263] = 0x00;
                    }
                    if (a == 41) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[264] = rand() % 0xFF;
                        else
                            pkt_ptr[264] = 0x00;
                    }
                    if (a == 42) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[265] = rand() % 0xFF;
                        else
                            pkt_ptr[265] = 0x00;
                    }
                    if (a == 43) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[266] = rand() % 0xFF;
                        else
                            pkt_ptr[266] = 0x00;
                    }
                    if (a == 44) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[267] = rand() % 0xFF;
                        else
                            pkt_ptr[267] = 0x00;
                    }
                    if (a == 45) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[268] = rand() % 0xFF;
                        else
                            pkt_ptr[268] = 0x00;
                    }
                    if (a == 46) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[269] = rand() % 0xFF;
                        else
                            pkt_ptr[269] = 0x00;
                    }
                    if (a == 47) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[270] = rand() % 0xFF;
                        else
                            pkt_ptr[270] = 0x00;
                    }
                    if (a == 48) {
                        b = rand() % 5;
                        if (b<3) {
                            rand_str_gen(mac, 6);
                            memcpy(&pkt_ptr[271], mac, 6);
                        }
                        else
                            memcpy(&pkt_ptr[271], null_string, 6);
                    }
                    if (a == 49) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[277] = rand() % 0xFF;
                        else
                            pkt_ptr[277] = 0x00;
                    }
                    if (a==50) {
                        b= rand() % 512;
                        *plen = mlen + b;
                        if (b<128) {
                            rand_str_gen(junk, b);
                            memcpy(&pkt_ptr[277], junk, b);
                        }
                        else {
                            memcpy(&pkt_ptr[277], null_string, b);
                        }
                    }

                    break;

                case query:

                    if (a == 17) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[240] = rand() % 0xFF;
                        else
                            pkt_ptr[240] = 0x00;
                    }
                    if (a == 18) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[241] = rand() % 0xFF;
                        else
                            pkt_ptr[241] = 0x00;
                    }
                    if (a == 19) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[242] = rand() % 0xFF;
                        else
                            pkt_ptr[242] = 0x00;
                    }
                    if (a == 20) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[243] = rand() % 0xFF;
                        else
                            pkt_ptr[243] = 0x00;
                    }
                    if (a == 21) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[244] = rand() % 0xFF;
                        else
                            pkt_ptr[244] = 0x00;
                    }
                    if (a == 22) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[245] = rand() % 0xFF;
                        else
                            pkt_ptr[245] = 0x00;
                    }
                    if (a == 23) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[246] = rand() % 0xFF;
                        else
                            pkt_ptr[246] = 0x00;
                    }
                    if (a == 24) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[247] = rand() % 0xFF;
                        else
                            pkt_ptr[247] = 0x00;
                    }
                    if (a == 25) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[248] = rand() % 0xFF;
                        else
                            pkt_ptr[248] = 0x00;
                    }
                    if (a == 26) {
                        b = rand() % 5;
                        if (b<3)
                            pkt_ptr[249] = rand() % 0xFF;
                        else
                            pkt_ptr[249] = 0x00;
                    }

                    if (a==27) {
                        b= rand() % 512;
                        *plen = mlen + b;
                        if (b<128) {
                            rand_str_gen(junk, b);
                            memcpy(&pkt_ptr[249], junk, b);
                        }
                        else {
                            memcpy(&pkt_ptr[249], null_string, b);
                        }
                    }

                    break;

                default:
                    break;
            }
        }



    }

}






