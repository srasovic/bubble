

/*
 ##############################################################################
 Revision #      1.0
 Name:               :  msdp_fuzzer.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Routines for fuzzing over MSDP protocol data.
 ##############################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_msdp.h"


extern u_char *null_string;

void fuzz_msdp(u_char *packet, struct msdp_header *msdp_hdr) {

    msdp_hdr->len = htons(0x004a);

    u_char *open_ptr = packet;

    time_t t;
    srand((unsigned) time(&t));

    int top, count, params_count, field_count, md_field_count, disc;
    int i, a, b, c, d, e;

    u_int16_t len, res1;
    u_char rp[4], group[4], source[4], data[54];

    memset(rp, '\0', 4);
    memset(group, '\0', 4);
    memset(source, '\0', 4);
    memset(data, '\0', 54);


    field_count = 10;
    md_field_count = field_count/2;

    top = rand() % 6;

    if (top <= 3)
        count = 1;

    else {
        count = 1 + rand() / (RAND_MAX / (md_field_count - 1 + 1) + 1);
    }


    for (i = 0; i<count; i++) {

        a = 1 + rand() / (RAND_MAX / (field_count - 1 + 1) + 1);

        if (a == 1) {

            open_ptr[0] = rand() % 0xFF;
        }

        else if (a == 2) {

            len = rand() % 0xFFFF;

            b = 1 + rand() / (RAND_MAX / (2 - 1 + 1) + 1);

            if (b == 1) {
                open_ptr[1] = len;
                open_ptr[2] = len >> 8;
            }
            if (b == 2) {
                open_ptr[2] = len;
                open_ptr[1] = len >> 8;
            }

            msdp_hdr->len = htons(len);

        }

        else if (a == 3) {

            open_ptr[3] = rand() % 0xFF;

        }

        else if (a == 4) {

            rand_str_gen(rp, 4);
            memcpy(&open_ptr[4], rp, 4);

        }

        else if (a == 5) {

            res1 = rand() % 0xFFFF;

            b = 1 + rand() / (RAND_MAX / (2 - 1 + 1) + 1);

            if (b == 1) {
                open_ptr[7] = res1;
                open_ptr[8] = res1 >> 8;
            }
            if (b == 2) {
                open_ptr[8] = res1;
                open_ptr[7] = res1 >> 8;
            }

        }

        else if (a == 6) {

            open_ptr[9] = rand() % 0xFF;

        }

        else if (a == 7) {

            open_ptr[10] = rand() % 0xFF;

        }

        else if (a == 8) {

            rand_str_gen(group, 4);
            memcpy(&open_ptr[11], group, 4);

        }

        else if (a == 9) {

            rand_str_gen(source, 4);
            memcpy(&open_ptr[15], source, 4);

        }

        else {

//            this is simple and dirty:

            d = 1 + rand() / (RAND_MAX / (5 - 1 + 1) + 1);

            if (d == 1) {

                b = 1 + rand() / (RAND_MAX / (54 - 1 + 1) + 1);
                c = msdp_hdr->len - 20 - b;
                memcpy(&open_ptr[msdp_hdr->len - 20 + c], null_string, b);

            }

            else if (d == 2) {

                memcpy(&open_ptr[msdp_hdr->len], null_string, 74);
                msdp_hdr->len =  msdp_hdr->len + htons(74);

            }

            else if (d == 3) {

                memcpy(&open_ptr[msdp_hdr->len], null_string, 74);
                msdp_hdr->len =  msdp_hdr->len + htons(74);
                open_ptr[1] = msdp_hdr->len;
                open_ptr[2] = msdp_hdr->len >> 8;

            }

            else if (d == 4) {
                msdp_hdr->len = htons(24);
                open_ptr[1] = msdp_hdr->len;
                open_ptr[2] = msdp_hdr->len >> 8;
            }

            else {

                b = 1 + rand() / (RAND_MAX / (54 - 1 + 1) + 1);

                rand_str_gen(data, b);
                c = msdp_hdr->len - 20 - b;
                memcpy(&open_ptr[msdp_hdr->len - 20 + c], data, b);

            }


        }



    }



}
