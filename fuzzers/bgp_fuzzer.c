

/*
 ##############################################################################
 Revision #      1.0
 Name:               :  bgp_fuzzer.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Routines for fuzzing over BGP protocol data.
 ##############################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_bgp.h"

#define MAX_HDRS    20

extern u_char *null_string;
extern int init;

extern u_int32_t packet_size;

extern int bgp_update_offsets[MAX_HDRS];
extern int bgp_update_path_offsets[MAX_HDRS][MAX_HDRS];
extern int bgp_update_nlri_offsets[MAX_HDRS][5];



size_t fuzz_bgp_open(u_char *packet, struct bgp_hdr *bgp_hdr) {

    fprintf(stderr, "%d.Fuzzing BGP OPEN with %d bytes of %s data\n", init+1, packet_size, tuple.protocol);
    init++;

    u_char *open_ptr = packet;
    u_char *dummy = calloc(1, 1024);

    time_t t;
    srand((unsigned) time(&t));

    int top, count, params_count, field_count, md_field_count, disc;
    int i, a, b, c, d, e;

    u_char marker1[4];
    u_char marker2[4];
    u_char marker3[4];
    u_char marker4[4];
    u_char marker[16];

    u_int16_t ln, holdtime, my_as;
    u_int8_t type, version, plen;
    u_char identifier[4];
    u_char parameter[128];

    memset(marker, '\0', 16);
    memset(marker1, '\0', 4);
    memset(marker2, '\0', 4);
    memset(marker3, '\0', 4);
    memset(marker4, '\0', 4);
    memset(identifier, '\0', 4);

    i = params_count = 0;
    c = bgp_params_offsets[0];
    while (bgp_params_offsets[i]) {
        params_count++;
        i++;
    }
    params_count--;

    field_count = (8+params_count);
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

            b = 1 + rand() / (RAND_MAX / (10 - 1 + 1) + 1);

            if (b == 1) {
                rand_str_gen(marker1, 4);
                memcpy(open_ptr, marker1, 4);
            }
            else if (b == 2) {
                rand_str_gen(marker2, 4);
                memcpy(&open_ptr[4], marker2, 4);
            }
            else if (b == 3) {
                rand_str_gen(marker3, 4);
                memcpy(&open_ptr[8], marker3, 4);
            }
            if (b == 4) {
                rand_str_gen(marker4, 4);
                memcpy(&open_ptr[12], marker4, 4);
            }
            else {
                rand_str_gen(marker, b);
                memcpy(&open_ptr[16-b], marker, b);
            }
        }

        else if (a == 2) {

            ln = rand() % 0xFFFF;

            b = 1 + rand() / (RAND_MAX / (2 - 1 + 1) + 1);

            if (b == 1) {
                open_ptr[16] = ln;
                open_ptr[17] = ln >> 8;
            }
            if (b == 2) {
                open_ptr[17] = ln;
                open_ptr[16] = ln >> 8;
            }

        }

        else if (a == 3) {

            type = rand() % 0xFF;
            open_ptr[18] = type;

        }

        else if (a == 4) {

            // I don't think this would work, but nevertheless:
            b = 1 + rand() / (RAND_MAX / (2 - 1 + 1) + 1);

            if (b == 1) {
                version = 0xFF;
                open_ptr[19] = type;
            }
            else {
                version = 0x00;
                open_ptr[19] = type;
            }

        }

        else if (a == 5) {

            my_as = rand() % 0xFFFF;

            b = 1 + rand() / (RAND_MAX / (2 - 1 + 1) + 1);

            if (b == 1) {
                open_ptr[20] = my_as;
                open_ptr[21] = my_as >> 8;
            }
            if (b == 2) {
                open_ptr[21] = my_as;
                open_ptr[20] = my_as >> 8;
            }

        }

        else if (a == 6) {

            holdtime = rand() % 0xFFFF;

            b = 1 + rand() / (RAND_MAX / (2 - 1 + 1) + 1);

            if (b == 1) {
                open_ptr[22] = holdtime;
                open_ptr[23] = holdtime >> 8;
            }
            if (b == 2) {
                open_ptr[22] = holdtime;
                open_ptr[23] = holdtime >> 8;
            }

        }

        else if (a == 7) {

            b = 1 + rand() / (RAND_MAX / (9 - 1 + 1) + 1);

            if (b == 1) {
                rand_str_gen(identifier, 2);
                memcpy(&open_ptr[24], identifier, 2);
            }
            else if (b == 2) {
                rand_str_gen(identifier, 2);
                memcpy(&open_ptr[25], identifier, 2);
            }
            else if (b == 3) {
                rand_str_gen(identifier, 2);
                memcpy(&open_ptr[26], identifier, 2);
            }
            else if (b == 4) {
                rand_str_gen(identifier, 3);
                memcpy(&open_ptr[24], identifier, 3);
            }
            else if (b == 5) {
                rand_str_gen(identifier, 3);
                memcpy(&open_ptr[25], identifier, 3);
            }
            else if (b == 6) {
                rand_str_gen(identifier, 4);
                memcpy(&open_ptr[24], identifier, 4);
            }
            else if (b == 7) {
                open_ptr[24] = 0xFF;
                open_ptr[25] = 0xFF;
                open_ptr[26] = 0xFF;
                open_ptr[27] = 0xFF;
            }
            else if (b == 8) {
                open_ptr[24] = 0x7F;
                open_ptr[25] = 0xFF;
                open_ptr[26] = 0xFF;
                open_ptr[27] = 0xFF;
            }
            else if (b == 9) {
                open_ptr[24] = 0x00;
                open_ptr[25] = 0x00;
                open_ptr[26] = 0x00;
                open_ptr[27] = 0x00;
            }


        }

        else if (a == 8) {

            plen = rand() % 255;
            open_ptr[28] = plen;

        }

        else {

            c = rand() % params_count;

            d = 1 + rand() / (RAND_MAX / (7 - 1 + 1) + 1);

            if (d == 1) {
                open_ptr[bgp_params_offsets[c]] = rand() % 255;
            }

            else if (d == 2) {
                open_ptr[bgp_params_offsets[c]+1] = rand() % 255;
            }

            else if (d == 3) {
                open_ptr[bgp_params_offsets[c]+2] = rand() % 255;
            }

            else if (d == 4) {
                open_ptr[bgp_params_offsets[c]+3] = rand() % 255;
            }

            else {

                plen = open_ptr[bgp_params_offsets[c]+3];
                e = rand() % 3;

                if (e) {
                    rand_str_gen(parameter, plen);
                    memcpy(&open_ptr[bgp_params_offsets[c]+4], parameter, plen);
                }
                else {
                    plen = rand() % 124;
                    if (plen == 0)
                        bgp_hdr->len = htons(bgp_params_offsets[c] + plen);
                    else if (plen == 1)
                        open_ptr[bgp_params_offsets[c]] = 0x00;
                    else {
                        memcpy(&open_ptr[bgp_params_offsets[c]+4], null_string, plen);
                        bgp_hdr->len = htons(bgp_params_offsets[c] + plen);
                    }

                }
            }

    }



}

    return htons(bgp_hdr->len);

}


size_t fuzz_bgp_update(u_char *packet, struct bgp_update *bgp_update, int num_hdrs, int mode) {


    int i, j, k, l, p, r, s, n, c, offset;
    int fuzzed_hdr, fuzzed_element, fuzzed_path_field, fuzzed_nlri_field;

    int flags, len, code;

    int wr, tpa;
    int origin_data;
    char as_path_data = 0;
    char nh_data[4] = {0};
    char nlri_data[4] = {0};
    char oi_data[4] = {0};

    u_int32_t med;

    u_int16_t community_as, community_value;
    int num_communities;

    int cluster_num;
    u_int32_t cluster_id;

    int alen, rlen;
    char aggregator[8];

    u_int32_t tlv_len;

    int ls_count = 0;

    struct as_segment {

        u_int8_t seg_type;
        u_int8_t seg_len;
        u_char seg_id[32];
        struct as_segment *next;
    };

    struct as_segment *as, *head_as;

    char tlv_id[16];


    u_int32_t as_len;

    struct link_state {

        u_int16_t tlv_type;
        u_int16_t tlv_len;
        u_char tlv_id[32];
        struct link_state *next;
    };

    struct link_state *ls, *head_ls;

    int aigp_len;

    struct aigp {

        u_int8_t aigp_type;
        u_int16_t aigp_len;
        u_char aigp_id[11];
        struct aigp *next;
    };

    struct aigp *aigp, *head_aigp;


    int ecomm_len;

    struct ext_comm {

        u_int8_t ecomm_type;
        u_int8_t ecomm_subtype;
        u_int16_t as2;
        u_int32_t as4;
        struct ext_comm *next;
    };

    struct ext_comm *ecomm, *head_ecomm;

    int tun_encap_len = 0, tcode_len = 0, sub_len = 0;

    struct sub_tun_tlv_encode{

        u_int16_t sub_type;
        u_int16_t sub_len;
        u_char sub_value[16];
        struct sub_tun_tlv_encode *next;

    };

    struct tun_tlv_encode {

        u_int16_t encode_type;
        u_int16_t encode_len;
        struct sub_tun_tlv_encode *sub;
        struct tun_tlv_encode *next;
    };

    struct tun_tlv_encode *tcode, *head_tcode;
    struct sub_tun_tlv_encode *subcode, *head_subcode;


   	int mpnlri_len, rand_mpnlri_len;
    u_int16_t afi;
    u_int8_t safi, nh_len = 0, spna;
    u_char nhna[24];
    u_char nlri[124] = {0};


    u_int8_t tunnel_flag, rand_tunnel_len, tunnel_type;
    u_char tunnel_info[124] = {0};

    u_char attr_set_info[124] = {0};
    u_int8_t rand_attr_set_len;


    struct bgp_update *bgp_update_ptr, *bgp_update_head;


    if (mode == MODE_SINGLE)
        n = 1;
    else {
        n = rand() %num_hdrs;                       // number of headers to fuzz
        while (!n)
            n = rand() %num_hdrs;
    }


    bgp_update_head = calloc(n, sizeof(struct bgp_update));


    while (n) {

        fuzzed_hdr = rand() %num_hdrs;              // header to fuzz in this iteration

        //debugging:
        fuzzed_hdr = 0;

        bgp_update_ptr = &bgp_update[fuzzed_hdr];
        bgp_update_head->path_list = &bgp_update_ptr->path_list[0];
        bgp_update_head->nlri_list = &bgp_update_ptr->nlri_list[0];

        k = j = l = 0;
        offset = 0;

        fuzzed_element = rand() %9+1;                // fuzzing sub-header, path attr or nlri


        //debugging:
        fuzzed_element = 5;

        if (fuzzed_element < 2){                                        // this is a sub-header to randomize

            j = rand() %4;

            if (j==0) {
                wr = rand() %0xFFFF;
                packet[BGP_HDR_SIZE + bgp_update_offsets[fuzzed_hdr]] = wr;
                packet[BGP_HDR_SIZE + bgp_update_offsets[fuzzed_hdr]+1] = wr >> 8;
            }

            else if (j==1) {
                packet[BGP_HDR_SIZE + bgp_update_offsets[fuzzed_hdr]] = 0xFF;
                packet[BGP_HDR_SIZE + bgp_update_offsets[fuzzed_hdr]+1] = 0xFF;
            }

            else if (j==2) {
                tpa = rand() %0xFFFF;
                packet[BGP_HDR_SIZE + bgp_update_offsets[fuzzed_hdr]+2] = tpa;
                packet[BGP_HDR_SIZE + bgp_update_offsets[fuzzed_hdr]+3] = tpa >>8;
            }

            else if (j==3) {
                packet[BGP_HDR_SIZE + bgp_update_offsets[fuzzed_hdr]+2] = 0xFF;
                packet[BGP_HDR_SIZE + bgp_update_offsets[fuzzed_hdr]+3] = 0xFF;
            }

            else if (j==4) {
                packet[BGP_HDR_SIZE + bgp_update_offsets[fuzzed_hdr]+2] = 0x00;
                packet[BGP_HDR_SIZE + bgp_update_offsets[fuzzed_hdr]+3] = 0x00;
            }



        }


        else if (fuzzed_element >= 2 && fuzzed_element <= 7) {

            while (bgp_update_path_offsets[fuzzed_hdr][k])
                k++;
            if (k)
                fuzzed_path_field = rand() %k;                          //this is a path attr to randomize
            else
                continue;

            for (c = 0; c<=fuzzed_path_field; c++) {
                code = bgp_update_ptr->path_list->code;
                bgp_update_ptr->path_list = bgp_update_ptr->path_list->next;
            }

            bgp_update_ptr->path_list = bgp_update_head->path_list;


            switch (code) {

                case ORIGIN:

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p ==0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {
                        origin_data = rand() %0xFF+1;
                        offset = offset+3;
                        packet[offset] = origin_data;
                    }

                        break;

                case AS_PATH:

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p ==0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {
                        len = packet[offset+2];
                        offset = offset+3;

                        r = rand() %3;

                        if (len>1) {

                            if (r == 0)
                                memset(&packet[offset], 0, len);
                            else if (r == 1)
                                memset(&packet[offset], 0xFF, len);
                            else {
                                memset(&packet[offset], rand() % 0xFF, len);
                            }

                        }

                    }

                    break;

                case NEXT_HOP:

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p ==0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {
                        memset(nh_data, 0, 4);
                        len = 4;
                        if (rand() %2)
                            rand_str_gen((u_char *)nh_data, len);
                        else
                            memset(nh_data, 0xFF, len);
                        offset = offset+3;
                        memcpy(&packet[offset],nh_data, len);
                    }

                    break;

                case MULTI_EXIT_DISC:
                case LOCAL_PREF:

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p ==0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {
                        len = 4;
                        med = rand() %0xFFFFFFFF+1;
                        offset = offset+3;
                        if (rand() %2) {
                            packet[offset] = med;
                            packet[offset+1] = med >>8;
                            packet[offset+2] = med >>16;
                            packet[offset+3] = med >>24;
                        }
                        else{
                            packet[offset+3] = med;
                            packet[offset+2] = med >>8;
                            packet[offset+1] = med >>16;
                            packet[offset] = med >>24;
                        }
                    }

                    break;

                case ATOMIC_AGGREGATE:

                    p = rand() %2;


                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p)
                        packet[offset] = 0xFF;
                    else
                        packet[offset] = rand() % 0xFF;

                    break;


                case AGGREGATOR:

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p ==0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1) {                               len = rand() %0xFF+1;                           offset = offset+2;
                        packet[offset] = len;                     }

                    else {

                        len = 6;
                        offset = offset+3;

                        r = rand() %4;

                        if (r == 0) {
                            packet[offset] = 0xFF;
                            packet[offset+1] = 0xFF;
                        }

                        if (r == 1) {
                            packet[offset] = 0x00;
                            packet[offset+1] = 0x00;
                        }

                        else if (r == 2) {
                            packet[offset+2] = 0xFF;
                            packet[offset+3] = 0xFF;
                            packet[offset+4] = 0xFF;
                            packet[offset+5] = 0xFF;

                        }

                        else {
                            packet[offset+2] = 0x00;
                            packet[offset+3] = 0x00;
                            packet[offset+4] = 0x00;
                            packet[offset+5] = 0x00;

                        }

                    }

                    break;


                case COMMUNITY:

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p ==0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {

                        len = packet[offset+2];
                        num_communities = len/4;
                        r = rand() %num_communities+1;
                        offset = offset+3;

                        s = rand() %6;
                        if (s == 0) {
                            community_as = rand() %0xFFFF;
                            packet[offset+(r*4 - 4)] = community_as;
                            packet[offset+(r*4 - 3)] = community_as >>8;
                        }
                        else if (s == 1) {
                            community_as = 0xFFFF;
                            packet[offset+(r*4 - 4)] = community_as;
                            packet[offset+(r*4 - 3)] = community_as >>8;
                        }
                        else if (s == 2) {
                            community_as = 0x0000;
                            packet[offset+(r*4 - 4)] = community_as;
                            packet[offset+(r*4 - 3)] = community_as >>8;
                        }
                        else if (s == 3) {
                            community_value = rand() %0xFFFF;
                            packet[offset+(r*4 - 2)] = community_value;
                            packet[offset+(r*4 - 2)] = community_value>>8;
                        }
                        else if (s == 4) {
                            community_value = 0xFFFF;
                            packet[offset+(r*4 - 2)] = community_value;
                            packet[offset+(r*4 - 2)] = community_value>>8;
                        }

                        else {
                            community_value = 0x0000;
                            packet[offset+(r*4 - 2)] = community_value;
                            packet[offset+(r*4 - 2)] = community_value>>8;
                        }

                    }

                    break;

                case ORIGINATOR_ID:

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p ==0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {
                        memset(nh_data, 0, 4);
                        len = 4;
                        if (rand() %2)
                            rand_str_gen((u_char *)oi_data, len);
                        else
                            memset(oi_data, 0xFF, len);
                        offset = offset+3;
                        memcpy(&packet[offset],oi_data, len);
                    }

                    break;

                case CLUSTER_LIST:

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p ==0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {

                        len = packet[offset+2];
                        cluster_num = len/4;
                        r = rand() %cluster_num+1;
                        offset = offset+3;

                        s = rand() %3;
                        if (s == 0) {
                            cluster_id = rand() %0xFFFFFFFF;
                            packet[offset+(r*4 - 4)] = cluster_id;
                            packet[offset+(r*4 - 3)] = cluster_id >>8;
                            packet[offset+(r*4 - 2)] = cluster_id >>16;
                            packet[offset+(r*4 - 1)] = cluster_id >>24;
                        }
                        else if (s == 1) {
                            cluster_id = 0xFFFFFFFF;
                            packet[offset+(r*4 - 4)] = cluster_id;
                            packet[offset+(r*4 - 3)] = cluster_id >>8;
                            packet[offset+(r*4 - 2)] = cluster_id >>16;
                            packet[offset+(r*4 - 1)] = cluster_id >>24;
                        }
                        else if (s == 2) {
                            cluster_id = 0x00000000;
                            packet[offset+(r*4 - 4)] = cluster_id;
                            packet[offset+(r*4 - 3)] = cluster_id >>8;
                            packet[offset+(r*4 - 2)] = cluster_id >>16;
                            packet[offset+(r*4 - 1)] = cluster_id >>24;
                        }
                    }

                    break;


                case AS4_AGGREGATOR:

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p ==0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {

                        len = 8;
                        offset = offset+3;

                        r = rand() %5;

                        if (r == 0) {
                            packet[offset] = 0xFF;
                            packet[offset+1] = 0xFF;
                            packet[offset+2] = 0xFF;
                            packet[offset+3] = 0xFF;
                        }

                        if (r == 1) {
                            packet[offset] = 0x00;
                            packet[offset+1] = 0x00;
                            packet[offset+2] = 0x00;
                            packet[offset+3] = 0x00;
                        }

                        else if (r == 2) {
                            packet[offset+4] = 0xFF;
                            packet[offset+5] = 0xFF;
                            packet[offset+6] = 0xFF;
                            packet[offset+7] = 0xFF;

                        }

                        else if (r == 3) {
                            packet[offset+4] = 0x00;
                            packet[offset+5] = 0x00;
                            packet[offset+6] = 0x00;
                            packet[offset+7] = 0x00;

                        }

                        else {
                            alen = rand() % len;
                            rlen = len - alen;
                            rand_str_gen((u_char *)aggregator, rand()%alen);
                            memcpy(&packet[offset+rlen], aggregator, alen);
                        }

                    }

                    break;


                case BGP_LS:

                    ls = calloc(1, sizeof(struct link_state));

                    p = rand() %6;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p == 0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1 ) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {

                        offset = offset+2;
                        len = packet[offset];

                        head_ls = &ls[0];

                        while (len) {

                            memcpy(&ls->tlv_type, &packet[offset+1], 2);
                            memcpy(&ls->tlv_len, &packet[offset+3], 2);

                            memcpy(tlv_id, &packet[offset+5], htons(ls->tlv_len));

                            tlv_len = htons(ls->tlv_len);

                            s = rand() %3;

                            if (s == 0) {
                                memset(ls->tlv_id, 0, htons(ls->tlv_len));
                                memcpy(&packet[offset+5], ls->tlv_id, htons(ls->tlv_len));
                                ls->tlv_type = 0x0000;
                                ls->tlv_len = 0x0000;
                                memcpy(&packet[offset+1], &ls->tlv_type, 2);
                                memcpy(&packet[offset+3], &ls->tlv_len, 2);
                            }

                            else if (s == 1) {
                                memset(&ls->tlv_id, 0xFF, htons(ls->tlv_len));
                                memcpy(&packet[offset+5], ls->tlv_id, htons(ls->tlv_len));
                                ls->tlv_type = 0xFFFF;
                                ls->tlv_len = 0xFFFF;
                                memcpy(&packet[offset+1], &ls->tlv_type, 2);
                                memcpy(&packet[offset+3], &ls->tlv_len, 2);
                            }

                            else if (s == 2) {
                                rand_str_gen(ls->tlv_id, htons(ls->tlv_len));
                                memcpy(&packet[offset+5], ls->tlv_id, htons(ls->tlv_len));
                                ls->tlv_type = rand() % 1200;
                                ls->tlv_len = rand() % 0xFFFF;
                                memcpy(&packet[offset+1], &ls->tlv_type, 2);
                                memcpy(&packet[offset+3], &ls->tlv_len, 2);
                            }

                            else if (s == 3) {
                                rand_str_gen(ls->tlv_id, htons(ls->tlv_len));
                                memcpy(&packet[offset+5], ls->tlv_id, htons(ls->tlv_len));
                                ls->tlv_type = 0x0000;
                                ls->tlv_len = 0xFFFF;
                                memcpy(&packet[offset+1], &ls->tlv_type, 2);
                                memcpy(&packet[offset+3], &ls->tlv_len, 2);
                            }

                            else if (s == 4) {
                                memset(ls->tlv_id, 0, htons(ls->tlv_len));
                                memcpy(&packet[offset+5], ls->tlv_id, htons(ls->tlv_len));
                                ls->tlv_type = rand() % 1200;
                                ls->tlv_len = rand() % 0xFFFF;
                                memcpy(&packet[offset+1], &ls->tlv_type, 2);
                                memcpy(&packet[offset+3], &ls->tlv_len, 2);
                            }

                            else {
                                memset(&ls->tlv_id, 0xFF, htons(ls->tlv_len));
                                memcpy(&packet[offset+5], ls->tlv_id, htons(ls->tlv_len));
                                ls->tlv_type = rand() % 1200;
                                ls->tlv_len = 0x0000;
                                memcpy(&packet[offset+1], &ls->tlv_type, 2);
                                memcpy(&packet[offset+3], &ls->tlv_len, 2);
                            }

                            offset = offset + 4 +  tlv_len;

                            len = len - 4 - tlv_len;
                            ls->next = calloc(1, sizeof(struct link_state));
                            ls = ls->next;
                            ls_count++;
                        }

                        ls = head_ls;


                        head_ls = &ls[0];

                    }

                    while(ls) {
                        head_ls= ls;
                        ls = ls->next;
                        free(head_ls);
                    }


                    break;


                case AS4_PATH:

                    as = calloc(1, sizeof(struct as_segment));

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p == 0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1 ) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {


                        offset = offset+2;
                        len = packet[offset];

                        head_as = &as[0];

                        while (len) {

                            memcpy(&as->seg_type, &packet[offset+1], 1);
                            memcpy(&as->seg_len, &packet[offset+2], 1);
                            as_len = as->seg_len*4;

                            if (as_len) {


                                memcpy(&as->seg_id, &packet[offset+3], as_len);


                                s = rand() %6;

                                if (s == 0) {
                                    memset(as->seg_id, 0, as_len);
                                    memcpy(&packet[offset+3], as->seg_id, as_len);
                                    as->seg_type = 0x00;
                                    as->seg_len = 0x00;
                                    memcpy(&packet[offset+1], &as->seg_type, 1);
                                    memcpy(&packet[offset+2], &as->seg_len, 1);
                                }

                                else if (s == 1) {
                                    memset(&as->seg_id, 0xFF, as_len);
                                    memcpy(&packet[offset+3], as->seg_id, as_len);
                                    as->seg_type = 0xFF;
                                    as->seg_len = 0xFF;
                                    memcpy(&packet[offset+1], &as->seg_type, 1);
                                    memcpy(&packet[offset+2], &as->seg_len, 1);
                                }

                                else if (s == 2) {
                                    rand_str_gen(as->seg_id, as_len);
                                    memcpy(&packet[offset+3], as->seg_id, as_len);
                                    as->seg_type = rand() % 0xFF;
                                    as->seg_len = rand() % 0xFF;
                                    memcpy(&packet[offset+1], &as->seg_type, 1);
                                    memcpy(&packet[offset+2], &as->seg_len, 1);
                                }

                                else if (s == 3) {
                                    rand_str_gen(as->seg_id, as_len);
                                    memcpy(&packet[offset+3], as->seg_id, as_len);
                                    as->seg_type = 0x00;
                                    as->seg_len = 0xFF;
                                    memcpy(&packet[offset+1], &as->seg_type, 1);
                                    memcpy(&packet[offset+2], &as->seg_len, 1);
                                }

                                else if (s == 4) {
                                    memset(as->seg_id, 0, as_len);
                                    memcpy(&packet[offset+3], as->seg_id, as_len);
                                    as->seg_type = 0xFF;
                                    as->seg_len = rand() % 0xFF;
                                    memcpy(&packet[offset+1], &as->seg_type, 1);
                                    memcpy(&packet[offset+2], &as->seg_len, 1);
                                }

                                else {
                                    memset(&as->seg_id, 0xFF, as_len);
                                    memcpy(&packet[offset+3], as->seg_id, as_len);
                                    as->seg_type = rand() % 0xFF;
                                    as->seg_len = 0x00;
                                    memcpy(&packet[offset+1], &as->seg_type, 1);
                                    memcpy(&packet[offset+2], &as->seg_len, 1);
                                }

                            }

                            offset = offset + 2 +  as_len;

                            len = len - 2 - as_len;
                            as->next = calloc(1, sizeof(struct as_segment));
                            as = as->next;

                        }

                        as = head_as;
                    }

                    while(as) {
                        head_as= as;
                        as = as->next;
                        free(head_as);

                    }


                    break;


                case AIGP:

                    aigp = calloc(1, sizeof(struct aigp));

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p == 0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1 ) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {

                        offset = offset+2;
                        len = packet[offset];

                        head_aigp = &aigp[0];

                        while (len) {

                            aigp->aigp_type = packet[offset+1];
                            memcpy(&aigp->aigp_len, &packet[offset+2], 2);

                            memcpy(&aigp->aigp_id, &packet[offset+4], htons(aigp->aigp_len));

                            aigp_len = htons(aigp->aigp_len)*8;

                            s = rand() %6;

                            if (s == 0) {
                                memset(aigp->aigp_id, 0, aigp_len);
                                memcpy(&packet[offset+4], aigp->aigp_id, aigp_len);
                                aigp->aigp_type = 0x00;
                                aigp->aigp_len = 0x0000;
                                memcpy(&packet[offset+1], &aigp->aigp_type, 1);
                                memcpy(&packet[offset+2], &aigp->aigp_len, 2);
                            }

                            else if (s == 1) {
                                memset(&aigp->aigp_id, 0xFF, aigp_len);
                                memcpy(&packet[offset+4], aigp->aigp_id, aigp_len);
                                aigp->aigp_type = 0xFF;
                                aigp->aigp_len = 0xFFFF;
                                memcpy(&packet[offset+1], &aigp->aigp_type, 1);
                                memcpy(&packet[offset+2], &aigp->aigp_len, 2);
                            }

                            else if (s == 2) {
                                rand_str_gen(aigp->aigp_id, aigp_len);
                                memcpy(&packet[offset+4], aigp->aigp_id, aigp_len);
                                aigp->aigp_type = rand() % 0xFF;
                                aigp->aigp_len = rand() % 0xFFFF;
                                memcpy(&packet[offset+1], &aigp->aigp_type, 1);
                                memcpy(&packet[offset+2], &aigp->aigp_len, 2);
                            }

                            else if (s == 3) {
                                rand_str_gen(aigp->aigp_id, aigp_len);
                                memcpy(&packet[offset+4], aigp->aigp_id, aigp_len);
                                aigp->aigp_type = 0x00;
                                aigp->aigp_len = 0xFFFF;
                                memcpy(&packet[offset+1], &aigp->aigp_type, 1);
                                memcpy(&packet[offset+2], &aigp->aigp_len, 2);
                            }

                            else if (s == 4) {
                                memset(aigp->aigp_id, 0, aigp_len);
                                memcpy(&packet[offset+4], aigp->aigp_id, aigp_len);
                                aigp->aigp_type = 0xFF;
                                aigp->aigp_len = rand() % 0xFFFF;
                                memcpy(&packet[offset+1], &aigp->aigp_type, 1);
                                memcpy(&packet[offset+2], &aigp->aigp_len, 2);
                            }

                            else  {
                                memset(&aigp->aigp_id, 0xFF, aigp_len);
                                memcpy(&packet[offset+4], aigp->aigp_id, aigp_len);
                                aigp->aigp_type = rand() % 0xFF;
                                aigp->aigp_len = 0x0000;
                                memcpy(&packet[offset+1], &aigp->aigp_type, 1);
                                memcpy(&packet[offset+2], &aigp->aigp_len, 2);
                            }

                            offset = offset + 4 +  aigp_len;

                            len = len - 3 - aigp_len;
                            aigp->next = calloc(1, sizeof(struct aigp));
                            aigp = aigp->next;

                        }

                        aigp = head_aigp;

                    }


                    while(aigp) {
                        head_aigp= aigp;
                        aigp = aigp->next;
                        free(head_aigp);

                    }

                    break;

                case EXTENDED_COMMUNITIES:



                    ecomm = calloc(1, sizeof(struct ext_comm));

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p == 0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1 ) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {


                        offset = offset+2;
                        len = packet[offset];

                        head_ecomm = &ecomm[0];

                        while (len) {

                            memcpy(&ecomm->ecomm_type, &packet[offset+1], 1);
                            memcpy(&ecomm->ecomm_subtype, &packet[offset+2], 1);
                            memcpy(&ecomm->as2, &packet[offset+3], 2);
                            memcpy(&ecomm->as4, &packet[offset+5], 4);

                            ecomm_len = 8;

                            if (ecomm_len) {

                                s = rand() %6;

                                if (s == 0) {
                                    ecomm->ecomm_type = 0x00;
                                    ecomm->ecomm_subtype = 0x00;
                                    memcpy(&packet[offset+1], &ecomm->ecomm_type, 1);
                                    memcpy(&packet[offset+2], &ecomm->ecomm_subtype, 1);
                                    memset(&ecomm->as2, 0, 2);
                                    memset(&ecomm->as4, 0, 4);
                                    memcpy(&packet[offset+3], &ecomm->as2, 2);
                                    memcpy(&packet[offset+5], &ecomm->as4, 4);
                                }

                                else if (s == 1) {
                                    ecomm->ecomm_type = 0xFF;
                                    ecomm->ecomm_subtype = 0xFF;
                                    memcpy(&packet[offset+1], &ecomm->ecomm_type, 1);
                                    memcpy(&packet[offset+2], &ecomm->ecomm_subtype, 1);
                                    memset(&ecomm->as2, 0xFF, 2);
                                    memset(&ecomm->as4, 0xFF, 4);
                                    memcpy(&packet[offset+3], &ecomm->as2, 2);
                                    memcpy(&packet[offset+5], &ecomm->as4, 4);
                                }

                                else if (s == 2) {
                                    ecomm->ecomm_type = rand() % 0xFF;
                                    ecomm->ecomm_subtype = rand() % 0xFF;
                                    memcpy(&packet[offset+1], &ecomm->ecomm_type, 1);
                                    memcpy(&packet[offset+2], &ecomm->ecomm_subtype, 1);
                                    ecomm->as2 = rand() % 0xFFFF;
                                    ecomm->as4 = rand() % 0xFFFFFFFF;
                                    memcpy(&packet[offset+3], &ecomm->as2, 2);
                                    memcpy(&packet[offset+5], &ecomm->as4, 4);
                                }

                                else if (s == 3) {
                                    ecomm->ecomm_type = 0x00;
                                    ecomm->ecomm_subtype = rand() % 0xFF;
                                    memcpy(&packet[offset+1], &ecomm->ecomm_type, 1);
                                    memcpy(&packet[offset+2], &ecomm->ecomm_subtype, 1);
                                    ecomm->as2 = rand() % 0xFFFF;
                                    ecomm->as4 = rand() % 0xFFFFFFFF;
                                    memcpy(&packet[offset+3], &ecomm->as2, 2);
                                    memcpy(&packet[offset+5], &ecomm->as4, 4);
                                }

                                else if (s == 4) {
                                    ecomm->ecomm_type = 0xFF;
                                    ecomm->ecomm_subtype = rand() % 0xFF;
                                    memcpy(&packet[offset+1], &ecomm->ecomm_type, 1);
                                    memcpy(&packet[offset+2], &ecomm->ecomm_subtype, 1);
                                    ecomm->as2 = 0x0000;
                                    ecomm->as4 = 0x00000000;
                                    memcpy(&packet[offset+3], &ecomm->as2, 2);
                                    memcpy(&packet[offset+5], &ecomm->as4, 4);
                                }

                                else {
                                    ecomm->ecomm_type = rand() % 0xFF;
                                    ecomm->ecomm_subtype = 0x00;
                                    memcpy(&packet[offset+1], &ecomm->ecomm_type, 1);
                                    memcpy(&packet[offset+2], &ecomm->ecomm_subtype, 1);
                                    ecomm->as2 = 0xFFFF;
                                    ecomm->as4 = 0xFFFFFFFF;
                                    memcpy(&packet[offset+3], &ecomm->as2, 2);
                                    memcpy(&packet[offset+5], &ecomm->as4, 4);
                                }

                            }

                            offset = offset + ecomm_len;

                            len = len - ecomm_len;
                            ecomm->next = calloc(1, sizeof(struct ext_comm));
                            ecomm = ecomm->next;

                        }

                        ecomm = head_ecomm;
                    }

                    while(ecomm) {
                        head_ecomm= ecomm;
                        ecomm = ecomm->next;
                        free(head_ecomm);

                    }


                    break;


                case TUNNEL_ENCAP:

                    tcode = calloc(1, sizeof(struct tun_tlv_encode));

                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    if (p == 0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1 ) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {

                        offset = offset+2;
                        len = packet[offset];

                        head_tcode = &tcode[0];

                        while (len) {

                            memcpy(&tcode->encode_type, &packet[offset+1], 2);
                            memcpy(&tcode->encode_len, &packet[offset+3], 2);

                            tun_encap_len = htons(tcode->encode_len);

                            s = rand() %6;

                            if (s == 0) {
                                tcode->encode_type = 0x0000;
                                memcpy(&packet[offset+1], &tcode->encode_type, 2);
                            }

                            else if (s == 1) {
                                tcode->encode_type = 0xFFFF;
                                memcpy(&packet[offset+1], &tcode->encode_type, 2);
                            }

                            else if (s == 2) {
                                tcode->encode_type = rand() % 0xFFFF;
                                memcpy(&packet[offset+1], &tcode->encode_type, 2);
                            }

                            else if (s == 3) {
                                tcode->encode_len = 0x0000;
                                memcpy(&packet[offset+3], &tcode->encode_len, 2);
                            }

                            else if (s == 4) {
                                tcode->encode_len = 0xFFFF;
                                memcpy(&packet[offset+3], &tcode->encode_len, 2);
                            }

                            else if (s == 5) {
                                tcode->encode_len = rand() % 0xFFFF;
                                memcpy(&packet[offset+3], &tcode->encode_len, 2);
                            }

                            tcode->sub = calloc(1, sizeof(struct sub_tun_tlv_encode));
                            subcode = tcode->sub;
                            head_subcode = &subcode[0];

                            while (tun_encap_len) {

                                subcode->sub_type = packet[offset+5];
                                subcode->sub_len = packet[offset+6];
                                memcpy(subcode->sub_value, &packet[offset+7], subcode->sub_len);

                                sub_len = subcode->sub_len;

                                r = rand() %9;

                                if (r==0) {

                                    subcode->sub_type = rand() %0xFF;
                                    packet[offset+5] = subcode->sub_type;

                                }
                                else if (r==1) {

                                    subcode->sub_type = 0xFF;
                                    packet[offset+5] = subcode->sub_type;

                                }

                                else if (r==2){

                                    subcode->sub_type = 0x00;
                                    packet[offset+5] = subcode->sub_type;

                                }

                                else if (r==3){

                                    subcode->sub_len = rand() %0xFF;
                                    packet[offset+6] = subcode->sub_len;

                                }

                                else if (r==4){

                                    subcode->sub_len = 0xFF;
                                    packet[offset+6] = subcode->sub_len;

                                }

                                else if (r==5){

                                    subcode->sub_len = 0x00;
                                    packet[offset+6] = subcode->sub_len;

                                }

                                else if (r==6){

                                    rand_str_gen(subcode->sub_value, sub_len);
                                    memcpy(&packet[offset+7], subcode->sub_value, sub_len);

                                }

                                else if (r==7){

                                    memset(subcode->sub_value, 0, sub_len);
                                    memcpy(&packet[offset+7], subcode->sub_value, sub_len);

                                }

                                else {

                                    memset(subcode->sub_value, 0xFF, sub_len);
                                    memcpy(&packet[offset+7], subcode->sub_value, sub_len);

                                }


                                offset = offset + 2 + sub_len;
                                tun_encap_len = tun_encap_len - 2 - sub_len;
                                tcode_len = tcode_len + 2 + sub_len;

                                subcode->next = calloc(1, sizeof(struct sub_tun_tlv_encode));
                                subcode = subcode->next;
                            }

                            tcode_len +=4;
                            offset = offset +4;
                            len = len - tcode_len;
                            tcode_len = 0;

                            tcode->next = calloc(1, sizeof(struct tun_tlv_encode));
                            tcode = tcode->next;

                        }

                        tcode = head_tcode;
                        subcode = tcode->sub;


                    }


                    while(tcode) {
                        head_tcode= tcode;

                        while(subcode) {
                            head_subcode= subcode;
                            subcode = subcode->next;
                            free(head_subcode);
                        }

                        tcode = tcode->next;
                        free(head_tcode);
                    }

                    break;


                case MP_REACH_NLRI:


                    p = rand() %8;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    nh_len = packet[offset+6];

                    if (p == 0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1 ) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else if (p == 2) {

                        afi = rand() %0xFF+1;
                        offset = offset + 3;
                        packet[offset] = afi;
                        packet[offset+1] = afi >>8;
                    }

                    else if (p == 3 ) {
                        safi = rand() %0xFF+1;
                        offset = offset+5;
                        packet[offset] = safi;
                    }

                    else if (p == 4 ) {
                        nh_len = rand() %0xFF+1;
                        offset = offset+6;
                        packet[offset] = nh_len;
                    }

                    else if (p == 5) {

                        rand_str_gen((u_char *)nhna, nh_len);
                        offset = offset+7;
                        memcpy(&packet[offset], nhna, nh_len);

                    }

                    else if (p == 6) {
                        spna = rand() %0xFF+1;
                        offset = offset+7+nh_len;
                        packet[offset] = spna;
                    }


                    else {

                        offset = offset+2;
                        len = packet[offset];

                        mpnlri_len = len - 5 - nh_len;
                        offset = offset + 6 + nh_len;

                        rand_mpnlri_len = rand() % mpnlri_len +1;

                        /*
                         For the time being, NLRI will be handled as a string.
                         Once the function is allowed to parse through SAFIs, this will change:
                         */

                        r = rand() % 3;

                        if (r == 0)
                            rand_str_gen((u_char *)nlri, rand_mpnlri_len);

                        else if (r == 1)
                            memset(nlri, 0, rand_mpnlri_len);

                        else
                            memset(nlri, 0xFF, rand_mpnlri_len);

                        memcpy(&packet[offset+mpnlri_len-rand_mpnlri_len], nlri, rand_mpnlri_len);

                    }


                    break;


                case MP_UNREACH_NLRI:

                    p = rand() %6;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    nh_len = packet[offset+6];

                    if (p == 0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1 ) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else if (p == 2) {

                        afi = rand() %0xFF+1;
                        offset = offset + 3;
                        packet[offset] = afi;
                        packet[offset+1] = afi >>8;
                    }

                    else if (p == 3 ) {
                        safi = rand() %0xFF+1;
                        offset = offset+5;
                        packet[offset] = safi;
                    }

                    else if (p == 4) {
                        spna = rand() %0xFF+1;
                        offset = offset+7+nh_len;
                        packet[offset] = spna;
                    }


                    else {

                        offset = offset+2;
                        len = packet[offset];

                        mpnlri_len = len - 3;
                        offset = offset + 4;

                        rand_mpnlri_len = rand() % mpnlri_len +1;

                        /*
                         For the time being, NLRI will be handled as a string.
                         Once the function is allowed to parse through SAFIs, this will change:
                         */

                        r = rand() %3;

                        if (r == 0)
                            rand_str_gen((u_char *)nlri, rand_mpnlri_len);

                        else if (r == 1)
                            memset(nlri, 0, rand_mpnlri_len);

                        else
                            memset(nlri, 0xFF, rand_mpnlri_len);

                        memcpy(&packet[offset+mpnlri_len-rand_mpnlri_len], nlri, rand_mpnlri_len);

                    }


                    break;


                case PMSI_TUNNEL:

                    p = rand() %5;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    nh_len = packet[offset+6];

                    if (p == 0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1 ) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else if (p == 2) {

                        tunnel_flag = rand() %0x07+1;
                        offset = offset + 3;
                        packet[offset] = tunnel_flag;
                    }

                    else if (p == 3) {

                        tunnel_type = rand() %0x0A+1;
                        offset = offset + 4;
                        packet[offset] = tunnel_type;
                    }

                    else {

                        offset = offset+2;
                        len = packet[offset];
                        offset = offset + 3;
                        len -= 2;
                        /*
                         For the time being, Tunnel Info will be handled as a string.
                         Once the function is allowed to parse through PMSI, this will change:
                         */

                        r = rand() %3;
                        rand_tunnel_len = rand() % len +1;

                        if (r == 0)
                            rand_str_gen((u_char *)tunnel_info, rand_tunnel_len);

                        else if (r == 1)
                            memset(tunnel_info, 0, rand_tunnel_len);

                        else
                            memset(tunnel_info, 0xFF, rand_tunnel_len);

                        memcpy(&packet[offset+len-rand_tunnel_len], tunnel_info, rand_tunnel_len);

                    }


                    break;

                case ATTR_SET:


                    p = rand() %3;

                    for (c = 0; c<=fuzzed_hdr; c++)
                        offset = bgp_update_path_offsets[fuzzed_hdr][fuzzed_path_field] + bgp_update_offsets[fuzzed_hdr];

                    nh_len = packet[offset+6];

                    if (p == 0) {
                        flags = rand() %0xFF+1;
                        packet[offset] = flags;
                    }

                    else if (p ==1 ) {
                        len = rand() %0xFF+1;
                        offset = offset+2;
                        packet[offset] = len;
                    }

                    else {

                        offset = offset+2;
                        len = packet[offset];
                        offset++;

                        /*
                         For the time being, this entire attribute will be handled as a string.
                         Once the function is allowed to parse through attribute in a callback to fuzz_bgp_update(), this will change:
                         */

                        r = rand() %3;
                        rand_attr_set_len = rand() % len +1;

                        if (r == 0)
                            rand_str_gen((u_char *)attr_set_info, rand_attr_set_len);

                        else if (r == 1)
                            memset(tunnel_info, 0, rand_attr_set_len);

                        else
                            memset(tunnel_info, 0xFF, rand_attr_set_len);

                        memcpy(&packet[offset+len-rand_attr_set_len], attr_set_info, rand_attr_set_len);

                    }


                    break;



                default:
                    break;
            }

        }


        else {

            while (bgp_update_nlri_offsets[fuzzed_hdr][l])
                l++;
            if (l)
                fuzzed_nlri_field = rand() %l;                          //this is a nlri to randomize
            else
                continue;

            for (c = 0; c<=fuzzed_nlri_field; c++) {
                bgp_update_ptr->nlri_list = bgp_update_ptr->nlri_list->next;
            }

            bgp_update_ptr->nlri_list = bgp_update_head->nlri_list;


            p = rand() %2;

            for (c = 0; c<=fuzzed_hdr; c++)
                offset = bgp_update_nlri_offsets[fuzzed_hdr][fuzzed_nlri_field] + bgp_update_offsets[fuzzed_hdr];

            if (p == 0) {

                len = packet[offset];

                if (len>=0 && len<=8)
                    len = 1;
                else if (len>=9 && len<=16)
                    len = 2;
                else if (len>=17 && len<=24)
                    len = 3;
                else if (len>=25 && len<=32)
                    len = 4;


                r = rand() %2;

                if (r) {
                    if (len > 1) {
                        rand_str_gen((u_char *)nlri_data, len);
                        memcpy(&packet[offset+1], nlri_data, len);
                    }
                    else
                        packet[offset+1] =  rand() %0xFF+1;
                }
                else {
                    if (len > 1) {
                        memset(nlri_data, 0, len);
                        memcpy(&packet[offset+1], nlri_data, len);
                    }
                    else
                        packet[offset+1] =  0x00;

                }

            }

            else {

                r = rand() %3;

                if (r == 0)
                    packet[offset] =  0x00;
                else if (r == 1)
                    packet[offset] =  0xFF;
                else
                    packet[offset] = rand() %0xFF;

            }

        }


        n--;
    }



    fprintf(stderr, "%d.Fuzzing BGP UPDATE with %d bytes of %s data\n", init+1, packet_size, tuple.protocol);
    init++;

    return packet_size;

}


size_t fuzz_bgp_notify(u_char *packet, struct bgp_hdr *bgp_hdr) {

    fprintf(stderr, "%d.Fuzzing BGP NOTIFY with %d bytes of %s data\n", init+1, packet_size, tuple.protocol);
    init++;


}
