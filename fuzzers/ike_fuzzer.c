


/*
 ##############################################################################
 Revision #      1.0
 Name:               :  ew_fuzzer.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Routines for fuzzing over IKE protocol data.
 ##############################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_ike.h"


u_char *null_str = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";


int get_ike_payload_count(const u_char *pkt_ptr, u_int32_t total_hdr_len) {

    int count = 0;
    u_int16_t *plen;
    u_int16_t len = 0;
    int i = 0;

    u_int8_t np = pkt_ptr[16];
    int header_len_left = total_hdr_len - sizeof(struct ikev2_main) + sizeof(int);
    ike_payload_offsets[i] = sizeof(struct ikev2_main) - sizeof(int);
    ike_payload_types[i] = np;
    i++;

    if (np) {

        while (np) {

            np = pkt_ptr[total_hdr_len-header_len_left];
            plen = (u_int16_t *)&pkt_ptr[total_hdr_len-header_len_left+2];
            len = ntohs(*plen);
            header_len_left = header_len_left - len;
            ike_payload_offsets[i] = ike_payload_offsets[i-1] + len;
            ike_payload_types[i] = np;
            count++;
            i++;
        }

        ike_payload_offsets[i-1] = 0;
        ike_payload_types[i-1] = 0;

        return count;
    }

    else {
        fprintf(stderr, "No Payload for the type. Not sure what to do with this packet. Exiting.\n");
        exit(-1);
    }
}


void get_ike_trans_offsets(int trans_num, u_char *pkt_ptr, int curr_offset) {

	int i = 0;
	u_int16_t len;
	trans_offsets[i] = curr_offset;
	i++;

	for (;i<trans_num;i++) {
		len = pkt_ptr[curr_offset + 2];
		trans_offsets[i] = curr_offset + len;
		i++;
	}

}


void fuzz_ike_payload(int payload_count, u_char * pkt_ptr) {

    int w, p, r, j, k=0, i, x, g;
    static int z =0;

    int ike_payload_type;
    u_int16_t ike_payload_len;
    u_int16_t *plen;

    int curr_offset;

    u_int8_t np;
    u_int8_t critical;
    u_int16_t len;

    u_int16_t dh_group;

    u_int8_t proposal;
    u_int8_t prot_id;
    u_int8_t spi_size;
    u_int8_t trans_num;

    u_int8_t trans_type;
    u_int16_t trans_id;
    u_int16_t trans_len;
    u_int32_t trans_att_type;

    u_int8_t cert_encoding;
    u_int8_t id_type;
    u_int8_t auth_method;
    u_int8_t nts;
    u_int8_t tst;
    u_int8_t sel_len;
    u_int8_t sport;
    u_int8_t eport;

    u_int16_t not_msg_type;
    u_int16_t port;

    char rand_str_1[8];
    char rand_str_2[16];
    char rand_str_4[32];
    char rand_str[128];
    u_char len_str_1[1];
    u_char len_str_2[2];

    if (payload_count == 1)
        w = 1;
    else {
        w = rand() % payload_count;       // TLV to fuzz
        while (w==0)
            w = rand() % payload_count;
    }

    /*
     for (i = 0; i<w; i++)
     payload_list_size = ike_payload_offsets[i];
     */

    ike_payload_type = ike_payload_types[w-1];
    plen = (u_int16_t*)&pkt_ptr[ike_payload_offsets[w-1]+2];
    ike_payload_len =  ntohs(*plen);

    switch(ike_payload_type) {

    	case SA_ASSOC:
    		r = rand() % 20;
    		while (r == 0)
    			r = rand() % 20;
    		if (r > 10) {
	    		trans_num = pkt_ptr[ike_payload_offsets[w-1]+11];
	    		curr_offset = ike_payload_offsets[w-1]+12;
	    		get_ike_trans_offsets(trans_num, &pkt_ptr[ike_payload_offsets[w-1]+12], curr_offset);
	    		r = rand() % trans_num;
	    		while (r == 0)
	    			r = rand() % trans_num;
	    		trans_len = ntohs(pkt_ptr[trans_offsets[r]+2]);
	    		if (trans_len == 12) {
	    			p = rand() % 6;
	    			while (p == 0)
	    				p = rand() % 6;
	    		}
	    		else {
	    			p = rand() % 5;
	    			while (p == 0)
	    				p = rand() % 5;
	    		}
	    		if (p == 1) {
	    			np = rand();
	    			pkt_ptr[trans_offsets[r]] = np;
	    		}
	    		else if (p == 2) {
	    			critical = rand();
	    			pkt_ptr[trans_offsets[r]+1] = critical;
	    		}
	    		else if (p == 3) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[trans_offsets[r]+2], rand_str_2, sizeof(u_int16_t));
	    		}
	    		else if (p == 4) {
	    			trans_type = rand();
	    			pkt_ptr[trans_offsets[r]+4] = trans_type;
	    		}
	    		else if (p == 5) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[trans_offsets[r]+5], rand_str_2, sizeof(u_int16_t));
	    		}
	    		else if (p == 6) {
	    			trans_att_type = rand();
	    			pkt_ptr[trans_offsets[r]+7] = trans_att_type;
	    		}

	    	}

	    	else {
	    		if (r == 1) {
	    			np = rand();
	    			pkt_ptr[ike_payload_offsets[w-1]] = np;
	    		}
	    		else if (r == 2) {
	    			critical = rand();
	    			pkt_ptr[ike_payload_offsets[w-1]+1] = critical;
	    		}
	    		else if (r == 3) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
	    		}
	    		else if (r == 4) {
	    			np = rand();
	    			pkt_ptr[ike_payload_offsets[w-1]+4] = np;
	    		}
	    		else if (r == 5) {
	    			critical = rand();
	    			pkt_ptr[ike_payload_offsets[w-1]+5] = critical;
	    		}
	    		else if (r == 6) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+6], rand_str_2, sizeof(u_int16_t));
	    		}
	    		else if (r == 7) {
	    			proposal = rand();
	    			pkt_ptr[ike_payload_offsets[w-1]+8] = proposal;
	    		}
	    		else if (r == 8) {
	    			prot_id = rand();
	    			pkt_ptr[ike_payload_offsets[w-1]+9] = prot_id;
	    		}
	    		else if (r == 9) {
	    			spi_size = rand();
	    			pkt_ptr[ike_payload_offsets[w-1]+10] = spi_size;
	    		}
	    		else if (r == 10) {
	    			trans_num = rand();
	    			pkt_ptr[ike_payload_offsets[w-1]+11] = trans_num;
	    		}


	    		else if (r == 5) {
	    			len = ntohs(pkt_ptr[ike_payload_offsets[w-1]+2]) - 6;
	    			rand_str_gen(rand_str, len);
	    			memcpy((u_char *)&pkt_ptr[ike_payload_offsets[w-1]+6], rand_str, len);
	    		}
	    	}

    		break;

    	case KEY_EXCH:
    		r = rand() % 5;
    		while (r == 0)
    			r = rand() % 5;

    		if (r == 1) {
    			np = rand();
    			pkt_ptr[ike_payload_offsets[w-1]] = np;
    		}
    		else if (r == 2) {
    			critical = rand();
    			pkt_ptr[ike_payload_offsets[w-1]+1] = critical;
    		}
    		else if (r == 3) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
    		}
    		else if (r == 4) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+4], rand_str_2, sizeof(u_int16_t));
    		}

    		else if (r == 5) {
    			len = ntohs(pkt_ptr[ike_payload_offsets[w-1]+2]) - 6;
    			rand_str_gen(rand_str, len);
    			memcpy((u_char *)&pkt_ptr[ike_payload_offsets[w-1]+6], rand_str, len);
    		}

    		break;

    	case NONCE:
    	case VID:
    		r = rand() % 5;
    		while (r == 0)
    			r = rand() % 5;

    		if (r == 1) {
    			np = rand();
    			pkt_ptr[ike_payload_offsets[w-1]] = np;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 2) {
    			critical = rand();
    			pkt_ptr[ike_payload_offsets[w-1]+1] = critical;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 3) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
    		}
    		else if (r == 4) {
    			len = ntohs(pkt_ptr[ike_payload_offsets[w-1]+2]) - 4;
    			rand_str_gen(rand_str, len);
    			memcpy((u_char *)&pkt_ptr[ike_payload_offsets[w-1]+4], rand_str, len);
    		}
            else
    			memcpy((u_char *)&pkt_ptr[ike_payload_offsets[w-1]], null_str, 4);
            break;

        case FRAG:
            r = rand() % 4;
    		while (r == 0)
    			r = rand() % 4;

    		if (r == 1) {
    			np = rand();
    			pkt_ptr[ike_payload_offsets[w-1]] = np;
                x=rand() %4;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 2) {
    			critical = rand();
    			pkt_ptr[ike_payload_offsets[w-1]+1] = critical;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 3) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
    		}
            else
    			memcpy((u_char *)&pkt_ptr[ike_payload_offsets[w-1]], null_str, 4);
    		break;

        case ENCR:
    		r = rand() % 5;
    		while (r == 0)
    			r = rand() % 5;

    		if (r == 1) {
    			np = rand();
    			pkt_ptr[ike_payload_offsets[w-1]] = np;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 2) {
    			critical = rand();
    			pkt_ptr[ike_payload_offsets[w-1]+1] = critical;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 3) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
    		}
            if (r == 4) {
                cert_encoding = rand() % 255;
                pkt_ptr[ike_payload_offsets[w-1]+4]= cert_encoding;
            }
    		else if (r == 5) {
    			len = ntohs(pkt_ptr[ike_payload_offsets[w-1]+2]) - 4;
                if (len) {
                    rand_str_gen(rand_str, len);
                    memcpy((u_char *)&pkt_ptr[ike_payload_offsets[w-1]+5], rand_str, len);
                }
    		}
            break;

        case CERT:
        case CERT_REQ:
    		r = rand() % 5;
    		while (r == 0)
    			r = rand() % 5;

    		if (r == 1) {
    			np = rand();
    			pkt_ptr[ike_payload_offsets[w-1]] = np;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 2) {
    			critical = rand();
    			pkt_ptr[ike_payload_offsets[w-1]+1] = critical;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 3) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
    		}
            if (r == 4) {
                rand_str_gen(rand_str, 4);
                memcpy((u_char *)&pkt_ptr[ike_payload_offsets[w-1]+4], rand_str, 4);
            }
    		else if (r == 5) {
    			len = ntohs(pkt_ptr[ike_payload_offsets[w-1]+2]) - 4;
                if (len) {
                    rand_str_gen(rand_str, len);
                    memcpy((u_char *)&pkt_ptr[ike_payload_offsets[w-1]+8], rand_str, len);
                }
    		}
            break;

        case NOTIFY:
    		r = rand() % 7;
    		while (r == 0)
    			r = rand() % 7;

    		if (r == 1) {
    			np = rand();
    			pkt_ptr[ike_payload_offsets[w-1]] = np;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 2) {
    			critical = rand();
    			pkt_ptr[ike_payload_offsets[w-1]+1] = critical;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 3) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
    		}
            if (r == 4) {
                prot_id = rand() % 255;
                pkt_ptr[ike_payload_offsets[w-1]+4]= prot_id;
            }
            if (r == 5) {
                spi_size = rand() % 255;
                pkt_ptr[ike_payload_offsets[w-1]+5]= spi_size;
            }
            if (r == 6) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+6], rand_str_2, sizeof(u_int16_t));
            }

    		else if (r == 7) {
    			len = ntohs(pkt_ptr[ike_payload_offsets[w-1]+2]) - 8;
                if (len) {
                    rand_str_gen(rand_str, len);
                    memcpy((u_char *)&pkt_ptr[ike_payload_offsets[w-1]+8], rand_str, len);
                }
    		}
            break;

        case IDENT:
    		r = rand() % 7;
    		while (r == 0)
    			r = rand() % 7;

    		if (r == 1) {
    			np = rand();
    			pkt_ptr[ike_payload_offsets[w-1]] = np;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 2) {
    			critical = rand();
    			pkt_ptr[ike_payload_offsets[w-1]+1] = critical;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 3) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
    		}
            if (r == 4) {
                id_type = rand() % 255;
                pkt_ptr[ike_payload_offsets[w-1]+4]= id_type;
            }
            if (r == 5) {
                prot_id = rand() % 255;
                pkt_ptr[ike_payload_offsets[w-1]+5]= prot_id;
            }
            if (r == 6) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+6], rand_str_2, sizeof(u_int16_t));
            }

    		else if (r == 7) {
    			len = ntohs(pkt_ptr[ike_payload_offsets[w-1]+2]) - 8;
                if (len) {
                    rand_str_gen(rand_str, len);
                    memcpy((u_char *)&pkt_ptr[ike_payload_offsets[w-1]+8], rand_str, len);
                }
    		}
            break;

        case AUTH:
    		r = rand() % 5;
    		while (r == 0)
    			r = rand() % 5;

    		if (r == 1) {
    			np = rand();
    			pkt_ptr[ike_payload_offsets[w-1]] = np;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 2) {
    			critical = rand();
    			pkt_ptr[ike_payload_offsets[w-1]+1] = critical;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 3) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
    		}
            if (r == 4) {
                auth_method = rand() % 255;
                pkt_ptr[ike_payload_offsets[w-1]+4]= auth_method;
            }
    		else if (r == 5) {
    			len = ntohs(pkt_ptr[ike_payload_offsets[w-1]+2]) - 8;
                if (len) {
                    rand_str_gen(rand_str, len);
                    memcpy((u_char *)&pkt_ptr[ike_payload_offsets[w-1]+8], rand_str, len);
                }
    		}
            break;

        case TSI:
        case TSR:
    		r = rand() % 12;
    		while (r == 0)
    			r = rand() % 7;

    		if (r == 1) {
    			np = rand();
    			pkt_ptr[ike_payload_offsets[w-1]] = np;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 2) {
    			critical = rand();
    			pkt_ptr[ike_payload_offsets[w-1]+1] = critical;
                x=rand() %2;
                if (x==0){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==1){
                    len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+2] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+3] = len;
                }
                if (x==2){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    len = rand() %10;
                    sprintf(len_str_1, "%d", htons(len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+3], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 3) {
                rand_str_gen(rand_str_2, 2);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+2], rand_str_2, sizeof(u_int16_t));
    		}
            else if (r == 4) {
                nts = rand() % 255;
                pkt_ptr[ike_payload_offsets[w-1]+4]= prot_id;
            }
            else if (r == 5) {
                tst = rand() % 255;
                pkt_ptr[ike_payload_offsets[w-1]+8]= spi_size;
            }
            else if (r == 6) {
                prot_id = rand() % 255;
                pkt_ptr[ike_payload_offsets[w-1]+9]= prot_id;
            }
    		else if (r == 7) {
                x=rand() %2;
                if (x==0){
                    sel_len = rand() %255;
                    pkt_ptr[ike_payload_offsets[w-1]+10] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+11] = sel_len;
                }
                if (x==1){
                    sel_len = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+10] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+11] = sel_len;
                }
                if (x==2){
                    sel_len = rand() %255;
                    sprintf(len_str_1, "%d", htons(sel_len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+10], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    sel_len = rand() %10;
                    sprintf(len_str_1, "%d", htons(sel_len));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+11], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+10], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 8) {
                x=rand() %2;
                if (x==0){
                    sport = rand() %255;
                    pkt_ptr[ike_payload_offsets[w-1]+12] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+13] = sport;
                }
                if (x==1){
                    sport = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+12] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+13] = sport;
                }
                if (x==2){
                    sport = rand() %255;
                    sprintf(len_str_1, "%d", htons(sport));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+12], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    sport = rand() %10;
                    sprintf(len_str_1, "%d", htons(sport));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+13], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+12], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 9) {
                x=rand() %2;
                if (x==0){
                    eport = rand() %255;
                    pkt_ptr[ike_payload_offsets[w-1]+14] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+15] = eport;
                }
                if (x==1){
                    eport = rand() %10;
                    pkt_ptr[ike_payload_offsets[w-1]+14] = 0x00;
                    pkt_ptr[ike_payload_offsets[w-1]+15] = eport;
                }
                if (x==2){
                    eport = rand() %255;
                    sprintf(len_str_1, "%d", htons(eport));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+14], len_str_1, sizeof(u_int8_t));
                }
                if (x==3){
                    eport = rand() %10;
                    sprintf(len_str_1, "%d", htons(eport));
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+15], len_str_1, sizeof(u_int8_t));
                }
                if (x==4) {
                    rand_str_gen(rand_str_2, 2);
                    memcpy(&pkt_ptr[ike_payload_offsets[w-1]+14], rand_str_2, sizeof(u_int16_t));
                }
    		}
    		else if (r == 10) {
                rand_str_gen(rand_str_4, 4);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+16], rand_str_4, sizeof(u_int32_t));
    		}
    		else if (r == 11) {
                rand_str_gen(rand_str_4, 4);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+20], rand_str_4, sizeof(u_int32_t));
    		}
            else {
                rand_str_gen(rand_str_4, 4);
                memcpy(&pkt_ptr[ike_payload_offsets[w-1]+5], rand_str_4, 3);
            }
            break;


    	default:
            fprintf(stderr, "Payload type not recognized.\n");
            exit(-1);
    }

    // Additional level of null fuzzing:

    /*
    x = rand() % 20;

    if (x==0) {
        g = rand() % payload_count;
        memcpy((u_char *)&pkt_ptr[ike_payload_offsets[g-1]], null_str, 12);
    }
    */
    /*

     if (r==0) {
     rand_str_gen(tlv_rand_str, strlen(tlv_rand_str));
     memcpy((u_char *)&pkt_ptr[tlv_list_size+12], tlv_rand_str, tlv_value_size);
     }

     if (r==1) {
     agg = rand() % 2;
     pkt_ptr[tlv_list_size] = agg;

     }

     if (r==2) {
     type3 = rand() % 128;
     pkt_ptr[tlv_list_size+3] = type3;
     }


     if (r==3) {
     rand_str_gen(tlv_rand_str_4, strlen(tlv_rand_str_4));
     memcpy((u_char *)&pkt_ptr[tlv_list_size+4], tlv_rand_str_4, 4);
     }

     if (r==4) {
     tag = rand() % 2;
     pkt_ptr[tlv_list_size+8] = tag;
     }
     */

}


