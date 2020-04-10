

/*
 *  $Id: fuzz.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  fuzz_ew.h - Network fuzzing library header file for IKE protocol
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */


#define IKE_PORT    500
#define NATT_PORT    4500


#define IKE_SA_INIT 34
#define INFORMATIONAL   37

#define SA_ASSOC 	33
#define KEY_EXCH	34
#define IDENT		35
#define CERT        37
#define CERT_REQ    38
#define AUTH		39
#define NONCE		40
#define NOTIFY		41
#define VID 		43
#define TSI         44
#define TSR         45
#define ENCR        46
#define FRAG 		132



struct ikev2_main {
    double i_cookie;
    double r_cookie;
    u_int8_t next_payload;
    u_int8_t version;
    u_int8_t exchange_type;
    u_int8_t flags;
    u_int32_t msg_id;
    u_int32_t len;
};

struct ikev2_payload {
    u_int8_t next_payload;
    u_int8_t critical;
    u_int16_t len;
    u_char *data;
};

struct ikev2_transform_payload {
    u_int8_t next_payload;
    u_int8_t critical;
    u_int16_t len;
    u_int8_t type;
    u_int16_t id;
};


struct ikev2_sa_payload {
    struct ikev2_payload ike2_payload;
    u_int8_t next_payload;
    u_int8_t critical;
    u_int16_t len;
    u_int8_t proposal_num;
    u_int8_t prot_id;
    u_int8_t spi_size;
    u_int8_t transforms;
    struct ikev2_transform_payload trans_number[65500];
};


int ike_payload_offsets[64];
int ike_payload_types[64];
int trans_offsets[64];




void get_ike_trans_offsets(int trans_num, u_char *pkt_ptr, int curr_offset);

int get_ike_payload_count(const u_char *pkt_ptr, u_int32_t total_hdr_len);

void parse_ike_payload_offsets(const u_char *pkt_ptr, u_int32_t total_hdr_len, int payload_count);

void fuzz_ike_payload(int payload_count, u_char *pkt_ptr);

void build_ike_session(u_char *pkt_ptr, struct tuple *tuple, struct pcap_pkthdr header, u_char *init_packet, const u_char *full_packet);



