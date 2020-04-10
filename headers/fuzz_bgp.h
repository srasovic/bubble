
/*
 *  $Id: fuzz_bgp.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  fuzz_bgp.h - Network fuzzing library header file for BGP protocol
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */



#define BGP_PORT        179

// BGP message types:

#define OPEN            0x01
#define UPDATE          0x02
#define NOTIFICATION    0x03
#define KEEPALIVE       0x04
#define ROUTE_REFRESH   0x05


// BGP Path Attribute types:

#define RESERVED                    0
#define ORIGIN                      1
#define AS_PATH                     2
#define NEXT_HOP                    3
#define MULTI_EXIT_DISC             4
#define LOCAL_PREF                  5
#define ATOMIC_AGGREGATE            6
#define AGGREGATOR                  7
#define COMMUNITY                   8
#define ORIGINATOR_ID               9
#define CLUSTER_LIST                10
#define MP_REACH_NLRI               14
#define MP_UNREACH_NLRI             15
#define EXTENDED_COMMUNITIES        16
#define AS4_PATH                    17
#define AS4_AGGREGATOR              18
#define PMSI_TUNNEL                 22
#define TUNNEL_ENCAP                23
#define TRAFFIC_ENG                 24
#define IPv6_ADDR_SPEC              25
#define AIGP                        26
#define PE_DIST_LABEL               27
#define BGP_LS                      29
#define ATTR_SET                    128

#define BGP_HDR_SIZE        19
#define BGP_OPEN_SIZE       10


#define MODE_SINGLE         1
#define MODE_MULTIPLE       0xFF

int bgp_msg_type;
u_int16_t bgp_my_as;

int bgp_params_offsets[64];
int bgp_param_list_size;
int bgp_data_len;


struct bgp_hdr {

    u_int32_t marker1;
    u_int32_t marker2;
    u_int32_t marker3;
    u_int32_t marker4;
    u_int16_t len;
    u_int8_t type;
    struct bgp_hdr *next;
};

struct bgp_open {

    u_int8_t version;
    u_char my_as[2];
    u_int16_t holdtime;
    u_char identifier[4];
    u_int8_t param_len;
    struct bgp_opt_param_capabilities *params;
};


struct bgp_update {

    u_int16_t wr_len;
    u_int16_t tpa_len;
    struct bgp_path_attribute *path_list;
    struct bgp_nlri *nlri_list;
    struct bgp_update *next;
};


struct bgp_notification {

    u_int8_t maj_err_code;
    u_int8_t min_err_code;
    u_char *data;
};


struct bgp_opt_param_capabilities {

    u_int8_t type;
    u_int8_t len;
    u_int8_t ctype;
    u_int8_t clen;
    u_char *value;
};


struct bgp_path_attribute {

    u_int8_t flags;
    u_int8_t code;
    u_int8_t len;
    u_char *data;
    struct bgp_path_attribute *next;
};


struct bgp_nlri {

    u_int8_t prefix_len;
    u_char *data;
    struct bgp_nlri *next;
};




unsigned int asdot_convert(u_char * asn_s, int len);


void build_bgp_session(struct tuple * tuple);

void build_dummy_bgp_open(struct bgp_open *open);

size_t build_dummy_bgp_update(struct bgp_update *bgp_update, struct bgp_hdr *bgp_hdr, int num_hdrs);

size_t build_dummy_bgp_notify(struct bgp_notification *notify);

void build_dummy_bgp_keepalive(struct bgp_hdr *keepalive);


size_t fuzz_bgp_open(u_char *packet, struct bgp_hdr *bgp_hdr);

size_t fuzz_bgp_update(u_char *packet, struct bgp_update *bgp_update, int num_hdrs, int mode);

size_t fuzz_bgp_notify(u_char *packet, struct bgp_hdr *bgp_hdr);


void parse_bgp_params(u_char *params, size_t param_list_size);


void run_bgp_update(pcap_t *pc, struct pcap_pkthdr *pkt, u_int8_t *pkt_ptr);

void run_bgp_open(pcap_t *pc, struct pcap_pkthdr *pkt, u_int8_t *pkt_ptr);

void run_bgp_notify(pcap_t *pc, struct pcap_pkthdr *pkt, u_int8_t *pkt_ptr);


int parse_recvd_bgp_packet(int sockfd, u_char *r_packet, int psize);

void deallocate_bgp_update_data(struct bgp_update *bgp_update, int num_hdrs);

