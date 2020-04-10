/*
 *  $Id: fuzz.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  fuzz.h - Network fuzzing library header file
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */




#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/select.h>
#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <dumbnet.h>
#include <postgresql/libpq-fe.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <libssh/libssh.h>
#include <pthread.h>



#define L2HDR_LEN   14

#define IPSEG_LEN   34
#define IP_UDPSEG_LEN   42
#define IP_TCPSEG_LEN  54

#define IPv6_UDPSEG_LEN     62
#define IPv6_TCPSEG_LEN  74
#define IPv6_IPSEG_LEN   54

#define ARPHDR_SIZE 28
#define IPHDR_SIZE  20
#define IP6HDR_SIZE  40
#define UDPHDR_SIZE     8
#define TCPSYNHDR_SIZE	40
#define TCPHDR_SIZE 	20

#define MAX_PACK_ARRAY_SIZE   32088
#define MAX_PACK_SIZE      4584
#define REG_PACK_SIZE     1024

#define MACSIZE 6

#define FAIL 0
#define SUCCESS 1

#define PING_FAIL 0
#define BUF_OVFL 1

#define MAC_ADDR_LEN    6
#define MAC_ADDR_STR_LEN    18


#define ETHERTYPE_IP6 0x86DD

#define CURR_INSTR_SETS 10




struct tuple {
    u_char *mode;
    u_char *source;
    u_char *destination;
    u_char *intf;
    u_char *file;
    u_char *protocol;
    u_char *dport;
    int num;
    double timer;
    u_char *hw_address;
    u_char *db_pass;
    u_char *db_protocol;
    int db_display;
    int db_load;
    int test_num;
    int quit;
    int verbose;
    u_char *os_data;
    u_char *os_type;
    int instrumentation;
    char *instrumentation_signature;
    char *instrumentation_preset;
    int cpu;
    char *enable_pass;
    char *user;
    char *user_pass;
    char *comment;
    pthread_t *ssh_tid;
    char test_id[][20];
} tuple;



struct type_of_packet {
    u_char l3_type[5];
    u_char l4_type[8];
};


struct fuzzed_data {
	u_int32_t offset;
	u_int32_t size;
	u_char *fdata;
	u_char *fname;
};


struct type_of_packet *type_of_packet;


int pack_size[7];

int userid, groupid;


void print_help(void);

bool is_prime(int number);

void tuple_db_sanity(void);

int convert_xstring_to_dec(u_char *string, int size);

void rand_str_gen(u_char *rand_str, size_t length);

void rand_ipv4_gen(u_char* address_string, u_char *address);

void rand_ipv4_octet_gen(u_char* address_string, int octet, u_char *address);

void dest_ipv4_overwrite(u_char* address_string, u_char * destination);

void dest_ipv6_overwrite(u_char* address_string, u_char * destination);


void get_mac_address(u_char *address, u_char *mac_addr_str);

void get_mac_address_6(u_char *address, u_char *mac_addr_str);

void parse_mac_output(u_char *mac_address);

void find_route_entry(u_char *address, u_char *gw_address);



void packet_save(u_char *packet, int packet_size);

int calc_failed_percentage(int failed_count, int packet_count);


int get_data_offset(char * protocol);


bool check_ipv4_addr(u_char *address);

bool check_ipv6_addr(u_char *address);


void parse_l3_info (const u_char *pkt_ptr);

void parse_l3_l4_info(const u_char *pkt_ptr);

u_char * parse_ipv6_hdrs(int8_t l4_prot);


void get_userid(void);

int ping_to_uut(u_char *destination);

int ping6_to_uut(struct tuple *tuple);

void set_environment(u_char *address);

void no_failure_log(void);

void vsig_handler(int sig, siginfo_t *info, void * context);




libnet_t * build_libnet_link_adv(struct tuple * tuple);

void build_pack(struct tuple * tuple);

void build_session(struct tuple * tuple);


void build_ew_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet, const u_char *o_packet);

void build_arp_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet);

void build_ipv4_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet);

void build_ipv6_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet);

void build_icmp_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet);

void build_udp_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet);

void build_tcp_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet);


void build_ike_session(u_char *pkt_ptr, struct tuple *tuple, struct pcap_pkthdr header, u_char *init_packet, const u_char *full_packet);

void build_bgp_session(struct tuple * tuple);



void save_pkt_desc_html(struct type_of_packet *type_of_packet, const u_char *o_packet, u_char *f_packet, int psize, struct fuzzed_data *ew_fdata, u_char *test_id);

void mark_changed_data(u_char *m_packet, u_char *t_packet, struct fuzzed_data *ew_fdata);


int ew_fdata_find_duplicates_sort(struct fuzzed_data *ew_fdata, struct fuzzed_data *ew_fdata_c);

int ew_fdata_find_dup_elems(struct fuzzed_data *ew_fdata, struct fuzzed_data *ew_fdata_c);


