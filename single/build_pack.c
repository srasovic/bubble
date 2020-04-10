
/*
 ##########################################################################################
 Revision #      1.0
 Name:               :  build_pack.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Packet builder routines for non-session fuzzing.
 ##########################################################################################
 */


#include "../headers/fuzz.h"
//#include "fuzz_ew.h"
#include "../headers/fuzz_ike.h"
#include "../headers/fuzz_arp.h"
#include "../headers/fuzz_ipv4.h"
#include "../headers/fuzz_ipv6.h"
#include "../headers/instrumentation.h"
#include "../headers/database.h"



libnet_t * build_libnet_link_adv(struct tuple * tuple) {

    libnet_t *libt_init = NULL;
    char err[256];

    //should never be here:

	if (tuple->intf == NULL) {
	    libt_init = libnet_init(LIBNET_LINK_ADV, NULL, err);
        fprintf(stderr, "Interface not specified. Initializing testing interface to the first interface on the system.\n");
    }
	else
	    libt_init = libnet_init(LIBNET_LINK_ADV, tuple->intf, err);

	if (libt_init==NULL){
        fprintf(stderr, "Error Initializing libnet: %s\n", err);
        libnet_destroy(libt_init);
        exit(-1);
    }
    else
        return libt_init;
}


void build_pack(struct tuple * tuple) {


    /*

     This mode is reserved for non-stateful protocols that do not require to establish a 2-way communication.
     It is also used by protocols that communicate directly on the L2/L3: ICMP, OSPF, ARP, etc...
     Energywise bellow is just an exception to this rule, being the first one that was developed.

     */


    type_of_packet = (struct type_of_packet *) calloc(1, sizeof(struct type_of_packet));

    int result =0;
    const u_char *packet;
    struct pcap_pkthdr header;
    pcap_t *pc;
    char perrbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program filter;
    bpf_u_int32 maskp=0;

    char protocol;
    char *filter_exp;


    /*
    if (strncmp(tuple->protocol, "energywise", 10)==0) {
        protocol = 'e';
        filter_exp = "port 43440";
    }
    */

    if (strncmp(tuple->protocol, "arp", 3)==0) {
        protocol = 'a';
        filter_exp = "arp";
    }
/*
    else if (strncmp(tuple->protocol, "udp", 3)==0) {
        protocol = 'u';
        filter_exp = "udp";
    }
    else if (strncmp(tuple->protocol, "tcp", 3)==0) {
        protocol = 't';
        filter_exp = "tcp";
    }
    else if (strncmp(tuple->protocol, "ipv4", 4)==0) {
        protocol = '4';
        filter_exp = "ip";
    }
    else if (strncmp(tuple->protocol, "ipv6", 4)==0) {
        protocol = '6';
        filter_exp = "ip6";
    }
 */

    else  {
        fprintf(stderr, "Uknown protocol. Please try again.\n");
        exit(-1);
    }



    if (!tuple->file) {
        read_sample_db_pack(tuple->db_pass, tuple->protocol);
        tuple->file = "temp1.pcap";
    }


    pc = pcap_open_offline(tuple->file, perrbuf);

    if (!pc) {
        fprintf(stderr, "Unable to open a capture file. Exiting.\n");
        result = access("temp1.pcap", F_OK);
        if (result!=-1)
            remove("temp1.pcap");
        exit(-1);
    }

    /*
    	
	Bug caught by Singh, Sandeep Kumar:
	
	int f = pcap_compile(pc, &filter, filter_exp, 1, maskp);

	This worked, but is now broken in the current release of libpcap. 
	The bug is related to snapshot issues with pcap_snaplen() internally being called by compile module.
    	Setting snaplen manually to avoid the issue - it's a hack that works, but may need to be changed later.
    
    */
	
    int f = pcap_compile_nopcap(1520, DLT_EN10MB, &filter, filter_exp, 1, maskp);


    if (f<0) {
        fprintf(stderr, "Filter compilation failed. Exiting.\n");
        result = access("temp1.pcap", F_OK);
        if (result!=-1)
            remove("temp1.pcap");
        exit(-1);
    }

    int s = pcap_setfilter(pc, &filter);

    if (s<0) {
        fprintf(stderr, "pcap_setfilter() failed. Exiting.\n");
        result = access("temp1.pcap", F_OK);
        if (result!=-1)
            remove("temp1.pcap");
        exit(-1);
    }

    packet = (const u_char *)pcap_next(pc, &header);

    //perhaps the better check here would be "if(!header.len)..."

    if (!packet){
        fprintf(stderr, "No %s packet to read. Exiting.\n", tuple->protocol);
        result = access("temp1.pcap", F_OK);
        if (result!=-1)
            remove("temp1.pcap");
        exit(-1);
    }

    result = access("temp1.pcap", F_OK);
    if (result!=-1)
        remove("temp1.pcap");


    switch (protocol) {
        /*
        case 'e' :
            parse_l3_l4_info(packet);
            if (strncmp(type_of_packet->l3_type, "ipv6", 4)==0) {
                fprintf(stderr, "Unsupported Energywise L3 protocol.\n");
                exit(-1);
            }
            break;
            */
        case '4' :
        case '6' :
        case 't' :
        case 'u' :
            break;
        case 'a' :
            parse_l3_info(packet);
            if (strncmp(type_of_packet->l3_type, "ipv4", 4)!=0) {
                fprintf(stderr, "Unsupported ARP L3 protocol.\n");
                exit(-1);
            }
            break;
        default:
            //should not end up here.
            break;
    }

    int data_offset = get_data_offset(tuple->protocol);


    u_char *data_ptr = calloc(1, header.len);
    data_ptr = (u_char *)packet + data_offset;
    u_char *init_packet = calloc(1, header.len);
    memcpy(init_packet, data_ptr, header.len);

    /*
    if (protocol == 'e') {

        if ((!tuple->mode)||(strncmp(tuple->mode, "single", 5)==0))
            build_ew_pack(data_ptr, tuple, header, init_packet, packet);
        else {
            fprintf(stderr, "Not yet implemented.\n");
            exit(-1);
        }
    }
    */

    if (protocol == 'a') {
        build_arp_pack(data_ptr, tuple, header, init_packet);
    }

    else {
        fprintf(stderr, "Never should have been here...Report!\n");
        exit(-1);
    }

    data_ptr = NULL;
    free(data_ptr);
    init_packet = NULL;
    free(init_packet);
}



