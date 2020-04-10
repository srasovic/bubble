


/*
 #####################################################################################################
 Revision #      1.0
 Name:               :  build_pack_ipv6.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Packet builder routines for non-session fuzzing over IPv6 protocol data.
 #####################################################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_ipv6.h"
#include "../headers/instrumentation.h"
#include "../headers/database.h"


u_char protocol[64];


void build_ipv6_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet) {


    /*
     Draft:
     */


    libnet_t *libt;
    libnet_ptag_t eth_tag;

    struct libnet_ether_addr *my_mac;

    int n, x=0, i;
    int init =0;
    int maclen;

    int payload_len = IP6HDR_SIZE;

    u_int8_t dst_mac[6];
    u_char *mac_addr_str, *mac_addr;


    libt = build_libnet_link_adv(tuple);

    dest_ipv6_overwrite(tuple->destination, pkt_ptr+24);

    my_mac = libnet_get_hwaddr(libt);

    /*
     mac_addr_str = get_mac_address(tuple->destination);
     mac_addr = libnet_hex_aton(mac_addr_str, &maclen);

     for (i=0; i < maclen; i++)
     dst_mac[i] = mac_addr[i];
     */

    maclen = MACSIZE;
    for (i=0;i<maclen;i++)
        dst_mac[i] = 0xff;

    fprintf(stderr, "Fuzzing against ");
    for (i=0; i < maclen; i++) {
        fprintf(stderr, "%02X", dst_mac[i]);
        if ( i < maclen-1 )
            fprintf(stderr, ":");
    }
    fprintf(stderr, "\n\n");


    memcpy(init_packet, pkt_ptr, header.len);


    if ((eth_tag =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, 0x86dd, (uint8_t *)pkt_ptr, payload_len, libt, 0))==-1)          //change payload size here.
        fprintf(stderr, "Error building ETHERNET header: %s\n", libnet_geterror(libt));


    if (tuple->num == 1) {

        fuzz_ipv6(pkt_ptr);

        if ((eth_tag =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, 0x86dd, (uint8_t *)pkt_ptr, payload_len, libt, eth_tag))==-1)
            fprintf(stderr, "Error building ETHERNET header: %s\n", libnet_geterror(libt));

        if ((n =libnet_write(libt))==-1) {
            fprintf(stderr, "Error writing packet: %s\n",libnet_geterror(libt));
            exit(-1);
        }

        else
            fprintf(stderr, "Fuzzing %d bytes of %s data\n", n, tuple->protocol);
    }

    else if (!tuple->num ) {

        while (1) {

            memcpy(pkt_ptr, init_packet, header.len);

            fuzz_ipv6(pkt_ptr);

            if ((eth_tag =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, 0x86dd, (uint8_t *)pkt_ptr, payload_len, libt, eth_tag))==-1)
                fprintf(stderr, "Error building ETHERNET header: %s\n", libnet_geterror(libt));

            if ((n =libnet_write(libt))==-1) {
                fprintf(stderr, "Error writing packet: %s\n",libnet_geterror(libt));
                exit(-1);
            }

            else
                fprintf(stderr, "%d.Fuzzing %d bytes of %s data\n", init+1, n, tuple->protocol);

            usleep(tuple->timer);
        }
    }

    else {

        while (init<tuple->num) {

            memcpy(pkt_ptr, init_packet, header.len);

            fuzz_ipv6(pkt_ptr);

            if ((eth_tag =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, 0x86dd, (uint8_t *)pkt_ptr, payload_len, libt, eth_tag))==-1)
                fprintf(stderr, "Error building ETHERNET header: %s\n", libnet_geterror(libt));

            if ((n =libnet_write(libt))==-1) {
                fprintf(stderr, "Error writing packet: %s\n",libnet_geterror(libt));
                exit(-1);
            }

            else
                fprintf(stderr, "%d.Fuzzing %d bytes of %s data\n", init+1, n, tuple->protocol);

            usleep(tuple->timer);
            init++;
        }
    }

    free(mac_addr);
    libnet_destroy(libt);
}
