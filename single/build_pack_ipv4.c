


/*
 #####################################################################################################
 Revision #      1.0
 Name:               :  build_pack_ipv4.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Packet builder routines for non-session fuzzing over IPv4 protocol data.
 #####################################################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_ipv4.h"
#include "../headers/instrumentation.h"
#include "../headers/database.h"


u_char protocol[64];


void build_ipv4_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet) {


    libnet_t *libt;
    libnet_ptag_t eth_tag;

    struct libnet_ether_addr *my_mac;

    int n, x=0, i;
    int init =0;
    int maclen, payl;

    int payload_len = IPHDR_SIZE;

    u_int8_t dst_mac[6];
    u_char *mac_addr_str, *mac_addr;


    libt = build_libnet_link_adv(tuple);


    dest_ipv4_overwrite(tuple->destination, pkt_ptr+16);

    my_mac = libnet_get_hwaddr (libt);

    //mac_addr_str = get_mac_address(tuple->destination);

    mac_addr = libnet_hex_aton(mac_addr_str, &maclen);

    for (i=0; i < maclen; i++)
        dst_mac[i] = mac_addr[i];
    fprintf(stderr, "Fuzzing against ");
    for (i=0; i < maclen; i++) {
        fprintf(stderr, "%02X", dst_mac[i]);
        if ( i < maclen-1 )
            fprintf(stderr, ":");
    }
    fprintf(stderr, "\n\n");


    memcpy(init_packet, pkt_ptr, header.len);


    if ((eth_tag =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_IP, (uint8_t *)pkt_ptr, payload_len, libt, 0))==-1)
        fprintf(stderr, "Error building ETHERNET header: %s\n", libnet_geterror(libt));



    if (tuple->num == 1) {

        fuzz_ipv4(pkt_ptr);

        if ((eth_tag =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_IP, (uint8_t *)pkt_ptr, payload_len, libt, eth_tag))==-1)
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

            fuzz_ipv4(pkt_ptr);

            payl = rand() % 1500;

            if (payl/400 >= 3)
                payload_len = payl;
            else
                payload_len = IPHDR_SIZE;

            if ((eth_tag =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_IP, (uint8_t *)pkt_ptr, payload_len, libt, eth_tag))==-1)
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

            fuzz_ipv4(pkt_ptr);

            payl = rand() % 1500;

            if (payl/400 >= 3)
                payload_len = payl;
            else
                payload_len = IPHDR_SIZE;


            if ((eth_tag =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_IP, (uint8_t *)pkt_ptr, payload_len, libt, eth_tag))==-1)
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
