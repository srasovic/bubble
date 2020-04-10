
/*
 ##############################################################################################
 Revision #      1.0
 Name:               :  build_pack_arp.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Packet builder routines for non-session fuzzing over ARP protocol data.
 ##############################################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_arp.h"
#include "../headers/instrumentation.h"
#include "../headers/database.h"


u_char protocol[64];
char rand_str[254];

u_int8_t *mac_addr;


void build_arp_pack(u_char *pkt_ptr, struct tuple * tuple, struct pcap_pkthdr header, u_char *init_packet) {


    u_char *o_packet = calloc(1, header.len);

    u_char mac_addr_str[MAC_ADDR_STR_LEN];

    libnet_t *libt;
    libnet_ptag_t eth_tag = LIBNET_PTAG_INITIALIZER, arp_tag = LIBNET_PTAG_INITIALIZER;

    struct libnet_ether_addr *my_mac;

    int max_hdr_fields = 9;

    int n, x=0, i, j;
    int init =0;
    int maclen;
    int pack_num = 0, move_size = 0;
    int plen_it = 0;

    int payload_len = ARPHDR_SIZE, temp_len;

    u_int8_t dst_mac[6];

    int ping_result;

    u_int8_t *packet;
    u_int32_t packet_size;

    time_t rawtime;
    struct tm * timeinfo;
    char time_buffer[80];

    int move_to_md = 0;
    static int fail_count = 0, packet_count = 0;
    int failed_percent = 0;

    packet = NULL;

    char *pqueue[7];
    for (i=0;i<7;i++){
        pqueue[i] = calloc(1, MAX_PACK_SIZE);
    }

    u_char test_id[10];
    memset(test_id, '\0', 10);


    pthread_t *ctid = tuple->ssh_tid;

    char *pack_delimiter = "***";

    struct db_table_entry *new_entry = (struct db_table_entry *) calloc(1, sizeof(struct db_table_entry));

    strncpy(new_entry->protocol, "arp", 3);

    strncat(new_entry->packet_type, type_of_packet->l3_type, 4);

    PGconn *conn = create_db_conn(tuple->db_pass);


    char *os = "Unknown";

    if (tuple->os_data){
        tuple->os_data[34] = '\0';
        strncpy(new_entry->os_version_device, tuple->os_data, 34);
    }
    else
        strncpy(new_entry->os_version_device, os, strlen(os));

    strncpy(new_entry->problem_type, "crash", 5);

    if (tuple->comment) {
        tuple->comment[sizeof(new_entry->comment)] = '\0';
        strncpy(new_entry->comment, tuple->comment, sizeof(new_entry->comment));
    }
    else
        memset(new_entry->comment, '\0', sizeof(new_entry->comment));


    libt = build_libnet_link_adv(tuple);

    my_mac = libnet_get_hwaddr (libt);

    if (!mac_set) {
        fprintf(stderr, "Destination not specified. Using broadcast MAC address.\n");
        maclen = MACSIZE;
        for (i=0;i<maclen;i++)
            dst_mac[i] = 0xff;
    }

    else {

        get_mac_address(tuple->destination, mac_addr_str);

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
    }



    if (tuple->num == 1) {

        memcpy(pkt_ptr, init_packet, header.len);

        fuzz_arp(pkt_ptr);

        if ((eth_tag =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_ARP, (uint8_t *)pkt_ptr, payload_len, libt, eth_tag))==-1)
            fprintf(stderr, "Error building ETHERNET header: %s\n", libnet_geterror(libt));

        if (libnet_adv_cull_packet(libt, &packet, &packet_size) == -1) {
            fprintf(stderr,"libnet_adv_cull_packet() failed: %s\n",\
                    libnet_geterror(libt));
        }


        for (i=0;i<3;i++) {

            if ((n =libnet_write(libt))==-1) {
                fprintf(stderr, "Error writing packet: %s\n",libnet_geterror(libt));
                exit(-1);
            }

            else
                ping_result = ping_to_uut(tuple->destination);
        }

        fprintf(stderr, "%d.Fuzzing %d bytes of %s data\n", init+1, n, tuple->protocol);
        init++;


        if (ping_result==FAIL) {

            fprintf(stderr, "----- Test failed - saving to database.\n");

            time(&rawtime);
            timeinfo = localtime (&rawtime);
            strftime (time_buffer, 80, "%X",timeinfo);

            if (tuple->verbose) {
                fprintf(stderr, "-- %s -- Saving the following packet to packet.pcap: \n", time_buffer);
                //     packet_save(packet, packet_size);
            }

            libnet_adv_free_packet(libt, packet);
            packet = NULL;
            memset(time_buffer, '\0', strlen(time_buffer));

        }

        packet = NULL;
    }


    else if (!tuple->num) {


        while (1) {

            memcpy(pkt_ptr, init_packet, header.len);
            payload_len = ARPHDR_SIZE;
            temp_len = payload_len;

            struct fuzzed_data *arp_fdata = calloc((max_hdr_fields), sizeof(struct fuzzed_data));


            /*
             Initial algorithm for switching to multidimensional fuzzer.
             In the future, this should instead be an AI algorithm.
             */

            if (move_to_md==1)
                fuzz_arp_multid(pkt_ptr);

            else if (packet_count >= 20) {

                failed_percent = calc_failed_percentage(fail_count, packet_count);

                if (failed_percent <= 10) {
                    move_to_md = 1;
                    fuzz_arp_multid(pkt_ptr);
                }

                else
                    fuzz_arp(pkt_ptr);
            }

            else
                fuzz_arp(pkt_ptr);


            libnet_clear_packet(libt);

            plen_it = rand() % 80;


            if (is_prime(plen_it)) {
                payload_len = rand() % 254;

                plen_it = rand() % 80;

                if (is_prime(plen_it)) {
                    rand_str_gen(rand_str, payload_len);
                    strncat(&pkt_ptr[ARPHDR_SIZE], rand_str, temp_len + payload_len);
                    payload_len = payload_len+temp_len;
                }
                else
                    payload_len = ARPHDR_SIZE;
            }


            if ((eth_tag =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_ARP, (uint8_t *)pkt_ptr, payload_len, libt, 0))==-1)
                fprintf(stderr, "Error building ETHERNET header: %s\n", libnet_geterror(libt));


            if (libnet_adv_cull_packet(libt, &packet, &packet_size) == -1) {
                fprintf(stderr,"libnet_adv_cull_packet() failed: %s\n",\
                        libnet_geterror(libt));
            }


            if (tuple->instrumentation) {
                db_packet_save(packet, packet_size, pqueue[pack_num]);

                if (pack_num == 0) {
                    memset(ssh_entry->binary_pack_data, '\0', strlen(pqueue[pack_num]));

                    strncpy(&(ssh_entry->binary_pack_data[0]), pqueue[pack_num], strlen(pqueue[pack_num]));
                    strncpy(&ssh_entry->binary_pack_data[strlen(pqueue[pack_num])], pack_delimiter, strlen(pack_delimiter));
                }
                else {
                    move_size = (strlen(pqueue[pack_num])+3)*pack_num;
                    strncpy(&(ssh_entry->binary_pack_data[move_size]), pqueue[pack_num], strlen(pqueue[pack_num]));
                    strncpy(&ssh_entry->binary_pack_data[move_size+strlen(pqueue[pack_num])], pack_delimiter, strlen(pack_delimiter));
                }

                pack_num++;
                if (pack_num==7)
                    pack_num=0;


                if (ssh_alert) {
                    //do_stuff here: insert entry in db.
                    pthread_join(*ctid, NULL);
                    insert_new_db_entry(conn, ssh_entry->protocol, ssh_entry);
                    get_db_current_test_id(tuple->protocol, test_id);
//                    save_pkt_desc_html(type_of_packet, o_packet, packet, packet_size, arp_fdata, test_id);
                    free(ssh_entry);
                    exit(1);
                }
            }


            for (i=0;i<3;i++) {

                if ((n =libnet_write(libt))==-1) {
                    fprintf(stderr, "Error writing packet: %s\n",libnet_geterror(libt));
                    exit(-1);
                }

                else
                    ping_result = ping_to_uut(tuple->destination);

            }


            fprintf(stderr, "%d.Fuzzing %d bytes of %s data\n", init+1, n, tuple->protocol);

            init++;
            packet_count++;



            if (ping_result==FAIL) {

                fprintf(stderr, "----- Test failed - saving to database.\n");

                time(&rawtime);
                timeinfo = localtime (&rawtime);
                strftime (time_buffer, 80, "%X",timeinfo);

                db_packet_save(packet, packet_size, pass_packet);
                strncpy(new_entry->binary_pack_data, pass_packet, strlen(pass_packet));
                //This needs to change:
                db_packet_save(pkt_ptr, payload_len, pass_packet);
                strncpy(new_entry->binary_diff_data, pass_packet, strlen(pass_packet));

                strncpy(new_entry->misc_description, "\0\0\0", 3);

                if (tuple->verbose) {
                    fprintf(stderr, "-- %s -- Test failed. Saving the following packet to packet.pcap: \n", time_buffer);
                    packet_save(packet, packet_size);
                }

                libnet_adv_free_packet(libt, packet);
                packet = NULL;
                memset(time_buffer, '\0', strlen(time_buffer));

                if (tuple->quit){
                    exit(1);
                }

                fail_count++;

            }

            packet = NULL;

            usleep(tuple->timer);
            free(arp_fdata);

        }
    }


    else {

        while (init<tuple->num) {

            memcpy(pkt_ptr, init_packet, header.len);

            fuzz_arp(pkt_ptr);

            if ((eth_tag =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_ARP, (uint8_t *)pkt_ptr, payload_len, libt, eth_tag))==-1)
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
    free(type_of_packet);
    libnet_destroy(libt);
}


