


/*
 ##############################################################################
 Revision #      1.0
 Name:               :  ios_socket_bgp.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  I/O socket routines for BGP protocol data.
 ##############################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/socket_ops.h"


int parse_recvd_bgp_packet(int sockfd, u_char *r_packet, int psize) {

    int type_ptr = 18;

    if (psize == -1) {

        if (errno == EBADF) {
            fprintf(stderr, "Invalid socket id.\n");
            close_tcp_session(sockfd);
            return -1;
        }
        else if (errno == ECONNREFUSED){
            fprintf(stderr, "RST received. Attempting new session.\n");
            close_tcp_session(sockfd);
            return -1;
        }
        else {
            fprintf(stderr, "Unspecified error occured during socket establishment.\n");
            exit(-1);
        }
    }

    else {

        if ((int)(r_packet[type_ptr]) == 0x01 || (int)(r_packet[type_ptr]) == 0x04)
            return (int)(r_packet[type_ptr]);

        else if ((int)(r_packet[type_ptr]) == 0x03) {

            fprintf(stderr, "\t---> Received NOTIFICATION from peer: ");

            switch ((int)r_packet[type_ptr+1]) {
                case 1:
                    fprintf(stderr, "Major Error Code: Message Header Error(0x%X). ", r_packet[type_ptr+1]);
                    fprintf(stderr, "Minor Error Code: ");
                    if ((int)r_packet[type_ptr+2] == 0)
                        fprintf(stderr, "Unknown.\n");
                    else if ((int)r_packet[type_ptr+2] == 1)
                        fprintf(stderr, "Connection Not Synchronized.\n");
                    else if ((int)r_packet[type_ptr+2] == 2)
                        fprintf(stderr, "Bad Message Length.\n");
                    else if ((int)r_packet[type_ptr+2] == 3)
                        fprintf(stderr, "Bad Message Type.\n");
                    break;
                case 2:
                    fprintf(stderr, "Major Error Code: Open Message Error(0x%X). ", r_packet[type_ptr+1]);
                    fprintf(stderr, "Minor Error Code: ");
                    if ((int)r_packet[type_ptr+2] == 0)
                        fprintf(stderr, "Unknown.\n");
                    else if ((int)r_packet[type_ptr+2] == 1)
                        fprintf(stderr, "Unsupported Version Number.\n");
                    else if ((int)r_packet[type_ptr+2] == 2)
                        fprintf(stderr, "Bad Peer AS.\n");
                    else if ((int)r_packet[type_ptr+2] == 3)
                        fprintf(stderr, "Bad BGP Identifier.\n");
                    else if ((int)r_packet[type_ptr+2] == 4)
                        fprintf(stderr, "Unsupported Optional Parameter.\n");
                    else if ((int)r_packet[type_ptr+2] == 5)
                        fprintf(stderr, "Auth Failure.\n");
                    else if ((int)r_packet[type_ptr+2] == 6)
                        fprintf(stderr, "Unacceptable Hold-Timer.\n");
                    else if ((int)r_packet[type_ptr+2] == 7)
                        fprintf(stderr, "Unsupported Capability.\n");
                    else if ((int)r_packet[type_ptr+2] == 8)
                        fprintf(stderr, "Unknown.\n");
                    break;
                case 3:
                    fprintf(stderr, "Major Error Code: Update Message Error(0x%X). ", r_packet[type_ptr+1]);
                    fprintf(stderr, "Minor Error Code: ");
                    if ((int)r_packet[type_ptr+2] == 0)
                        fprintf(stderr, "Unknown.\n");
                    else if ((int)r_packet[type_ptr+2] == 1)
                        fprintf(stderr, "Malformed Attribute List.\n");
                    else if ((int)r_packet[type_ptr+2] == 2)
                        fprintf(stderr, "Unrecognized Well-known Attribute.\n");
                    else if ((int)r_packet[type_ptr+2] == 3)
                        fprintf(stderr, "Missing Well-known Attribute.\n");
                    else if ((int)r_packet[type_ptr+2] == 4)
                        fprintf(stderr, "Attribute Flags Error.\n");
                    else if ((int)r_packet[type_ptr+2] == 5)
                        fprintf(stderr, "Attribute Length Error.\n");
                    else if ((int)r_packet[type_ptr+2] == 6)
                        fprintf(stderr, "Invalid ORIGIN Attribute.\n");
                    else if ((int)r_packet[type_ptr+2] == 7)
                        fprintf(stderr, "AS Routing Loop.\n");
                    else if ((int)r_packet[type_ptr+2] == 8)
                        fprintf(stderr, "Invalid NEXT_HOP Attribute.\n");
                    else if ((int)r_packet[type_ptr+2] == 9)
                        fprintf(stderr, "Optional Attribute Error.\n");
                    else if ((int)r_packet[type_ptr+2] == 10)
                        fprintf(stderr, "Invalid Network Field.\n");
                    else if ((int)r_packet[type_ptr+2] == 11)
                        fprintf(stderr, "Malformed AS_PATH.\n");
                    break;
                case 4:
                    fprintf(stderr, "Major Error Code: Hold Timer Expired(0x%X). ", r_packet[type_ptr+1]);
                    break;
                case 5:
                    fprintf(stderr, "Major Error Code: FSM Error(0x%X). ", r_packet[type_ptr+1]);
                    fprintf(stderr, "Minor Error Code: ");
                    if ((int)r_packet[type_ptr+2] == 0)
                        fprintf(stderr, "Unknown.\n");
                    else if ((int)r_packet[type_ptr+2] == 1)
                        fprintf(stderr, "Receive Unexpected Message in OpenSent State.\n");
                    else if ((int)r_packet[type_ptr+2] == 2)
                        fprintf(stderr, "Receive Unexpected Message in OpenConfirm State.\n");
                    else if ((int)r_packet[type_ptr+2] == 3)
                        fprintf(stderr, "Receive Unexpected Message in Established State.\n");
                    break;
                case 6:
                    fprintf(stderr, "Major Error Code: Cease(0x%X). ", r_packet[type_ptr+1]);
                    fprintf(stderr, "Minor Error Code: ");
                    if ((int)r_packet[type_ptr+2] == 0)
                        fprintf(stderr, "Unknown.\n");
                    else if ((int)r_packet[type_ptr+2] == 1)
                        fprintf(stderr, "Maximum Number of Prefixes Reached.\n");
                    else if ((int)r_packet[type_ptr+2] == 2)
                        fprintf(stderr, "Administrative Shutdown.\n");
                    else if ((int)r_packet[type_ptr+2] == 3)
                        fprintf(stderr, "Peer De-configured.\n");
                    else if ((int)r_packet[type_ptr+2] == 4)
                        fprintf(stderr, "Administrative Reset.\n");
                    else if ((int)r_packet[type_ptr+2] == 5)
                        fprintf(stderr, "Connection Rejected.\n");
                    else if ((int)r_packet[type_ptr+2] == 6)
                        fprintf(stderr, "Other Configuration Change.\n");
                    else if ((int)r_packet[type_ptr+2] == 7)
                        fprintf(stderr, "Connection Collision Resolution.\n");
                    else if ((int)r_packet[type_ptr+2] == 8)
                        fprintf(stderr, "Out of Resources.\n");
                    break;

                default:
                    break;
            }

            close_tcp_session(sockfd);
            return -1;
        }

    }



}
