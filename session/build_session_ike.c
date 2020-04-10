
/*
 ##########################################################################################
 Revision #      1.0
 Name:               :  build_session_ike.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Packet builder routines for session fuzzing over IKE protocol data.
 ##########################################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_ike.h"
#include "../headers/instrumentation.h"
#include "../headers/database.h"
#include "../headers/socket_ops.h"


#define UDP_PROTO   17
#define TCP_PROTO   6
#define IP_PROTO   4
#define IPv6_PROTO   6

#define TTL 64

u_char protocol[64];


char ike_part_init_packet[] = {

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x21, 0x20, 0x22, 0x08, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0xa0, 0x22, 0x00, 0x00, 0x6c,
    0x00, 0x00, 0x00, 0x68, 0x01, 0x01, 0x00, 0x0b,
    0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0c,
    0x80, 0x0e, 0x01, 0x00, 0x03, 0x00, 0x00, 0x0c,
    0x01, 0x00, 0x00, 0x0c, 0x80, 0x0e, 0x00, 0x80,
    0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x03,
    0x03, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x02,
    0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x02,
    0x03, 0x00, 0x00, 0x08, 0x02, 0x00, 0x00, 0x01,
    0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x02,
    0x03, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x01,
    0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x02,
    0x03, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x08, 0x04, 0x00, 0x00, 0x0e,
    0x28, 0x00, 0x00, 0x88, 0x00, 0x02, 0x00, 0x00,
    0x50, 0xea, 0xf4, 0x54, 0x1c, 0x61, 0x24, 0x1b,
    0x59, 0x3f, 0x48, 0xcb, 0x12, 0x8c, 0xf1, 0x7f,
    0x5f, 0xd4, 0xd8, 0xe9, 0xe2, 0xfd, 0x3c, 0x66,
    0x70, 0xef, 0x08, 0xf6, 0x56, 0xcd, 0x83, 0x16,
    0x65, 0xc1, 0xdf, 0x1c, 0x2b, 0xb1, 0xc4, 0x92,
    0xca, 0xcb, 0xd2, 0x68, 0x83, 0x8e, 0x2f, 0x12,
    0x94, 0x12, 0x48, 0xec, 0x78, 0x4b, 0x5d, 0xf3,
    0x57, 0x87, 0x36, 0x1b, 0xba, 0x5b, 0x34, 0x6e,
    0xec, 0x7e, 0x39, 0xc1, 0xc2, 0x2d, 0xf9, 0x77,
    0xcc, 0x19, 0x39, 0x25, 0x64, 0xeb, 0xb7, 0x85,
    0x5b, 0x16, 0xfc, 0x2c, 0x58, 0x56, 0x11, 0xfe,
    0x49, 0x71, 0x32, 0xe9, 0xe8, 0x2d, 0x27, 0xbe,
    0x78, 0x71, 0x97, 0x7a, 0x74, 0x42, 0x30, 0x56,
    0x62, 0xa2, 0x99, 0x9c, 0x56, 0x0f, 0xfe, 0xd0,
    0xa2, 0xe6, 0x8f, 0x72, 0x5f, 0xc3, 0x87, 0x4c,
    0x7c, 0x9b, 0xa9, 0x80, 0xf1, 0x97, 0x57, 0x92,
    0x2b, 0x00, 0x00, 0x18, 0x97, 0x40, 0x6a, 0x31,
    0x04, 0x4d, 0x3f, 0x7d, 0xea, 0x84, 0x80, 0xe9,
    0xc8, 0x41, 0x5f, 0x84, 0x49, 0xd3, 0x8c, 0xee,
    0x2b, 0x00, 0x00, 0x17, 0x43, 0x49, 0x53, 0x43,
    0x4f, 0x2d, 0x44, 0x45, 0x4c, 0x45, 0x54, 0x45,
    0x2d, 0x52, 0x45, 0x41, 0x53, 0x4f, 0x4e, 0x2b,
    0x00, 0x00, 0x3b, 0x43, 0x49, 0x53, 0x43, 0x4f,
    0x28, 0x43, 0x4f, 0x50, 0x59, 0x52, 0x49, 0x47,
    0x48, 0x54, 0x29, 0x26, 0x43, 0x6f, 0x70, 0x79,
    0x72, 0x69, 0x67, 0x68, 0x74, 0x20, 0x28, 0x63,
    0x29, 0x20, 0x32, 0x30, 0x30, 0x39, 0x20, 0x43,
    0x69, 0x73, 0x63, 0x6f, 0x20, 0x53, 0x79, 0x73,
    0x74, 0x65, 0x6d, 0x73, 0x2c, 0x20, 0x49, 0x6e,
    0x63, 0x2e, 0x2b, 0x00, 0x00, 0x12, 0x43, 0x49,
    0x53, 0x43, 0x4f, 0x2d, 0x47, 0x52, 0x45, 0x2d,
    0x4d, 0x4f, 0x44, 0x45, 0x00, 0x00, 0x00, 0x14,
    0x40, 0x48, 0xb7, 0xd5, 0x6e, 0xbc, 0xe8, 0x85,
    0x25, 0xe7, 0xde, 0x7f, 0x00, 0xd6, 0xc2, 0xd3 };


char ike_dummy_packet[] = {
    0x54, 0xc1, 0x84, 0x96, 0x1b, 0xc3, 0xfd, 0x77,
    0x63, 0x86, 0xaa, 0x22, 0x73, 0xed, 0x39, 0x72,
    0x2e, 0x20, 0x23, 0x08, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x05, 0x44,
    0x26, 0x00, 0x03, 0x3d, 0x04, 0x30, 0x82, 0x03,
    0x34, 0x30, 0x82, 0x02, 0x1c, 0xa0, 0x03, 0x02,
    0x01, 0x02, 0x02, 0x01, 0x15, 0x30, 0x0d, 0x06,
    0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x0b, 0x05, 0x00, 0x30, 0x14, 0x31, 0x12,
    0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
    0x09, 0x76, 0x70, 0x6e, 0x63, 0x61, 0x2e, 0x6f,
    0x72, 0x67, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x35,
    0x30, 0x36, 0x30, 0x36, 0x31, 0x30, 0x31, 0x33,
    0x31, 0x35, 0x5a, 0x17, 0x0d, 0x31, 0x36, 0x30,
    0x36, 0x30, 0x35, 0x31, 0x30, 0x31, 0x33, 0x31,
    0x35, 0x5a, 0x30, 0x38, 0x31, 0x14, 0x30, 0x12,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0b, 0x65,
    0x61, 0x73, 0x74, 0x76, 0x70, 0x6e, 0x2e, 0x6f,
    0x72, 0x67, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
    0x01, 0x16, 0x11, 0x73, 0x69, 0x74, 0x65, 0x31,
    0x40, 0x65, 0x61, 0x73, 0x74, 0x76, 0x70, 0x6e,
    0x2e, 0x6f, 0x72, 0x67, 0x30, 0x82, 0x01, 0x22,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
    0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a,
    0x02, 0x82, 0x01, 0x01, 0x00, 0xca, 0xb1, 0xaf,
    0x88, 0xa8, 0xcb, 0x9d, 0xb0, 0x51, 0xa0, 0x6a,
    0xaf, 0x71, 0x94, 0xc8, 0xd7, 0x26, 0x96, 0xb2,
    0xd1, 0xee, 0x63, 0xb6, 0x50, 0xa3, 0x20, 0x70,
    0xc4, 0xd0, 0x09, 0x2b, 0x1b, 0x16, 0x57, 0x28,
    0xb2, 0xfd, 0x19, 0x49, 0x48, 0xde, 0x45, 0xcd,
    0x19, 0x4f, 0x25, 0x18, 0x74, 0x46, 0x5b, 0xf6,
    0x16, 0x8b, 0xb1, 0xce, 0x8d, 0xaa, 0x24, 0x49,
    0x97, 0x28, 0xc3, 0xda, 0x2b, 0xba, 0x93, 0xfe,
    0xa5, 0x9e, 0xb4, 0xce, 0x03, 0xb2, 0x27, 0x64,
    0xad, 0x83, 0x7a, 0xa7, 0xcf, 0x5d, 0x63, 0x45,
    0x03, 0x99, 0x46, 0x52, 0xa6, 0x9e, 0x4e, 0x40,
    0xa9, 0x90, 0xe2, 0xc4, 0x9c, 0x97, 0x31, 0x7a,
    0x18, 0xdf, 0xb9, 0x4d, 0xc5, 0x3e, 0x96, 0x5c,
    0xef, 0x92, 0x0e, 0x7f, 0x35, 0x88, 0x51, 0x98,
    0xb3, 0x7b, 0x24, 0x56, 0xc0, 0x84, 0xb7, 0x8f,
    0x5a, 0x2d, 0xc8, 0xc7, 0xab, 0x2f, 0xfc, 0x45,
    0xc6, 0xa0, 0x60, 0x99, 0x5a, 0xd5, 0xd7, 0x37,
    0xd4, 0xf9, 0x52, 0xf1, 0x7a, 0x09, 0x39, 0xe3,
    0x31, 0x37, 0x84, 0xab, 0x6f, 0xa8, 0xdf, 0x47,
    0x3f, 0x19, 0xe1, 0x04, 0x11, 0xdd, 0x55, 0xf8,
    0x2e, 0xa9, 0xf4, 0x15, 0xf9, 0xf4, 0xbc, 0xfc,
    0x13, 0xeb, 0x42, 0x1b, 0x8b, 0x23, 0x43, 0xcb,
    0xba, 0x8b, 0x63, 0x3c, 0x1d, 0x7d, 0x18, 0xc8,
    0xa3, 0x22, 0xd9, 0xe0, 0x64, 0x26, 0x7b, 0xd9,
    0x0f, 0x86, 0x3b, 0x0f, 0x98, 0x5f, 0x70, 0x64,
    0x3b, 0x9a, 0x86, 0x29, 0x2d, 0x0b, 0x9c, 0xbe,
    0x29, 0xf1, 0xd3, 0xd5, 0x62, 0xb5, 0x2e, 0x48,
    0x02, 0x2c, 0x0d, 0x3d, 0xfb, 0xb4, 0x62, 0x62,
    0xbf, 0x7f, 0x6d, 0x90, 0x73, 0x47, 0xc1, 0x62,
    0x68, 0xb9, 0x67, 0x55, 0xa7, 0x51, 0xba, 0xbf,
    0x6b, 0xbb, 0x40, 0x5b, 0x00, 0xf7, 0x06, 0xff,
    0x1b, 0xfd, 0xe7, 0xd8, 0x15, 0x02, 0x03, 0x01,
    0x00, 0x01, 0xa3, 0x6d, 0x30, 0x6b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30,
    0x00, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f,
    0x04, 0x04, 0x03, 0x02, 0x03, 0xb8, 0x30, 0x27,
    0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x20, 0x30,
    0x1e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05,
    0x07, 0x03, 0x01, 0x06, 0x08, 0x2b, 0x06, 0x01,
    0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x05, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x02,
    0x30, 0x00, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0x5f, 0xf0, 0xee,
    0x07, 0xaa, 0xb7, 0x3d, 0x37, 0xaa, 0x04, 0x8d,
    0x72, 0xbf, 0x01, 0xb0, 0x67, 0x1a, 0x87, 0x2e,
    0x4c, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    0x03, 0x82, 0x01, 0x01, 0x00, 0x4d, 0x3f, 0xa7,
    0xb4, 0x32, 0x84, 0x66, 0x88, 0xa4, 0x00, 0x07,
    0x33, 0x3b, 0x3e, 0xcd, 0x99, 0xdf, 0xfb, 0x1d,
    0xfd, 0x86, 0x23, 0x07, 0xf1, 0xaa, 0xba, 0xb4,
    0x16, 0x38, 0xfa, 0x52, 0x25, 0xf3, 0x43, 0x88,
    0x96, 0x5f, 0xac, 0xee, 0xf4, 0x01, 0x3f, 0x76,
    0x04, 0xce, 0xf5, 0x1b, 0xae, 0xa5, 0xdf, 0x80,
    0x73, 0x42, 0xfd, 0xec, 0xd1, 0x7d, 0x6d, 0xe9,
    0xc9, 0xb2, 0x43, 0x1c, 0xeb, 0xe9, 0x49, 0x1d,
    0xb4, 0x51, 0x2d, 0xc1, 0x80, 0xd0, 0x2c, 0xd7,
    0x62, 0x80, 0x76, 0xc8, 0xe3, 0xe1, 0xc1, 0x6b,
    0xf6, 0x43, 0x23, 0x50, 0xec, 0x5a, 0x5a, 0x01,
    0xb4, 0x8e, 0xa1, 0xa5, 0x06, 0x1f, 0x7e, 0xc6,
    0xfb, 0x4c, 0x0a, 0xc1, 0x71, 0x25, 0x56, 0x58,
    0x83, 0x52, 0x08, 0x61, 0x7e, 0x2d, 0xa6, 0x01,
    0xbf, 0x09, 0x08, 0x3d, 0xc4, 0xff, 0x3b, 0x0d,
    0x1b, 0x91, 0x57, 0x4d, 0xec, 0x12, 0xf5, 0x45,
    0x5e, 0x4a, 0xfe, 0x76, 0x51, 0xfd, 0x28, 0xe8,
    0xad, 0xa8, 0x46, 0xdb, 0xa0, 0x2f, 0x09, 0xc8,
    0x82, 0x2c, 0xcf, 0x48, 0x29, 0xf7, 0xfe, 0x7b,
    0xb3, 0x8f, 0x1b, 0x7c, 0xc9, 0x1d, 0xc3, 0xb6,
    0x2b, 0xb8, 0xc8, 0x42, 0x1a, 0xb3, 0x92, 0x56,
    0xb7, 0x55, 0x28, 0x19, 0x61, 0x12, 0x65, 0xb9,
    0xd8, 0xb0, 0xe1, 0x0f, 0x15, 0xe6, 0x80, 0x9d,
    0x06, 0x18, 0x2b, 0x45, 0xfd, 0x31, 0x46, 0x26,
    0xd2, 0x12, 0x92, 0x39, 0xec, 0x2d, 0x6f, 0xbd,
    0xac, 0x44, 0x0e, 0x9f, 0x75, 0xf7, 0x80, 0x6e,
    0x95, 0xea, 0xe4, 0x4e, 0xcc, 0x6d, 0x62, 0xe1,
    0x05, 0xc2, 0x05, 0xe6, 0x8f, 0x47, 0x25, 0x84,
    0xa1, 0x37, 0xa1, 0x8b, 0x1d, 0xca, 0x5c, 0xcf,
    0xbe, 0xa4, 0x67, 0xb2, 0x15, 0xcc, 0xfa, 0x8a,
    0x4b, 0x17, 0x7e, 0x56, 0xd9, 0x78, 0x2f, 0xcc,
    0xbf, 0xad, 0xc5, 0x95, 0x35, 0x29, 0x00, 0x00,
    0x19, 0x04, 0x44, 0x76, 0x41, 0xe5, 0x26, 0x8a,
    0xd6, 0xa4, 0xbc, 0x5b, 0x98, 0x24, 0x60, 0xaa,
    0x0c, 0x66, 0x10, 0x3c, 0x05, 0xc3, 0x23, 0x00,
    0x00, 0x08, 0x00, 0x00, 0x40, 0x08, 0x29, 0x00,
    0x00, 0x42, 0x09, 0x00, 0x00, 0x00, 0x30, 0x38,
    0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x13, 0x0b, 0x65, 0x61, 0x73, 0x74, 0x76,
    0x70, 0x6e, 0x2e, 0x6f, 0x72, 0x67, 0x31, 0x20,
    0x30, 0x1e, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x11, 0x73,
    0x69, 0x74, 0x65, 0x31, 0x40, 0x65, 0x61, 0x73,
    0x74, 0x76, 0x70, 0x6e, 0x2e, 0x6f, 0x72, 0x67,
    0x29, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x00,
    0x27, 0x00, 0x00, 0x08, 0x00, 0x00, 0x40, 0x08,
    0x21, 0x00, 0x01, 0x08, 0x01, 0x00, 0x00, 0x00,
    0x8d, 0x44, 0x0f, 0x20, 0x8c, 0x33, 0x9f, 0x57,
    0x98, 0x41, 0xac, 0xdd, 0x18, 0x03, 0xe6, 0xdd,
    0x02, 0x53, 0xf2, 0x47, 0x5c, 0x57, 0xb9, 0x3e,
    0x8e, 0xf5, 0x67, 0x01, 0xed, 0x53, 0xd0, 0x0b,
    0xec, 0x67, 0x2e, 0xc9, 0x17, 0x5a, 0x7c, 0x64,
    0xaa, 0xb8, 0x1a, 0x17, 0x59, 0x98, 0x35, 0x1b,
    0x61, 0xaf, 0x24, 0x2c, 0xe7, 0xf9, 0xd0, 0xaa,
    0xec, 0x05, 0x6b, 0x4e, 0xf5, 0x08, 0x77, 0x80,
    0x82, 0x6c, 0xa9, 0x06, 0x95, 0x4e, 0x1e, 0x7d,
    0x92, 0xc7, 0x66, 0x9a, 0xa4, 0xa5, 0xad, 0x5b,
    0xed, 0x11, 0x9f, 0xdf, 0xa8, 0x52, 0xfb, 0xeb,
    0x23, 0x4e, 0x6d, 0x1e, 0xb5, 0x3d, 0xb8, 0x6f,
    0x8e, 0x07, 0x4d, 0x6a, 0x87, 0xf0, 0x60, 0x6f,
    0x8d, 0x6d, 0xc7, 0x61, 0xe2, 0xa2, 0xc4, 0x2f,
    0x3f, 0x96, 0x76, 0xfc, 0x58, 0xed, 0xad, 0x6f,
    0x15, 0x06, 0x9a, 0x85, 0x6d, 0xf6, 0xe1, 0x92,
    0x1e, 0x15, 0xbe, 0xb7, 0xae, 0x76, 0x98, 0x63,
    0xd0, 0xa4, 0x7e, 0xf9, 0xa1, 0x43, 0x44, 0x79,
    0xf9, 0x97, 0x40, 0x09, 0xc4, 0x0d, 0x1e, 0x7a,
    0xa5, 0xf7, 0xda, 0x4d, 0xdf, 0x1a, 0x86, 0xc7,
    0x5f, 0xc9, 0x41, 0x60, 0xc9, 0x53, 0x5f, 0x50,
    0x72, 0x6f, 0x73, 0xf8, 0xdf, 0xbb, 0xb7, 0xeb,
    0x1b, 0xd3, 0x48, 0x32, 0x9d, 0x2f, 0xa3, 0xb0,
    0x7c, 0x09, 0xea, 0x7b, 0x79, 0xed, 0x49, 0x2c,
    0x32, 0xd0, 0x75, 0xbf, 0x10, 0x1e, 0x27, 0x6a,
    0xa1, 0x7b, 0x17, 0x81, 0xde, 0xdc, 0xc7, 0x68,
    0x30, 0x69, 0x9e, 0x71, 0x90, 0x9b, 0x46, 0x1c,
    0xd3, 0xb2, 0x9e, 0x3b, 0xa1, 0x17, 0xc4, 0xf0,
    0x63, 0x62, 0x5a, 0xfc, 0xf3, 0xbd, 0xc6, 0xfc,
    0x7d, 0xa8, 0x0a, 0x95, 0x29, 0xbf, 0xf8, 0x64,
    0xc0, 0x7e, 0x1b, 0x42, 0xad, 0x61, 0x96, 0x1e,
    0xe5, 0x02, 0x12, 0xd7, 0x20, 0x23, 0x3b, 0xf0,
    0x2c, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x38,
    0x01, 0x03, 0x04, 0x05, 0xc4, 0x85, 0xad, 0x58,
    0x03, 0x00, 0x00, 0x0c, 0x01, 0x00, 0x00, 0x0c,
    0x80, 0x0e, 0x00, 0x80, 0x03, 0x00, 0x00, 0x08,
    0x01, 0x00, 0x00, 0x03, 0x03, 0x00, 0x00, 0x08,
    0x03, 0x00, 0x00, 0x02, 0x03, 0x00, 0x00, 0x08,
    0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08,
    0x05, 0x00, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x18,
    0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10,
    0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x00,
    0x0a, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x18,
    0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10,
    0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x0a, 0x00,
    0xc0, 0xa8, 0x0a, 0xff };


void build_ike_session(u_char *pkt_ptr, struct tuple *tuple, struct pcap_pkthdr header, u_char *init_packet, const u_char *full_packet) {


    u_char *o_packet = calloc(1, header.len);

    u_char *r_packet = calloc(1, 5*header.len);

    u_char *ike_init_packet = calloc(1, sizeof(ike_part_init_packet)+8);
    int i_cookie_num;
    u_char i_cookie[8], r_cookie[8];

    fd_set read_set;
    int rc;

    int cnt=0;
    while(cnt<header.len) {
        o_packet[cnt] = full_packet[cnt];
        cnt++;
    }

    libnet_t *libt;
    struct libnet_in6_addr ip6_dst_addr, ip6_src_addr, ip6_my_addr;
    libnet_ptag_t ip, ipv6, udp, tcp, tcp_opt, eth;
    ip = ipv6 = udp = tcp = eth = LIBNET_PTAG_INITIALIZER;
    struct libnet_ether_addr *my_mac;
    u_int16_t ip_id;
    char errbuf[LIBNET_ERRBUF_SIZE];

    u_int32_t src_ip, dst_ip;
    u_int8_t dst_mac[ETH_ADDR_LEN];
    u_int8_t *mac_addr;
    u_char mac_addr_str[MAC_ADDR_STR_LEN];

    int payload_len, ip_len, ipv6_len, udp_len, tcp_len;
    int i, j, n, length, maclen, pack_num=0;
    int move_size=0;

    int l3_prot, l4_prot;
    static int count =1;
    int init =0;
    int ping_result;

    pcap_t *pc;
    struct pcap_pkthdr *pkt;
    char perr[256];
    int res;
    struct bpf_program filter;
    bpf_u_int32 maskp=0;

    char filter_exp[150];
    u_char *tport = "udp port ";
    u_char *filter_ext = " && dst host ";
    u_char port[5];

    memset(filter_exp, '\0', 150);
    memset(port, '\0', 5);

    u_char test_id[10];
    memset(test_id, '\0', 10);

    struct packet_tuple *packet_tuple = calloc(1, sizeof(struct packet_tuple));

    int move_to_md = 0;
    static int fail_count = 0, packet_count = 0;
    int failed_percent = 0;
    int test_result;

    int servlen =0;
    int ike_init_packet_len, ike_dummy_packet_len;

    char *pqueue[7];
    for (i=0;i<7;i++){
        pqueue[i] = calloc(1, MAX_PACK_SIZE);
    }

    u_int8_t *packet;
    u_int32_t packet_size;

    u_char *pass_packet = calloc(1, MAX_PACK_SIZE);

    memset(mac_addr_str, '\0', MAC_ADDR_STR_LEN);

    packet = NULL;

    int max_hdr_fields = 8;

    time_t rawtime;
    struct timeval timeout;
    struct tm * timeinfo;
    char time_buffer[80];

    pthread_t *ctid = tuple->ssh_tid;

    strncpy(protocol, "ike ", 3);
    char *pack_delimiter = "***";

    struct db_table_entry *new_entry = (struct db_table_entry *) calloc(1, sizeof(struct db_table_entry));

    strncpy(new_entry->protocol, protocol, strlen(protocol));

	strncpy(new_entry->packet_type, type_of_packet->l4_type, 3);
	strncat(new_entry->packet_type, " over ", 6);
	strncat(new_entry->packet_type, type_of_packet->l3_type, 4);

    PGconn *conn = create_db_conn(tuple->db_pass);

    //Here's a test case:

    os_data = (char *)calloc(1, 34);
    char *os = "Unknown";

    if (tuple->os_data){
        tuple->os_data[34] = '\0';
        strncpy(os_data, tuple->os_data, 34);
    }
    else
        strncpy(os_data, os, strlen(os));

    strncpy(new_entry->os_version_device, os_data, 34);

    strncpy(new_entry->problem_type, "crash", 5);

    if (tuple->comment) {
        tuple->comment[28] = '\0';
        strncpy(new_entry->comment, tuple->comment, 28);
    }
    else
        memset(new_entry->comment, '\0', sizeof(new_entry->comment));


    if (strncmp(type_of_packet->l3_type, "ipv6", 4)==0)
        l3_prot = IPv6_PROTO;
    else if (strncmp(type_of_packet->l3_type, "ipv4", 4)==0)
        l3_prot = IP_PROTO;
    l4_prot = UDP_PROTO;


    if (l3_prot== IPv6_PROTO) {

        fprintf(stdout, "IKE protocol is currently not supported with IPv6 transport. Exiting.\n");            //for now. Will add later:
        exit(-1);

        /*

         udp_len = tcp_len = header.len-IPv6_IPSEG_LEN;
         ipv6_len = header.len - L2HDR_LEN;

         if (l4_prot== UDP_PROTO) {

         payload_len = header.len - IPv6_UDPSEG_LEN;

         if (udp = libnet_build_udp(libnet_get_prand(LIBNET_PR16), EW_PORT, udp_len, 0, (uint8_t *)pkt_ptr, payload_len, libt, 0) == -1)
         fprintf(stderr, "Error building UDP header: %s\n", libnet_geterror(libt));
         }

         else if (l4_prot== TCP_PROTO) {

         payload_len = header.len - IPv6_TCPSEG_LEN;

         if (tcp = libnet_build_tcp(tcp_sp, EW_PORT, tcp_seq, tcp_ack, tcp_flags, tcp_win, 0, 0, tcp_len, (uint8_t *)pkt_ptr, payload_len, libt, 0) == -1)
         fprintf(stderr, "Error building TCP header: %s\n", libnet_geterror(libt));

         pc = pcap_open_live(tuple->intf, 1520, 1, 1000, perr);

         int f = pcap_compile(pc, &filter, filter_exp, 1, maskp);
         if (f<0) {
         fprintf(stderr, "Filter compilation failed. Exiting.\n");
         exit(-1);
         }

         int s = pcap_setfilter(pc, &filter);
         if (s<0) {
         fprintf(stderr, "Filter failed. Exiting.\n");
         exit(-1);
         }

         // Dont forget to set iptables entry!!!

         }


         if (!tuple->source)
         ip6_src_addr = libnet_get_ipaddr6(libt);
         else
         ip6_src_addr = libnet_name2addr6(libt, tuple->source, LIBNET_DONT_RESOLVE);

         ip6_my_addr = libnet_get_ipaddr6(libt);

         if ((uint32_t*)&ip6_my_addr.__u6_addr != (uint32_t*)&ip6_src_addr.__u6_addr) {
         fprintf(stderr, "Spoofing isn't supported for TCP sessions in non-proxy mode.\n");
         exit(-1);
         }

         ip6_dst_addr = libnet_name2addr6(libt, tuple->destination, LIBNET_DONT_RESOLVE);


         if (ipv6 = libnet_build_ipv6(ipv6_tc, ipv6_flow, ipv6_len, l4_prot, 64, ip6_src_addr, ip6_dst_addr, 0, 0, libt, 0) == -1)
         fprintf(stderr, "Error building IPv6 header: %s\n", libnet_geterror(libt));
         if ((eth =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_IP6, NULL, 0, libt, 0))==-1)
         fprintf(stderr, "Error building ETHERNET header: %s\n", libnet_geterror(libt));

         */
    }

    else {
        libt = build_libnet_link_adv(tuple);

        if (!tuple->source) {
            src_ip = libnet_get_ipaddr4(libt);
            tuple->source = libnet_addr2name4(src_ip, LIBNET_DONT_RESOLVE);
        }
        else
            src_ip = libnet_name2addr4(libt, tuple->source, LIBNET_DONT_RESOLVE);

        dst_ip = libnet_name2addr4(libt, tuple->destination, LIBNET_DONT_RESOLVE);
    }

    if (libnet_get_ipaddr4(libt) != src_ip) {
        fprintf(stderr, "Spoofing isn't supported for IKE in session mode.\n");
        exit(-1);
    }

    u_int32_t total_hdr_len = 0;
    u_int32_t *lp = (u_int32_t *)&pkt_ptr[24];
    total_hdr_len = ntohl(*lp);

    u_int32_t dummy_hdr_len = 0;
    u_int32_t *dummy_lp = (u_int32_t *)&ike_dummy_packet[24];
    dummy_hdr_len = ntohl(*dummy_lp);

    u_int8_t ike_version = pkt_ptr[17];

    if (ike_version == 0x01) {
        fprintf(stderr, "Not supported in this iteration.\n");
//        exit(-1);
    }

    u_int8_t ike_exchange_type = pkt_ptr[18];
    int payload_count = 0, dummy_payload_count = 0;

    if (ike_exchange_type == 0x22) {

        payload_count = get_ike_payload_count(pkt_ptr, total_hdr_len);

        ike_dummy_packet_len = sizeof(ike_dummy_packet);

        ike_init_packet_len = sizeof(ike_part_init_packet)+8;

        dummy_payload_count = get_ike_payload_count(ike_dummy_packet, dummy_hdr_len);

    }

    else if (ike_exchange_type == 0x25) {

        ike_init_packet_len = sizeof(ike_part_init_packet)+8;

        payload_count = get_ike_payload_count(pkt_ptr, total_hdr_len);
    }



    if (0) {
        exit(-1);
    }

   /* if (tuple->num == 1) {

        struct fuzzed_data *ike_fdata = calloc((max_hdr_fields+tlv_count), sizeof(struct fuzzed_data));

        memcpy(pkt_ptr, init_packet, header.len);

        fuzz_ew(pkt_ptr, total_hdr_len, tlv_count, ike_fdata);

        udp = libnet_build_udp(libnet_get_prand(LIBNET_PR16), EW_PORT, udp_len, 0, (uint8_t *)pkt_ptr, payload_len, libt, udp);
        ip = libnet_build_ipv4(ip_len, 0, 0, 0, 64, IPPROTO_UDP, 0, src_ip, dst_ip, 0, 0, libt, ip);
        if ((eth =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_IP, NULL, 0, libt, eth))==-1)
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

        fprintf(stderr, "Fuzzing %d bytes of %s data\n", n, tuple->protocol);
        fprintf(stderr, "Sent 1 packet to %s\n", tuple->destination);
        init++;


        if (ping_result==FAIL) {

            fprintf(stderr, "----- Test failed - saving to database.\n");

            time(&rawtime);
            timeinfo = localtime (&rawtime);
            strftime (time_buffer, 80, "%X",timeinfo);

            db_packet_save(packet, packet_size, pass_packet);
            strncpy(new_entry->binary_pack_data, pass_packet, strlen(pass_packet));
            db_packet_save(pkt_ptr, payload_len, pass_packet);
            strncpy(new_entry->binary_diff_data, pass_packet, strlen(pass_packet));

            insert_new_db_entry(conn, new_entry->protocol, new_entry);

            if (tuple->verbose) {
                fprintf(stderr, "-- %s -- Test failed. Saving the following packet to packet.pcap: \n", time_buffer);
                packet_save(packet, packet_size);
            }

            libnet_adv_free_packet(libt, packet);
            packet = NULL;
            memset(time_buffer, '\0', strlen(time_buffer));
            if (tuple->quit) {
                exit(1);
            }
            fail_count++;

        }

        packet = NULL;
    } */



    else if (!tuple->num ) {

        while (1) {

            memcpy(pkt_ptr, init_packet, header.len);

            struct fuzzed_data *ike_fdata = calloc((max_hdr_fields+payload_count), sizeof(struct fuzzed_data));

/*

            if (move_to_md==1)
                fuzz_ew_multid(pkt_ptr, total_hdr_len, tlv_count, ike_fdata);

            else if (packet_count >= 20) {
                failed_percent = calc_failed_percentage(fail_count, packet_count);
                if (failed_percent <= 10) {
                    move_to_md = 1;
                    fuzz_ew_multid(pkt_ptr, total_hdr_len, tlv_count, ike_fdata);
                }
                else
                    fuzz_ew(pkt_ptr, total_hdr_len, tlv_count, ike_fdata);
            }

            else
                fuzz_ew(pkt_ptr, total_hdr_len, tlv_count, ike_fdata);
*/

            fuzz_ike_payload(payload_count, pkt_ptr);


            if (ike_exchange_type == 0x25) {

                if (l3_prot == IP_PROTO) {

                    packet_tuple->tcp_dp = IKE_PORT;

                    servlen = sizeof(struct sockaddr_in);

                    payload_len = header.len - IP_UDPSEG_LEN;

                    get_udp_socket(tuple->source, tuple->destination, packet_tuple);

                    i_cookie_num = rand();
                    sprintf(i_cookie, "%d", i_cookie_num);
                    strncpy(ike_init_packet, i_cookie, 8);
                    memcpy(&ike_init_packet[8], ike_part_init_packet, sizeof(ike_part_init_packet));

                    FD_ZERO(&read_set);
                    FD_SET(packet_tuple->sockfd, &read_set);

                    timeout.tv_sec = 2;
                    timeout.tv_usec = 0;

                    if ((n =sendto(packet_tuple->sockfd, ike_init_packet, ike_init_packet_len, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen))==-1) {
                        fprintf(stderr, "Error writing packet.\n");
                        exit(-1);
                    }

                    rc = select(FD_SETSIZE, &read_set, NULL, NULL, &timeout);

                    if (rc) {
                        if ((n =recvfrom(packet_tuple->sockfd, r_packet, ike_init_packet_len, 0, (struct sockaddr *)&(packet_tuple->serveraddr), &servlen))==-1) {
                            fprintf(stderr, "Error reading packet.\n");
                            exit(-1);
                        }

                        u_char msg_id[] = {0x00,0x00,0x00,0x01};

                        strncpy(pkt_ptr, ike_init_packet, 8);
                        strncpy(&pkt_ptr[8], &r_packet[8], 8);
                        strncpy(&pkt_ptr[19], msg_id, 4);
                        pkt_ptr[19] = 0x08;

                        sprintf(port, "%d", packet_tuple->tcp_sp);
                        strncat(filter_exp, tport, strlen(tport));
                        strncat(filter_exp, port, strlen(port));
                        strncat(filter_exp, filter_ext, strlen(filter_ext));
                        strncat(filter_exp, tuple->destination, strlen(tuple->destination));

                        pc = pcap_open_live(tuple->intf, 1520, 1, 1000, perr);

                        int f = pcap_compile(pc, &filter, filter_exp, 1, maskp);
                        if (f<0) {
                            fprintf(stderr, "Filter compilation failed. Exiting.\n");
                            exit(-1);
                        }

                        int s = pcap_setfilter(pc, &filter);
                        if (s<0) {
                            fprintf(stderr, "Filter failed. Exiting.\n");
                            exit(-1);
                        }


                        for (i=0;i<3;i++) {

                            if ((n =sendto(packet_tuple->sockfd, pkt_ptr, payload_len, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen))==-1) {
                                fprintf(stderr, "Error writing packet.\n");
                                exit(-1);
                            }

                            else {
                                pcap_next_ex(pc, &pkt, (const u_char **)&packet);
                                packet_size = pkt->len;
                                ping_result = ping_to_uut(tuple->destination);
                            }
                        }

                        fprintf(stderr, "%d.Fuzzing %d bytes of %s data\n", init+1, n, tuple->protocol);
                        usleep(tuple->timer);
                        close(packet_tuple->sockfd);
                        memset(filter_exp, '\0', 150);
                        pcap_freecode(&filter);
                        pcap_close(pc);

                    }

                    else
                        ping_result = ping_to_uut(tuple->destination);


                    if (ping_result && !rc) {

                        fprintf(stderr, "UUT is not responding to this test.\n");
                    }

                    else if (!ping_result && !rc) {
                        exit(-1);
                    }

                    else
                        close(packet_tuple->sockfd);


                }

                if (ping_result==FAIL) {

                    fprintf(stderr, "----- Test failed - saving to database.\n");

                    time(&rawtime);
                    timeinfo = localtime (&rawtime);
                    strftime (time_buffer, 80, "%X",timeinfo);

                    db_packet_save(pkt_ptr, payload_len, pass_packet);
                    strncpy(new_entry->binary_pack_data, pass_packet, strlen(pass_packet));
                    //This needs to change:
                    db_packet_save(pkt_ptr, payload_len, pass_packet);
                    strncpy(new_entry->binary_diff_data, pass_packet, strlen(pass_packet));

                    if (type_of_packet) {

                        if (strncmp(type_of_packet->l4_type, "tcp", 3)==0)
                            strncpy(new_entry->misc_description, "tcp", 3);
                        else if (strncmp(type_of_packet->l4_type, "udp", 3)==0)
                            strncpy(new_entry->misc_description, "udp", 3);
                        else
                            strncpy(new_entry->misc_description, "\0\0\0", 3);

                    }


                    insert_new_db_entry(conn, new_entry->protocol, new_entry);

                    /*
                     get_db_current_test_id(tuple->protocol, test_id);
                     save_pkt_desc_html(type_of_packet, o_packet, packet, packet_size, ike_fdata, test_id);
                     */

                    if (tuple->verbose) {
                        fprintf(stderr, "-- %s -- Test failed. Saving the following packet to packet.pcap: \n", time_buffer);
                        packet_save(packet, packet_size);
                    }

                    packet = NULL;
                    memset(time_buffer, '\0', strlen(time_buffer));

                    if (tuple->quit){
                        exit(1);
                    }
                    fail_count++;

                }


            }


            else if(ike_exchange_type == 0x22) {

                packet_tuple->tcp_dp = IKE_PORT;

                servlen = sizeof(struct sockaddr_in);

                payload_len = header.len - IP_UDPSEG_LEN;

                get_udp_socket(tuple->source, tuple->destination, packet_tuple);

                i_cookie_num = rand();
                sprintf(i_cookie, "%d", i_cookie_num);
                strncpy(pkt_ptr, i_cookie, 8);

                sprintf(port, "%d", packet_tuple->tcp_sp);
                strncat(filter_exp, tport, strlen(tport));
                strncat(filter_exp, port, strlen(port));
                strncat(filter_exp, filter_ext, strlen(filter_ext));
                strncat(filter_exp, tuple->destination, strlen(tuple->destination));

                pc = pcap_open_live(tuple->intf, 1520, 1, 1000, perr);

                int f = pcap_compile(pc, &filter, filter_exp, 1, maskp);
                if (f<0) {
                    fprintf(stderr, "Filter compilation failed. Exiting.\n");
                    exit(-1);
                }

                int s = pcap_setfilter(pc, &filter);
                if (s<0) {
                    fprintf(stderr, "Filter failed. Exiting.\n");
                    exit(-1);
                }

                FD_ZERO(&read_set);
                FD_SET(packet_tuple->sockfd, &read_set);

                timeout.tv_sec = 2;
                timeout.tv_usec = 0;

                if ((n =sendto(packet_tuple->sockfd, pkt_ptr, payload_len, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen))==-1) {
                    fprintf(stderr, "Error writing packet.\n");
                    exit(-1);
                }


                else {
                    pcap_next_ex(pc, &pkt, (const u_char **)&packet);
                    packet_size = pkt->len;
                }

                rc = select(FD_SETSIZE, &read_set, NULL, NULL, &timeout);

                if (rc) {

                    if ((n =recvfrom(packet_tuple->sockfd, r_packet, ike_init_packet_len, 0, (struct sockaddr *)&(packet_tuple->serveraddr), &servlen))==-1) {
                        fprintf(stderr, "Error reading packet.\n");
                        exit(-1);
                    }

                    fuzz_ike_payload(dummy_payload_count, ike_dummy_packet);

                    u_char msg_id[] = {0x00,0x00,0x00,0x01};
                    memcpy(r_cookie, &r_packet[8], 8);

                    memcpy(&ike_dummy_packet[8], r_cookie, 8);
                    memcpy(ike_dummy_packet, i_cookie, 8);

                    for (i=0;i<3;i++) {

                        if ((n =sendto(packet_tuple->sockfd, ike_dummy_packet, ike_dummy_packet_len, 0, (const struct sockaddr *)&(packet_tuple->serveraddr), servlen))==-1) {
                            fprintf(stderr, "Error writing packet.\n");
                            exit(-1);
                        }

                        else {
                            pcap_next_ex(pc, &pkt, (const u_char **)&packet);
                            packet_size = pkt->len;
                            ping_result = ping_to_uut(tuple->destination);
                        }
                    }

                    fprintf(stderr, "%d.Fuzzing %d bytes of %s data\n", init+1, n, tuple->protocol);
                    packet_count++;
                    usleep(tuple->timer);
                    close(packet_tuple->sockfd);
                    memset(filter_exp, '\0', 150);
                    pcap_freecode(&filter);
                    pcap_close(pc);

                }

                else
                    ping_result = ping_to_uut(tuple->destination);


                if (ping_result && !rc) {

                    fprintf(stderr, "UUT is not responding to this test.\n");
                    }

                else if (!ping_result && !rc) {
                    fprintf(stderr, "UUT is not responding. Since this is a result of the initial IKE_INIT_SA packet, it is highly unlikely that it caused a crash. Exiting.\n");
                    exit(-1);
                }

                else
                    close(packet_tuple->sockfd);

                if (ping_result==FAIL) {

                    fprintf(stderr, "----- Test failed - saving to database.\n");

                    time(&rawtime);
                    timeinfo = localtime (&rawtime);
                    strftime (time_buffer, 80, "%X",timeinfo);

                    db_packet_save(ike_dummy_packet, ike_dummy_packet_len, pass_packet);
                    strncpy(new_entry->binary_pack_data, pass_packet, strlen(pass_packet));
                    //This needs to change:
                    db_packet_save(pkt_ptr, payload_len, pass_packet);
                    strncpy(new_entry->binary_diff_data, pass_packet, strlen(pass_packet));

                    if (type_of_packet) {

                        if (strncmp(type_of_packet->l4_type, "tcp", 3)==0)
                            strncpy(new_entry->misc_description, "tcp", 3);
                        else if (strncmp(type_of_packet->l4_type, "udp", 3)==0)
                            strncpy(new_entry->misc_description, "udp", 3);
                        else
                            strncpy(new_entry->misc_description, "\0\0\0", 3);

                    }


                    insert_new_db_entry(conn, new_entry->protocol, new_entry);

                    /*
                     get_db_current_test_id(tuple->protocol, test_id);
                     save_pkt_desc_html(type_of_packet, o_packet, packet, packet_size, ike_fdata, test_id);
                     */

                    if (tuple->verbose) {
                        fprintf(stderr, "-- %s -- Test failed. Saving the following packet to packet.pcap: \n", time_buffer);
                        packet_save(packet, packet_size);
                    }

                    packet = NULL;
                    memset(time_buffer, '\0', strlen(time_buffer));

                    if (tuple->quit){
                        exit(1);
                    }
                    fail_count++;

                }


            }

            /*

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
                        free(ssh_entry);
                        exit(1);
                    }
                }

            */

            packet = NULL;

            memset(packet_tuple, '\0', sizeof(packet_tuple));
            usleep(tuple->timer);
            free(ike_fdata);

            init++;
            packet_count++;

        }

    }

    /* else {

        while (init<tuple->num) {

            struct fuzzed_data *ike_fdata = calloc((max_hdr_fields+tlv_count), sizeof(struct fuzzed_data));

            memcpy(pkt_ptr, init_packet, header.len);

            if (move_to_md==1)
                fuzz_ew_multid(pkt_ptr, total_hdr_len, tlv_count, ike_fdata);

            else if (packet_count >= 20) {
                failed_percent = calc_failed_percentage(fail_count, packet_count);
                if (failed_percent <= 10) {
                    move_to_md = 1;
                    fuzz_ew_multid(pkt_ptr, total_hdr_len, tlv_count, ike_fdata);
                }
                else
                    fuzz_ew(pkt_ptr, total_hdr_len, tlv_count, ike_fdata);
            }

            else
                fuzz_ew(pkt_ptr, total_hdr_len, tlv_count, ike_fdata);

            udp = libnet_build_udp(libnet_get_prand(LIBNET_PR16), EW_PORT, udp_len, 0, (uint8_t *)pkt_ptr, payload_len, libt, udp);
            ip = libnet_build_ipv4(ip_len, 0, 0, 0, 64, IPPROTO_UDP, 0, src_ip, dst_ip, 0, 0, libt, ip);
            if ((eth =libnet_build_ethernet(dst_mac, my_mac->ether_addr_octet, ETHERTYPE_IP, NULL, 0, libt, eth))==-1)
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


            if (ping_result==FAIL) {

                fprintf(stderr, "----- Test failed - saving to database.\n");

                time(&rawtime);
                timeinfo = localtime (&rawtime);
                strftime (time_buffer, 80, "%X",timeinfo);

                db_packet_save(packet, packet_size, pass_packet);
                strncpy(new_entry->binary_pack_data, pass_packet, strlen(pass_packet));
                db_packet_save(pkt_ptr, payload_len, pass_packet);
                strncpy(new_entry->binary_diff_data, pass_packet, strlen(pass_packet));

                insert_new_db_entry(conn, new_entry->protocol, new_entry);

                if (tuple->verbose) {
                    fprintf(stderr, "-- %s -- Test failed. Saving the following packet to packet.pcap: \n", time_buffer);
                    packet_save(packet, packet_size);
                }

                libnet_adv_free_packet(libt, packet);
                packet = NULL;
                memset(time_buffer, '\0', strlen(time_buffer));
                if (tuple->quit) {
                    exit(1);
                }
                fail_count++;

            }

            packet = NULL;

            usleep(tuple->timer);

        }
    } */

    free(type_of_packet);
    libnet_destroy(libt);


}


