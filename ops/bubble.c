

/*
    ##############################################################################
    Revision #      1.0
    Name:               :  bubble.c
    Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
    Description         :  Main file for fuzzing over protocol data.
    ##############################################################################
*/


#include "../headers/fuzz.h"
//#include "fuzz_ew.h"
#include "../headers/fuzz_bgp.h"
#include "../headers/fuzz_dhcp.h"
#include "../headers/fuzz_arp.h"
#include "../headers/instrumentation.h"
#include "../headers/database.h"


bool fail_flag = 0;


char *null_string = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";


struct option longopts[] = {

    {"mode",   required_argument, 0, 'm'},
    {"source",   required_argument, 0, 's'},
    {"destination",  required_argument, 0, 'd'},
    {"interface",     required_argument, 0, 'i'},
    {"file",   required_argument, 0, 'f'},
    {"protocol",   required_argument, 0, 'p'},
    {"dport",   required_argument, 0, '8'},
    {"timer",   required_argument, 0, 't'},
    {"user",   required_argument, 0, 'u'},
    {"user-pass",   required_argument, 0, 'a'},
    {"enable-pass",   required_argument, 0, 'c'},
    {"quit-on-fail",   no_argument, 0, 'q'},
    {"verbose",   no_argument, 0, 'v'},
    {"show-db",   no_argument, 0, 'e'},
    {"instrumentation",   no_argument, 0, 'x'},
    {"instrumentation-sig",   required_argument, 0, 'z'},
    {"instrumentation-preset",   required_argument, 0, '6'},
    {"cpu",   required_argument, 0, '7'},
    {"load-db",   optional_argument, 0, 'l'},
    {"db-table",   required_argument, 0, 'b'},
    {"os-version",   required_argument, 0, 'o'},
    {"os-type",   required_argument, 0, 'y'},
    {"db-password",   required_argument, 0, 'r'},
    {"remove-db-entry",   optional_argument, 0, '5'},
    {"dump-mode",   required_argument, 0, '1'},
    {"dump-packet",   optional_argument, 0, '2'},
    {"dump-file",   required_argument, 0, '3'},
    {"comment",   required_argument, 0, '4'},
    {NULL, 	   0, 				  0, 0}

};


int main (int argc, char ** argv) {

	char ch;
    int i, indexptr = 0;

    u_char *tests = NULL;
    u_char *test_id = NULL;

    u_char *token;
    const u_char comma[2] = ",";

    u_char *dump_mode= NULL;
    u_char *capture_file=NULL;


    struct ssh_constr instr_session;
    instr_session.channel = calloc(1, sizeof(ssh_channel));
    instr_session.session = calloc(1, sizeof(ssh_session));

    struct sigaction lsig, vsig;

    lsig.sa_flags=SA_SIGINFO;
    lsig.sa_handler = (void *)no_failure_log;
    sigemptyset(&lsig.sa_mask);

    vsig.sa_flags=SA_SIGINFO;
    vsig.sa_handler = (void *)vsig_handler;
    sigemptyset(&vsig.sa_mask);

    sigaction(SIGINT,&lsig, NULL);
    sigaction(SIGHUP,&lsig, NULL);
    sigaction(SIGSEGV,&vsig, NULL);

    atexit(no_failure_log);


    while ((ch = getopt_long(argc, argv, ":s:d:i:f:p:n:t:r:b:o:y:z:u:a:c:l:m:1:2:3:4:5:6:7:xeqv", longopts, &indexptr)) != -1) {

        switch(ch) {

            case 'm':
                tuple.mode = optarg;
                break;
            case 's':
                tuple.source= optarg;
                break;
            case 'i':
                tuple.intf = optarg;
                break;
            case 'd':
                tuple.destination = optarg;
                break;
            case 'f':
                tuple.file = optarg;
                break;
            case 'p':
                tuple.protocol = optarg;
                break;
            case 'n':
                tuple.num = atoi(optarg);
                break;
            case 't':
                tuple.timer = (double)atoi(optarg);
                break;
            case 'q':
                tuple.quit = 1;
                break;
            case 'v':
                tuple.verbose = 1;
                break;
            case 'l':
                if (optarg)
                    tests = optarg;
                else
                    tuple.db_load = 1;
                break;
            case 'r':
                tuple.db_pass = optarg;
                break;
            case '5':
                if (optarg)
                    test_id = optarg;
                else
                    test_id = "all";
                break;
            case 'b':
                tuple.db_protocol = optarg;
                break;
            case 'e':
                tuple.db_display = 1;
                break;
            case 'a':
                tuple.user_pass = optarg;
                break;
            case 'u':
                tuple.user = optarg;
                break;
            case 'c':
                tuple.enable_pass = optarg;
                break;
            case 'o':
                tuple.os_data = optarg;
                break;
            case 'y':
                tuple.os_type = optarg;
                break;
            case 'x':
                tuple.instrumentation = 1;
                break;
            case 'z':
                tuple.instrumentation_signature = optarg;
                break;
            case '6':
                tuple.instrumentation_preset = optarg;
                break;
            case '7':
                if (strncmp(optarg,"0", 1) == 0) {
                    fprintf(stderr, "Illegal value for cpu. CPU treshchold can not be 0.\n");
                    exit(-1);
                }
                else
                    tuple.cpu = atoi(optarg);
                break;
            case '1':
                dump_mode = optarg;
                break;
            case '2':
                if (optarg)
                    tests = optarg;
                break;
            case '3':
                capture_file = optarg;
                break;
            case '4':
                tuple.comment = optarg;
                break;
            case 'h':
            case '8':
                tuple.dport = optarg;
                break;
            case '?':
            default:
                    print_help();
                exit(-1);
        }
    }


    for (i = optind; i < argc; i++)
        printf("Redundant argument - %s\n", argv[i]);

    i =0;

    get_userid();


    if (tuple.mode) {

        if (!tuple.intf) {
            fprintf(stderr, "Please specify an interface for testing.\n");
            exit(-1);
        }

        if (strncmp(tuple.mode, "single", 5)==0){

            check_protocol_single_mode(&instr_session);
            build_pack(&tuple);
            return 0;

        }

        else if (strncmp(tuple.mode, "session", 7)==0){

            check_protocol_session_mode(&instr_session);
            build_session(&tuple);
            return 0;

        }

        else if (strncmp(tuple.mode, "dumb", 4)==0){
            fprintf(stderr, "Not yet implemented\n");
            exit(-1);
        }

        else if (strncmp(tuple.mode, "mitm", 4)==0){
            fprintf(stderr, "Not yet implemented\n");
            exit(-1);
        }

        else {
            fprintf(stderr, "Illegal mode chosen. Exiting.\n");
            exit(-1);
        }


    }


    else {


        if (tests) {

            token = strtok(tests, comma);

            while(token!=NULL) {
                memset(tuple.test_id[i], '\0', 20);
                strncpy(tuple.test_id[i], token, strlen(token));
                token = strtok(NULL, comma);
                i++;
            }
            tuple.test_num = i;
        }

        if (dump_mode) {

            tuple_db_sanity();

            if (strncmp(dump_mode, "console", 7)==0) {
                dump_db_packet_to_console(tuple.db_protocol, tuple.db_pass);
                exit(1);
            }
            else {
                if (!capture_file){
                    fprintf(stderr, "No capture file defined.\n");
                    exit(-1);

                }
                dump_db_packet_to_capture(tuple.db_protocol, tuple.db_pass, capture_file);
                exit(1);
            }

        }


        if (tuple.db_display) {

            tuple_db_sanity();

            display_db_table(tuple.db_protocol, tuple.db_pass);
            exit(1);
        }


        if (test_id) {

            tuple_db_sanity();

            delete_db_entry(tuple.db_protocol, test_id);
            exit(1);
        }


        if (tuple.test_num || tuple.db_load) {

            if (!tuple.intf) {
                fprintf(stderr, "Please specify an interface for testing.\n");
                exit(-1);
            }

            tuple_db_sanity();

            send_packet_from_db((u_char *)tuple.db_pass, (u_char *)tuple.db_protocol);
            exit(1);
        }


        if (!tuple.intf) {
            fprintf(stderr, "Please specify an interface for testing.\n");
            exit(-1);
        }

        check_protocol_single_mode(&instr_session);

        build_pack(&tuple);

        return 0;
    }

}


