

/*
 *  $Id: fuzz.h,v 1.0 2014/10/10 00:30:00 route Exp $
 *
 *  instrumentation.h - Network fuzzing library header file for Instrumentation tasks
 *
 *  Written by Sasa Rasovic <sasa@rasovic.net>
 *
 */



#define INSTRUMENTATION_FAILED 1
#define INSTRUMENTATION_OK 0


struct ssh_constr {
    ssh_channel channel;
    ssh_session session;
};

struct process_constr {
    u_char process_name[5][24];
    float process_cpu_util[5];
};

bool ssh_alert;

char *os_data;

void get_os_details(char *buffer, char *os_details_string);

bool calculate_cpu_percentage(char *buffer, struct process_constr* top5);

bool parse_ssh_response(char *buffer);

void ssh_connect_cisco_uut(struct ssh_constr *);

void * run_instrumentation(void *);

void check_protocol_single_mode(struct ssh_constr *instr_session);

void check_protocol_session_mode(struct ssh_constr *instr_session);
