
/*
 ##############################################################################
 Revision #      1.0
 Name:               :  instrumentation.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Instrumentation routines for gathering additional data from UUT.
 ##############################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/instrumentation.h"
#include "../headers/database.h"

u_char *os_version;

static u_char *temp_buffer;
static int parse_flag;
static bool cpu_flag;


#define MAX_BUFF_SIZE   25600

#define CSCO_HIGHCPU    1
#define CSCO_MEMLEAK    2

// ...


u_char *cisco_high_cpu_cmd = "show processes cpu sorted 5sec\n";
u_char *cisco_memleak_cmd = "show memory summary\n";



void *run_instrumentation(void *arg) {

    int nbytes, wbytes, i;
    struct ssh_constr *instr_session = (struct ssh_constr *)arg;

    u_char cmd_buffer[MAX_BUFF_SIZE];
    u_char buffer[MAX_BUFF_SIZE];

    memset(cmd_buffer, '\0', MAX_BUFF_SIZE);
    memset(buffer, '\0', MAX_BUFF_SIZE);

    ssh_channel channel = instr_session->channel;
    ssh_session session = instr_session->session;

    /*

     Setup the base for new db entry:
     (The rest would come later, if the ssh_alert alarms.)

     */

    if (tuple.comment)
        strncpy(ssh_entry->comment, tuple.comment, sizeof(ssh_entry->comment));

    strncpy(ssh_entry->protocol, tuple.protocol, strlen(tuple.protocol));
	strncpy(ssh_entry->packet_type, type_of_packet->l4_type, 3);
	strncat(ssh_entry->packet_type, " over ", 6);
	strncat(ssh_entry->packet_type, type_of_packet->l3_type, 4);
    strncpy(ssh_entry->os_version_device, os_version, sizeof(ssh_entry->os_version_device));


    if (tuple.instrumentation_preset) {


        if (strncmp(tuple.os_type, "cisco-ios", 9)==0) {

            if (strncmp(tuple.instrumentation_preset, "highcpu", 7)==0) {
                strncpy(cmd_buffer, cisco_high_cpu_cmd, strlen(cisco_high_cpu_cmd));
                parse_flag = CSCO_HIGHCPU;
            }
            else if (strncmp(tuple.instrumentation_preset, "memleak", 7)==0) {
                strncpy(cmd_buffer, cisco_memleak_cmd, strlen(cisco_memleak_cmd));
                parse_flag = CSCO_MEMLEAK;
            }
            //...
            else {
                fprintf(stderr, "Illegal option, ignoring: %s. Running a default preset - HighCPU.\n", tuple.instrumentation_preset);
                strncpy(cmd_buffer, cisco_high_cpu_cmd, strlen(cisco_high_cpu_cmd));
                parse_flag = CSCO_HIGHCPU;
            }
        }

        while (!ssh_alert) {

            do {
                sleep(5);
                wbytes = ssh_channel_write(channel, cmd_buffer, sizeof(cmd_buffer));
                nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
                ssh_alert = parse_ssh_response(buffer);
                if(ssh_alert)
                    break;
            }
            while (nbytes>0);

        }

    }


    else {

        parse_flag = 0;

        while (!ssh_alert) {

            do {
                nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
                ssh_alert = parse_ssh_response(buffer);
                if(ssh_alert)
                    break;
            }
            while (nbytes>0);

        }
    }

    /*

     Give the main thread enough time (3 seconds) to finish the ping routine if it's in the middle of it.
     This should be done by signal passing between threads perhaps in the next version:

     */

  	ssh_disconnect(session);
  	ssh_free(session);
    free(os_version);
	pthread_exit(NULL);
}


void ssh_connect_cisco_uut(struct ssh_constr * ssh_constr) {


    if (tuple.instrumentation && !tuple.instrumentation_signature &&!tuple.instrumentation_preset) {
        fprintf(stderr, "Instrumentation requested but no instrumentation signature present. Existing.\"\n\n");
        exit(-1);
    }

    if (tuple.instrumentation_signature && tuple.instrumentation_preset) {
        fprintf(stderr, "Custom signature and signature preset can not be both configured. Existing.\n\n");
        exit(-1);
    }

    if (tuple.instrumentation_preset) {
        if ((strncmp(tuple.instrumentation_preset, "highcpu", 7)==0) && !tuple.cpu) {
            fprintf(stderr, "CPU threshold must be defined when instrumentation-present 'highcpu' is requested.\n");
            exit(-1);
        }
    }


    u_char buffer[25600];
	u_char pass_buffer[256];

    os_version = calloc(1, 1024);

    char *cmd_terminal = "terminal monitor\n";
    char *cmd_terminal_len = "terminal len 0\n";
	char *enable = "enable\n";
    char *cmd_version ="show version\n";

	u_char *enable_pass = calloc(1, strlen(tuple.enable_pass)+1);
	strncpy(enable_pass, tuple.enable_pass, strlen(tuple.enable_pass));
	enable_pass[strlen(tuple.enable_pass)] = '\n';


	int rc, nbytes;
	ssh_channel channel;
    ssh_session instr_session;

    // Open session and set options
  	instr_session = ssh_new();

    fprintf(stderr, "Instrumentation thread started: SSH connection to UUT in progress.\n");

    if (instr_session == NULL)
        exit(-1);

  	ssh_options_set(instr_session, SSH_OPTIONS_HOST, tuple.destination);

#ifdef SSH_VERBOSE

    int verbosity = SSH_LOG_PROTOCOL;

    ssh_options_set(instr_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

#endif

  	// Connect to server
  	rc = ssh_connect(instr_session);
  	if (rc != SSH_OK)
  	{
    	fprintf(stderr, "Error connecting to host: %s\n",
                ssh_get_error(instr_session));
    	ssh_free(instr_session);
    	exit(-1);
  	}

#ifdef SSH_VERBOSE

    fprintf(stderr, "Connected. Authenticating.\n");

#endif

  	// Authenticate ourselves
    rc = ssh_options_set(instr_session, SSH_OPTIONS_USER, tuple.user);
    rc = ssh_userauth_password(instr_session, NULL, tuple.user_pass);
    if (rc != SSH_AUTH_SUCCESS)
    {
	    fprintf(stderr, "Error authenticating with password: %s\n",
	            ssh_get_error(instr_session));
	    ssh_disconnect(instr_session);
	    ssh_free(instr_session);
	    exit(-1);
    }

    channel = ssh_channel_new(instr_session);
  	if (channel == NULL) {
  		fprintf(stderr, "Unable to open SSH channel to UUT\n\n");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(instr_session);
	    ssh_free(instr_session);
  		exit(-1);
  	}

	rc = ssh_channel_open_session(channel);
  	if (rc != SSH_OK)
  	{
	    fprintf(stderr, "Unable to open SSH channel session to UUT\n\n");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(instr_session);
	    ssh_free(instr_session);
  		exit(-1);
    }


	rc = ssh_channel_request_shell(channel);
  	if (rc != SSH_OK) {
	    printf("Error getting a ssh shell\n");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(instr_session);
	    ssh_free(instr_session);
        exit(-1);
    }


	nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);                          // Need to add some error checking.
  	while (nbytes>0) {
	    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

	nbytes = ssh_channel_write(channel, enable, strlen(enable));
	if (!nbytes) {
        fprintf(stderr, "ERROR in channel write\n");
    }

    u_char *res = NULL;
    u_char *pass_expected = "Password:";

	nbytes = ssh_channel_read(channel, pass_buffer, sizeof(pass_buffer), 0);
	while (nbytes>0) {
        res = strstr(pass_buffer, pass_expected);
        if (res)
            break;
        else
            nbytes = ssh_channel_read(channel, pass_buffer, sizeof(pass_buffer), 0);
	}

	//should parse pass_buffer for consistency here

	ssh_channel_write(channel, enable_pass, strlen(enable_pass));

	if (!nbytes) {
        fprintf(stderr, "ERROR in channel write\n");
        exit(-1);
    }

    fprintf(stderr, "Authenticated. ");
    fprintf(stderr, "Building tests...\n\n");

    nbytes = ssh_channel_read(channel, pass_buffer, sizeof(pass_buffer), 0);
	while (nbytes>0) {
        nbytes = ssh_channel_read(channel, pass_buffer, sizeof(pass_buffer), 0);
	}

    memset(buffer, 0, sizeof(buffer));                                      // we don't care about any output coming after sending enable pass.

	ssh_channel_write(channel, cmd_terminal, strlen(cmd_terminal));

    nbytes = ssh_channel_read(channel, pass_buffer, sizeof(pass_buffer), 0);
	while (nbytes>0) {
        nbytes = ssh_channel_read(channel, pass_buffer, sizeof(pass_buffer), 0);
	}

    memset(buffer, 0, sizeof(buffer));                                      // we don't care about any output coming after sending 'terminal monitor'.


    ssh_channel_write(channel, cmd_terminal_len, strlen(cmd_terminal_len));

    nbytes = ssh_channel_read(channel, pass_buffer, sizeof(pass_buffer), 0);
    while (nbytes>0) {
        nbytes = ssh_channel_read(channel, pass_buffer, sizeof(pass_buffer), 0);
    }

    memset(buffer, 0, sizeof(buffer));                                      // we don't care about any output coming after sending 'terminal len 0'.


    ssh_constr->channel =  channel;
    ssh_constr->session = instr_session;

    ssh_channel_write(channel, cmd_version, strlen(cmd_version));

	do
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    while (nbytes>0);

	get_os_details(buffer, os_version);

	memset(buffer, 0, sizeof(buffer));

    free(enable_pass);

}


void get_os_details(char *buffer, char *os_details_string) {

    const char newline[2] = "\n";

    temp_buffer = calloc(1, strlen(buffer) +1);

    temp_buffer = strtok(buffer, newline);
    strncpy(os_details_string, temp_buffer, strlen(temp_buffer));

    temp_buffer = NULL;
    free(temp_buffer);

}



bool calculate_cpu_percentage(char *buffer, struct process_constr* top5) {

    const char percent[2] = "%";
    const char newline[2] = "\n";
    const char mark[9] = ": ";
    const char proc_mark[2] = "\r";

    int global_cpu = 0, i;

    u_char proc[5][6];
    u_char process_name[5][24];

    for (i=0;i<5;i++) {
        memset(proc[i], '\0', 6);
        memset(process_name[i], '\0', 24);
    }

    float process_cpu_util[5];

    u_char *buffer_copy = calloc(1, strlen(buffer));
    strncpy(buffer_copy, buffer, strlen(buffer));

    u_char *temp_buffer = calloc(1, strlen(buffer) +1);
    u_char *cpu_buffer = calloc(1, 3);
    u_char *process_name_tmp = calloc(1, 24);

    u_char *proc_sanitized;

    temp_buffer = strstr(buffer, mark);
    cpu_buffer = strtok(temp_buffer, percent);


    cpu_buffer = &cpu_buffer[2];
    global_cpu = atoi(cpu_buffer);


    if (global_cpu > tuple.cpu) {

        cpu_flag = true;

        fprintf(stderr, "Cought ssh_alert: ");

        fprintf(stderr, "High CPU detected - %d%% utilization.\n\n", global_cpu);

        temp_buffer = strstr(buffer_copy, newline);
        temp_buffer = strstr(&temp_buffer[1], newline);
        temp_buffer = strstr(&temp_buffer[1], newline);

        for (i=0;i<5;i++) {

            strncpy(proc[i], &temp_buffer[41], 6);
            process_cpu_util[i] = atof(proc[i]);
            strncpy(process_name_tmp, &temp_buffer[66],24);
            proc_sanitized = strtok(process_name_tmp, proc_mark);
            strncpy(process_name[i], proc_sanitized, strlen(proc_sanitized));
            temp_buffer = strstr(&temp_buffer[1], newline);

        }

        for (i = 0; i<5;i++) {

            if (process_cpu_util[i] >(tuple.cpu/10)) {
                top5->process_cpu_util[i] = process_cpu_util[i];
                strncpy(top5->process_name[i], process_name[i], strlen(process_name[i]));
            }

        }

    }


    temp_buffer = NULL;
    cpu_buffer = NULL;
    buffer_copy = NULL;
    process_name_tmp = NULL;

    free(temp_buffer);
    free(cpu_buffer);
    free(buffer_copy);
    free(process_name_tmp);

    return cpu_flag;

}


bool parse_ssh_response(char *buffer){

    char *res = NULL;
    char *sres = NULL;
    char *sig_custom = NULL;

    int i;
    char percent[3];
    memset(percent, 0, 3);

    struct process_constr *top5 = calloc(1, sizeof(struct process_constr));

    char u_problem_type[1024];
    memset(u_problem_type, '\0', 1024);

    char *problem_type_custom = "Custom signature: ";

    //this is a placeholder for the future pre-set suggested problem types:

    char *problem_type_highcpu = "List of possible culprit processes:\n\n";
    char *problem_type_memleak = "Memory Leak ";


    if (parse_flag) {
        switch (parse_flag) {
            case CSCO_HIGHCPU:
                cpu_flag = calculate_cpu_percentage(buffer, top5);
                if (cpu_flag) {

                    strncpy(u_problem_type, problem_type_highcpu, strlen(problem_type_highcpu));

                    i =0;

                    while(top5->process_cpu_util[i]) {

                        strncat(u_problem_type, "\t", 1);
                        strncat(u_problem_type, top5->process_name[i], strlen(top5->process_name[i]));
                        strncat(u_problem_type, " - ", 3);
                        sprintf(percent, "%d", (int)top5->process_cpu_util[i]);
                        strncat(u_problem_type, percent, strlen(percent));
                        strncat(u_problem_type, "%%", 1);
                        strncat(u_problem_type, " \n", 2);
                        i++;
                        memset(percent, 0, 3);

                    }
                    fprintf(stderr, "%s\n", u_problem_type);
                    free(top5);
                    strncpy(ssh_entry->problem_type, "High CPU detected", sizeof(ssh_entry->problem_type));
                    return SUCCESS;
                }
                else
                    return FAIL;

                break;
            case CSCO_MEMLEAK:
                //
                fprintf(stderr, "preset not yet implemented.\n");
                exit(-1);
                break;
            default:
                break;
        }
    }

    else {

        sig_custom = tuple.instrumentation_signature;
        res = strstr(buffer, sig_custom);

        if (res) {
            strncpy(u_problem_type, problem_type_custom, strlen(problem_type_custom));
            strncat(u_problem_type, "\"", 1);
            strncat(u_problem_type, tuple.instrumentation_signature, strlen(tuple.instrumentation_signature));
            strncat(u_problem_type, "\"", 1);
            strncpy(ssh_entry->problem_type, u_problem_type, sizeof(ssh_entry->problem_type));
            fprintf(stderr, "Got alert - logging suspicious array of packets to the database.\n\n");
            return SUCCESS;
        }

        else
            return FAIL;


    }




}


/*
 void get_os_details2(char *buffer, char *os_details_string) {


 char *temp_buffer = calloc(1, strlen(buffer) +1);


 strncpy(temp_buffer, buffer, strlen(buffer));

 fprintf(stderr, "Fetching OS and device version\n\n");

 char *os_details = calloc(1, strlen(temp_buffer));
 const char *release =" Experimental Version";
 const char *cisco ="Cisco IOS";
 const char comma[2] = ",";
 char *token;
 char *res;
 res = strstr(temp_buffer, cisco);

 token = strtok(res, comma);
 strncpy(os_details, token, strlen(token));

 while ((strncmp(token, release, strlen(release))!=0)){
 token = strtok(NULL, comma);
 strncat(os_details, token, strlen(token));
 }

 res = strstr(os_details, release);

 strncpy(os_details_string, os_details, (strlen(os_details)-strlen(res)));
 free(temp_buffer);
 free(os_details);

 }
 */
