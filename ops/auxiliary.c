
/*
 ##############################################################################
 Revision #      1.0
 Name:               :  auxiliary.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Auxiliary routines for fuzzing over protocol data.
 ##############################################################################
 */


#include "../headers/fuzz.h"
//#include "fuzz_ew.h"
#include "../headers/fuzz_bgp.h"
#include "../headers/fuzz_dhcp.h"
#include "../headers/fuzz_arp.h"
#include "../headers/fuzz_ipv4.h"
#include "../headers/fuzz_ipv6.h"
#include "../headers/instrumentation.h"
#include "../headers/database.h"
#include "../headers/socket_ops.h"


extern bool fail_flag;



void print_help() {

    fprintf(stderr, "bubble 1.0 protocol fuzzer\n");
    fprintf(stderr, "Usage: bubble --mode <running mode> --destination-address <address> --file <pcap_file> [Options]\n\n");
    fprintf(stderr, "OPTIONS:\n");
    fprintf(stderr, "\t-m/--mode <single|dumb|session|mitm>: \n\t\tsingle: not trying to establish a session. Usefull for testing against non stateful protocol or features. If not specified, a specification testing in single packet mode is performed.\n\t\tdumb: black box testing using single packet mode.\n\t\tsession: establishes full application level session to the destination and runs specification testing against it.\n\t\tmitm: establishes a man-in-the-middle session between L2 points and injects malformed packets into the existing session. Hint: this mode uses L2 ARP poisoning to position the node as MiTM.\n");
    fprintf(stderr, "\t-s/ --source-address <address>: If not specified, the address of the first interface on the system is used. \n\t\tFor tests executed from DB, if not specified, existing address is used. Otherwise, specified source address is used to overwrite DB test.\n");
    fprintf(stderr, "\t-i/ --interface <interface>: If not specified, the first interface on the system.\n");
    fprintf(stderr, "\t-p/ --protocol <protocol>: arp, energywise, ike, msdp, dhcpv4, bgp, dns. \n");
    fprintf(stderr, "\t-p/ --dport <dest port>: If not specified, a default port for protocol is used. \n");
    fprintf(stderr, "\t-n/ --number <number of packets>: Default is continuous. \n\t\tWhen used with --load-db specifies a number of times a specific test will execute.\n");
    fprintf(stderr, "\t-t/ --timer <time between packets in microseconds>: Default is 1 second. \n\t\tLonger values are recommended when observing multiple problems on the UUT.\n");
    fprintf(stderr, "\t-q/ --quit-on-fail: Exits the program as soon as it detects a failed test.\n");
    fprintf(stderr, "\t-v/ --verbose: Verbose logging of failed tests: \n\t\tpacket.pcap and bubble_log.txt files are created and packet is dumped on the console.\n");
    fprintf(stderr, "DB OPTIONS:\n");
    fprintf(stderr, "\t--comment <comment>: Add a comment to the test_id. \n\t\tRequires arguments --db-table and --db-password.\n");
    fprintf(stderr, "\t--show-db: Show the contents of the database. \n\t\tRequires arguments --db-table and --db-password.\n");
    fprintf(stderr, "\t--db-table <table_name>: Specifies the protocol table from the database (this is the same argument as with -p). \n\t\tRequires argument --db-password.\n");
    fprintf(stderr, "\t--db-password <password>: Specifies password to access database. \n\t\tRequires argument --db-table.\n");
    fprintf(stderr, "\t--load-db[test_id]: Loads the contents of the database to fuzz from it. \n\t\tRequires arguments --db-table and --db-password. \n\t\tOptionally, argument --load-db=x,y,z or -l x,y,z... can be used to execute only specific tests from the database.\n");
    fprintf(stderr, "\t--remove-db-entry [test_id]: Removes test_id form the table. \n\t\tIf specified without <test_id> all entries from the table are removed. \n\t\tRequires arguments --db-table and --db-password.\n");
    fprintf(stderr, "\t--dump-mode <console|capture>: Allows for exporting packet either to console in hex, or to capture file. \n\t\tOptionally, --dump-packet can be used to specify a test_id to export. If mode is capture, --dump-file is required. \n\t\tRequires arguments --db-table and --db-password.\n");
    fprintf(stderr, "\t--dump-packet[test_id]: Show the contents of the database. \n\t\tRequires arguments --db-table and --db-password.\n");
    fprintf(stderr, "\t--dump-file <file_name>: Used when --dump-mode is set to capture. \n\t\tRequires arguments --db-table and --db-password.\n");
    fprintf(stderr, "INSTRUMENTATION OPTIONS:\n");
    fprintf(stderr, "\t--os-version <os_device_version>: A string used to specify the Operating system version of the UUT. \n\t\tIf not used, SSH instrumentation thread will try to collect it from the device, and if instrumentation is not invoked, \"Unknown\" will be used in the DB for failed tests. \n\t\tRequires arguments --db-table and --db-password.\n");
    fprintf(stderr, "\t--os-type <os_device_type>: A string used to specify the Operating system type of the UUT. Currently supported type: cisco-ios. \n\t\tIf not used, SSH instrumentation thread will not be able to continue.\n\t\tRequires arguments --db-table and --db-password.\n");
    fprintf(stderr, "\t--instrumentation: Invokes SSH instrumentation to collect more feedback form the UUT. \n\t\tRequires arguments --user, --user-pass and --enable-passw.\n\n");
    fprintf(stderr, "\t--instrumentation-sig: Invokes SSH instrumentation against a specific 'signature' on the UUT. This option is used to catch various console printed conditions and logs. \n\t\tRequires arguments --instrumentation, --user, --user-pass and --enable-passw.\n\n");
    fprintf(stderr, "\t--instrumentation-preset: Used to run instrumentation presets: highcpu, memleak, etc. \n\t\tRequires arguments --instrumentation, --os-type, --user, --user-pass and --enable-passw.\n\n");
    fprintf(stderr, "\t--cpu: Used define CPU utilization threshold in percents for triggering instrumentation preset when highcpu preset is configured. \n\t\tRequires arguments --instrumentation-preset highcpu, --instrumentation, --os-type, --user, --user-pass and --enable-passw.\n\n");    fprintf(stderr, "EXAMPLES:\n");
    fprintf(stderr, "\tsudo bubble --mode session -i eth0 -s 192.168.0.1 -d 192.168.1.100 -p dhcpv4\n");
    fprintf(stderr, "\tsudo bubble -i eth0 -s 192.168.0.1 -d 192.168.1.100 -f packet.pcap -p energywise\n");
    fprintf(stderr, "\tsudo bubble --show-db --db-table energywise --db-password postgres\n");
    fprintf(stderr, "\tsudo bubble --load-db=1,25,1009 --db-table energywise --db-password postgres -n 3\n");
    fprintf(stderr, "\tsudo bubble --remove-db-entry=99 --db-table energywise --db-password postgres\n");
    fprintf(stderr, "\tsudo bubble -i eth0 -s 192.168.0.1 -d 192.168.1.100 -f packet.pcap -p energywise --instrumentation --user cisco --user-pass cisco123 --enable-pass cisco123\n\n");

}


void get_userid(void){

    struct passwd *s;
    //u_char *login = getlogin();
    s = getpwuid(getuid());
    userid = s->pw_uid;
    groupid = s->pw_gid;

}


void set_environment(u_char *address){

    system("sysctl -w net.ipv4.ping_group_range=\"0 10000\" > /dev/null");

    int ping_result, i;
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    u_char buf[sizeof(struct in_addr)];

    struct in6_addr dst_v6;

    int family;

    int s = 0;

    s = inet_pton(AF_INET6, tuple.destination, &dst_v6);

    if (s == 0) {
        s = inet_pton(AF_INET, tuple.destination, buf);
        if (s!=1) {
            fprintf(stderr, "Destination addres specified is neither in IPv4 nor in IPv6 presentation format.\n");
            exit(-1);
        }
        else
            family = 4;
    }
    else
        family = 6;


    char * log_caption = "Bubble log\n==========\n\nFailed testing attempts:\n\n";

    int fd = creat("bubble_log.txt", mode);
    int fc = creat("packet.pcap", mode);

    i = write(fd, log_caption, strlen(log_caption));

    close(fd);
    close(fc);

    fprintf(stderr, "Testing for reachability - sending ICMP...\n");

    if (family == 4) {

        for (i=0;i<5;i++) {

            ping_result = ping_to_uut(address);

            if (ping_result) {
                fprintf(stderr, "UUT Reachable.\n\n");
                break;
            }
        }
    }

    else if (family == 6) {

        ping_result = ping6_to_uut(&tuple);

        if (ping_result) {
            fprintf(stderr, "UUT Reachable.\n\n");
        }
    }

    if (!ping_result) {
        fprintf(stderr, "\n\nUUT not reachable. Please correct it and try again.\n");
        exit(-1);
    }
}


void no_failure_log(void) {

    char *no_failure = "No detected failures.\n\n";
    u_char *iptables_entry_del = "iptables -D OUTPUT -p tcp --dport 43440 --tcp-flags RST RST -j DROP > /dev/null 2>&1";

    int fd, i;

    if (type_of_packet) {
        if (strncmp(type_of_packet->l4_type, "tcp", 3)==0)
            system(iptables_entry_del);
    }


    if (fail_flag == 0) {

        fd = open("bubble_log.txt", O_WRONLY | O_APPEND);

        chown("bubble_log.txt", userid, groupid);
        chmod("bubble_log.txt", S_IRWXU | S_IRWXG | S_IRWXO);

        setgid(groupid);
        setuid(userid);
        remove("packet.pcap");

        i = write(fd, no_failure, strlen(no_failure));
        close(fd);
        fail_flag = 1;
        exit(-1);

    }
}


void vsig_handler(int sig, siginfo_t *info, void * context){

    char *sig_err = (char *)calloc(1, 150);
    snprintf(sig_err, sizeof(sig_err), "Error number %d. Bubble PID %d received a SIGSEGV signal with signal code %d.\n", info->si_errno, (int)info->si_pid, info->si_code);

    if (sig==SIGSEGV) {
        fprintf(stderr, "%s\n", sig_err);
        perror("Segmentation fault:");
        free(sig_err);
        exit(-1);
    }
}


void tuple_db_sanity(void) {

    if (!tuple.db_protocol) {
        fprintf(stderr, "Please specify database table.\n");
        exit(-1);
    }
    if (!tuple.db_pass) {
        tuple.db_pass = "postgres";
        fprintf(stderr, "Not specified db password - using postgres as a default password.\n");
    }

}


bool is_prime(int number) {

    int i;

    for (i = 2; i < number; i++)
    {
        if (number % i == 0 && i != number)
            return false;
    }
    return true;
}


int calc_failed_percentage (int failed_count, int packet_count) {

    int n = failed_count*100/packet_count;
    return n;
}


void check_protocol_single_mode(struct ssh_constr *instr_session) {

    int result = 0, choice = 0;

    int terr;
    pthread_t tid;


    if (!tuple.protocol){
        fprintf(stderr, "Please specify a protocol to fuzz.\n");
        exit(-1);
    }

    if ((strncmp(tuple.protocol, "arp", 3)==0)) {

        if (!tuple.destination)
            mac_set = false;
        else
            mac_set =true;

    }
/*
    else if ((strncmp(tuple.protocol, "energywise", 10)==0)) {


        if (tuple.file) {
            result = access(tuple.file, F_OK);
            if (result==-1) {
                fprintf(stderr, "Unable to access capture file. Try again.\n");
                exit(-1);
            }
        }

        fprintf(stderr, "What do you want to fuzz?\n");
        fprintf(stderr, "1. EW header\n");
        fprintf(stderr, "2. EW TLVs\n");
        fprintf(stderr, "3. Both\n");
        fprintf(stderr, "Please specify the choice: ");

        scanf("%d", &choice);

        if (choice == 1)
            ew_flags = 1;
        else if (choice == 2)
            ew_flags = 2;
        else if (choice == 3)
            ew_flags=3;
        else {
            fprintf(stderr, "Try again please.\n");
            exit(-1);
        }

    }

    */

    else {
        fprintf(stderr, "Protocol unknown or unsupported in single mode. Try again.\n");
        exit(-1);
    }


    if (!tuple.destination) {
        fprintf(stderr, "Please specify a destination address.\n");
        exit(-1);
    }

    if (!tuple.timer)
        tuple.timer = 1000000;

    if (!tuple.db_pass) {
        tuple.db_pass = "postgres";
        fprintf(stderr, "Database password not specified for DB connectivity - using 'postgres' as a default password.\n");
    }


    set_environment(tuple.destination);

    if ((tuple.instrumentation_preset || tuple.instrumentation_signature) && !tuple.instrumentation)
        fprintf(stderr, "--instrumentation switch is not specified. Ignoring --instrumentation-sig or --instrumentation-preset options.\n");

    if (tuple.instrumentation){

        if (!tuple.os_type) {
            fprintf(stderr, "I can't run instrumentation against an uknown OS type.\n");
            exit(-1);
        }

        ssh_entry = (struct db_table_entry *) calloc(1, sizeof(struct db_table_entry));

        if (strncmp(tuple.os_type, "cisco-ios", 9)==0)
            ssh_connect_cisco_uut(instr_session);
        else {
            fprintf(stderr, "Not yet implemented.\n");
            exit(-1);
        }

        terr = pthread_create(&tid, NULL, run_instrumentation, instr_session);
        if (terr != 0) {
            printf("\ncan't create thread :[%s]", strerror(terr));
            exit(-1);
        }
    }

    tuple.ssh_tid = &tid;

}


void check_protocol_session_mode(struct ssh_constr *instr_session) {

    int result = 0, choice = 0;

    int terr;
    pthread_t tid;

    if (!tuple.destination) {
        fprintf(stderr, "Please specify a destination address.\n");
        exit(-1);
    }

    if (!tuple.source) {
        fprintf(stderr, "Please specify a source address.\n");
        exit(-1);
    }

    if (!tuple.intf) {
        fprintf(stderr, "Please specify a source interface.\n");
        exit(-1);
    }

    if (!tuple.timer)
        tuple.timer = 1000000;

    if (!tuple.db_pass) {
        tuple.db_pass = "postgres";
        fprintf(stderr, "Database password not specified for DB connectivity - using postgres as a default password.\n");
    }


    if (!tuple.protocol){
        fprintf(stderr, "Please specify a protocol to fuzz.\n");
        exit(-1);
    }

    else if ((strncmp(tuple.protocol, "ike", 3)==0)) {


        if (tuple.file) {
            result = access(tuple.file, F_OK);
            if (result==-1) {
                fprintf(stderr, "Unable to access capture file. Try again.\n");
                exit(-1);
            }
        }
    }

    else if ((strncmp(tuple.protocol, "bgp", 3)==0)){


        fprintf(stderr, "Please specify my AS for BGP fuzzing:\n");
        fprintf(stderr, "My AS: ");

        scanf("%d", &choice);

        bgp_my_as = choice;

        if (tuple.file) {
            fprintf(stderr, "Ignoring capture file for session fuzzing.\n");
        }
    }

    else if ((strncmp(tuple.protocol, "dhcpv4", 6)==0)) {

        /*
         fprintf(stderr, "Are you simulating client or server?\n");
         fprintf(stderr, "1. Client\n");
         fprintf(stderr, "2. Server\n");
         fprintf(stderr, "Please specify the choice: ");

         scanf("%d", &choice);

         if (choice == 1)
         dhcp_sim_mode = DHCP_CLIENT;
         else if (choice == 2)
         dhcp_sim_mode = DHCP_SERVER;
         else {
         fprintf(stderr, "Please specify the simulation mode.\n");
         exit(-1);
         }
         */

        dhcp_sim_mode = DHCP_CLIENT;

        if (tuple.file) {
            fprintf(stderr, "Ignoring capture file for session fuzzing.\n");
        }
    }

    else if ((strncmp(tuple.protocol, "msdp", 4)==0)) {

        if (tuple.file) {
            fprintf(stderr, "Ignoring capture file for session fuzzing.\n");
        }
    }

    else if ((strncmp(tuple.protocol, "dns", 3)==0)) {

        if (tuple.file) {
            fprintf(stderr, "Ignoring capture file for session fuzzing.\n");
        }
    }


    else {
        fprintf(stderr, "Not yet implemented\n");
        exit(-1);
    }


    set_environment(tuple.destination);

    if ((tuple.instrumentation_preset || tuple.instrumentation_signature) && !tuple.instrumentation)
        fprintf(stderr, "--instrumentation switch is not specified. Ignoring --instrumentation-sig or --instrumentation-sig-set options.\n");

    if (tuple.instrumentation){

        ssh_entry = (struct db_table_entry *) calloc(1, sizeof(struct db_table_entry));

        ssh_connect_cisco_uut(instr_session);

        terr = pthread_create(&tid, NULL, run_instrumentation, instr_session);
        if (terr != 0) {
            printf("\ncan't create thread :[%s]", strerror(terr));
            exit(-1);
        }
    }

    tuple.ssh_tid = &tid;


}


int get_data_offset(char * protocol) {

    /* Need to make this much more intelligent and add offsets for other protocols later.
     In case of higher protocols (L5-L7) real parsing of the packet will have to be performed before assigning the offset:
     Currently assumes regular Ethernet II frame and IP header of 20 bytes
     */

    if (strncmp(type_of_packet->l3_type, "ipv6", 4)==0) {

        if (strncmp(tuple.protocol, "energywise", 10)==0) {
            if (strncmp(type_of_packet->l4_type, "udp", 3)==0)
                return IPv6_IPSEG_LEN;
            if (strncmp(type_of_packet->l4_type, "tcp", 3)==0)
                return IPv6_IPSEG_LEN;
        }
        else if (strncmp(tuple.protocol, "ike", 3)==0)
            return IPv6_UDPSEG_LEN;
        else if (strncmp(tuple.protocol, "bgp", 3)==0)
            return IPv6_TCPSEG_LEN;
        else if (strncmp(tuple.protocol, "udp", 3)==0)
            return IPv6_IPSEG_LEN;
        else if (strncmp(tuple.protocol, "tcp", 3)==0)
            return IPv6_IPSEG_LEN;
        else if (strncmp(tuple.protocol, "icmp", 4)==0)
            return IPv6_IPSEG_LEN;
        else if (strncmp(tuple.protocol, "ipv6", 4)==0)
            return L2HDR_LEN;
    }

    else if (strncmp(type_of_packet->l3_type, "ipv4", 4)==0) {

        if (strncmp(tuple.protocol, "energywise", 10)==0) {
            if (strncmp(type_of_packet->l4_type, "udp", 3)==0)
                return IP_UDPSEG_LEN;
            if (strncmp(type_of_packet->l4_type, "tcp", 3)==0)
                return IP_TCPSEG_LEN;
        }
        if (strncmp(tuple.protocol, "ike", 3)==0)
            return IP_UDPSEG_LEN;
        if (strncmp(tuple.protocol, "bgp", 3)==0)
            return IP_TCPSEG_LEN;
        if (strncmp(tuple.protocol, "udp", 3)==0)
            return IPSEG_LEN;
        if (strncmp(tuple.protocol, "tcp", 3)==0)
            return IPSEG_LEN;
        if (strncmp(tuple.protocol, "icmp", 4)==0)
            return IPSEG_LEN;
        if (strncmp(tuple.protocol, "ipv4", 4)==0)
            return L2HDR_LEN;
        if (strncmp(tuple.protocol, "arp", 3)==0)
            return L2HDR_LEN;
    }

}


int convert_xstring_to_dec(u_char *string, int size) {

    int i = 0, result = 0, rsize = size-1;

    while (i<size) {
        if (i==0)
            result = result + string[rsize];
        else
            result = result + string[rsize]* (i*256);
        rsize--;
        i++;
    }

    return result;
}


void rand_str_gen(u_char *rand_str, size_t length) {

    char charset[] = "0123456789"
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ.;:!@#$%^&*()_+=/";

    bool prime = false;
    int x = rand();

    if (x%2) {

        prime = is_prime(length*rand());

        if (prime) {
            while (length-- > 0)
                *rand_str++ = '\0';
        }
        else {
            while (length-- > 0) {
                size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
                *rand_str++ = charset[index];
            }
        }
    }

    else {
        if (length*rand() % 13 == 0) {
            while (length-- > 0) {
                *rand_str++ = '\0';
            }
        }

        else {
            while (length-- > 0) {
                size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
                *rand_str++ = charset[index];
            }
        }
    }

    *rand_str = '\0';
}


void rand_ipv4_gen(u_char* address_string, u_char *address) {

    struct sockaddr_in sa;

    inet_pton(AF_INET, address_string, &(sa.sin_addr));
    sa.sin_addr.s_addr = ntohl(sa.sin_addr.s_addr);
    sa.sin_addr.s_addr += rand() % 255;
    sa.sin_addr.s_addr = htonl(sa.sin_addr.s_addr);

    inet_ntop(AF_INET, &(sa.sin_addr), address, INET_ADDRSTRLEN);

    if (!strncmp(address+strlen(address)-3, "255", 3) || !strncmp(address+strlen(address)-2, ".0", 2))
        rand_ipv4_gen(address_string, address);
}

void rand_ipv4_octet_gen(u_char* address_string, int octet, u_char *address) {

    struct sockaddr_in sa;

    int i, j, k, size;
    size = strlen(address_string);

    u_char oct[3];
    memset(oct, 0, 3);

    u_char *address_ptr = address_string;

    for (j=1, k=0;j<octet; ) {
        if (address_ptr[k] == '.')
            j++;
        k++;
    }

    strncpy(address, address_ptr, k);

    i = k;

    if (octet == 4)
        i = size - k;
    else {
        while (address_ptr[i]!='.')
            i++;
    }

    int new = rand() % 255;

    sprintf(oct, "%d", new );

    if (octet==4)
        strncat(address, oct, strlen(oct));

    else {
        strncat(address, oct, strlen(oct));
        strncat(address, &address_ptr[i], size-i);
    }


    if (!strncmp(address+strlen(address)-3, "255", 3) || !strncmp(address+strlen(address)-2, ".0", 2))
        rand_ipv4_octet_gen(address_string, octet, address);
}


void dest_ipv4_overwrite(u_char* supplied_address, u_char * mem_destination) {


    char *address_string = calloc(1, INET_ADDRSTRLEN);

    memcpy(address_string, supplied_address, INET_ADDRSTRLEN);

    u_char buf[4];
    int i;
    char *token;
    const char dot[2] = ".";

    token = strtok(address_string, dot);

    for (i=0;i<4;i++) {
        if (token==NULL)
            break;
        buf[i] = atoi(token);
        if (buf[i]<0 || buf[i]>255){
            fprintf(stderr, "Wrong IP address format. Try again\n");
            exit(-1);
        }
        token = strtok(NULL, dot);
    }
    memcpy(mem_destination, buf, 4);

    free(address_string);
}


bool check_ipv4_addr(u_char *address){
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, address, &(sa.sin_addr));
    return result != 0;
}


bool check_ipv6_addr(u_char *address){
    struct sockaddr_in6 sa;
    int result = inet_pton(AF_INET6, address, &(sa.sin6_addr));
    return result != 0;
}


void packet_save(u_char *packet, int packet_size) {

    fail_flag = true;

    time_t rawtime;
    struct tm * timeinfo;
    time(&rawtime);
    char time_buffer_pcap[80], time_buffer_log[80];

    u_char * pcap_hdr_string = "+---------+---------------+----------+\n";
    u_char *pcap_hdr_ethernet = "   ETHER\n";
    u_char *pcap_hdr_pad = "|0   |";

    u_char pcap_packet[2048];

    int i, j, fd, fc;


    fd = open("packet.pcap", O_WRONLY| O_APPEND | O_CREAT);
    fc = open("bubble_log.txt", O_WRONLY| O_APPEND | O_CREAT);

    if (fd==-1) {
        fprintf(stderr, "Unable to open packet.pcap\n");
        exit(-1);
    }

    if (fc==-1) {
        fprintf(stderr, "Unable to open bubble_log.txt\n");
        exit(-1);
    }

    chown("packet.pcap", userid, groupid);
    chmod("packet.pcap", S_IRWXU | S_IRWXG | S_IRWXO);
    chown("bubble_log.txt", userid, groupid);
    chmod("bubble_log.txt", S_IRWXU | S_IRWXG | S_IRWXO);

    /*
     Changing of the UID/GID should be done by first calling audit_getloginuid() to get the loginuid and then pass it to setuid().
     This, however, requires libaudit library to get loaded and at this point, this doesn't look portable.
     The current decision is to set up a certain UID/GID at the program invocation (via init.sh script or .config file)
     and then use that UID/GID as a bubble user on the system.
     */

    setgid(groupid);
    setuid(userid);

    FILE * fp, *fpr;

    fp = fdopen(fd, "a");
    fpr = fdopen(fc, "a");

    timeinfo = localtime (&rawtime);

    /*
     I have no clue what do those 2 numbers after HH:MM:SS stand for. (111,111) - should check wireshark code for that.
     Apparently, changing them to some other value makes no difference to the .pcap file readability.
     But they both have to be present as 3-digit numbers other than 000.
     Guess those are needed for milisecond resolution or so - will fix this part in the future if needed.
     */

    strftime (time_buffer_pcap, 80, "%X,111,111",timeinfo);
    strftime (time_buffer_log, 80, "%X",timeinfo);
    strncpy(pcap_packet, pcap_hdr_string, strlen(pcap_hdr_string));
    strncat(pcap_packet, time_buffer_pcap, strlen(time_buffer_pcap));
    strncat(pcap_packet, pcap_hdr_ethernet, strlen(pcap_hdr_ethernet));
    strncat(pcap_packet, pcap_hdr_pad, strlen(pcap_hdr_pad));


    i = write(fd, pcap_packet, strlen(pcap_packet));

    fprintf(fpr, "-- %s -- Test failed. The following packet was executed:\n", time_buffer_log);

    for (i=0; i < packet_size; i++) {

        j = fprintf(fp, "%02x|", packet[i]);
        j = fprintf(stderr, "%02x|", packet[i]);
        j = fprintf(fpr, "%02x|", packet[i]);

    }

    fprintf(fpr, "\n");
    fprintf(fpr, "Packet is saved to packet.pcap\n");
    fprintf(fpr, "\n\n");
    fprintf(stderr, "\n\n");
    fprintf(fp, "\n\n");

    memset(pcap_packet, '\0', strlen(pcap_packet));

    fclose(fp);
    fclose(fpr);

    close(fd);
    close(fc);

    setgid(0);
    setuid(0);
}


void get_mac_address(u_char *address, u_char *mac_addr_str) {

    static int num =0;
    arp_t *ah;

    struct arp_entry dst;
    struct addr dest;

    u_char gw_address[128];
    memset(gw_address, '\0', sizeof(gw_address));

    eth_t *e;
    eth_addr_t *ea;


    char ping[40] = "ping -c 2 ";
    char ping6[100] = "ping6 -c 2 ";

    char *null = " > /dev/null";

    int a, b=1;

//    fprintf(stderr, "Pinging the destination to get the MAC address\n");

    if (strncmp(type_of_packet->l3_type, "ipv4", 4)==0) {
        strncat(ping, address, 16);
        strncat(ping, null, strlen(null));
        b = system(ping);
        if (b<0) {
            fprintf(stderr, "Unable to ping destination. Exiting.\n");
            exit(-1);
        }
        num++;

        find_route_entry(address, gw_address);

        if (strncmp(gw_address, "\0", 1) == 0)
            a = addr_pton(address, &dest);
        else
            a = addr_pton(gw_address, &dest);

        if (a!=0) {
            fprintf(stderr, "Error converting address. Exiting.\n");
            exit(-1);
        }

        dst.arp_pa = dest;

        ah = arp_open();
        a = arp_get(ah, &dst);

        if (a<0) {
            fprintf(stderr, "Destination entry not in the ARP table. Exiting.\n");
            exit(-1);
        }

        sprintf(mac_addr_str, "%s", addr_ntoa(&(dst.arp_ha)));

    }

    else {
        strncat(ping6, address, strlen(address));
        strncat(ping6, null, strlen(null));
        b = system(ping6);
        if (b<0) {
            fprintf(stderr, "Unable to ping destination. Exiting.\n");
            exit(-1);
        }
        find_route_entry(address, gw_address);
        get_mac_address_6(gw_address, mac_addr_str);
    }

    /*
    if (a!=0){
        if (num == 0) {
            fprintf(stderr, "Pinging the destination to get the MAC address\n");
            b = system(ping);
            num++;
        }
        else
            b = -1;
    }

    if (a!=0 || !b) {
        if (num == 0)
            fprintf(stderr, "Unable to obtain the MAC address - using my own MAC address as source.\n");
        int s, t;
        struct ifreq buffer;
        u_char p[17];
        u_char *u = calloc(1, sizeof(p));

        s = socket(PF_INET, SOCK_DGRAM, 0);

        memset(&buffer, 0x00, sizeof(buffer));

        strcpy(buffer.ifr_name, tuple.intf);

        ioctl(s, SIOCGIFHWADDR, &buffer);

        close(s);

        for( s = t = 0; s < 6; s++, t=t+3 )
            sprintf(&p[t], "%02X:", (unsigned char)buffer.ifr_hwaddr.sa_data[s]);
        strncpy(u, p, 17);
        return u;

    }
     */

}


void find_route_entry(u_char *address, u_char *gw_address) {

    route_t        *r = NULL;
    struct route_entry *e = NULL;
    int             i = 0;

    if ((e = calloc(1, sizeof(struct route_entry))) == NULL)
        fprintf(stderr, "malloc problem\n");

    if ((i = addr_pton(address, &((*e).route_dst))) < 0)
        fprintf(stderr, "addr_pton problem\n");

    if ((r = route_open()) == NULL) {
        fprintf(stderr, "route_open problem. Exiting.\n");
        exit(-1);
    }

    if ((i = route_get(r, e)) < 0) {
        route_close(r);
        free(e);
        gw_address = NULL;
    }

    else {
        sprintf(gw_address, "%s", addr_ntoa(&((*e).route_gw)));
        free(e);
        route_close(r);
    }
}


void get_mac_address_6(u_char *address, u_char *mac_addr_str) {

    /*

    Not the most elegant solution, but it avoids dealing with a cumbersom netlink interface.

    */

    char ip6_cmd[100] = "ip -6 neigh show ";
    char *redir = " > temp.txt";

    strncat(ip6_cmd, address, strlen(address));
    strncat(ip6_cmd, redir, strlen(redir));
    int b = system(ip6_cmd);


    u_char mac_address[MAC_ADDR_STR_LEN-1];

    parse_mac_output(mac_address);
    strncpy(mac_addr_str, mac_address, (MAC_ADDR_STR_LEN-1));

}


void parse_mac_output(u_char *mac_address) {

    u_char buf[128];
    u_char * delim = "lladdr ";

    char *temp;

    int result = access("temp.txt", F_OK);
    if (result==-1) {
        fprintf(stderr, "Unable to parse the mac address. Exiting.\n");
        exit(-1);
    }

    int fd = open("temp.txt", O_RDONLY);

    int r = read(fd, buf, sizeof(buf));
    if (!r || r==0) {
        fprintf(stderr, "Unable to parse the mac address. Exiting.\n");
        exit(-1);
    }

    temp = strstr(buf, delim);
    strncpy(mac_address, &temp[strlen(delim)], (MAC_ADDR_STR_LEN-1));
    remove("temp.txt");

}

/*
int ew_fdata_find_dup_elems(struct fuzzed_data *ew_fdata, struct fuzzed_data *ew_fdata_c) {

	struct fuzzed_data *temp = calloc(1, sizeof(struct fuzzed_data));

    int i, k;
    i = k = 0;

    while((ew_fdata_c[k].size)) {
        k++;
    }
    temp = ew_fdata;

    k = k-1;

    if (k==0)
        return 0;

    for (i = 0; i<k; i++) {
    	if (ew_fdata_c[i].offset == temp->offset) {
    		ew_fdata_c[i].fdata = strdup(temp->fdata);
    		return 1;
    	}
    }

    return 0;
}


void ew_fdata_sort_elems(struct fuzzed_data *ew_fdata, struct fuzzed_data *ew_fdata_c) {

	int i, k, l, j, m, c = 0;
	i = 0;


	while (ew_fdata_c[i].size)
		i++;

	j = i-1;

	while (ew_fdata_c[k].offset < ew_fdata->offset)
		k++;

    m = k;

    if (k+1==i) {
        ew_fdata_c[k] = *ew_fdata;
        return;
    }

	l = j-k;

	struct fuzzed_data *temp_chain = calloc(l, sizeof(struct fuzzed_data));

	while (k<j) {
		temp_chain[c].fdata = strdup(ew_fdata_c[k].fdata);
		temp_chain[c].fname = strdup(ew_fdata_c[k].fname);
		temp_chain[c].offset = ew_fdata_c[k].offset;
		temp_chain[c].size = ew_fdata_c[k].size;
		k++;
		c++;
	}


	ew_fdata_c[m].fdata = strdup(ew_fdata->fdata);
	ew_fdata_c[m].fname = strdup(ew_fdata->fname);
	ew_fdata_c[m].offset = ew_fdata->offset;
	ew_fdata_c[m].size = ew_fdata->size;

	for (c=0; m<j;m++,c++) {
		ew_fdata_c[m+1].fdata = strdup(temp_chain[c].fdata);
		ew_fdata_c[m+1].fname = strdup(temp_chain[c].fname);
		ew_fdata_c[m+1].offset = temp_chain[c].offset;
		ew_fdata_c[m+1].size = temp_chain[c].size;
	}



    free(temp_chain);
}
*/
