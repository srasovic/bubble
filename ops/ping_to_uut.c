
#include "../headers/fuzz.h"

//note, to allow root to use icmp sockets, run:
//sysctl -w net.ipv4.ping_group_range="0 0"


int ping_to_uut(u_char *destination) {


    struct in_addr dst;

    if (inet_aton(destination, &dst) == 0) {

        perror("inet_aton");
        printf("%s isn't a valid IP address\n", destination);
        exit(-1);
    }

    int sequence = 1, i;
    int count =0;
    time_t t;
    static int iteration = 1;

    if (iteration == 3) {
        iteration =1;
        return FAIL;
    }

    struct icmphdr icmp_hdr;
    struct sockaddr_in addr;

    int sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        close(sock);
        exit(-1);
    }

    srand((unsigned) time(&t));


    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr = dst;

    memset(&icmp_hdr, 0, sizeof icmp_hdr);
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = rand();         //arbitrary id


    unsigned char data[128];
    int rc;
    struct timeval timeout = {2, 0};        //wait max 2 seconds for a reply
    fd_set read_set;
    socklen_t slen;
    struct icmphdr rcv_hdr;

    icmp_hdr.un.echo.sequence = sequence++;
    memcpy(data, &icmp_hdr, sizeof icmp_hdr);
    memcpy(data + sizeof icmp_hdr, "hello", 5); //icmp payload
    rc = sendto(sock, data, sizeof icmp_hdr + 5,
                0, (struct sockaddr*)&addr, sizeof addr);
    if (rc <= 0) {
        perror("Sendto");
        close(sock);
        exit(-1);
    }
    //puts("Sent ICMP\n");

    memset(&read_set, 0, sizeof read_set);
    FD_SET(sock, &read_set);

    //wait for a reply with a timeout
    rc = select(sock + 1, &read_set, NULL, NULL, &timeout);
    if (rc == 0) {
        close(sock);
        return FAIL;
    } else if (rc < 0) {
        if (errno == EINTR)
            exit;
        else {
            perror("Select");
            close(sock);
            exit(-1);
        }
    }

    slen = 0;
    rc = recvfrom(sock, data, sizeof data, 0, NULL, &slen);
    if (rc <= 0) {
        perror("recvfrom");
        close(sock);
        exit(-1);
    } else if (rc < sizeof rcv_hdr) {
        printf("Error, got short ICMP packet, %d bytes\n", rc);
        close(sock);
        return FAIL;
    }

    memcpy(&rcv_hdr, data, sizeof rcv_hdr);

    if (rcv_hdr.type == ICMP_ECHOREPLY) {
        //printf("ICMP Reply, id=0x%x, sequence =  0x%x\n",
        //              icmp_hdr.un.echo.id, icmp_hdr.un.echo.sequence);
        close(sock);
        return SUCCESS;
    }

    else {
        printf("Got ICMP packet with type 0x%x ?!?\n", rcv_hdr.type);
        close(sock);
        return FAIL;
    }

    close(sock);
}
