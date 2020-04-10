


/*
 ##############################################################################
 Revision #      1.0
 Name:               :  dns_fuzzer.c
 Author/Contributor  :  Sasa Rasovic <sasa@rasovic.net>
 Description         :  Routines for fuzzing over DNS protocol data.
 ##############################################################################
 */


#include "../headers/fuzz.h"
#include "../headers/fuzz_dns.h"

extern int plen[13];

u_char name[124];

void fuzz_dns_client_pack(u_char *cpack, struct queries *qrs, int alen) {

    int a, b, c, d, e, i, slen, aptr;

    a = rand() % 400;

    //debug:
    //a = 280;

    if (a<100) {

        //fuzz the header

        b = rand() % 6+1;

        if (b == 1){

            c = rand() %3+1;

            if (c==1) {
                cpack[0] = 0xFF;
                cpack[1] = 0xFF;
            }
            if (c==2) {
                cpack[0] = 0x00;
                cpack[1] = 0x00;
            }
        }

        else if (b==2) {

            c = rand() %4+1;
            if (c==1)
                cpack[2] = rand() %0xFF+1;
            if (c==2)
                cpack[3] = rand() %0xFF+1;
            if (c==3) {
                cpack[2] = 0xFF;
                cpack[3] = 0xFF;
            }
            if (c==4) {
                cpack[2] = 0x00;
                cpack[3] = 0x00;
            }
        }

        else if (b==3) {

            c = rand() %4+1;
            if (c==1)
                cpack[4] = rand() %0xFF+1;
            if (c==2)
                cpack[5] = rand() %0xFF+1;
            if (c==3) {
                cpack[4] = 0xFF;
                cpack[5] = 0xFF;
            }
            if (c==4) {
                cpack[4] = 0x00;
                cpack[5] = 0x00;
            }

        }

        else if (b==4) {

            c = rand() %4+1;
            if (c==1)
                cpack[6] = rand() %0xFF+1;
            if (c==2)
                cpack[7] = rand() %0xFF+1;
            if (c==3) {
                cpack[6] = 0xFF;
                cpack[7] = 0xFF;
            }
            if (c==4) {
                cpack[6] = 0x00;
                cpack[7] = 0x00;
            }

        }

        else if (b==5) {

            c = rand() %4+1;
            if (c==1)
                cpack[8] = rand() %0xFF+1;
            if (c==2)
                cpack[9] = rand() %0xFF+1;
            if (c==3) {
                cpack[8] = 0xFF;
                cpack[9] = 0xFF;
            }
            if (c==4) {
                cpack[8] = 0x00;
                cpack[9] = 0x00;
            }
        }

        else {

            c = rand() %4+1;
            if (c==1)
                cpack[10] = rand() %0xFF+1;
            if (c==2)
                cpack[11] = rand() %0xFF+1;
            if (c==3) {
                cpack[10] = 0xFF;
                cpack[11] = 0xFF;
            }
            if (c==4) {
                cpack[10] = 0x00;
                cpack[11] = 0x00;
            }
        }
    }


    else if (a<200) {

        //fuzz one attribute within a single query:

        if (alen>1)
            b = rand() % alen;
        else
            b = 0;

        slen = strlen(qrs[b].name);
        aptr = plen[b];

        c = rand() % 10+1;

        if (c<5) {

                    rand_str_gen(name, (rand() % slen));
                    memcpy(&cpack[aptr], name, strlen(qrs[b].name));


        }

        else if (c<9) {

            d = rand() %10+1;

            if (d<4)
                cpack[aptr+slen+2] = rand() %61+1;
            if (d==4 || d==5)
                cpack[aptr+slen+1] = rand() %0xFF+1;
            if (d==6 || d==7 || d==8)
                cpack[aptr+slen+2] = rand() %0xFF+1;
            if (d==9) {
                cpack[aptr+slen+1] = 0xFF;
                cpack[aptr+slen+2] = 0xFF;
            }
            if (d==10) {
                cpack[aptr+slen+1] = 0x00;
                cpack[aptr+slen+2] = 0x00;
            }
        }

        else {

            d = rand() %4+1;

            if (d==1)
                cpack[aptr+slen+3] = rand() %0xFF+1;
            if (d==2)
                cpack[aptr+slen+4] = rand() %0xFF+1;
            if (d==3) {
                cpack[aptr+slen+3] = 0xFF;
                cpack[aptr+slen+4] = 0xFF;
            }
            if (d==4) {
                cpack[aptr+slen+3] = 0x00;
                cpack[aptr+slen+4] = 0x00;
            }
        }

    }


    else if (a<300) {
        //fuzz an attribute within multiple queries

        if (alen>=1) {

            e = rand() % alen+1;

            for (i = 1; i<e; i++) {

                if (alen>1)
                    b = rand() % alen;
                else
                    b = 0;

                slen = strlen(qrs[b].name);
                aptr = plen[b];


                c = rand() % 10+1;

                if (c<5) {

                    rand_str_gen(name, (rand() % slen));
                    memcpy(&cpack[aptr], name, strlen(qrs[b].name));

                }

                else if (c<9) {

                    d = rand() %10+1;

                    if (d<4)
                        cpack[aptr+slen+2] = rand() %61+1;
                    if (d==4 || d==5)
                        cpack[aptr+slen+1] = rand() %0xFF+1;
                    if (d==6 || d==7 || d==8)
                        cpack[aptr+slen+2] = rand() %0xFF+1;
                    if (d==9) {
                        cpack[aptr+slen+1] = 0xFF;
                        cpack[aptr+slen+2] = 0xFF;
                    }
                    if (d==10) {
                        cpack[aptr+slen+1] = 0x00;
                        cpack[aptr+slen+2] = 0x00;
                    }
                }

                else {

                    d = rand() %4+1;

                    if (d==1)
                        cpack[aptr+slen+3] = rand() %0xFF+1;
                    if (d==2)
                        cpack[aptr+slen+4] = rand() %0xFF+1;
                    if (d==3) {
                        cpack[aptr+slen+3] = 0xFF;
                        cpack[aptr+slen+4] = 0xFF;
                    }
                    if (d==4) {
                        cpack[aptr+slen+3] = 0x00;
                        cpack[aptr+slen+4] = 0x00;
                    }
                }
            }
        }
    }


    else {
        //fuzz both attribute and header


        b = rand() % 6+1;

        if (b == 1){

            c = rand() %3+1;

            if (c==1) {
                cpack[0] = 0xFF;
                cpack[1] = 0xFF;
            }
            if (c==2) {
                cpack[0] = 0x00;
                cpack[1] = 0x00;
            }
        }

        else if (b==2) {

            c = rand() %4+1;
            if (c==1)
                cpack[2] = rand() %0xFF+1;
            if (c==2)
                cpack[3] = rand() %0xFF+1;
            if (c==3) {
                cpack[2] = 0xFF;
                cpack[3] = 0xFF;
            }
            if (c==4) {
                cpack[2] = 0x00;
                cpack[3] = 0x00;
            }
        }

        else if (b==3) {

            c = rand() %4+1;
            if (c==1)
                cpack[4] = rand() %0xFF+1;
            if (c==2)
                cpack[5] = rand() %0xFF+1;
            if (c==3) {
                cpack[4] = 0xFF;
                cpack[5] = 0xFF;
            }
            if (c==4) {
                cpack[4] = 0x00;
                cpack[5] = 0x00;
            }

        }

        else if (b==4) {

            c = rand() %4+1;
            if (c==1)
                cpack[6] = rand() %0xFF+1;
            if (c==2)
                cpack[7] = rand() %0xFF+1;
            if (c==3) {
                cpack[6] = 0xFF;
                cpack[7] = 0xFF;
            }
            if (c==4) {
                cpack[6] = 0x00;
                cpack[7] = 0x00;
            }

        }

        else if (b==5) {

            c = rand() %4+1;
            if (c==1)
                cpack[8] = rand() %0xFF+1;
            if (c==2)
                cpack[9] = rand() %0xFF+1;
            if (c==3) {
                cpack[8] = 0xFF;
                cpack[9] = 0xFF;
            }
            if (c==4) {
                cpack[8] = 0x00;
                cpack[9] = 0x00;
            }
        }

        else {

            c = rand() %4+1;
            if (c==1)
                cpack[10] = rand() %0xFF+1;
            if (c==2)
                cpack[11] = rand() %0xFF+1;
            if (c==3) {
                cpack[10] = 0xFF;
                cpack[11] = 0xFF;
            }
            if (c==4) {
                cpack[10] = 0x00;
                cpack[11] = 0x00;
            }
        }

               if (alen>1)
            b = rand() % alen;
        else
            b = 0;

        slen = strlen(qrs[b].name);
        aptr = plen[b];

        c = rand() % 10+1;

        if (c<5) {

                    rand_str_gen(name, (rand() % slen));
                    memcpy(&cpack[aptr], name, strlen(qrs[b].name));

        }

        else if (c<9) {

            d = rand() %10+1;

            if (d<4)
                cpack[aptr+slen+2] = rand() %61+1;
            if (d==4 || d==5)
                cpack[aptr+slen+1] = rand() %0xFF+1;
            if (d==6 || d==7 || d==8)
                cpack[aptr+slen+2] = rand() %0xFF+1;
            if (d==9) {
                cpack[aptr+slen+1] = 0xFF;
                cpack[aptr+slen+2] = 0xFF;
            }
            if (d==10) {
                cpack[aptr+slen+1] = 0x00;
                cpack[aptr+slen+2] = 0x00;
            }
        }

        else {

            d = rand() %4+1;

            if (d==1)
                cpack[aptr+slen+3] = rand() %0xFF+1;
            if (d==2)
                cpack[aptr+slen+4] = rand() %0xFF+1;
            if (d==3) {
                cpack[aptr+slen+3] = 0xFF;
                cpack[aptr+slen+4] = 0xFF;
            }
            if (d==4) {
                cpack[aptr+slen+3] = 0x00;
                cpack[aptr+slen+4] = 0x00;
            }
        }
    }

}
