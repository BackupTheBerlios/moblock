/*
 * MoBlock.c - Morpheus' Blocker
 *
 * Copyright (C) 2004 Morpheus (ebutera at users.berlios.de)
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <libipq.h>
#include <signal.h>

#define MB_VERSION 0.2

#define BUFSIZE 2048
#define PAYLOADSIZE 21

#define IS_UDP (packet->payload[9] == 17)
#define IS_TCP (packet->payload[9] == 6)

#define SRC_ADDR (*(in_addr_t *)((packet->payload)+12))
#define DST_ADDR (*(in_addr_t *)((packet->payload)+16))

// rbt datatypes/functions

typedef enum {
    STATUS_OK,
    STATUS_MEM_EXHAUSTED,
    STATUS_DUPLICATE_KEY,
    STATUS_KEY_NOT_FOUND 
} statusEnum;
                
//typedef enum { BLACK, RED } nodeColor;

typedef unsigned long keyType;            /* type of key */
                
typedef struct {
    char blockname[50];                  /* data */
    unsigned long ipmax;
    int hits;
} recType;   

extern statusEnum find(keyType key, recType *rec);
extern statusEnum insert(keyType key, recType *rec);
extern void ll_show();
extern void ll_log();

// end of headers

static void die(struct ipq_handle *h)
{
	ipq_perror("myblock");
        ipq_destroy_handle(h);
        exit(-1);
}

char *ip2str(in_addr_t ip)
{
	static int bn = 0;
	static char buff[32][4];
	struct in_addr a;
	char *rtn;

	a.s_addr = ip;
	if (bn > 3) bn = 0;
	strcpy(buff[bn], inet_ntoa(a));
	rtn = buff[bn++];
	return rtn;
}

void print_addr( FILE *f, in_addr_t ip, int port )
{
	if (port == -1)
		fprintf(f, "%s:*", ip2str(ip));
	else
		fprintf(f, "%s:%d", ip2str(ip), port);
	fflush(stdout);
}

void ranged_insert(char *name,char *ipmin,char *ipmax)
{
    recType tmprec;
    int ret;

    strncpy(tmprec.blockname,name,50);		// 50 = recType.blockname lenght
    tmprec.ipmax=ntohl(inet_addr(ipmax));
    tmprec.hits=0;
    if ( (ret=insert(ntohl(inet_addr(ipmin)),&tmprec)) != STATUS_OK  )
        switch(ret) {
            case STATUS_MEM_EXHAUSTED:
                fprintf(stderr,"Error inserting range, MEM_EXHAUSTED.\n");
                break;
            case STATUS_DUPLICATE_KEY:
                fprintf(stderr,"Duplicated range ( %s )\n",name);
                break;
            default:
                fprintf(stderr,"Unexpected return value from ranged_insert()!\n");
                fprintf(stderr,"Return value was: %d\n",ret);
                break;
        }                
    //else printf("Inserted: %lu|%lu|\n",ntohl(inet_addr(ipmin)),tmprec.ipmax);
}


void loadlist(void)
{
	FILE *fp;
	ssize_t count;
	char *line = NULL;
        size_t len = 0;
	int ntot=0;
	char name[50],ipmin[16],ipmax[16];		// ! name lenght = recType.blockname lenght (rbt.h) !
	
	fp=fopen("/etc/guarding.p2p","r");
	if ( fp == NULL ) {
		fprintf(stderr,"Error opening /etc/guarding.p2p, aborting...\n");
		exit(-1);
	}
	while ( (count=getline(&line,&len,fp)) != -1 ) {
		if ( count > 10 )
		{
			strncpy(name,strtok(line,":"),50);		// !! with malformed guarding.p2p it segfaults !!
			strncpy(ipmin,strtok(NULL,"-"),16);
			strncpy(ipmax,strtok(NULL,"\n"),16);
			ranged_insert(name,ipmin,ipmax);
			ntot++;
		} else fprintf(stderr,"Short guarding.p2p line, skipping it...\n");
	}
	if (line)
		free(line);
	printf("Ranges loaded: %d\n",ntot);
}

void my_sahandler(int sig)
{
    switch( sig ) {
        case SIGUSR1:
            printf("Got SIGUSR1!\n");
            ll_show();
            break;
        case SIGUSR2:
            printf("Got SIGUSR2!\n");
            ll_log();
            break;
        default:
            fprintf(stderr,"Received signal = %d but not handled\n",sig);
            break;
    }
}

void init_sa()
{
    struct sigaction my_sa;
    
    my_sa.sa_handler=my_sahandler;
    my_sa.sa_flags=SA_RESTART;
    
    if ( sigaction(SIGUSR1,&my_sa,NULL) < 0 ) {
        perror("FATAL! Error setting signal handler for SIGUSR1\n");
        exit(-1);
    }
    if ( sigaction(SIGUSR2,&my_sa,NULL) < 0 ) {
        perror("FATAL! Error setting signal handler for SIGUSR2\n");
        exit(-1);
    }
}

int main(int argc, char **argv)
{
	int status=0;
        unsigned char buf[BUFSIZE];
        recType tmprec;        
        struct ipq_handle *h;
        ipq_packet_msg_t *packet;
	
	init_sa();	
	loadlist();
	
        h = ipq_create_handle(0, PF_INET);
        if (!h)
	        die(h);

        status = ipq_set_mode(h, IPQ_COPY_PACKET, PAYLOADSIZE);
        if (status < 0)
                die(h);
		
        do {
                status = ipq_read(h, buf, BUFSIZE, 0);
                if (status < 0)
                      die(h);

                switch (ipq_message_type(buf)) {
	                case NLMSG_ERROR:
        	                fprintf(stderr, "Received error message %d\n", ipq_get_msgerr(buf));
                                break;
 			case IPQM_PACKET:
//                                ipq_packet_msg_t *packet = ipq_get_packet(buf);
                                packet=ipq_get_packet(buf);				
				switch ( packet->hook ) {
                                    case NF_IP_LOCAL_IN:
                                           if ( find(ntohl(SRC_ADDR),&tmprec) == STATUS_OK ) {
                                               status=ipq_set_verdict(h,packet->packet_id,NF_DROP,0,NULL);
                                               fprintf(stdout,"Blocked IN: %s,hits: %d,SRC: %s\n",tmprec.blockname,tmprec.hits,ip2str(SRC_ADDR));
                                           } else status = ipq_set_verdict(h, packet->packet_id,NF_ACCEPT,0,NULL);
                                           break;
                                    case NF_IP_LOCAL_OUT:
                                           if ( find(ntohl(DST_ADDR),&tmprec) == STATUS_OK ) {
                                               status=ipq_set_verdict(h,packet->packet_id,NF_DROP,0,NULL);
                                               fprintf(stdout,"Blocked OUT: %s,hits: %d,DST: %s\n",tmprec.blockname,tmprec.hits,ip2str(DST_ADDR));
                                           } else status = ipq_set_verdict(h, packet->packet_id,NF_ACCEPT,0,NULL);
                                           break;
                                    default:
                                          fprintf(stderr,"Not NF_LOCAL_IN/OUT packet!\n");
                                          break;
                                }
                                if (status < 0)
                                    die(h);
                                break;
                        default:
                               fprintf(stderr, "Unknown message type!\n");
                               break;
                }
          } while (1);

          ipq_destroy_handle(h);
          return 0;
}
