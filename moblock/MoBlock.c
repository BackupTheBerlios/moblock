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
#include <regex.h>

#define MB_VERSION	"0.4"

#define BUFSIZE		2048
#define PAYLOADSIZE	21

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
                
typedef unsigned long keyType;            /* type of key */
                
typedef struct {
    char blockname[60];                  /* data */
    unsigned long ipmax;
    int hits;
} recType;   

extern statusEnum find(keyType key, recType *rec);
extern statusEnum insert(keyType key, recType *rec);
extern void ll_show(FILE *logf);
extern void ll_log();

// end of headers

static FILE* logfile;

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

    strncpy(tmprec.blockname,name,60);		// 60 = recType.blockname lenght
    tmprec.ipmax=ntohl(inet_addr(ipmax));
    tmprec.hits=0;
    if ( (ret=insert(ntohl(inet_addr(ipmin)),&tmprec)) != STATUS_OK  )
        switch(ret) {
            case STATUS_MEM_EXHAUSTED:
                fprintf(logfile,"Error inserting range, MEM_EXHAUSTED.\n");
                break;
            case STATUS_DUPLICATE_KEY:
                fprintf(logfile,"Duplicated range ( %s )\n",name);
                break;
            default:
                fprintf(logfile,"Unexpected return value from ranged_insert()!\n");
                fprintf(logfile,"Return value was: %d\n",ret);
                break;
        }                
}


void loadlist_pg1(char* filename)
{
	FILE *fp;
	ssize_t count;
	char *line = NULL;
        size_t len = 0;
	int ntot=0;
	regex_t regmain;
	regmatch_t matches[4];
	int i;

	regcomp(&regmain, "^(.*)[:]([0-9.]*)[-]([0-9.]*)$", REG_EXTENDED);

	fp=fopen(filename,"r");
	if ( fp == NULL ) {
		fprintf(logfile,"Error opening %s, aborting...\n", filename);
		exit(-1);
	}
	while ( (count=getline(&line,&len,fp)) != -1 ) {
		for(i=count-1; i>=0; i--) {
			if ((line[i] == '\r') || (line[i] == '\n') || (line[i] == ' ')) {
				line[i] = 0;
			} else {
				break;
			}
		}
	   
		if (strlen(line) == 0)
			continue;

		if (!regexec(&regmain, line, 4, matches, 0)) {
			line[matches[1].rm_eo] = 0;
			line[matches[2].rm_eo] = 0;
			line[matches[3].rm_eo] = 0;

			ranged_insert(line+matches[1].rm_so, 
				      line+matches[2].rm_so, 
				      line+matches[3].rm_so);
			ntot++;
		} else {
			fprintf(logfile,"Short guarding.p2p line %s, skipping it...\n", line);
		}
	}
	if (line)
		free(line);
	fclose(fp);
	fprintf(logfile,"Ranges loaded: %d\n",ntot);
	fflush(logfile);
}

void loadlist_pg2(char *filename)		// experimental, no check for list sanity
{
    FILE *fp;
    int i,retval,ntot=0;
    char name[100],ipmin[16];			// hope we don't have a list with longer names...
    uint32_t start_ip, end_ip;
    struct in_addr startaddr,endaddr;

    fp=fopen(filename,"r");
    if ( fp == NULL ) {
        fprintf(logfile,"Error opening %s, aborting...\n", filename);
        exit(-1);
    }
                                        
    fgetc(fp);					// skip first 4 bytes, don't know what they are
    fgetc(fp);
    fgetc(fp);
    retval=fgetc(fp);

    while ( retval != EOF ) {
        i=0;
        do {
            name[i]=fgetc(fp);
            i++;
        } while ( name[i-1] != 0x00 && name[i-1] != EOF);
        if ( name[i-1] != EOF ) {
            name[i-1]='\0';
            fread(&start_ip,4,1,fp);
            fread(&end_ip,4,1,fp);
            startaddr.s_addr=start_ip;
            endaddr.s_addr=end_ip;
            strcpy(ipmin,inet_ntoa(startaddr));
            ranged_insert(name,ipmin,inet_ntoa(endaddr));
            ntot++;
        }
        else {
            retval=EOF;
        }
    }
    fclose(fp);
    fprintf(logfile,"Ranges loaded: %d\n",ntot);
    fflush(logfile);
}

void loadlist_dat(char *filename)
{
    FILE *fp;
    int ntot=0;
    char readbuf[200], *name, start_ip[16], end_ip[16];
    unsigned short ip1_0, ip1_1, ip1_2, ip1_3, ip2_0, ip2_1, ip2_2, ip2_3;
    
    fp=fopen(filename,"r");
    if ( fp == NULL ) {
        fprintf(logfile,"Error opening %s, aborting...\n", filename);
        exit(-1);
    }
    
    while ( fgets(readbuf,200,fp) != NULL ) {
        if ( readbuf[0] == '#') continue;		// comment line, skip
        sscanf(readbuf,"%hd.%hd.%hd.%hd - %hd.%hd.%hd.%hd", &ip1_0, &ip1_1, &ip1_2, &ip1_3,
                                                            &ip2_0, &ip2_1, &ip2_2, &ip2_3);
        name=readbuf+42;
        name[strlen(name)-1]='\0';		// strip ending \n
        sprintf(start_ip,"%d.%d.%d.%d",ip1_0, ip1_1, ip1_2, ip1_3);
        sprintf(end_ip,"%d.%d.%d.%d",ip2_0, ip2_1, ip2_2, ip2_3);
        ranged_insert(name, start_ip, end_ip);
        ntot++;
    }
    fclose(fp);
    fprintf(logfile,"Ranges loaded: %d\n",ntot);
    fflush(logfile);                                        
}

void my_sahandler(int sig)
{
    switch( sig ) {
        case SIGUSR1:
            fprintf(logfile,"Got SIGUSR1! Dumping stats...\n");
            ll_show(logfile);
            break;
        case SIGUSR2:
            fprintf(logfile,"Got SIGUSR2! Dumping stats to /var/log/MoBlock.stats\n");
            ll_log();
            break;
        case SIGHUP:
            fprintf(logfile,"Got SIGHUP! Dumping stats and exiting.\n");
            ll_log();
            exit(0);
         case SIGTERM:
            fprintf(logfile,"Got SIGTERM! Dumping stats and exiting.\n");
            ll_log();
            exit(0);
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
    if ( sigaction(SIGHUP,&my_sa,NULL) < 0 ) {
        perror("FATAL! Error setting signal handler for SIGHUP\n");
        exit(-1);
    }
    if ( sigaction(SIGTERM,&my_sa,NULL) < 0 ) {
        perror("FATAL! Error setting signal handler for SIGTERM\n");
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

	if (argc < 3) {
	        fprintf(stderr, "\nMoBlock %s",MB_VERSION);
		fprintf(stderr, "\nSyntax: MoBlock [-dn] <blocklist> <logfile>\n\n");
		fprintf(stderr, "\t-d\tblocklist is an ipfilter.dat file\n");
		fprintf(stderr, "\t-n\tblocklist is a peerguardian 2.x file (.p2b)\n\n");
		exit(1);
	}

	if (argc == 3 )
	    logfile = fopen(argv[2], "a");
        else logfile = fopen(argv[3], "a");
        
        if (logfile == NULL) {
	    fprintf(stderr, "Unable to open logfile %s\n", argv[2]);
	    exit(-1);
        }
   
	init_sa();	
	
	if ( !strcmp(argv[1],"-d") )	// ipfilter.dat file format
	    loadlist_dat(argv[2]);
        else if ( !strcmp(argv[1],"-n")	)	// peerguardian 2.x file format
                  loadlist_pg2(argv[2]);
             else loadlist_pg1(argv[1]);	// no -dn options
	
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
                                packet=ipq_get_packet(buf);				
				switch ( packet->hook ) {
                                    case NF_IP_LOCAL_IN:
                                           if ( find(ntohl(SRC_ADDR),&tmprec) == STATUS_OK ) {
                                               status=ipq_set_verdict(h,packet->packet_id,NF_DROP,0,NULL);
                                               fprintf(logfile,"Blocked IN: %s,hits: %d,SRC: %s\n",tmprec.blockname,tmprec.hits,ip2str(SRC_ADDR));
                                               fflush(logfile);
                                           } else status = ipq_set_verdict(h, packet->packet_id,NF_ACCEPT,0,NULL);
                                           break;
                                    case NF_IP_LOCAL_OUT:
                                           if ( find(ntohl(DST_ADDR),&tmprec) == STATUS_OK ) {
                                               status=ipq_set_verdict(h,packet->packet_id,NF_DROP,0,NULL);
                                               fprintf(logfile,"Blocked OUT: %s,hits: %d,DST: %s\n",tmprec.blockname,tmprec.hits,ip2str(DST_ADDR));
                                               fflush(logfile);
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
