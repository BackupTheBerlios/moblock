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
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include <signal.h>
#include <regex.h>

// in Makefile define LIBIPQ to use soon-to-be-deprecated ip_queue,
// NFQUEUE for ipt_NFQUEUE (from kernel 2.6.14)

#ifdef LIBIPQ
	#include <libipq.h>
#endif
#ifdef NFQUEUE
	#include <libnetfilter_queue/libnetfilter_queue.h>
#endif

#define MB_VERSION	"0.8"

#define BUFSIZE		2048
#define PAYLOADSIZE	21
#define BNAME_LEN	80

#define IS_UDP (packet->payload[9] == 17)
#define IS_TCP (packet->payload[9] == 6)

#define SRC_ADDR(payload) (*(in_addr_t *)((payload)+12))
#define DST_ADDR(payload) (*(in_addr_t *)((payload)+16))

// rbt datatypes/functions

typedef enum {
    STATUS_OK,
    STATUS_MEM_EXHAUSTED,
    STATUS_DUPLICATE_KEY,
    STATUS_KEY_NOT_FOUND,
	STATUS_MERGED,
	STATUS_SKIPPED
} statusEnum;
                
typedef unsigned long keyType;            /* type of key */
                
typedef struct {
    char blockname[BNAME_LEN];                  /* data */
    unsigned long ipmax;
    int hits;
} recType;   

extern statusEnum find(keyType key, recType *rec);
extern statusEnum find2(keyType key1, keyType key2, recType *rec);
extern statusEnum insert(keyType key, recType *rec);
extern void ll_show(FILE *logf);
extern void ll_log();
extern void ll_clear();
extern void destroy_tree();

// end of headers

FILE *logfile;
char *logfile_name=NULL;
const char* pidfile_name="/var/run/moblock.pid";

struct {			//holds list type and filename
	enum { LIST_DAT = 0, LIST_PG1, LIST_PG2} type;
	char filename[100];
} blocklist_info;

int merged_ranges=0, skipped_ranges=0;

#ifdef LIBIPQ
static void die(struct ipq_handle *h)
{
	ipq_perror("MoBlock");
        ipq_destroy_handle(h);
		exit(-1);
}
#endif

char *ip2str(in_addr_t ip)
{
	static char buf[2][ sizeof("aaa.bbb.ccc.ddd") ];
	static short int index=0;
	
	sprintf(buf[index],"%d.%d.%d.%d",
			(ip) & 0xff,
			(ip >> 8) & 0xff,
			(ip >> 16) & 0xff,
			(ip >> 24) & 0xff);
	
	if (index) {
		index=0;
		return buf[1];
	}
	else return buf[index++];
}

void print_addr( FILE *f, in_addr_t ip, int port )
{
	if (port == -1)
		fprintf(f, "%s:*", ip2str(ip));
	else
		fprintf(f, "%s:%d", ip2str(ip), port);
	fflush(stdout);
}

inline void ranged_insert(char *name,char *ipmin,char *ipmax)
{
    recType tmprec;
    int ret;

	if ( strlen(name) > (BNAME_LEN-1) ) {
		strncpy(tmprec.blockname, name, BNAME_LEN);
		tmprec.blockname[BNAME_LEN-1]='\0';	
	}
	else strcpy(tmprec.blockname,name);
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
			case STATUS_MERGED:
				merged_ranges++;
				break;
			case STATUS_SKIPPED:
				skipped_ranges++;
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
	printf("* Ranges loaded: %d\n",ntot);
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
	printf("* Ranges loaded: %d\n",ntot);
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
        sscanf(readbuf,"%hd.%hd.%hd.%hd - %hd.%hd.%hd.%hd ,", &ip1_0, &ip1_1, &ip1_2, &ip1_3,
                                                            &ip2_0, &ip2_1, &ip2_2, &ip2_3);
        name=readbuf+42;
        name[strlen(name)-2]='\0';		// strip ending \r\n
        sprintf(start_ip,"%d.%d.%d.%d",ip1_0, ip1_1, ip1_2, ip1_3);
        sprintf(end_ip,"%d.%d.%d.%d",ip2_0, ip2_1, ip2_2, ip2_3);
        ranged_insert(name, start_ip, end_ip);
        ntot++;
    }
    fclose(fp);
    fprintf(logfile,"Ranges loaded: %d\n",ntot);
	printf("* Ranges loaded: %d\n",ntot);
}

void reopen_logfile(void)
{
	if (logfile != NULL) {
        	fclose(logfile);
		logfile=NULL;
	}
	logfile=fopen(logfile_name,"a");
	if (logfile == NULL) {
		fprintf(stderr, "Unable to open logfile %s\n", logfile_name);
		exit(-1);
	}
	fprintf(logfile, "Reopening logfile.\n");
}

void my_sahandler(int sig)
{
	switch( sig ) {
        	case SIGUSR1:
			fprintf(logfile,"Got SIGUSR1! Dumping stats...\n");
			ll_show(logfile);
			reopen_logfile();
			break;
		case SIGUSR2:
			fprintf(logfile,"Got SIGUSR2! Dumping stats to /var/log/MoBlock.stats\n");
			ll_log();
			break;
		case SIGHUP:
			fprintf(logfile,"\nGot SIGHUP! Dumping and resetting stats, reloading blocklist\n\n");
			ll_log();
			ll_clear();		// clear stats list
			destroy_tree();		// clear loaded ranges
			switch (blocklist_info.type) {
				case LIST_DAT:
					loadlist_dat(blocklist_info.filename);
					break;
				case LIST_PG1:
					loadlist_pg1(blocklist_info.filename);
					break;
				case LIST_PG2:
					loadlist_pg2(blocklist_info.filename);
					break;
				default:
					fprintf(logfile,"Unknown blocklist type while reloading list, contact the developer!\n");
					break;
			}
			reopen_logfile();
			break;
		case SIGTERM:
			fprintf(logfile,"Got SIGTERM! Dumping stats and exiting.\n");
			ll_log();
			exit(0);
		default:
			fprintf(logfile,"Received signal = %d but not handled\n",sig);
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

#ifdef NFQUEUE
static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
						struct nfq_data *nfa, void *data)
{
	int id=0, status=0;
	struct nfqnl_msg_packet_hdr *ph;
	char *payload;
	recType tmprec;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
		nfq_get_payload(nfa, &payload);

		switch (ph->hook) {
			case NF_IP_LOCAL_IN:
				if ( find(ntohl(SRC_ADDR(payload)),&tmprec) == STATUS_OK ) {
					status=nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					fprintf(logfile,"Blocked IN: %s,hits: %d,SRC: %s\n",tmprec.blockname,tmprec.hits,ip2str(SRC_ADDR(payload)));
				} else status = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
				break;
			case NF_IP_LOCAL_OUT:
				if ( find(ntohl(DST_ADDR(payload)),&tmprec) == STATUS_OK ) {
					status=nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					fprintf(logfile,"Blocked OUT: %s,hits: %d,DST: %s\n",tmprec.blockname,tmprec.hits,ip2str(DST_ADDR(payload)));
				} else status = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
				break;
			case NF_IP_FORWARD:
				if ( find2(ntohl(SRC_ADDR(payload)), ntohl(DST_ADDR(payload)), &tmprec) == STATUS_OK ) {
					status=nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
					fprintf(logfile,"Blocked FWD: %s,hits: %d,SRC: %s, DST: %s\n",
								tmprec.blockname, tmprec.hits, ip2str(SRC_ADDR(payload)), ip2str(DST_ADDR(payload)));
					fflush(logfile);
				} else status = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
				break;
			default:
				fprintf(logfile,"Not NF_LOCAL_IN/OUT/FORWARD packet!\n");
				break;
		}
	}
	else {
		fprintf(logfile,"NFQUEUE: can't get msg packet header.\n");
		return(1);		// from nfqueue source: 0 = ok, >0 = soft error, <0 hard error
	}
	fflush(logfile);
	return(0);
}
#endif

short int netlink_loop(unsigned short int queuenum)
{
#ifdef LIBIPQ		//use old libipq interface, deprecated

	struct ipq_handle *h;
	ipq_packet_msg_t *packet;
	int status=0;
	unsigned char buf[BUFSIZE];
	recType tmprec;        
	
	h = ipq_create_handle(0, PF_INET);
	if (!h) die(h);

	status = ipq_set_mode(h, IPQ_COPY_PACKET, PAYLOADSIZE);
	if (status < 0) die(h);
		
	do {
		status = ipq_read(h, buf, BUFSIZE, 0);
		if (status < 0) die(h);

		switch (ipq_message_type(buf)) {
			case NLMSG_ERROR:
				fprintf(logfile, "Received error message %d\n", ipq_get_msgerr(buf));
				break;
			case IPQM_PACKET:
				packet=ipq_get_packet(buf);				
				switch ( packet->hook ) {
					case NF_IP_LOCAL_IN:
						if ( find(ntohl(SRC_ADDR(packet->payload)),&tmprec) == STATUS_OK ) {
							status=ipq_set_verdict(h,packet->packet_id,NF_DROP,0,NULL);
							fprintf(logfile,"Blocked IN: %s,hits: %d,SRC: %s\n",tmprec.blockname,tmprec.hits,ip2str(SRC_ADDR(packet->payload)));
							fflush(logfile);
						} else status = ipq_set_verdict(h, packet->packet_id,NF_ACCEPT,0,NULL);
						break;
					case NF_IP_LOCAL_OUT:
						if ( find(ntohl(DST_ADDR(packet->payload)),&tmprec) == STATUS_OK ) {
							status=ipq_set_verdict(h,packet->packet_id,NF_DROP,0,NULL);
							fprintf(logfile,"Blocked OUT: %s,hits: %d,DST: %s\n",tmprec.blockname,tmprec.hits,ip2str(DST_ADDR(packet->payload)));
							fflush(logfile);
						} else status = ipq_set_verdict(h, packet->packet_id,NF_ACCEPT,0,NULL);
						break;
					case NF_IP_FORWARD:
						if ( find2(ntohl(SRC_ADDR(packet->payload)), ntohl(DST_ADDR(packet->payload)), &tmprec) == STATUS_OK ) {
							status=ipq_set_verdict(h,packet->packet_id,NF_DROP,0,NULL);
							fprintf(logfile,"Blocked FWD: %s,hits: %d,SRC: %s, DST: %s\n",
										tmprec.blockname, tmprec.hits, ip2str(SRC_ADDR(packet->payload)), ip2str(DST_ADDR(packet->payload)));
							fflush(logfile);
						} else status = ipq_set_verdict(h, packet->packet_id,NF_ACCEPT,0,NULL);
						break;
					default:
						fprintf(logfile,"Not NF_LOCAL_IN/OUT/FORWARD packet!\n");
						break;
				}
				if (status < 0) die(h);
				break;
			default:
				fprintf(logfile, "Unknown message type!\n");
				break;
                }
	} while (1);

	ipq_destroy_handle(h);
	return 0;
#endif

#ifdef NFQUEUE		// use new NFQUEUE interface ( from kernel 2.6.14 )

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd,rv;
	char buf[BUFSIZE];

	h = nfq_open();
	if (!h) {
		fprintf(logfile, "Error during nfq_open()\n");
		exit(-1);
	}

	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(logfile, "error during nfq_unbind_pf()\n");
		exit(-1);
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(logfile, "Error during nfq_bind_pf()\n");
		exit(-1);
	}

	fprintf(logfile,"NFQUEUE: binding to queue '%hd'\n", queuenum);
	qh = nfq_create_queue(h,  queuenum, &nfqueue_cb, NULL);
	if (!qh) {
		fprintf(logfile, "error during nfq_create_queue()\n");
		exit(-1);
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, PAYLOADSIZE) < 0) {
		fprintf(logfile, "can't set packet_copy mode\n");
		exit(-1);
	}

	nh = nfq_nfnlh(h);
	fd = nfnl_fd(nh);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		nfq_handle_packet(h, buf, rv);
	}

	printf("NFQUEUE: unbinding from queue 0\n");
	nfq_destroy_queue(qh);
	nfq_close(h);
	return(0);
#endif

}

void print_options(void)
{
	printf("\nMoBlock %s by Morpheus",MB_VERSION);
	printf("\nSyntax: MoBlock -dnp <blocklist> [-b] [-q 0-65535] <logfile>\n\n");
	printf("\t-d\tblocklist is an ipfilter.dat file\n");
	printf("\t-n\tblocklist is a peerguardian 2.x file (.p2b)\n");
	printf("\t-p\tblocklist is a peerguardian file (.p2p)\n");
	printf("\t-q\t0-65535 NFQUEUE number (as specified in --queue-num with iptables)\n");
}

void on_quit()
{
	unlink(pidfile_name);
}

int main(int argc, char **argv)
{
	int ret=0;
	unsigned short int queuenum=0;

	if (argc < 3) {
		print_options();
		exit(-1);
	}
	if (access(pidfile_name,F_OK)==0) {
		fprintf(stderr,"pid file %s exists. Not starting",pidfile_name);
		exit(-1);
	}
	else {		//create pidfile
		FILE *pid_file;
		pid_t pid=getpid();
		pid_file=fopen(pidfile_name,"w");
		if (pid_file == NULL) {
			fprintf(stderr, "Unable to create pid_file\n");
			exit(-1);
		}
		fprintf(pid_file,"%i\n",pid);
		fclose(pid_file);
	}
	
	ret=atexit(on_quit);
	if ( ret ) {
		fprintf(stderr,"Cannot register exit function, terminating.\n");
		exit(-1);
	}

	init_sa();
	logfile=fopen(argv[argc-1],"a");
	if (logfile == NULL) {
	    fprintf(stderr, "Unable to open logfile %s\n", argv[argc-1]);
	    exit(-1);
	}
	logfile_name=malloc(strlen(argv[argc-1])+1);
	strcpy(logfile_name,argv[argc-1]);
	printf("* Logging to %s\n",logfile_name);
	
	while (1) {		//scan command line options
		ret=getopt(argc, argv, "d:n:p:q:");
		if ( ret == -1 ) break;
		
		switch (ret) {
			case 'd':			// ipfilter.dat file format
				loadlist_dat(optarg);
				blocklist_info.type=LIST_DAT;
				strcpy(blocklist_info.filename,optarg);
				printf("* Using .dat file format\n");
				break;
			case 'n':			// peerguardian 2.x file format .p2b
				loadlist_pg2(optarg);
				blocklist_info.type=LIST_PG2;
				strcpy(blocklist_info.filename,optarg);
				printf("* Using .p2b file format\n");
				break;
			case 'p':			// peerguardian file format .p2p
				loadlist_pg1(optarg);
				blocklist_info.type=LIST_PG1;
				strcpy(blocklist_info.filename,optarg);
				printf("* Using .p2p file format\n");
				break;
			case 'q':
				queuenum=(unsigned short int)atoi(optarg);
				break;
			case '?':			// unknown option
				print_options();
				exit(-1);
				break;
		}
	}
	
	printf("* Merged ranges: %d\n", merged_ranges);
	fprintf(logfile, "Merged ranges: %d\n", merged_ranges);
	printf("* Skipped useless ranges: %d\n", skipped_ranges);
	fprintf(logfile,"Skipped useless ranges: %d\n", skipped_ranges);
	fflush(NULL);

	netlink_loop(queuenum);
	exit(0);
}
