/*
 * ifstat.c	handy utility to read net interface statistics
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 * Reduced and rewritten for mortals and forked to ifstat2
 *              Robert Olsson <robert.olsson@its.uu.se>
 *
 */

#define VERSION "0.26-040315"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <fnmatch.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <math.h>

#include "libnetlink.h"
#include <linux/netdevice.h>

int scan_interval = 0;
int min_interval = 20;
int time_constant = 0;
int show_errors = 0;
int show_rtstat = 0;

double W;
char **patterns;
int npatterns;

char info_source[128];

/* Keep in sync */

struct net_device_rtstats
{
        unsigned long   in_hit;                 /* cache hits */
        unsigned long   in_slow;                /* slow path */
        unsigned long   in_slow_mc;             /* slow multicast*/
        unsigned long   in_hlist_search;        /* hash search */
};


#define MAXS (sizeof(struct net_device_stats)/sizeof(unsigned long))
#define RTMAXS (sizeof(struct net_device_rtstats)/sizeof(unsigned long))


struct ifstat_ent
{
	struct ifstat_ent	*next;
	char			*name;
	int			ifindex;
	unsigned long long	val[MAXS];
	double			rate[MAXS];
};

struct rtstat_ent
{
	struct rtstat_ent	*next;
	char			*name;
	int			ifindex;
	unsigned long	        ival[RTMAXS];
};

struct ifstat_ent *kern_db;
struct rtstat_ent *rtstat_db;

int ewma;
int overflow;

int match(char *id)
{
	int i;

	if (npatterns == 0)
		return 1;

	for (i=0; i<npatterns; i++) {
		if (!fnmatch(patterns[i], id, 0))
			return 1;
	}
	return 0;
}

int get_netstat_nlmsg(struct sockaddr_nl *who, struct nlmsghdr *m, void *arg)
{
	struct ifinfomsg *ifi = NLMSG_DATA(m);
	struct rtattr * tb[IFLA_MAX+1];
	int len = m->nlmsg_len;
	struct ifstat_ent *n;
	unsigned long ival[MAXS];
	int i;

	if (m->nlmsg_type != RTM_NEWLINK)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		return -1;

	if (!(ifi->ifi_flags&IFF_UP))
		return 0;

	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (tb[IFLA_IFNAME] == NULL || tb[IFLA_STATS] == NULL)
		return 0;

	n = malloc(sizeof(*n));
	if (!n)
		abort();
	n->ifindex = ifi->ifi_index;
	n->name = strdup(RTA_DATA(tb[IFLA_IFNAME]));
	memcpy(&ival, RTA_DATA(tb[IFLA_STATS]), sizeof(ival));
	for (i=0; i<MAXS; i++) {

#undef DO_L2_STATS
#ifdef DO_L2_STATS

		if(i == 2) n->ival[i] = n->ival[i]+4; /* RX CRC */
		if(i == 3) n->ival[i] = n->ival[i]+18; /* TX 14+4 E-hdr + CRC */
#endif
		n->val[i] = ival[i];
	}
	n->next = kern_db;
	kern_db = n;
	return 0;
}

int get_rtstat_nlmsg(struct sockaddr_nl *who, struct nlmsghdr *m, void *arg)
{
#ifndef IFLA_RTSTATS
		return -1;
#else
	struct ifinfomsg *ifi = NLMSG_DATA(m);
	struct rtattr * tb[IFLA_MAX+1];
	int len = m->nlmsg_len;
	struct rtstat_ent *n;
	unsigned long ival[RTMAXS];
	int i;

	if (m->nlmsg_type != RTM_NEWLINK)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		return -1;

	if (!(ifi->ifi_flags&IFF_UP))
		return 0;


	memset(tb, 0, sizeof(tb));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (tb[IFLA_IFNAME] == NULL || tb[IFLA_RTSTATS] == NULL)
		return 0;

	n = malloc(sizeof(*n));
	if (!n)
		abort();
	n->ifindex = ifi->ifi_index;
	n->name = strdup(RTA_DATA(tb[IFLA_IFNAME]));

	memcpy(&ival, RTA_DATA(tb[IFLA_RTSTATS]), sizeof(ival));

	for (i=0; i<RTMAXS; i++) {
		n->ival[i] = ival[i];
	}

	n->next = rtstat_db;
	rtstat_db = n;


	return 0;
#endif
}

void load_info(void)
{
	struct ifstat_ent *db, *n;
	struct rtnl_handle rth;

	if (rtnl_open(&rth, 0) < 0)
		exit(1);

	if (rtnl_wilddump_request(&rth, AF_INET, RTM_GETLINK) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(&rth, get_netstat_nlmsg, NULL, NULL, NULL) < 0) {
		fprintf(stderr, "Dump terminated\n");
		exit(1);
	}

	rtnl_close(&rth);

	db = kern_db;
	kern_db = NULL;

	while (db) {
		n = db;
		db = db->next;
		n->next = kern_db;
		kern_db = n;
	}
}


void load_rtinfo(void)
{
	struct rtstat_ent *db, *n;
	struct rtnl_handle rth;

	if (rtnl_open(&rth, 0) < 0)
		exit(1);

	if (rtnl_wilddump_request(&rth, AF_INET, RTM_GETLINK) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	if (rtnl_dump_filter(&rth, get_rtstat_nlmsg, NULL, NULL, NULL) < 0) {
			fprintf(stderr, "Dump terminated\n");
			exit(1);
	}
	rtnl_close(&rth);

	/*  make ifindex order */

	db = rtstat_db;
	rtstat_db = NULL;

	while (db) {
		n = db;
		db = db->next;
		n->next = rtstat_db;
		rtstat_db = n;
	}
}


/* 
   Read data from unix socket 
*/

void load_raw_table(FILE *fp)
{
	char buf[4096];
	struct ifstat_ent *db = NULL;
	struct ifstat_ent *n;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *p;
		char *next;
		int i;

		if (buf[0] == '#') {
			buf[strlen(buf)-1] = 0;
			strncpy(info_source, buf+1, sizeof(info_source)-1);
			continue;
		}
		if ((n = malloc(sizeof(*n))) == NULL)
			abort();

		if (!(p = strchr(buf, ' ')))
			abort();
		*p++ = 0;

		if (sscanf(buf, "%d", &n->ifindex) != 1)
			abort();
		if (!(next = strchr(p, ' ')))
			abort();
		*next++ = 0;

		n->name = strdup(p);
		p = next;

		for (i=0; i<MAXS; i++) {
			unsigned rate;
			if (!(next = strchr(p, ' ')))
				abort();
			*next++ = 0;
			if (sscanf(p, "%llu", n->val+i) != 1)
				abort();

			p = next;
			if (!(next = strchr(p, ' ')))
				abort();
			*next++ = 0;
			if (sscanf(p, "%u", &rate) != 1)
				abort();
			n->rate[i] = rate;
			p = next;
		}
		n->next = db;
		db = n;
	}

	while (db) {
		n = db;
		db = db->next;
		n->next = kern_db;
		kern_db = n;
	}
}

/* 
   Write data to socket 
*/

void dump_raw_db(FILE *fp)
{
	struct ifstat_ent *n;

	fprintf(fp, "#ovrf=%d EWMA=%d client-pid=%u -- %s\n", 
		overflow, ewma, getpid(), info_source);

	for (n=kern_db; n; n=n->next) {
		int i;

		fprintf(fp, "%d %s ", n->ifindex, n->name);
		for (i=0; i<MAXS; i++)
			fprintf(fp, "%llu %u ", n->val[i], (unsigned)n->rate[i]);
		fprintf(fp, "\n");
	}
}

void format_rate(FILE *fp, struct ifstat_ent *n, int i)
{
	char temp[64];
	if (n->val[i] > 1024*1024*1024)
		fprintf(fp, "%7lluM ", n->val[i]/(1024*1024));
	else if (n->val[i] > 1024*1024)
		fprintf(fp, "%7lluK ", n->val[i]/1024);
	else
		fprintf(fp, "%8llu ", n->val[i]);

	if (n->rate[i] > 1024*1024) {
		sprintf(temp, "%uM", (unsigned)(n->rate[i]/(1024*1024)));
		fprintf(fp, "%-6s ", temp);
	} else if (n->rate[i] > 1024) {
		sprintf(temp, "%uK", (unsigned)(n->rate[i]/1024));
		fprintf(fp, "%-6s ", temp);
	} else
		fprintf(fp, "%-6u ", (unsigned)n->rate[i]);
}

void print_head(FILE *fp)
{

	if(!show_errors) {
		fprintf(fp, "%42s", "RX --------------------------");	
		fprintf(fp, "%-30s\n", "   TX --------------------------");
		return;
	}

	fprintf(fp, "#%s\n", info_source);
	fprintf(fp, "%-15s ", "Interface");

	fprintf(fp, "%8s/%-6s ", "RX Pkts", "Rate");
	fprintf(fp, "%8s/%-6s ", "TX Pkts", "Rate");
	fprintf(fp, "%8s/%-6s ", "RX Data", "Rate");
	fprintf(fp, "%8s/%-6s\n","TX Data", "Rate");

	fprintf(fp, "%-15s ", "");
	fprintf(fp, "%8s/%-6s ", "RX Errs", "Rate");
	fprintf(fp, "%8s/%-6s ", "RX Drop", "Rate");
	fprintf(fp, "%8s/%-6s ", "RX Over", "Rate");
	fprintf(fp, "%8s/%-6s\n","RX Leng", "Rate");

	fprintf(fp, "%-15s ", "");
	fprintf(fp, "%8s/%-6s ", "RX Crc", "Rate");
	fprintf(fp, "%8s/%-6s ", "RX Frm", "Rate");
	fprintf(fp, "%8s/%-6s ", "RX Fifo", "Rate");
	fprintf(fp, "%8s/%-6s\n","RX Miss", "Rate");
	
	fprintf(fp, "%-15s ", "");
	fprintf(fp, "%8s/%-6s ", "TX Errs", "Rate");
	fprintf(fp, "%8s/%-6s ", "TX Drop", "Rate");
	fprintf(fp, "%8s/%-6s ", "TX Coll", "Rate");
	fprintf(fp, "%8s/%-6s\n","TX Carr", "Rate");

	fprintf(fp, "%-15s ", "");
	fprintf(fp, "%8s/%-6s ", "TX Abrt", "Rate");
	fprintf(fp, "%8s/%-6s ", "TX Fifo", "Rate");
	fprintf(fp, "%8s/%-6s ", "TX Hear", "Rate");
	fprintf(fp, "%8s/%-6s\n","TX Wind", "Rate");
}

void nformat_rate(FILE *fp, double x)
{
	char temp[64];
	unsigned long i = x;

        if (i > 1000*1000)
		sprintf(temp, "%7lu M", i/(1000*1000));
        else if (i > 5*1000)
		sprintf(temp, "%7lu k", i/(1000));
        else
		sprintf(temp, "%7lu  ", i);

	fprintf(fp, "%10s %s", temp, "pps ");
}

void nformat_bits(FILE *fp, double d)
{
	char temp[64];


	/*
	  IEC standard 1998
	  kbit = 1000 bits
	  Mbit = 10^6 bits
	  Gbit = 10^9 bits
	*/


        if (d > 128*1000) 
		sprintf(temp, "%3.1f M", d/(128*1000));

        else if (d > 128) 
		sprintf(temp, "%3.1f k", d/128);
        else 
		sprintf(temp, "%4.0f  ", d*8);

	fprintf(fp, "%10s %s", temp, "bit/s ");
}


void print_one_if(FILE *fp, struct ifstat_ent *n)
{
	int i;

	if(!show_errors) {

		fprintf(fp, "%-10s ", n->name);
		nformat_bits(fp, n->rate[2]);
		nformat_rate(fp, n->rate[0]);
		nformat_bits(fp, n->rate[3]);
		nformat_rate(fp, n->rate[1]);
		
		fprintf(fp, "%s", "\n");
		
		return;
	}  


	fprintf(fp, "%-15s ", n->name);
	for (i=0; i<4; i++)
		format_rate(fp, n, i);
	fprintf(fp, "\n");

	fprintf(fp, "%-15s ", "");
	format_rate(fp, n, 4);
	format_rate(fp, n, 6);
	format_rate(fp, n, 11);
	format_rate(fp, n, 10);
	fprintf(fp, "\n");

	fprintf(fp, "%-15s ", "");
	format_rate(fp, n, 12);
	format_rate(fp, n, 13);
	format_rate(fp, n, 14);
	format_rate(fp, n, 15);
	fprintf(fp, "\n");
	
	fprintf(fp, "%-15s ", "");
	format_rate(fp, n, 5);
	format_rate(fp, n, 7);
	format_rate(fp, n, 9);
	format_rate(fp, n, 17);
	fprintf(fp, "\n");
	
	fprintf(fp, "%-15s ", "");
	format_rate(fp, n, 16);
	format_rate(fp, n, 18);
	format_rate(fp, n, 19);
	format_rate(fp, n, 20);
	fprintf(fp, "\n");
}


void dump_kern_db(FILE *fp)
{
	struct ifstat_ent *n;


	print_head(fp);

	for (n=kern_db; n; n=n->next) {
		if (!match(n->name))
			continue;
		print_one_if(fp, n);
	}
}

static int children;

void sigchild(int signo)
{
}

void update_db(int interval)
{
	struct ifstat_ent *n, *is_new, *ns;

	
	n = kern_db;
	kern_db = NULL;

	load_info();

	is_new = kern_db; 
	kern_db = n;

	/* 
	   Update current as template to detect any
	   new or removed devs.
	*/
	for (ns = is_new; ns; ns = ns->next) {

		if(!scan_interval) 
			abort();

		for (n = kern_db; n; n = n->next) {
			if (ns->ifindex == n->ifindex) {
				int i;

				for (i = 0; i < MAXS; i++) { 
					unsigned long long diff;
					double sample;

					/* Handle one overflow correctly */

					if( ns->val[i] < n->val[i] ) {
						diff = (0xFFFFFFFF - n->val[i]) + ns->val[i]; 
						overflow++;
					}
					else 
						diff = ns->val[i] - n->val[i];

//					ns->ival[i] = n->ival[i]; /* For overflow check */
//					ns->val[i]  = n->val[i];

					if(interval <= min_interval) {
						ewma = -11;
						ns->rate[i] = n->rate[i];
						goto done;
					}
					
					/* Calc rate */
					
					sample = (double)(diff*1000)/interval;

                                        if (interval >= scan_interval) {
                                                ns->rate[i] =  n->rate[i]+ W*(sample-n->rate[i]);
						ewma = 1;
                                        } else if (interval >= 1000) {
                                                if (interval >= time_constant) {
                                                        ns->rate[i] = sample;
							ewma = 2;
                                                } else {
                                                        double w = W*(double)interval/scan_interval;
                                                        ns->rate[i] = n->rate[i] + w*(sample-n->rate[i]);
							ewma = 3;
                                                }
                                        }
				done:;
				}

				/* Remove old table */

				while (kern_db != n) {
					struct ifstat_ent *tmp = kern_db;
					kern_db = kern_db->next;
					free(tmp->name);
					free(tmp);
				};
				kern_db = n->next;
				free(n->name);
				free(n);
				break;
			}
		}
	}	
	kern_db = is_new; /* The most recent devs from rt_netlink */
}

#define T_DIFF(a,b) (((a).tv_sec-(b).tv_sec)*1000 + ((a).tv_usec-(b).tv_usec)/1000)

void server_loop(int fd)
{
	struct timeval snaptime;
	struct pollfd p;

	p.fd = fd;
	p.events = p.revents = POLLIN;

	load_info();

	for (;;) {
		int status;
		int tdiff;
		struct timeval now;

		sprintf(info_source, "pid=%d sampling_interval=%d time_const=%d",
			getpid(), scan_interval/1000, time_constant/1000);



		gettimeofday(&now, NULL);
		tdiff = T_DIFF(now, snaptime);

//		if (tdiff >= 0) { 
			update_db(tdiff);
			snaptime = now;
			tdiff = 0;
//		}
		if (poll(&p, 1, scan_interval-tdiff) > 0
		    && (p.revents&POLLIN)) {
			int clnt = accept(fd, NULL, NULL);

			if (clnt >= 0) {
				pid_t pid;

				/*
				  Wee assume forking will be ok
				  so update database here not
				  have races with forked process
				*/

				gettimeofday(&now, NULL);
				tdiff = T_DIFF(now, snaptime);
//				if (tdiff >= min_interval) {
					update_db(tdiff);
					snaptime = now;
					tdiff = 0;
//				}
				if (children >= 5) {
					close(clnt);
				} else if ((pid = fork()) != 0) {

					if (pid>0) 
						children++;
					close(clnt);
				} else {
					FILE *fp = fdopen(clnt, "w");
					if (fp) {
						/* Write on clients socket */
						dump_raw_db(fp);
					}
					exit(0);
				}
			}
		}
		while (children && waitpid(-1, &status, WNOHANG) > 0)
			children--;
	}
}

int verify_forging(int fd)
{
	struct ucred cred;
	int olen = sizeof(cred);
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, (void*)&cred, &olen) ||
	    olen < sizeof(cred))
		return -1;
	if (cred.uid == getuid() || cred.uid == 0)
		return 0;
	return -1;
}


void dump_rtstat_db(FILE *fp)
{
	struct rtstat_ent *n;

	load_rtinfo();

	fprintf(fp, "%-15s ", "Interface");
	fprintf(fp, "%-10s ", "  in_hit");
	fprintf(fp, "%-10s ", " in_slow");
	fprintf(fp, "%-10s ", "in_slow_mc");
	fprintf(fp, "%-10s ", "h_search");
	fprintf(fp, "%s", "\n");

	for (n=rtstat_db; n; n=n->next) {
		if (!match(n->name))
			continue;

		fprintf(fp, "%-13s ", n->name);

		fprintf(fp, "%10lu %10lu %10lu %10lu\n", 
			n->ival[0], n->ival[1], n->ival[2], n->ival[3]);
	}
}

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
        fprintf(stderr,
"Usage: ifstat2 [ -h?vVzrnasd:t: ] [ PATTERN [ PATTERN ] ]\n"
                );

        fprintf(stderr, " client options:\n");
        fprintf(stderr, "  -e extended statistics\n");
        fprintf(stderr, "  -v print version\n");
        fprintf(stderr, "  -h this help\n");

        fprintf(stderr, " daemon options;\n");
        fprintf(stderr, "  -d SECS -- scan interval in SECS seconds and daemonize\n");
        fprintf(stderr, "  -t SECS -- time constant for average calc [60] (t>d)\n");

        exit(-1);
}

int main(int argc, char *argv[])
{
	struct sockaddr_un sun;
	int ch;
	int fd;

	while ((ch = getopt(argc, argv, "h?vVd:t:er")) != EOF) {
		switch(ch) {

		case 'e':
			show_errors = 1;
			break;
		case 'd':
			scan_interval = 1000*atoi(optarg);
			break;
		case 't':
			if (sscanf(optarg, "%d", &time_constant) != 1 ||
			    time_constant <= 0) {
				fprintf(stderr, "ifstat: invalid time constant divisor\n");
				exit(-1);
			}
			break;
		case 'r' :
			show_rtstat = 1;
			break;

		case 'v':
		case 'V':
			printf("ifstat2 utility, %s\n", VERSION);
			exit(0);
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	/* Setup for abstract unix socket */

	sun.sun_family = AF_UNIX;
	sun.sun_path[0] = 0;
	sprintf(sun.sun_path+1, "ifstat%d", getuid());

	if (scan_interval > 0) {
		if (time_constant == 0)
			time_constant = 60;
		time_constant *= 1000;
		
		W = 1 - 1/exp(log(10)*(double)scan_interval/time_constant);


		if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
			perror("ifstat: socket");
			exit(-1);
		}
		if (bind(fd, (struct sockaddr*)&sun, 2+1+strlen(sun.sun_path+1)) < 0) {
			perror("ifstat: bind");
			exit(-1);
		}
		if (listen(fd, 5) < 0) {
			perror("ifstat: listen");
			exit(-1);
		}
		if (fork())
			exit(0);
		chdir("/");
		close(0); close(1); close(2); setsid();
		signal(SIGPIPE, SIG_IGN);
		signal(SIGCHLD, sigchild);
		server_loop(fd);
		exit(0);
	}

	/* Client section */

	patterns = argv;
	npatterns = argc;

	if(show_rtstat) {
		dump_rtstat_db(stdout);
		exit(0);
	}

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0 &&
	    (connect(fd, (struct sockaddr*)&sun, 2+1+strlen(sun.sun_path+1)) == 0
	     || (strcpy(sun.sun_path+1, "ifstat0"),
		 connect(fd, (struct sockaddr*)&sun, 2+1+strlen(sun.sun_path+1)) == 0))
	    && verify_forging(fd) == 0) {
		FILE *sfp = fdopen(fd, "r");

		/* Read from daemon */

		load_raw_table(sfp);

		fclose(sfp);
		dump_kern_db(stdout);
		exit(0);
	}
	perror("socket ");
	exit(-1);
}

