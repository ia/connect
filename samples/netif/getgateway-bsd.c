#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

static void get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info);

int
main(void)
{
	struct rt_msghdr *rtm;
	struct sockaddr *sa, *sa0;
	struct sockaddr_in *sin;
	struct sockaddr *rti_info[RTAX_MAX];

	int mib[7];
	size_t needed;
	char *pbuf, *next, *lim;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_DUMP;
	mib[5] = 0;

	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0) {
		perror("sysctl");
		exit(1);
	}	
        if ((pbuf = (void*)calloc(needed, 1)) == NULL) {
                perror("calloc");
		exit(1);
        }
	if (sysctl(mib, 6, pbuf, &needed, NULL, 0) < 0) {
		perror("sysctl");
		exit(1);
	}	
	lim = pbuf + needed;

	for (next = pbuf; next < lim; next += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)next;

		if (rtm->rtm_version != RTM_VERSION)
			continue;

		sa = (struct sockaddr *)(rtm + 1);
		get_rtaddrs(rtm->rtm_addrs, sa, rti_info);

                if (sa->sa_family != AF_INET)
			continue;

		sin = (struct sockaddr_in *)(rti_info[RTAX_DST]);

		if (rtm->rtm_flags & RTF_GATEWAY &&
			sin != NULL && sin->sin_addr.s_addr == 0) {
                	sin = (struct sockaddr_in *)(rti_info[RTAX_GATEWAY]);
                	if (sin != NULL)
                		printf("gateway: %s\n", inet_ntoa(sin->sin_addr.s_addr));
		}
	}

			
#if 0
		sin = (struct sockaddr_in *)(rti_info[RTAX_DST]);
		if (sin != NULL)
		printf("destination: %s\n", inet_ntoa(sin->sin_addr.s_addr));
		sin = (struct sockaddr_in *)(rti_info[RTAX_GATEWAY]);
		if (sin != NULL)
		printf("gateway: %s\n", inet_ntoa(sin->sin_addr.s_addr));
		sa0 = sa + RTAX_NETMASK;
		sin = (struct sockaddr_in *)(rti_info[RTAX_NETMASK]);
		if (sin != NULL)
		printf("netmask: %s, sa len = %u\n", inet_ntoa(sin->sin_addr.s_addr), sa0->sa_len);
		printf("-----\n");
#endif

}

/*
 * Copyright (c) 1983, 1988, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

static void
get_rtaddrs(int addrs, struct sockaddr *sa, struct sockaddr **rti_info)
{
int     i;

        for (i = 0; i < RTAX_MAX; i++) {
                if (addrs & (1 << i)) {
                        rti_info[i] = sa;
                        sa = (struct sockaddr *)((char *)(sa) +
                            ROUNDUP(sa->sa_len));
                } else
                        rti_info[i] = NULL;
        }
}

