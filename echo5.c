#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <sys/mman.h> /* PROT_* */
#include <sys/ioctl.h> /* ioctl */
#include <sys/param.h>
#include <sys/poll.h>
#include <sys/socket.h> /* sockaddr.. */
#include <arpa/inet.h> /* ntohs */

#include <sys/epoll.h>

#include <net/if.h>	/* ifreq */
#include <net/ethernet.h>

#include <netinet/if_ether.h>
#include <netinet/in.h> /* sockaddr_in */
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "net/netmap.h"
#include "net/netmap_user.h"

#include "nm_util.h"

char *version = "$ID$";
int verbose = 0;
static int do_abort = 0;

	static void
sigint_h(int sig)
{
	(void)sig;  /* UNUSED */
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}

struct pesudo_udphdr { 
	unsigned int saddr, daddr; 
	unsigned char unused; 
	unsigned char protocol; 
	unsigned short udplen; 
}; 

unsigned short in_cksum(unsigned short *addr, int len) 
{ 
	int sum=0; 
	unsigned short res=0; 
	while( len > 1)  { 
		sum += *addr++; 
		len -=2; 
	} 
	if( len == 1) { 
		*((unsigned char *)(&res))=*((unsigned char *)addr); 
		sum += res; 
	} 
	sum = (sum >>16) + (sum & 0xffff); 
	sum += (sum >>16) ; 
	res = ~sum; 
	return res; 
}

int is_dns_query(char *buff, int len)
{
	struct ethhdr *eh;
	struct iphdr *ip;
	struct udphdr *udp;

	char *ip_buff = buff + 14;

	eh = (struct ethhdr*)buff;
	ip = (struct iphdr*) (ip_buff);
	udp = (struct udphdr *) (ip_buff + sizeof(struct iphdr));

	if (eh->h_proto != ntohs(0x0800))
	{
		return 1;
	}

	if (ip->protocol != IPPROTO_UDP )
	{
		return 2;
	}

	if (udp->dest != ntohs(53))
	{
		return 3;
	}

	char *p = (ip_buff ) + 12;               
	if (verbose > 1)
	{
		printf("recv:%d, IP:%d.%d.%d.%d:%d => %d.%d.%d.%d:%d\n", len,
				p[0]&0XFF,p[1]&0XFF,p[2]&0XFF,p[3]&0XFF, htons(udp->source),
				p[4]&0XFF,p[5]&0XFF,p[6]&0XFF,p[7]&0XFF, htons(udp->dest)); 
	}

	return 0;
}

int echo_dns_query(char *buff, int n)
{
	u_int32_t tmpaddr;
	u_int16_t tmpport;
	char check_buf[512] = {0};

	char *ip_buff = buff + 14;

	struct iphdr* ip = (struct iphdr*)ip_buff; 
	struct udphdr * udp = (struct udphdr*) (ip_buff + sizeof(struct iphdr ));
	char *query = (char *)( ip_buff + sizeof(struct iphdr ) + sizeof(struct udphdr));

	//chage DNS query flag 
	query[2] |= 0x80;

	//Change ip header
	tmpaddr = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmpaddr;
	ip->check = 0;
	ip->check = in_cksum((unsigned short *)ip_buff, sizeof(struct iphdr));  

	// change UDP header
	tmpport = udp->source;
	udp->source = udp->dest;
	udp->dest = tmpport;
	udp->check = 0;

	{
		int udp_len = n - sizeof(struct iphdr ) - 14;

		memset(check_buf, 0x0, 512);
		memcpy(check_buf + sizeof(struct pesudo_udphdr), (char*)udp, udp_len);
		struct pesudo_udphdr * pudph = (struct pesudo_udphdr *)check_buf;

		pudph->saddr = ip->saddr ; 
		pudph->daddr = ip->daddr; 
		pudph->unused=0; 
		pudph->protocol=IPPROTO_UDP; 
		pudph->udplen=htons(udp_len);

		udp->check = in_cksum((unsigned short *)check_buf, 
				udp_len +  sizeof(struct pesudo_udphdr) );
	}

	// change Ethnet header
	{
		unsigned char mac_temp[ETH_ALEN]={0};
		struct ethhdr *eh = (struct ethhdr *)buff;

		memcpy(mac_temp,eh->h_dest,ETH_ALEN);
		memcpy(eh->h_dest, eh->h_source, ETH_ALEN);
		memcpy(eh->h_source, mac_temp, ETH_ALEN);
	}

	return 0;
}

int dns_packet_process(char *buff, int len)
{
	echo_dns_query(buff, len);
	return 0;
}


//#define NO_SWAP
static int process_rings(struct netmap_ring *rxring, 
		struct netmap_ring *txring,
		u_int limit)
{
	u_int j, k, m = 0;
	u_int f = 0;

	j = rxring->cur; /* RX */
	k = txring->cur; /* TX */
	if (rxring->avail < limit)
		limit = rxring->avail;
	if (txring->avail < limit)
		limit = txring->avail;
	while (m < limit) {
		struct netmap_slot *rs = &rxring->slot[j];
		struct netmap_slot *ts = &txring->slot[k];
		char *rxbuf = NETMAP_BUF(rxring, rs->buf_idx);
#ifdef NO_SWAP
		char *txbuf = NETMAP_BUF(txring, ts->buf_idx);
#else
		uint32_t pkt;
#endif
		if (0 != is_dns_query(rxbuf, rs->len)) {
			if (verbose > 1) D("rx[%d] is not DNS query", j);
			goto NEXT_L; /* best effort! */
		}else {
			if (verbose > 1) D("echo: rx[%d] is DNS query", j);
			dns_packet_process(rxbuf, rxring->slot[j].len);
		}

		if (ts->buf_idx < 2 || rs->buf_idx < 2) {
			D("wrong index rx[%d] = %d  -> tx[%d] = %d",
					j, rs->buf_idx, k, ts->buf_idx);
			sleep(2);
		}

#ifndef NO_SWAP
		pkt = ts->buf_idx;
		ts->buf_idx = rs->buf_idx;
		rs->buf_idx = pkt;
#endif

		/* copy the packet lenght. */
		if (rs->len < 14 || rs->len > 2048)
			D("wrong len %d rx[%d] -> tx[%d]", rs->len, j, k);
		else if (verbose > 1)
			D("send len %d rx[%d] -> tx[%d]", rs->len, j, k);

		ts->len = rs->len;
#ifdef NO_SWAP
		pkt_copy(rxbuf, txbuf, ts->len);
#else
		/* report the buffer change. */
		// ts->flags |= NS_BUF_CHANGED;
		// rs->flags |= NS_BUF_CHANGED;
#endif /* NO_SWAP */

		k = NETMAP_RING_NEXT(txring, k);
		ts->flags |= NS_BUF_CHANGED;
		f++;
NEXT_L:	

		j = NETMAP_RING_NEXT(rxring, j);
		m++;

		rs->flags |= NS_BUF_CHANGED;
	}
	rxring->avail -= m;
	txring->avail -= f;
	rxring->cur = j;
	txring->cur = k;
	if (verbose > 1 && m > 0)
		D("sent %d packets to %p", m, txring);

	return (m);
}


static int move(struct my_ring *src, 
		u_int limit, int modify)
{
	struct netmap_ring *txring, *rxring;
	u_int m = 0, ri = src->begin, ti=src->begin;
	const char *msg = (src->queueid & NETMAP_SW_RING) ?
		"host->net" : "net->host";

	while (ri < src->end && ti < src->end) {
		rxring = NETMAP_RXRING(src->nifp, ri);
		txring = NETMAP_TXRING(src->nifp, ti);

		if (rxring->avail == 0) {
			ri++;
			continue;
		}
		if (txring->avail == 0) {
			ti++;
			continue;
		}
		m += process_rings(rxring, txring, limit);
		if (rxring->avail != 0 && txring->avail != 0 )
		{   	
			ti++;
			ri++;
		}
	}

	return (m);
}



static int count_packet(struct my_ring *me, int tx)
{
	u_int i, tot = 0;

	for (i = me->begin; i < me->end; i++) {
		struct netmap_ring *ring = tx ?
			NETMAP_TXRING(me->nifp, i) : NETMAP_RXRING(me->nifp, i);
		tot += ring->avail;
	}

	return tot;
}


/*
 * bridge [-v] if1 [if2]
 *
 * If only one name, or the two interfaces are the same,
 * bridges userland and the adapter. Otherwise bridge
 * two intefaces.
 */

#define MAX_EVENTS  2

	int
main(int argc, char **argv)
{
	struct epoll_event event[1], *events;
	int nfd, efd,s;

	int i, ch;
	u_int burst = 1024, wait_link = 4;
	struct my_ring me[1];
	int n0 = 0, n1= 0, ret;

	fprintf(stderr, "%s %s built %s %s\n",
			argv[0], version, __DATE__, __TIME__);

	bzero(me, sizeof(me));

	//----------------
	me[0].ifname =  "eth1";
	if (netmap_open(&me[0], 0, 0))
		return (1);

	//----------------------------
	efd = epoll_create(MAX_EVENTS);
	if (efd == -1)
	{
		printf("epoll_create failed\n");
		return 0;
	}

	{ 
		event[0].data.fd = me[0].fd;
		event[0].events = EPOLLIN | EPOLLOUT ;
		s = epoll_ctl(efd, EPOLL_CTL_ADD, me[0].fd, &event[0]);
		if (s == -1) {
			printf("epoll_ctl error \n");
			return 0;
		}
	}

	events = calloc(1, sizeof(struct epoll_event));

	D("Wait %d secs for link to come up...", wait_link);
	sleep(wait_link);
	D("Ready to go ....");

	/* main loop */
	signal(SIGINT, sigint_h);
	while (!do_abort) {

		nfd = epoll_wait(efd, events, MAX_EVENTS, -1);
		move(&me[0], burst, 0);
	}

	D("exiting");
	netmap_close(&me[1]);
	netmap_close(&me[0]);
	close(efd);

	return (0);
}


