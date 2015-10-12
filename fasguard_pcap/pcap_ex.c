/* $Id: pcap_ex.c,v 1.12 2005/10/16 22:58:14 dugsong Exp $ */

#ifdef _WIN32
# include <winsock2.h>
# include <iphlpapi.h>
#else
# include <sys/types.h>
# include <sys/ioctl.h>
# include <sys/time.h>
# include <fcntl.h>
# include <stdlib.h>
# include <string.h>
# include <signal.h>
# include <unistd.h>
#endif

#include <pcap/pcap.h>
#include "pcap_ex.h"

/* XXX - hack around older Python versions */
#include "patchlevel.h"
#if PY_VERSION_HEX < 0x02030000
int    PyGILState_Ensure() { return (0); }
void   PyGILState_Release(int gil) { }
#endif

int
pcap_ex_immediate(pcap_t *pcap)
{
#ifdef BIOCIMMEDIATE
	int n = 1;
	
	return ioctl(pcap_fileno(pcap), BIOCIMMEDIATE, &n);
#else
	return (0);
#endif
}

#ifdef _WIN32
/* XXX - set device list in libdnet order. */
static int
_pcap_ex_findalldevs(pcap_if_t **dst, char *ebuf)
{
        pcap_if_t *pifs, *cur, *prev, *next;
	int ret;
	
	if ((ret = pcap_findalldevs(&pifs, ebuf)) != -1) {
		/* XXX - flip script like a dyslexic actor */
		for (prev = NULL, cur = pifs; cur != NULL; ) {
			next = cur->next, cur->next = prev;
			prev = cur, cur = next;
		}
		*dst = prev;
	}
	return (ret);
}
#endif

char *
pcap_ex_name(char *name)
{
#ifdef _WIN32
	/*
	 * XXX - translate from libdnet logical interface name to
	 * WinPcap native interface name.
	 */
	static char pcap_name[256];
        pcap_if_t *pifs, *pif;
	char ebuf[128];
	int idx, i = 0;

	/* XXX - according to the WinPcap FAQ, no loopback support??? */
        if (strncmp(name, "eth", 3) != 0 || sscanf(name+3, "%u", &idx) != 1 ||
	    _pcap_ex_findalldevs(&pifs, ebuf) == -1) {
		return (name);
	}
	for (pif = pifs; pif != NULL; pif = pif->next) {
		if (i++ == idx) {
			strncpy(pcap_name, pif->name, sizeof(pcap_name)-1);
			pcap_name[sizeof(pcap_name)-1] = '\0';
			name = pcap_name;
			break;
		}
	}
	pcap_freealldevs(pifs);
	return (name);
#else
	return (name);
#endif
}

char *
pcap_ex_lookupdev(char *ebuf)
{
#ifdef _WIN32
	/* XXX - holy poo this sux */
	static char _ifname[8];
	MIB_IPADDRTABLE *ipaddrs;
	DWORD i, dsz, outip;
	pcap_if_t *pifs, *pif;
	struct pcap_addr *pa;
	char *name = NULL;
	int idx;
	
	/* Find our primary IP address. */
	ipaddrs = malloc((dsz = sizeof(*ipaddrs)));
	while (GetIpAddrTable(ipaddrs, &dsz, 0) == ERROR_INSUFFICIENT_BUFFER) {
		free(ipaddrs);
		ipaddrs = malloc(dsz);
	}
	outip = 0;
	for (i = 0; i < ipaddrs->dwNumEntries; i++) {
		if (ipaddrs->table[i].dwAddr != 0 &&
		    ipaddrs->table[i].dwAddr != 0x100007f
		    ) {
			outip = ipaddrs->table[i].dwAddr;
			break;
		}
	}
	free(ipaddrs);
	if (outip == 0) {
		/* XXX - default to first Ethernet interface. */
		return ("eth0");
	}
	/* Find matching pcap interface by IP. */
	if (_pcap_ex_findalldevs(&pifs, ebuf) == -1)
		return (name);
	
	for (pif = pifs, idx = 0; pif != NULL && name == NULL;
	    pif = pif->next, idx++) {
		for (pa = pif->addresses; pa != NULL; pa = pa->next) {
			if (pa->addr->sa_family == AF_INET &&
			    ((struct sockaddr_in *)pa->addr)->sin_addr.S_un.S_addr == outip) {
				sprintf(_ifname, "eth%d", idx);
				name = _ifname;
				break;
			}
		}
	}
	pcap_freealldevs(pifs);
	return (name);
#else
	return (pcap_lookupdev(ebuf));
#endif
}

static int __pcap_ex_gotsig;

#ifdef _WIN32
static BOOL CALLBACK
__pcap_ex_ctrl(DWORD sig)
{
	__pcap_ex_gotsig = 1;
	return (TRUE);
}
#else
static void
__pcap_ex_signal(int sig)
{
	__pcap_ex_gotsig = 1;
}
#endif

/* XXX - hrr, this sux */
void
pcap_ex_setup(pcap_t *pcap)
{
#ifdef _WIN32
	SetConsoleCtrlHandler(__pcap_ex_ctrl, TRUE);
#else
	signal(SIGINT, __pcap_ex_signal);
#endif
}

/* return codes: 1 = pkt, 0 = timeout, -1 = error, -2 = EOF */
int
pcap_ex_next(pcap_t *pcap, struct pcap_pkthdr **hdr, u_char **pkt)
{
#ifdef _WIN32
	if (__pcap_ex_gotsig) {
		__pcap_ex_gotsig = 0;
		return (-1);
	}
	return (pcap_next_ex(pcap, hdr, pkt));
#else
	static u_char *__pkt;
	static struct pcap_pkthdr __hdr;
	struct timeval tv = { 1, 0 };
	fd_set rfds;
	int fd, n;

	fd = pcap_fileno(pcap);
	for (;;) {
		if (__pcap_ex_gotsig) {
			__pcap_ex_gotsig = 0;
			return (-1);
		}
		if ((__pkt = (u_char *)pcap_next(pcap, &__hdr)) == NULL) {
			if (pcap_file(pcap) != NULL)
				return (-2);
			FD_ZERO(&rfds);
			FD_SET(fd, &rfds);
			n = select(fd + 1, &rfds, NULL, NULL, &tv);
			if (n <= 0)
				return (n);
		} else
			break;
	}
	*pkt = __pkt;
	*hdr = &__hdr;
	
	return (1);
#endif
}
