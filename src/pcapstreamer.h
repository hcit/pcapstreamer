#define _GNU_SOURCE
#ifndef __PCAPSTREAMER__
#define __PCAPSTREAMER__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <glib.h>
#include <pcap/pcap.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#define SNAPLEN              65535
#define PROMISC              1
#define TOMS                 0
#define OPTIMIZE             0
#define LOOPCNT              0

/*
 * declaring handle as global, so that pcap_breakloop() can work correctly.
 */
static pcap_t *handle = NULL;

/*
 * function declarations
 */
pcap_t* ps_init(gchar *device);
void ps_list_interfaces(void);
pcap_t* ps_get_default_interface(void);
struct bpf_program* ps_setup_filter(pcap_t *handle, gchar *pregex);
void ps_loop(pcap_t *handle, pcap_handler callbackfunc, guchar *args);
void ps_serialize(guchar *args, const struct pcap_pkthdr *h, const guchar *bytes);
void ps_parse(guchar *args, const struct pcap_pkthdr *h, const guchar *bytes);
guchar* ps_streamout(gint32 caplen, const guchar *bytes);
guchar* ps_hexstreamout(gint32 caplen, const guchar *bytes);

#ifndef PS_DLT_EN10MB
#define PS_DLT_EN10MB
#include <netinet/if_ether.h>
gint ps_dlt_EN10MB(gint32 caplen, const guchar *bytes);
#endif

#ifndef PS_DLT_LINUX_SLL
#define PS_DLT_LINUX_SLL
/*
 * using tcpdump's sll_header structure.
 * source: http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
 */
#define SLL_HDR_LEN          16
#define SLL_ADDRLEN          8
struct sll_header
{
  guint16 sll_pkttype;
  guint16 sll_hatype;
  guint16 sll_halen;
  guint8 sll_addr[SLL_ADDRLEN];
  guint16 sll_protocol;
};
gint ps_dlt_LINUX_SLL(gint32 caplen, const guchar *bytes);
#endif

#ifndef PS_IP
#define PS_IP
#include <netinet/ip.h>
gint ps_ip(gint32 caplen, const guchar *bytes);
#endif

#ifndef PS_TCP
#define PS_TCP
#include <netinet/tcp.h>
gint ps_tcp(gint32 caplen, const guchar *bytes);
#endif

#ifndef PS_UDP
#define PS_UDP
#include <netinet/udp.h>
gint ps_udp(gint32 caplen, const guchar *bytes);
#endif

#ifndef PS_ICMP
#define PS_ICMP
#include <netinet/ip_icmp.h>
gint ps_icmp(gint32 caplen, const guchar *bytes);
#endif

#endif /*__PCAPSTREAMER__*/
