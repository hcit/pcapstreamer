#ifndef __PCAPSTREAMER__
#define __PCAPSTREAMER__

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <pcap/pcap.h>
#include <sys/time.h>

#define PACKET_LENGTH 65535
#define PACKET_TIMEOUT 1000
#define PROMISC 0

static char errbuf[PCAP_ERRBUF_SIZE];

gchar* pcs_get_any_dev(void);
pcap_t* pcs_open(const gchar *interface);
void pcs_capture(pcap_t *handle);
#endif /*__PCAPSTREAMER__*/
