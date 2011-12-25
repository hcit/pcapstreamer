#include <pcapstreamer.h>

gchar* pcs_get_any_dev(void)
{
  pcap_if_t *alldevsp, *alldevsp_iter;
  gchar *interface = NULL;

  if(pcap_findalldevs(&alldevsp, errbuf) != 0)
    {
      g_printerr("pcs_get_first_dev(): %s\n", errbuf);
      exit(EXIT_FAILURE);
    }

  alldevsp_iter = alldevsp;
  while(alldevsp_iter != NULL)
    {
      if(g_strcmp0(alldevsp_iter->name, "any") == 0)
	break;
      alldevsp_iter = alldevsp_iter->next;
    }
  if(alldevsp_iter == NULL)
    {
      g_printerr("pcs_get_any_dev(): not able to find 'any' interface\n");
      exit(EXIT_FAILURE);
    }

  interface = g_strdup(alldevsp_iter->name);
  pcap_freealldevs(alldevsp);
  return(interface);
}

pcap_t* pcs_open(const gchar *interface)
{
  pcap_t *handle = NULL;

  if((handle = pcap_open_live(interface,
			      PACKET_LENGTH,
			      PROMISC,
			      PACKET_TIMEOUT,
			      errbuf)) == NULL)
    {
      g_printerr("pcs_open(): %s\n", errbuf);
      exit(EXIT_FAILURE);
    }
  return(handle);
}

static void serialize(const gchar *bytes, const guint len)
{
  gint byte_iter = 0;
  gint bit_iter = 0;
  guchar bit = 128;

  while(byte_iter < len)
    {
      bit_iter = 0;
      while(bit_iter < 8)
	{
	  g_print("%u", ((((guchar)bytes[byte_iter] << bit_iter) & bit) == 128 ? 1 : 0));
	  bit_iter++;
	}
      g_print(" ");
      byte_iter++;
    }
}

static void pcap_loop_callback(guchar *user,
			       const struct pcap_pkthdr *h,
			       const guchar *bytes)
{
  gchar captime[512];

  strftime(captime, 512, "%Y%m%d%H%M%S",localtime(&h->ts.tv_sec));
  g_printerr("[cl:%d l:%ld t:%s.%ld] ",
	     h->caplen,
	     h->len,
	     captime,
	     h->ts.tv_usec);
  /*
   * Converting bytes to strings. These bytes are captured by
   * Linux's 'any' interface, so they follow the following link-level
   * header http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
   * To know about linux ARPHRD_ types, following this link,
   * http://tomoyo.sourceforge.jp/cgi-bin/lxr/source/include/linux/if_arp.h
   */
  serialize(bytes, h->caplen);
  g_print("\n");
}

void pcs_capture(pcap_t *handle)
{
  pcap_loop(handle, 0, (pcap_handler) pcap_loop_callback, NULL);
  pcap_close(handle);
}
