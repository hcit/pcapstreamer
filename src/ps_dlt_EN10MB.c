#include <pcapstreamer.h>

gint ps_dlt_EN10MB(gint32 caplen, const guchar *bytes)
{
  struct ether_header *ether = (struct ether_header *) bytes;
  guchar *value = NULL;
  gint32 h_ether_type = 0;

  value = ps_hexstreamout(ETHER_ADDR_LEN, ether->ether_dhost);
  g_print(",ether_dhost=%s", value);
  g_free(value);

  value = ps_hexstreamout(ETHER_ADDR_LEN, ether->ether_shost);
  g_print(",ether_shost=%s", value);
  g_free(value);

  h_ether_type = ntohs(ether->ether_type);
  if(h_ether_type >= 0x0600)
    {
      /* source: http://www.networksorcery.com/enp/protocol/802/ethertypes.htm
       * ether_type < 0x0600 indicates payload size, ether_type >=0x0600
       * indicates type of inner protocol.
       */
      g_print(",ether_type=%d", h_ether_type);
    }
  else
    g_print(",ether_payload_length=%d", h_ether_type);

#ifdef PS_IP
  if((h_ether_type == ETHERTYPE_IP) && ((caplen - sizeof(struct ether_header)) > 0))
    ps_ip(caplen - sizeof(struct ether_header), bytes + sizeof(struct ether_header));
#endif

  return(1);
}
