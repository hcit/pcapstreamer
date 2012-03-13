#include <pcapstreamer.h>

gint ps_dlt_LINUX_SLL(gint32 caplen, const guchar *bytes)
{
  guchar *value = NULL;
  struct sll_header *sll = (struct sll_header *) bytes;
  g_print(",sll_pkttype=%d", ntohs(sll->sll_pkttype));
  g_print(",sll_hatype=%d", ntohs(sll->sll_hatype));
  g_print(",sll_halen=%d", ntohs(sll->sll_halen));
  value = ps_hexstreamout(SLL_ADDRLEN, (guchar *) sll->sll_addr);
  g_print(",sll_addr=%s", value);
  g_free(value);
  g_print(",sll_protocol=%d", ntohs(sll->sll_protocol));

#ifdef PS_IP
  if((ntohs(sll->sll_protocol) == ETHERTYPE_IP)
     && ((caplen - sizeof(struct sll_header)) > 0))
    ps_ip(caplen - sizeof(struct sll_header), bytes + sizeof(struct sll_header));
#endif

  return(1);
}
