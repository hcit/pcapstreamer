#include <pcapstreamer.h>

gint ps_udp(gint32 caplen, const guchar *bytes)
{
  guchar *value = NULL;
  struct udphdr *udp = (struct udphdr *) bytes;
  g_print(",uh_source=%d", ntohs(udp->source));
  g_print(",uh_dest=%d", ntohs(udp->dest));
  g_print(",uh_len=%d", ntohs(udp->len));
  g_print(",uh_check=%d", ntohs(udp->check));
  /*
   * printing data
   */
  if((ntohs(udp->len) - sizeof(struct udphdr)) > 0)
    {
      value = ps_streamout(ntohs(udp->len) - sizeof(struct udphdr),
			   bytes + sizeof(struct udphdr));
      g_print(",data=%s", value);
      g_free(value);
    }

  return(1);
}
