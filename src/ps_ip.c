#include <pcapstreamer.h>

gint ps_ip(gint32 caplen, const guchar *bytes)
{
  guchar *value = NULL;
  guint8 *s_addr = NULL;
  guint8 *d_addr = NULL;
  const guint8 *op = 0;
  struct ip *ip = (struct ip *) bytes;
  g_print(",ip_v=%d", ip->ip_v);
  /*
   * ip_hl contains header length in number of 4 byte word
   */
  g_print(",ip_hl=%d", ip->ip_hl * 4);
  g_print(",ip_tos=%d", ip->ip_tos);
  g_print(",ip_len=%d", ntohs(ip->ip_len));
  g_print(",ip_id=%d", ntohs(ip->ip_id));
  g_print(",IP_RF=%d", (ntohs(ip->ip_off) & IP_RF) == IP_RF ? 1 : 0);
  g_print(",IP_DF=%d", (ntohs(ip->ip_off) & IP_DF) == IP_DF ? 1 : 0);
  g_print(",IP_MF=%d", (ntohs(ip->ip_off) & IP_MF) == IP_MF ? 1 : 0);
  g_print(",ip_off=%d", ntohs(ip->ip_off) & IP_OFFMASK);
  g_print(",ip_ttl=%d", ip->ip_ttl);
  g_print(",ip_p=%d", ip->ip_p);
  g_print(",ip_sum=%d", ntohs(ip->ip_sum));
  s_addr = (guint8 *) &(ip->ip_src.s_addr);
  d_addr = (guint8 *) &(ip->ip_dst.s_addr);
  g_print(",ip_src=%d.%d.%d.%d", s_addr[0], s_addr[1], s_addr[2], s_addr[3]);
  g_print(",ip_dst=%d.%d.%d.%d", d_addr[0], d_addr[1], d_addr[2], d_addr[3]);
  /*
   * source: http://www.networksorcery.com/enp/protocol/ip.htm#Options
   * if header length is more than sizeof(struct ip), then we have multiple
   * options present, we need to decode them.
   */
  if((ip->ip_hl * 4) - sizeof(struct ip) > 0)
    g_print(",ip_opt_length=%ld", (ip->ip_hl * 4) - sizeof(struct ip));

#ifdef PS_TCP
  if((ip->ip_p == 6) && ((caplen - (ip->ip_hl * 4)) > 0))
    ps_tcp(caplen - (ip->ip_hl * 4), bytes + (ip->ip_hl * 4));
#endif

#ifdef PS_UDP
  if((ip->ip_p == 17) && ((caplen - (ip->ip_hl * 4)) > 0))
     ps_udp(caplen - (ip->ip_hl * 4), bytes + (ip->ip_hl * 4));
#endif

#ifdef PS_UDP
  if((ip->ip_p == 1) && ((caplen - (ip->ip_hl * 4)) > 0))
     ps_icmp(caplen - (ip->ip_hl * 4), bytes + (ip->ip_hl * 4));
#endif

  return(1);
}
