/* 
 * Copyright (c) <2012>, Mohan R <mohan43u@gmail.com>
 * All rights reserved.
 * 
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions are met:
 * 
 *   1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 *   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those
 *   of the authors and should not be interpreted as representing official policies,
 *   either expressed or implied, of the FreeBSD Project.
 */

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
