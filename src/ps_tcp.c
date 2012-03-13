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

gint ps_tcp(gint32 caplen, const guchar *bytes)
{
  guchar *value = NULL;
  struct tcphdr *tcp = (struct tcphdr*) bytes;
  g_print(",tcp_source=%d", ntohs(tcp->source));
  g_print(",tcp_dest=%d", ntohs(tcp->dest));
  g_print(",tcp_seq=%ld", (long int) ntohl(tcp->seq));
  g_print(",tcp_ack_seq=%ld", (long int) ntohl(tcp->ack_seq));
  g_print(",tcp_res1=%d", tcp->res1);
  /*
   * dataoffset contains tcp header length in number of 4 byte words
   */
  g_print(",tcp_doff=%d", tcp->doff * 4);
  g_print(",tcp_res1=%d", tcp->res1);
  g_print(",tcp_res2=%d", tcp->res2);
  g_print(",tcp_urg=%d", tcp->urg);
  g_print(",tcp_ack=%d", tcp->ack);
  g_print(",tcp_psh=%d", tcp->psh);
  g_print(",tcp_rst=%d", tcp->rst);
  g_print(",tcp_syn=%d", tcp->syn);
  g_print(",tcp_fin=%d", tcp->fin);
  g_print(",tcp_window=%d", htons(tcp->window));
  g_print(",tcp_check=%d", htons(tcp->check));
  g_print(",tcp_urg_ptr=%d", htons(tcp->urg_ptr));
  /*
   * source: http://www.networksorcery.com/enp/protocol/tcp.htm#Options
   * if dataoffset is more than sizeof(struct tcp), then we have multiple
   * options present, we need to decode them.
   */
  if(((tcp->doff * 4) - sizeof(struct tcphdr)) > 0)
    g_print(",tcp_opt_length=%ld", (tcp->doff * 4) - sizeof(struct tcphdr));

  /*
   * printing data in binary form
   */
  if((caplen - (tcp->doff * 4)) > 0)
    {
      value = ps_streamout(caplen - (tcp->doff * 4), bytes + (tcp->doff * 4));
      g_print(",data=%s", value);
      g_free(value);
    }

  return(1);
}
