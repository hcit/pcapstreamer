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
