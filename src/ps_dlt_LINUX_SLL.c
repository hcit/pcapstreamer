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
