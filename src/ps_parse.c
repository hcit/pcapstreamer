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

void ps_parse(guchar *args, const struct pcap_pkthdr *h, const guchar *bytes)
{
  int parsed = 0;
  pcap_t *handle = g_hash_table_lookup((GHashTable *) args, "handle");
  gint datalink = pcap_datalink(handle);
  gchar captime[512];

  if(h->len > h->caplen)
    {
      g_printerr("ps_serialize(): h->len is greater than h->caplen\n");
      exit(EXIT_FAILURE);
    }

  strftime(captime, 512, "%Y%m%d%H%M%S",localtime(&h->ts.tv_sec));
  g_print("[cl:%d l:%d t:%s.%ld dl:%s]",
	  h->caplen,
	  h->len,
	  captime,
	  h->ts.tv_usec,
	  pcap_datalink_val_to_name(datalink));

  switch(datalink)
    {
    case DLT_NULL:
#ifdef PS_DLT_NULL
      parsed = ps_dlt_NULL(h->caplen, bytes);
#endif
      break;
    case DLT_EN10MB:
#ifdef PS_DLT_EN10MB
      parsed = ps_dlt_EN10MB(h->caplen, bytes);
#endif
      break;
    case DLT_IEEE802:
#ifdef PS_DLT_IEEE802
      parsed = ps_dlt_IEEE802(h->caplen, bytes);
#endif
      break;
    case DLT_ARCNET:
#ifdef PS_DLT_ARCNET
      parsed = ps_dlt_ARCNET(h->caplen, bytes);
#endif
      break;
    case DLT_SLIP:
#ifdef PS_DLT_SLIP
      parsed = ps_dlt_SLIP(h->caplen, bytes);
#endif
      break;
    case DLT_PPP:
#ifdef PS_DLT_PPP
      parsed = ps_dlt_PPP(h->caplen, bytes);
#endif
      break;
    case DLT_FDDI:
#ifdef PS_DLT_FDDI
      parsed = ps_dlt_FDDI(h->caplen, bytes);
#endif
      break;
    case DLT_ATM_RFC1483:
#ifdef PS_DLT_ATM_RFC1483
      parsed = ps_dlt_ATM_RFC1483(h->caplen, bytes);
#endif
      break;
    case DLT_RAW:
#ifdef PS_DLT_RAW
      parsed = ps_dlt_RAW(h->caplen, bytes);
#endif
      break;
    case DLT_PPP_SERIAL:
#ifdef PS_DLT_PPP_SERIAL
      parsed = ps_dlt_PPP_SERIAL(h->caplen, bytes);
#endif
      break;
    case DLT_PPP_ETHER:
#ifdef PS_DLT_PPP_ETHER
      parsed = ps_dlt_PPP_ETHER(h->caplen, bytes);
#endif
      break;
    case DLT_C_HDLC:
#ifdef PS_DLT_C_HDLC
      parsed = ps_dlt_C_HDLC(h->caplen, bytes);
#endif
      break;
    case DLT_IEEE802_11:
#ifdef PS_DLT_IEEE802_11
      parsed = ps_dlt_IEEE802_11(h->caplen, bytes);
#endif
      break;
    case DLT_FRELAY:
#ifdef PS_DLT_FRELAY
      parsed = ps_dlt_FRELAY(h->caplen, bytes);
#endif
      break;
    case DLT_LOOP:
#ifdef PS_DLT_LOOP
      parsed = ps_dlt_LOOP(h->caplen, bytes);
#endif
      break;
    case DLT_LINUX_SLL:
#ifdef PS_DLT_LINUX_SLL
      parsed = ps_dlt_LINUX_SLL(h->caplen, bytes);
#endif
      break;
    case DLT_LTALK:
#ifdef PS_DLT_LTALK
      parsed = ps_dlt_LTALK(h->caplen, bytes);
#endif
      break;
    case DLT_PFLOG:
#ifdef PS_DLT_PFLOG
      parsed = ps_dlt_PFLOG(h->caplen, bytes);
#endif
      break;
    case DLT_PRISM_HEADER:
#ifdef PS_DLT_PRISM_HEADER
      parsed = ps_dlt_PRISM_HEADER(h->caplen, bytes);
#endif
      break;
    case DLT_IP_OVER_FC:
#ifdef PS_DLT_IP_OVER_FC
      parsed = ps_dlt_IP_OVER_FC(h->caplen, bytes);
#endif
      break;
    case DLT_SUNATM:
#ifdef PS_DLT_SUNATM
      parsed = ps_dlt_SUNATM(h->caplen, bytes);
#endif
      break;
    case DLT_IEEE802_11_RADIO:
#ifdef PS_DLT_IEEE802_11_RADIO
      parsed = ps_dlt_IEEE802_11_RADIO(h->caplen, bytes);
#endif
      break;
    case DLT_ARCNET_LINUX:
#ifdef PS_DLT_ARCNET_LINUX
      parsed = ps_dlt_ARCNET_LINUX(h->caplen, bytes);
#endif
      break;
    case DLT_LINUX_IRDA:
#ifdef PS_DLT_LINUX_IRDA
      parsed = ps_dlt_LINUX_IRDA(h->caplen, bytes);
#endif
      break;
    case DLT_LINUX_LAPD:
#ifdef PS_DLT_LINUX_LAPD
      parsed = ps_dlt_LINUX_LAPD(h->caplen, bytes);
#endif
      break;
    }
  if(parsed == 0)
    ps_serialize((guchar *) args, h, bytes);
  g_print("\n");
}
