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

gint ps_icmp(gint32 caplen, const guchar *bytes)
{
  gint32 headerlength = 0;
  struct icmp *icmp = (struct icmp *) bytes;
  guchar *value = NULL;

  g_print(",icmp_type=%d", icmp->icmp_type);
  headerlength = sizeof(icmp->icmp_type);

  g_print(",icmp_code=%d", icmp->icmp_code);
  headerlength += sizeof(icmp->icmp_code);

  g_print(",icmp_cksum=%d", ntohs(icmp->icmp_cksum));
  headerlength += sizeof(icmp->icmp_cksum);

  switch(icmp->icmp_type)
    {
      /*
       * source: http://www.networksorcery.com/enp/protocol/icmp.htm
       * parsing been done based on information from above link.
       */
    case 0: /* ICMP Echo Reply */
    case 8: /* ICMP Echo Request */
      {
	g_print(",icd_id=%d", ntohs(icmp->icmp_hun.ih_idseq.icd_id));
	headerlength += sizeof(icmp->icmp_hun.ih_idseq.icd_id);
	g_print(",icd_seq=%d", ntohs(icmp->icmp_hun.ih_idseq.icd_seq));
	headerlength += sizeof(icmp->icmp_hun.ih_idseq.icd_seq);

	if(caplen > headerlength)
	  {
	    value = ps_streamout(caplen - headerlength, bytes + headerlength);
	    g_print(",data=%s", value);
	    g_free(value);
	  }
      }
      break;
    case 3: /* ICMP Destination Unreachable */
      {
	g_print(",ipm_void=%d", ntohs(icmp->icmp_hun.ih_pmtu.ipm_void));
	headerlength += sizeof(icmp->icmp_hun.ih_pmtu.ipm_void);
	g_print(",ipm_nextmtu=%d", ntohs(icmp->icmp_hun.ih_pmtu.ipm_nextmtu));
	headerlength += sizeof(icmp->icmp_hun.ih_pmtu.ipm_nextmtu);

	/*
	 * source: http://www.networksorcery.com/enp/protocol/icmp/msg3.htm
	 * this is the IP packet which have the destination not reachable
	 */
	if(caplen > headerlength)
	  ps_ip(caplen - headerlength, bytes + headerlength);
      }
      break;
    case 11:
      {
	g_print(",ih_void=%d",ntohl(icmp->icmp_hun.ih_void));
	headerlength += sizeof(icmp->icmp_hun.ih_void);

	/*
	 * source: http://www.networksorcery.com/enp/protocol/icmp/msg11.htm
	 * this is the IP packet which got time exceeds message from different hops.
	 */
	if(caplen > headerlength)
	  ps_ip(caplen - headerlength, bytes + headerlength);
      }
      break;
    default:
      {
	if(caplen > headerlength)
	  {
	    value = ps_streamout(caplen - headerlength, bytes + headerlength);
	    g_print(",data=%s", value);
	    g_free(value);
	  }
      }
    }

  return(1);
}
