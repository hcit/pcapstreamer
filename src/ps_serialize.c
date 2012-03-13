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

guchar* ps_hexstreamout(gint32 caplen, const guchar *bytes)
{
  gint byte_iter = 0;
  GString *streamout = g_string_new("");
  guchar *out = NULL;

  while(byte_iter < caplen)
    {
      g_string_append_printf(streamout,
			     (streamout->len > 0 ? ":%x" : "%x"),
			     bytes[byte_iter]);
      byte_iter++;
    }
  out = g_strdup(streamout->str);
  g_string_free(streamout, TRUE);
  return(out);
}

guchar* ps_streamout(gint32 caplen, const guchar *bytes)
{
  gint byte_iter = 0;
  gint bit_iter = 0;
  guchar bit = 128;
  guchar lmbit = 0;
  GString *streamout = g_string_new("");
  guchar *out = NULL;

  while(byte_iter < caplen)
    {
      bit_iter = 0;
      g_string_append_printf(streamout, (streamout->len > 0 ? " " : ""));
      while(bit_iter < 8)
	{
	  lmbit = (guchar) (bytes[byte_iter] << bit_iter);
	  g_string_append_printf(streamout, "%u", ((lmbit & bit) == bit ? 1 : 0));
	  bit_iter++;
	}
      byte_iter++;
    }
  out = g_strdup(streamout->str);
  g_string_free(streamout, TRUE);
  return(out);
}

void ps_serialize(guchar *args, const struct pcap_pkthdr *h, const guchar *bytes)
{
  gchar captime[512];
  gchar *out = NULL;
  pcap_t *handle = g_hash_table_lookup((GHashTable *) args, "handle");
  gint datalink = pcap_datalink(handle);

  if(h->len > h->caplen)
    {
      g_printerr("ps_serialize(): h->len is greater than h->caplen\n");
      exit(EXIT_FAILURE);
    }

  strftime(captime, 512, "%Y%m%d%H%M%S",localtime(&h->ts.tv_sec));
  g_printerr("[cl:%d l:%d t:%s.%ld dl:%s] ",
	     h->caplen,
	     h->len,
	     captime,
	     h->ts.tv_usec,
	     pcap_datalink_val_to_name(datalink));
  out = ps_streamout(h->caplen, bytes);
  g_print("%s\n", out);
  g_free(out);
}
