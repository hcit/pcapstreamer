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
