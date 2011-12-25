#include <pcapstreamer.h>

int main(int argc, char *argv[])
{
  gchar *interface = NULL;
  pcap_t *handle = NULL;

  interface = pcs_get_any_dev();
  handle = pcs_open(interface);
  pcs_capture(handle);

  g_free(interface);
  return(0);
}
