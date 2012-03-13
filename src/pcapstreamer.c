#include <pcapstreamer.h>

static void ps_getopt(int argc, char *argv[], GHashTable *arguments)
{
  gchar opt = '\0';
  gchar usage[] = "[usage] pcapstreamer "
    "[-l|--listdevices] "
    "[-i|--interface name|default|NULL] "
    "[-p|--parse]"
    "[-h|--help] -- pcap_expression1 pcap_expression2 ..]\n";
  struct option longopts[] = {{"listdevices", 0, NULL, 'l'},
			      {"interface", 1, NULL, 'i'},
			      {"parse", 0, NULL, 'p'},
			      {"help", 0, NULL, 'h'}};
  gchar *pcapexp = NULL;

  if(argc < 2)
    {
      g_printerr("%s", usage);
      exit(EXIT_FAILURE);
    }

  while((opt = getopt_long(argc, argv, "li:ph", longopts, NULL)) != -1)
    {
      switch(opt)
	{
	case 'l':
	  {
	    g_hash_table_insert(arguments, "listdevices", "1");
	  }
	  break;
	case 'i':
	  {
	    g_hash_table_insert(arguments, "interface", optarg);
	  }
	  break;
	case 'p':
	  {
	    g_hash_table_insert(arguments, "parse", "1");
	  }
	  break;
	case 'h':
	  {
	    g_print("%s", usage);
	    exit(EXIT_SUCCESS);
	  }
	default:
	  {
	    g_printerr("ps_getopt(): unknown option '%c'\n", opt);
	    exit(EXIT_FAILURE);
	  }
	}
    }

  pcapexp = g_strjoinv(" ", &argv[optind]);
  g_hash_table_insert(arguments, "pcapexp", pcapexp);
}

static void signal_cb(gint signum)
{
  pcap_breakloop(handle);
}

int main(int argc, char *argv[])
{
  GHashTable *arguments = g_hash_table_new(g_str_hash, g_str_equal); 
  struct bpf_program *program = NULL;
  gchar *interface = NULL;
  gchar *pcapexp = NULL;

  ps_getopt(argc, argv, arguments);
  if(g_strcmp0(g_hash_table_lookup(arguments, "listdevices"), "1") == 0)
    {
      ps_list_interfaces();
      exit(EXIT_SUCCESS);
    }

  interface = g_hash_table_lookup(arguments, "interface");
  if(interface == NULL ||
     g_strcmp0(interface, "NULL") == 0 ||
     g_strcmp0(interface, "null") == 0)
    handle = ps_init(NULL);
  else if(g_strcmp0(interface, "default") == 0)
    handle = ps_get_default_interface();
  else
    handle = ps_init(interface);
  g_hash_table_insert(arguments, "handle", handle);

  pcapexp = g_hash_table_lookup(arguments, "pcapexp");
  if(pcapexp != NULL)
    {
      program = ps_setup_filter(handle, pcapexp);
      g_hash_table_insert(arguments, "bpf_program", program);
    }

  signal(SIGINT, signal_cb);
  if(g_strcmp0(g_hash_table_lookup(arguments, "parse"), "1") == 0)
    ps_loop(handle, ps_parse, (guchar *) arguments);
  else
    ps_loop(handle, ps_serialize, (guchar *) arguments);

  if(program != NULL)
    pcap_freecode(program);
  pcap_close(handle);
  g_hash_table_remove_all(arguments);
  g_printerr("main(): bye..\n");
  return(0);
}
