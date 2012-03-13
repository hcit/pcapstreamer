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
