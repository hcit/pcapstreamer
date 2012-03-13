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

pcap_t* ps_init(gchar *device)
{
  pcap_if_t *interfaces = NULL;
  pcap_if_t *interface = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];

  if(pcap_findalldevs(&interfaces, errbuf) == -1)
    {
      g_printerr("ps_init(): %s\n", errbuf);
      exit(EXIT_FAILURE);
    }

  if(device != NULL)
    {
      while(interfaces)
	{
	  if(g_strcmp0(device, interfaces->name) == 0)
	    {
	      interface = interfaces;
	      break;
	    }
	  interfaces = interfaces->next;
	}
      if(interface == NULL)
	{
	  g_printerr("ps_init(): libpcap cannot find interface %s\n", device);
	  exit(EXIT_FAILURE);
	}
    }
  else
    {
      g_printerr("ps_init(): opening NULL interface, which means listening on"
		 " all available interfaces\n");
    }

  memset(errbuf, 0, PCAP_ERRBUF_SIZE);
  handle = pcap_open_live(device, SNAPLEN, PROMISC, TOMS, errbuf);
  if(handle == NULL)
    {
      g_printerr("pcap_init(): %s\n", errbuf);
      exit(EXIT_FAILURE);
    }
  if(strlen(errbuf) > 0)
    g_printerr("pcap_init(): %s\n", errbuf);
  g_printerr("pcap_init(): listening on %s ..\n", device);

  pcap_freealldevs(interfaces);
  return(handle);
}

void ps_list_interfaces(void)
{
  pcap_if_t *interfaces = NULL;
  gchar errbuf[PCAP_ERRBUF_SIZE];

  if(pcap_findalldevs(&interfaces, errbuf) == -1)
    {
      g_printerr("ps_list_interfaces(): %s\n", errbuf);
      exit(EXIT_FAILURE);
    }

  while(interfaces)
    {
      g_print("ps_list_interfaces(): %s [%s]\n",
	      interfaces->name,
	      (interfaces->description != NULL ? interfaces->description : ""));
      interfaces = interfaces->next;
    }

  pcap_freealldevs(interfaces);
}

pcap_t* ps_get_default_interface(void)
{
  gchar *device = NULL;
  gchar errbuf[PCAP_ERRBUF_SIZE];

  device = pcap_lookupdev(errbuf);
  if(device == NULL)
    {
      g_printerr("ps_get_default_interface(): %s\n", errbuf);
      exit(EXIT_FAILURE);
    }

  return(ps_init(device));
}

struct bpf_program* ps_setup_filter(pcap_t *handle, gchar *pregex)
{
  struct bpf_program *program = g_new0(struct bpf_program, 1);

  memset(program, 0, sizeof(struct bpf_program));
  if(pcap_compile(handle, program, pregex, OPTIMIZE, PCAP_NETMASK_UNKNOWN) == -1)
    {
      g_printerr("ps_setup_filter(): %s\n", pcap_geterr(handle));
      exit(EXIT_FAILURE);
    }
  if(pcap_setfilter(handle, program) == -1)
    {
      g_printerr("ps_setup_filter(): %s\n", pcap_geterr(handle));
      exit(EXIT_FAILURE);
    }

  return(program);
}

void ps_loop(pcap_t *handle, pcap_handler callbackfunc, guchar *args)
{
  gint returncode = 1;

  returncode = pcap_loop(handle, LOOPCNT, callbackfunc, args);
  switch(returncode)
    {
    case 0:
      g_printerr("ps_loop(): loop cnt exhausted\n");
      break;
    case -1:
      {
	g_printerr("ps_loop(): %s\n", pcap_geterr(handle));
	exit(EXIT_FAILURE);
      }
      break;
    case -2:
      g_printerr("ps_loop(): pcap_breakloop() called\n");
      break;
    }
}
