# Makefile.am for pcapstreamer

bin_PROGRAMS = pcapstreamer
pcapstreamer_SOURCES = pcapstreamer.h \
			pcapstreamer.c \
			ps_libpcap_functions.c \
			ps_parse.c \
			ps_serialize.c \
			ps_dlt_EN10MB.c \
			ps_dlt_LINUX_SLL.c \
			ps_icmp.c \
			ps_ip.c \
			ps_tcp.c \
			ps_udp.c
pcapstreamer_CFLAGS = $(PKGCFG_CFLAGS) @PCAPCFG_CFLAGS@
pcapstreamer_LDFLAGS = $(PKGCFG_LIBS) @PCAPCFG_LIBS@