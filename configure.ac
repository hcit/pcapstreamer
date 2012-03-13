#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([pcapstreamer], [0.2], [mohan43u@gmail.com], [], [http://github.com/mohan43u/pcapstreamer])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([src/ps_dlt_EN10MB.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Add libraries using pkg-config
PKG_CHECK_MODULES([PKGCFG], [glib-2.0 gthread-2.0], [],[])

# Add libraries using pcap-config
PCAPCFG_CFLAGS=$(pcap-config --cflags)
PCAPCFG_LIBS=$(pcap-config --libs)
AC_SUBST(PCAPCFG_CFLAGS, $PCAPCFG_CFLAGS)
AC_SUBST(PCAPCFG_LIBS, $PCAPCFG_LIBS)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h errno.h string.h unistd.h getopt.h signal.h netinet/if_ether.h netinet/ip.h netinet/tcp.h netinet/udp.h netinet/ip_icmp.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 src/Makefile])
AC_OUTPUT
