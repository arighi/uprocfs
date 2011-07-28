#                                               -*- Autoconf -*-
AC_PREREQ([2.59])
AC_INIT([uprocfs], [0.3], [andrea@betterlinux.com])
AC_CONFIG_SRCDIR([src/uproc.c])
AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST
AC_CANONICAL_TARGET

AM_INIT_AUTOMAKE([1.9])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PROG_CC

AC_CHECK_HEADERS([stdlib.h string.h sys/socket.h linux/connector.h linux/cn_proc.h \
                  libgen.h unistd.h slang.h])

AC_DEFINE_UNQUOTED([__BITS_PER_LONG], `getconf LONG_BIT`, [__BITS_PER_LONG])
AC_DEFINE_UNQUOTED([PAGE_SIZE], `getconf PAGE_SIZE`, [PAGE_SIE])
AC_DEFINE_UNQUOTED([CACHELINE_SIZE], `getconf LEVEL1_DCACHE_LINESIZE`, [CACHELINE_SIZE])

PKG_CHECK_MODULES([fuse], [fuse], [],
		[AC_ERROR(libfuse not found: install libfuse-dev or fuse-devel)])

AC_CONFIG_FILES([Makefile \
                 etc/Makefile \
                 include/Makefile \
                 src/Makefile \
                 tools/Makefile])
AC_OUTPUT
