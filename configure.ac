# Init
AC_INIT([udperf], [0.0.1], [i.ucar86@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
CFLAGS+="-pedantic -Wall -std=gnu99"

# Checks for programs
AC_PROG_CC
AC_PREREQ

# Checks for header files
AC_CHECK_HEADERS([stdlib.h],, [AC_MSG_ERROR([<stdlib.h> required])])
AC_CHECK_HEADERS([arpa/inet.h],, [AC_MSG_ERROR([<arpa/inet.h> required])])
AC_CHECK_HEADERS([fcntl.h],, [AC_MSG_ERROR([<fcntl.h> required])])
AC_CHECK_HEADERS([sys/time.h],, [AC_MSG_ERROR([<sys/time.h> required])])

# Checks for typedefs, structures, and compiler characteristics
AC_TYPE_OFF_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions
AC_CHECK_FUNCS([gettimeofday],, [AC_MSG_ERROR([gettimeofday required])])
AC_CHECK_FUNCS([memset],, [AC_MSG_ERROR([memset required])])
AC_CHECK_FUNCS([socket],, [AC_MSG_ERROR([socket required])])
AC_CHECK_FUNCS([strtoul],, [AC_MSG_ERROR([strtoul required])])
AC_FUNC_MALLOC

# Defines
AC_ARG_ENABLE([cpu-counters],
  AS_HELP_STRING([--enable-cpu-counters],
    [enable CPU performance counters reporting]),
  AC_DEFINE([CPU_COUNTERS], [], [set CPU_COUNTERS]))
AC_ARG_ENABLE([dma-latency],
  AS_HELP_STRING([--enable-dma-latency],
    [enable specification of max latency]),
  AC_DEFINE([DMA_LATENCY], [], [set DMA_LATENCY]))

# Output files
AC_CONFIG_HEADERS([src/config.h])
AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
