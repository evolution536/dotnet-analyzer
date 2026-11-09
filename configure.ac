#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([dotnet-analyzer], [1.0])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([.])
AC_PREFIX_DEFAULT(/opt/dotnet-analyzer)

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_C_CONST
AC_LANG([C++])
CXXFLAGS='-Wall -std=c++11 -O3'

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([vector string sstream iostream cstdint cstring])

#AC_CHECK_LIB([lzo2], [lzo1x_decompress], [], [AC_MSG_ERROR(could not find liblzo2)])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_CHECK_FUNCS([memcpy fopen fread fwrite localtime strftime mktime])

AC_OUTPUT(Makefile)
