dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.5)
AC_INIT(pwsafe.cpp)

dnl Every other copy of the package version number gets its value from here
AM_INIT_AUTOMAKE(pwsafe, 0.1.3)

dnl create a config.h file (Automake will add -DHAVE_CONFIG_H)
AM_CONFIG_HEADER(config.h)

dnl add a --debug to ./configure's arguments
AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [compile in debug support]),,[ enable_debug=no ])

AC_SUBST(VERSION)

ISODATE=`date +%Y-%m-%d`
AC_SUBST(ISODATE)

AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_CC
AC_PROG_CXX
AC_CHECK_TOOL([STRIP],[strip])

dnl Check for X
AC_PATH_XTRA

dnl Checks for libraries.
AC_CHECK_LIB(crypto, SHA1_Init, [], [AC_MSG_ERROR(openssl (libssl) is required)])
AC_CHECK_LIB(ncurses, initscr, [], [AC_MSG_ERROR(libncurses is required)])
AC_CHECK_LIB(readline, readline, [], [AC_MSG_ERROR(libreadline is required)])

dnl check for the X libraries
if test "$have_x" = yes; then
  CPPFLAGS="$CPPFLAGS $X_CFLAGS $X_LIBS"
  AC_CHECK_LIB(X11, XOpenDisplay,, $X_EXTRA_LIBS)
  AC_CHECK_LIB(Xmu, XmuInternAtom,, $X_EXTRA_LIBS)
fi

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h sys/param.h sys/time.h time.h sys/mkdev.h sys/sysmacros.h string.h memory.h fcntl.h dirent.h sys/ndir.h ndir.h alloca.h locale.h)
AC_CHECK_HEADERS(stdint.h errno.h termios.h getopt.h)
AC_CHECK_HEADERS(openssl/sha.h openssl/blowfish.h openssl/rand.h, [], [AC_MSG_ERROR(openssl headers (libssl-dev) are required)])
AC_CHECK_HEADERS(curses.h, [], [AC_MSG_ERROR(curses.h (libncurses-dev) is required)])
AC_CHECK_HEADERS(readline/readline.h, [], [AC_MSG_ERROR(readline/readline.h (libreadline-dev) is required)])
AC_CHECK_HEADERS(netinet/in.h, [], [AC_MSG_ERROR(netinet/in.h is required)])
if test "$have_x" = yes; then
AC_CHECK_HEADERS(X11/Xlib.h X11/Xatom.h X11/Xmu/Atoms.h)
fi

AC_HEADER_MAJOR
AC_STRUCT_TM

dnl Checks for typedefs, structures, and compiler characteristics.

dnl Checks for library functions.
AC_CHECK_FUNC(getopt_long, [], [AC_MSG_ERROR(getopt_long() is needed)])
AC_CHECK_FUNC(tcsetattr, [], [AC_MSG_ERROR(tcsetattr() is needed)])
AC_CHECK_FUNC(readline, [], [AC_MSG_ERROR(readline() is needed)])


dnl older readline.h's declared readline() without any arguments and outside of 'extern "C"', which freaks out C++
AC_LANG_PUSH(C++)
AC_MSG_CHECKING([if readline.h needs extern "C"])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
    [[
#include <stdio.h>
#include <readline/readline.h>]],
    [[char*x=readline("test"); 
      return (x?0:1);]]
  )],
  [AC_MSG_RESULT(no)], 
  [AC_DEFINE(READLINE_H_NEEDS_EXTERN_C, 1, [Define to 1 if readline/readline.h needs extern "C"]) 
   AC_MSG_RESULT(yes)])
AC_LANG_POP(C++)


dnl if we enabled debug, remove the -O2 and add -g; actually I override the -O2 by following it with -O0
if test "$enable_debug" = yes; then
  CFLAGS="$CFLAGS -O0 -g"
  CXXFLAGS="$CXXFLAGS -O0 -g"
  LDADD="$LDADD -g"
fi

AC_SUBST(CXXFLAGS)

AC_OUTPUT(Makefile pwsafe.lsm pwsafe.spec)

