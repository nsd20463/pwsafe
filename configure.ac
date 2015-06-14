dnl Process this file with autoconf to produce a configure script.
dnl confgure.ac for pwsafe
dnl $Id$

AC_PREREQ(2.5)

dnl Every other copy of the package version number gets its value from the following line
dnl NOTE WELL: the ' ' after the comma is required by "./nsd release".
AC_INIT([pwsafe.cpp], [0.2.0])
AM_INIT_AUTOMAKE

dnl create a config.h file (Automake will add -DHAVE_CONFIG_H)
AM_CONFIG_HEADER(config.h)


dnl --with-openssl-dir=dir
AC_ARG_WITH(openssl-dir, AC_HELP_STRING([--with-openssl-dir=DIR], [indicate where openssl is installed (default=/usr)]),,)
if test "$with_openssl_dir" = no; then
  AC_MSG_ERROR(openssl is required is not supported)
fi
if test -n "$with_openssl_dir" && test "$with_openssl_dir" != yes; then
  CPPFLAGS="$CPPFLAGS -I${with_openssl_dir}/include"
  LDFLAGS="$LDFLAGS -L${with_openssl_dir}/lib"
fi


dnl --with-readline or without
AC_ARG_WITH(readline, AC_HELP_STRING([--with-readline], [use readline for read input (default=yes)]),,with_readline=yes)
if test "$with_readline" != no; then
  AC_DEFINE(WITH_READLINE, 1, [Define to 1 to enable use of gnu libreadline for input])
fi


dnl --with-getopt_long or without
dnl note: there is also a test to see if getopt_long exists. both it and this have to be true for it to be use
AC_ARG_WITH(getopt_long, AC_HELP_STRING([--with-getopt_long], [use getopt_long to parse arguments (default=yes if available)]),,with_getopt_long=yes)


dnl --enable-debug
AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [compile in debug support (default=no)]),,)


AC_SUBST(VERSION)

ISODATE=`date +%Y-%m-%d`
AC_SUBST(ISODATE)

AC_CANONICAL_HOST

dnl Checks for programs.
AC_PROG_INSTALL
AC_PROG_CC
AC_PROG_CXX
AC_CHECK_TOOL([STRIP],[strip])

dnl check for or fix up some types and functions
AC_TYPE_PID_T
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_CHECK_TYPES(long long)
AC_FUNC_MEMCMP

dnl Check for X
AC_PATH_XTRA

dnl if this is OS X then we're going to need -flat_namespace -supress undefined in order to build against the X libraries
dnl and since it doesn't hurt otherwise, always use the option (thanks to Robert)
case $ac_sys_system/$ac_sys_release in
  Darwin/*)LDFLAGS="$LDFLAGS -flat_namespace -undefined suppress";;
esac

dnl Checks for libraries.
dnl AM_WITH_REGEX
AC_CHECK_LIB(crypto, SHA1_Init, [], [AC_MSG_ERROR(openssl (libssl) is required)])
if test "$with_readline" != no; then
dnl look for libncurses, fall back to libcurses if it's not found
AC_CHECK_LIB(ncurses, initscr,
			 LIBS="$LIBS -lncurses"
			 HAVE_LIBNCURSES=
			 ,
			 AC_CHECK_LIB(curses, initscr,
						  LIBS="$LIBS -lcurses"
						  HAVE_LIBCURSES=
						  ,
						  AC_MSG_RESULT(no)
						  )
			 )
AC_CHECK_LIB(readline, readline, [], [AC_MSG_ERROR(libreadline cannot be found)])
dnl make sure libreadline works with the lib[n]curses we found
AC_MSG_CHECKING([if libreadline works with curses])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM(
    [[
#include <stdio.h>
#include <readline/readline.h>
    ]],[[
  char*x=readline("test"); 
  return (x?0:1);
    ]]
  )],
  [AC_MSG_RESULT(yes)],
  [AC_MSG_ERROR(no)]
)
fi

dnl check for the X libraries
if test "$have_x" = yes; then
  CPPFLAGS="$CPPFLAGS $X_CFLAGS $X_LIBS"
  AC_CHECK_LIB(X11, XOpenDisplay,, $X_EXTRA_LIBS)
  AC_CHECK_LIB(Xmu, XmuInternAtom,, $X_EXTRA_LIBS)
fi

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h sys/param.h sys/time.h time.h sys/types.h sys/mkdev.h sys/sysmacros.h string.h memory.h fcntl.h dirent.h sys/ndir.h ndir.h alloca.h locale.h fcntl.h signal.h sys/select.h sys/resource.h sys/socket.h sys/un.h sys/mman.h)
AC_CHECK_HEADERS(stdint.h errno.h termios.h getopt.h)
AC_CHECK_HEADERS(openssl/sha.h openssl/blowfish.h openssl/rand.h, [], [AC_MSG_ERROR(openssl headers (libssl-dev) are required)])
if test "$with_readline" != no; then
AC_CHECK_HEADERS(curses.h, [], [AC_MSG_ERROR(curses.h (lib[n]curses-dev) is required by readline)])
AC_CHECK_HEADERS(readline/readline.h, [], [AC_MSG_ERROR(readline/readline.h (libreadline-dev) can't be found)])
fi
AC_CHECK_HEADERS(netinet/in.h, [], [AC_MSG_ERROR(netinet/in.h is required)])
if test "$have_x" = yes; then
AC_CHECK_HEADERS(X11/Xlib.h X11/Xatom.h X11/Xmu/Atoms.h)
fi

AC_HEADER_MAJOR
AC_STRUCT_TM

dnl Checks for typedefs, structures, and compiler characteristics.

dnl MacOSX, for example, does not define socklen_t
AC_CHECK_TYPE(socklen_t,[AC_DEFINE(HAVE_SOCKLEN_T, 1, [Define to 1 if the type socklen_t exists])],,[
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
 ])


dnl Checks for library functions.
AC_SYS_POSIX_TERMIOS
if test "$am_cv_sys_posix_termios" != yes -a "$ac_cv_sys_posix_termios" != yes; then
  AC_MSG_ERROR("POSIX termios operations are required")
fi
if test "$with_getopt_long" != no; then
 AC_CHECK_FUNC(getopt_long, [AC_DEFINE(HAS_GETOPT_LONG, 1, [Define to 1 if getopt_long is supported])], [])
fi
AC_CHECK_FUNC(tcsetattr, [], [AC_MSG_ERROR(tcsetattr() is needed)])
AC_CHECK_FUNC(setrlimit, [AC_DEFINE(HAVE_SETRLIMIT, 1, [Define to 1 if setrlimit is supported])], [])
if test "$with_readline" != no; then
AC_CHECK_FUNC(readline, [], [AC_MSG_ERROR(readline() is needed)])
fi


if test "$with_readline" != no; then
dnl older readline.h's declared readline() without any arguments and outside of 'extern "C"', which freaks out C++
AC_LANG_PUSH(C++)
AC_MSG_CHECKING([if readline.h needs extern "C"])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
    [[
#include <stdio.h>
#include <readline/readline.h>
    ]],[[
  char*x=readline("test"); 
  return (x?0:1);
    ]]
  )],
  [AC_MSG_RESULT(no)], 
  [AC_DEFINE(READLINE_H_NEEDS_EXTERN_C, 1, [Define to 1 if readline/readline.h needs extern "C"]) 
   AC_MSG_RESULT(yes)])
AC_LANG_POP(C++)
fi


if test "$with_readline" != no; then
dnl slightly newer but still broken readline.h's use extern "C" but don't declare arguments as const
AC_LANG_PUSH(C++)
AC_MSG_CHECKING([if readline.h lacks 'const' in its declarations])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
    [[
#include <stdio.h>
#if READLINE_H_NEEDS_EXTERN_C
extern "C" {
#endif
#include <readline/readline.h>
#if READLINE_H_NEEDS_EXTERN_C
} // terminate extern "C"
#endif

    ]],[[
  const char* prompt = "abc";
  char*x = readline(prompt);
    ]]
  )],
  [AC_MSG_RESULT(no)],
  [AC_DEFINE(READLINE_H_USES_NO_CONST, 1, [Define to 1 if readline/readline.h doesn't properly declare arguments to be const])
   AC_MSG_RESULT(yes)])
AC_LANG_POP(C++)
fi

if test "$with_readline" != no; then
dnl some other broken readline.h's use extern "C" and declare arguments for most everything, except for the callback functions
AC_LANG_PUSH(C++)
AC_MSG_CHECKING([if readline.h lacks types in its declaration of callbacks])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
    [[
#include <stdio.h>
#if READLINE_H_NEEDS_EXTERN_C
extern "C" {
#endif
#include <readline/readline.h>
#if READLINE_H_NEEDS_EXTERN_C
} // terminate extern "C"
#endif

#ifdef READLINE_H_USES_NO_CONST
char* dummy_completion(char*, int) { return 0; }
#else
char* dummy_completion(const char*, int) { return 0; }
#endif
    ]],[[
  rl_completion_entry_function = dummy_completion;
    ]]
  )],
  [AC_MSG_RESULT(no)],
  [AC_DEFINE(READLINE_H_LACKS_TYPES_FOR_CALLBACKS, 1, [Define to 1 if readline/readline.h lacks proper declarations for callbacks])
   AC_MSG_RESULT(yes)])
AC_LANG_POP(C++)
fi


if test "$with_readline" != no; then
dnl some more readline.h's use extern "C" and declare const arguments, but the completion callback is expected to return int rather than char*
AC_LANG_PUSH(C++)
AC_MSG_CHECKING([if readline.h expects completion callbacks to return int])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
    [[
#include <stdio.h>
#if READLINE_H_NEEDS_EXTERN_C
extern "C" {
#endif
#include <readline/readline.h>
#if READLINE_H_NEEDS_EXTERN_C
} // terminate extern "C"
#endif

#ifdef READLINE_H_USES_NO_CONST
int dummy_completion(char*, int) { return 0; }
#else
int dummy_completion(const char*, int) { return 0; }
#endif
    ]],[[
  rl_completion_entry_function = dummy_completion;
    ]]
  )],
  [AC_DEFINE(READLINE_H_COMPLETION_RETURNS_INT, 1, [Define to 1 if readline/readline.h completion callback should return int rather than char*])
   AC_MSG_RESULT(yes)],
  [AC_MSG_RESULT(no)])
AC_LANG_POP(C++)
fi


dnl some systems do not supply getline()
AC_MSG_CHECKING([if getline() is supported])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
    [[
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
    ]],[[
    char* buf = 0;
    size_t len = 0;
    getline(&buf,&len,0);
    ]]
  )],
  [AC_DEFINE(HAS_GETLINE, 1, [Define to 1 if getline() is supported])
   AC_MSG_RESULT(yes)],
  [AC_MSG_RESULT(no)])



dnl if we enabled debug, remove the -O2 and add -g; actually I override the -O2 by following it with -O0
if test "$enable_debug" = yes; then
  CFLAGS="$CFLAGS -O0 -g"
  CXXFLAGS="$CXXFLAGS -O0 -g"
  LDADD="$LDADD -g"
fi

AC_SUBST(CXXFLAGS)

AC_OUTPUT(Makefile pwsafe.1 pwsafe.lsm pwsafe.spec)


