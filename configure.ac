dnl Process this file with autoconf to produce a configure script.
dnl confgure.ac for pwsafe
dnl $Id$

AC_PREREQ(2.5)
AC_INIT(pwsafe.cpp)

dnl Every other copy of the package version number gets its value from here
dnl (Except the header in the pwsafe.1)
AM_INIT_AUTOMAKE(pwsafe, 0.1.4)

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
AC_ARG_WITH(readline, 
            AC_HELP_STRING([--with-readline], [use readline for read input (default=yes)]),,with_readline=yes)
AC_MSG_RESULT($with_readline)

if test "$with_readline" != no; then
  AC_DEFINE(WITH_READLINE, 1, [Define to 1 to enable use of gnu libreadline for input])
fi

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

dnl Checks for libraries.
dnl AM_WITH_REGEX
AC_CHECK_LIB(crypto, SHA1_Init, [], [AC_MSG_ERROR(openssl (libssl) is required)])
if test "$with_readline" != no; then
AC_CHECK_LIB(ncurses, initscr, [], [AC_MSG_ERROR(libncurses (required by readline) can't be found)])
AC_CHECK_LIB(readline, readline, [], [AC_MSG_ERROR(libreadline can't be found)])
fi
dnl check for the X libraries
if test "$have_x" = yes; then
  CPPFLAGS="$CPPFLAGS $X_CFLAGS $X_LIBS"
  AC_CHECK_LIB(X11, XOpenDisplay,, $X_EXTRA_LIBS)
  AC_CHECK_LIB(Xmu, XmuInternAtom,, $X_EXTRA_LIBS)
fi

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h sys/param.h sys/time.h time.h sys/mkdev.h sys/sysmacros.h string.h memory.h fcntl.h dirent.h sys/ndir.h ndir.h alloca.h locale.h fcntl.h)
AC_CHECK_HEADERS(stdint.h errno.h termios.h getopt.h)
AC_CHECK_HEADERS(openssl/sha.h openssl/blowfish.h openssl/rand.h, [], [AC_MSG_ERROR(openssl headers (libssl-dev) are required)])
if test "$with_readline" != no; then
AC_CHECK_HEADERS(curses.h, [], [AC_MSG_ERROR(curses.h (libncurses-dev) is required by readline)])
AC_CHECK_HEADERS(readline/readline.h, [], [AC_MSG_ERROR(readline/readline.h (libreadline-dev) can't be found)])
fi
AC_CHECK_HEADERS(netinet/in.h, [], [AC_MSG_ERROR(netinet/in.h is required)])
if test "$have_x" = yes; then
AC_CHECK_HEADERS(X11/Xlib.h X11/Xatom.h X11/Xmu/Atoms.h)
fi

AC_HEADER_MAJOR
AC_STRUCT_TM

dnl Checks for typedefs, structures, and compiler characteristics.

dnl Checks for library functions.
AM_SYS_POSIX_TERMIOS
if test "$am_cv_sys_posix_termios" != yes; then
  AC_MSG_ERROR("POSIX termios operations are required")
fi
AC_CHECK_FUNC(getopt_long, [], [AC_MSG_ERROR(getopt_long() is needed)])
dnl AC_CHECK_FUNC(tcsetattr, [], [AC_MSG_ERROR(tcsetattr() is needed)])
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

dnl different versions of g++ implement allocators differently. Figure out what kind this g++ uses.
dnl Note: g++ 3.0 is too broken to be supported, use 2.96 or 3.y, y>=1.
AC_LANG_PUSH(C++)
AC_MSG_CHECKING([if std::basic_string uses SGI-style allocator])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
    [[
#include <string>
#include <memory>

class test_alloc {
public:
  static void* allocate(size_t) { return 0; }
  static void deallocate(void*, size_t) {}
  static void* reallocate(void*,size_t,size_t) { return 0; }
  bool operator==(const test_alloc&) const { return true; }
  bool operator!=(const test_alloc&) const { return false; }
};

typedef std::basic_string<char, std::string::traits_type, test_alloc> test_string;
    ]],[[
  test_string s("test");
  return s.size();
    ]]
  )],
  [AC_DEFINE(BASIC_STRING_USES_SGI_STYLE_ALLOCATOR, 1, [Define to 1 if std::basic_string uses SGI-style allocator])
   AC_MSG_RESULT(yes)],
  [AC_MSG_RESULT(no)])
AC_LANG_POP(C++)


dnl not all systems have fcntl(, F_SETFL, O_ASYNC) or fcntl(, F_SETOWN, )
AC_MSG_CHECKING([if fcntl() supports F_SETOWN and F_SETFL+O_ASYNC])
AC_COMPILE_IFELSE(
  [AC_LANG_PROGRAM(
    [[
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
    ]],[[
  fcntl(STDIN_FILENO, F_GETFL);
  fcntl(STDIN_FILENO, F_SETFL, O_ASYNC);
  fcntl(STDIN_FILENO, F_SETOWN, 1);
    ]]
  )],
  [AC_DEFINE(HAVE_FCNTL_SETOWN_AND_ASYNC, 1, [Define to 1 if fcntl() supports F_SETFL+O_ASYNC and F_SETOWN])
   AC_MSG_RESULT(yes)],
  [AC_MSG_RESULT(no)])



dnl if we enabled debug, remove the -O2 and add -g; actually I override the -O2 by following it with -O0
if test "$enable_debug" = yes; then
  CFLAGS="$CFLAGS -O0 -g"
  CXXFLAGS="$CXXFLAGS -O0 -g"
  LDADD="$LDADD -g"
fi

AC_SUBST(CXXFLAGS)

AC_OUTPUT(Makefile pwsafe.lsm pwsafe.spec)


