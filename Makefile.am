bin_PROGRAMS=pwsafe
pwsafe_SOURCES=pwsafe.cpp pwsafe.1 system.h aclocal.m4

#  uncomment the following if pwsafe requires the math library
pwsafe_LDADD=$(X_LIBS) $(X_PRE_LIBS)

EXTRA_DIST=pwsafe.lsm.in pwsafe.spec.in

#  if you write a self-test script named `chk', uncomment the
#  following and add `chk' to the EXTRA_DIST list
#TESTS=chk

#  install the man pages
man_MANS=pwsafe.1
