bin_PROGRAMS=pwsafe
pwsafe_SOURCES=pwsafe.cpp pwsafe.1 system.h aclocal.m4
pwsafe_LDADD=$(X_LIBS) $(X_PRE_LIBS)

EXTRA_DIST=pwsafe.lsm.in pwsafe.spec.in selftest

TESTS=test/read test/create test/edit test/merge

man_MANS=pwsafe.1

