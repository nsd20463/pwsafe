#!/bin/sh -x
# build pwsafe from source on a system where
#  * autoconf and friends are installed
#  * `make` is gnu make
# meaning linux, and possibly other OSes too
# The most common substitution is s/make/gmake/ on OSes where the default make is not gnu make.

aclocal && autoheader && automake --add-missing && autoconf && ./configure && make && make check
