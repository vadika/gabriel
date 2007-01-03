dnl
dnl configure.ac for Gabriel
dnl Copyright (C) 2007, Zeeshan Ali <zeenix@gstreamer.net>
dnl
dnl Gabriel is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl Gabriel is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with Gabriel; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
dnl

dnl Process this file with autoconf to produce a configure script.
AC_INIT([Gabriel], [0.1], [zeenix@gstreamer.net], [gabriel])
AC_PREREQ([2.60])
AC_CONFIG_SRCDIR([client/gabriel.c])
AM_INIT_AUTOMAKE

dnl Checks for programs.
AC_PROG_CC

dnl Check for client side dependencies

dnl Check for libssh
AC_CHECK_LIB(ssh, ssh_new,
  build_client="yes",
  AC_MSG_WARN("Can't find libssh. Gabriel client shall not be built.")
  build_client="no")

if test "x$build_client" = "xyes"; then
    dnl Check for glib2
    PKG_CHECK_MODULES(GLIB2,glib-2.0 >= 2.10,HAVE_GLIB2=yes,HAVE_GLIB2=no)
    AC_SUBST(GLIB2_LIBS)
AC_SUBST(GLIB2_CFLAGS)

    if test "x$HAVE_GLIB2" = "xno"; then
        AC_MSG_WARN([Can't find Glib2. Gabriel client shall not be built.])
        build_client="no"
    fi
fi

AM_CONDITIONAL([BUILD_CLIENT], [test x$build_client = xyes])

dnl Check for server side dependencies now
AC_CHECK_PROG([have_socat], [socat], yes, no)
if [test x$have_socat == xyes]; then
    AC_CHECK_PROG([have_dbus_daemon], [dbus-daemon], yes, no)
    if [test x$have_dbus_daemon == xno]; then
        AC_MSG_WARN([Can't find dbus-daemon. Gabriel server shall not be built.])
    fi
else
    AC_MSG_WARN([Can't find socat, Gabriel server shall not be built.])
fi

AM_CONDITIONAL([BUILD_SERVER],
               [test x$have_socat == xyes -a x$have_dbus_daemon == xyes])

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

dnl Done.
AC_CONFIG_FILES([Makefile
 client/Makefile
 server/Makefile
 ])
AC_OUTPUT

