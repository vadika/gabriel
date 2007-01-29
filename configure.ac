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
AC_CONFIG_SRCDIR([src/gabriel-main.c])
AM_INIT_AUTOMAKE

dnl Checks for programs.
AC_PROG_CC

dnl Check for dependencies

dnl Check for libssh
AC_CHECK_LIB(ssh, ssh_new,
  build_gabriel="yes",
  AC_MSG_ERROR("cannot find libssh. Gabriel shall not be built.")
  build_gabriel="no")

if test "x$build_gabriel" = "xyes"; then
    dnl Check for glib2
    PKG_CHECK_MODULES(GLIB2,glib-2.0 >= 2.10,HAVE_GLIB2=yes,HAVE_GLIB2=no)
    AC_SUBST(GLIB2_LIBS)
    AC_SUBST(GLIB2_CFLAGS)

    if test "x$HAVE_GLIB2" = "xno"; then
        AC_MSG_ERROR([cannot find Glib2. Gabriel shall not be built.])
        build_gabriel="no"
    fi
    
    dnl Check for D-Bus
    PKG_CHECK_MODULES(DBUS,dbus-1 >= 0.93,HAVE_DBUS=yes,HAVE_DBUS=no)
    AC_SUBST(DBUS_LIBS)
    AC_SUBST(DBUS_CFLAGS)

    if test "x$HAVE_DBUS" = "xno"; then
        AC_MSG_ERROR([cannot find D-Bus. Gabriel shall not be built.])
        build_gabriel="no"
    fi
fi

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(unistd.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

dnl Done.
AC_CONFIG_FILES([Makefile
 src/Makefile
 ])
AC_OUTPUT

