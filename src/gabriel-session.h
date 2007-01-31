/*
 * gabriel-session.h
 *
 * Part of Gabriel project
 * Copyright (C) 2007, Zeeshan Ali <zeenix@gstreamer.net>
 *
 * Gabriel is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Gabriel is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Gabriel; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __GABRIEL_SESSION_H__
#define __GABRIEL_SESSION_H__

#include <libssh/libssh.h>
#include <dbus/dbus.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <glib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <glib.h>

#define DEFAULT_HOST "localhost"

#define DEFAULT_TCP_PORT 1337
#define DEFAULT_TCP_ADDRESS "localhost"
#define DEFAULT_UNIX_ADDRESS "/tmp/gabriel"

#ifdef HAVE_ABSTRACT_SOCKETS
#define DEFAULT_DBUS_TRANSPORT "abstract-unix"
#else
#define DEFAULT_DBUS_TRANSPORT "unix"
#endif /* HAVE_ABSTRACT_SOCKETS */

typedef struct
{
    SSH_SESSION *ssh_session;
    gchar * transport_method;   /* D-Bus bus transport method to emulate */
    gchar *bus_address;         /* D-Bus bus address on the remote */
    gchar *socat_address;       /* socket address socat will connect */
                                /* to, on the remote */
} GabrielSession;

GabrielSession * gabriel_session_create (gchar * host,
                                         gchar * transport_method,
                                         gchar * bus_address,
                                         gchar * username,
                                         gchar * password);
void gabriel_session_free (GabrielSession * session);
void gabriel_handle_clients (GabrielSession * session,
                             gchar * bind_address,
                             gint tcp_port);

#endif /* __GABRIEL_SESSION_H__ */
