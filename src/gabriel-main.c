/*
 * gabriel-main.c
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

#include "gabriel-session.h"

gboolean shutting_down;

static void
signal_handler (gint sig_num)
{
    struct sigaction sig_action;

    switch (sig_num) {
        case SIGINT:
            /* reset the unix signals */
            sig_action.sa_flags = SA_RESETHAND;
            sigaction (SIGINT, &sig_action, NULL);
            sigaction (SIGTERM, &sig_action, NULL);
            shutting_down = TRUE;
            break;
        default:
            break;
    }
}

gint
main (gint argc, gchar ** argv)
{
    struct sigaction sig_action;
    GabrielSession *session;
    GOptionContext *context;
    GError *error = NULL;
    gchar *host = DEFAULT_HOST;
    gchar *username = NULL;
    gchar *password = NULL;
    gchar *transport_method = DEFAULT_DBUS_TRANSPORT;
    gchar *bind_address = NULL;
    gchar *bus_address = NULL;
    gint tcp_port = DEFAULT_TCP_PORT;
    gint ret = 0;

    GOptionEntry entries[] = {
        {"host", 'h', 0, G_OPTION_ARG_STRING, &host,
         "Hostname or IP of the remote host", "HOSTNAME"},
        {"username", 'u', 0, G_OPTION_ARG_STRING, &username,
         "Username on the remote host", "USERNAME"},
        {"password", 'p', 0, G_OPTION_ARG_STRING, &password,
         "Password on the remote host", "PASSWORD"},
        {"method", 'm', 0, G_OPTION_ARG_STRING, &transport_method,
         "The D-Bus transport method to use", "DBUS_TRANSPORT_METHOD"},
        {"bind", 'b', 0, G_OPTION_ARG_STRING, &bind_address,
         "The address to listen for D-Bus client connections on", "HOSTNAME"},
        {"bus-address", 'd', 0, G_OPTION_ARG_STRING, &bus_address,
         "The bus address of the remote D-Bus daemon",
         "BUS_ADDRESS"},
        {"port", 't', 0, G_OPTION_ARG_INT, &tcp_port,
         "The TCP port to listen for DBus client connections on", "PORT"},
        {NULL}
    };

    context = g_option_context_new ("- Gabriel");
    g_option_context_add_main_entries (context, entries, NULL);
    g_option_context_parse (context, &argc, &argv, &error);

    if (bus_address == NULL) {
        bus_address = (gchar *) g_getenv ("DBUS_SESSION_BUS_ADDRESS");

        if (bus_address == NULL) {
            g_critical ("The address of the D-Bus session bus must be"
                        "provided either using the commandline option"
                        "or the environment varriable"
                        "'DBUS_SESSION_BUS_ADDRESS'\n");
            ret = -1;
            goto beach;
        }
    }

    if (username == NULL) {
        username = (gchar *) g_get_user_name ();
    }

    /* set the unix signals */
    bzero (&sig_action, sizeof (sig_action));
    sig_action.sa_handler = signal_handler;
    sigaction (SIGINT, &sig_action, NULL);
    sigaction (SIGTERM, &sig_action, NULL);

    session =
        gabriel_session_create (host, transport_method, bus_address, username,
                                password);
    if (session == NULL) {
        ret = -2;
        goto beach;
    }

    shutting_down = FALSE;
    gabriel_handle_clients (session, bind_address, tcp_port);

    gabriel_session_free (session);

  beach:
    return ret;
}
