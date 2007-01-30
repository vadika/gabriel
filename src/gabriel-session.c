/*
 * gabriel-session.c
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
#include "gabriel-client.h"

extern gboolean shutting_down;

static gint
gabriel_create_tcp_server (GabrielSession * session,
                           gchar * local_address,
                           gint tcp_port)
{
    gint ret;
    gint tcp_server_sock;
    struct sockaddr_in addr;

    /* Now the client side */
    tcp_server_sock = socket (PF_INET, SOCK_STREAM, 0);
    if (tcp_server_sock < 0) {
	g_critical ("%s\n", strerror (errno));
	return tcp_server_sock;
    }

    memset (&addr, 0, sizeof (struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons (tcp_port);
    inet_aton (local_address, &(addr.sin_addr));
    
    ret = bind (tcp_server_sock,
               (struct sockaddr *) &addr,
               sizeof (struct sockaddr_in));
    if (ret != 0) {
	g_critical ("%s\n", strerror (errno));
	goto beach;
    }
    
    ret = listen (tcp_server_sock, 1024);
    if (ret != 0) {
        if (!shutting_down) {
            g_critical ("%s\n", strerror (errno));
        }
        goto beach;
    }

    g_print ("Listening to D-Bus clients on: \"tcp:host=%s,port=%d\"\n",
            local_address, tcp_port);

    return tcp_server_sock;

beach:
    close (tcp_server_sock);
    return -1;
}

void gabriel_handle_clients (GabrielSession * session,
                             gchar * local_address,
                             gint tcp_port)
{
    gint ret;
    gint server_socket;
    struct sockaddr_in addr;

    /* Now the client side */
    server_socket = gabriel_create_tcp_server (session, local_address, tcp_port);
    if (server_socket < 0) {
	return;
    }

    while (!shutting_down) {
	GabrielClient *client;
        gint client_sock;

        client_sock = accept (server_socket, NULL, NULL);
        if (client_sock < 0) {
            if (!shutting_down) {
                g_critical ("%s\n", strerror (errno));
            }
            goto beach;
        }

	client = gabriel_client_new (session, client_sock);
        gabriel_handle_client (client);
	gabriel_client_free (client);
    }

beach:
    close (server_socket);
}

void
gabriel_session_free (GabrielSession * session)
{
    if (session) {
        if (session->ssh_session) {
            ssh_disconnect (session->ssh_session);
        }
        
        if (session->socat_address) {
            g_free (session->socat_address);
        }

        g_free (session);
    }
}

static gboolean
gabriel_session_parse_bus_address (GabrielSession *session)
{
    gboolean dbus_ret;
    DBusAddressEntry **entries;
    gint num_entries;
    DBusError error;
    const gchar *method;

    dbus_error_init (&error);
    dbus_ret = dbus_parse_address (session->bus_address,
                                   &entries,
                                   &num_entries,
                                   &error);
    if (!dbus_ret || num_entries < 1) {
        if (dbus_error_is_set (&error)) {
            g_critical ("%s\n", strerror (errno));
        }

        else {
            g_critical ("Failed to parse D-Bus bus address: %s\n",
                        session->bus_address);
        }

        return FALSE;
    }

    /* We are only concerned with the first entry */
    method = dbus_address_entry_get_method (entries[0]);
       
    if (strcmp ("unix", method) == 0) {
        const gchar *address = dbus_address_entry_get_value (entries[0], "abstract");

        if (address != NULL) {
            session->socat_address = g_strjoin (":", "ABSTRACT-CONNECT", address, NULL);
        }
        
        else {
	    const gchar *address = dbus_address_entry_get_value (entries[0], "path");
	    
	    if (address != NULL) {
		session->socat_address = g_strjoin (":", "UNIX-CONNECT", address, NULL);
	    }

	    else {
		g_critical ("Failed to parse D-Bus bus address: %s\n",
			session->bus_address);
		return FALSE;
	    }
        }
    }

    else if (strcmp ("tcp", method) == 0) {
        const gchar *host;
        const gchar *port;

        host = dbus_address_entry_get_value (entries[0], "host");
        port = dbus_address_entry_get_value (entries[0], "port");

        if (host == NULL || port == NULL) {
            g_critical ("Failed to parse D-Bus bus address: %s\n",
                        session->bus_address);
            return FALSE;
        }
        
        else {
            session->socat_address = g_strjoin (":", "TCP4", host, port, NULL);
        }
    }

    else {
        g_critical ("Only following transport methods supported yet: "
                    "tcp, unix.\n");
        return FALSE;
    }

    dbus_address_entries_free (entries);
    dbus_error_free (&error);

    return TRUE;
}

GabrielSession *
gabriel_session_create (gchar * host,
                        gchar * bus_address,
                        gchar * username,
                        gchar * password)
{
    GabrielSession *session = g_new0 (GabrielSession, 1);
    SSH_OPTIONS *ssh_options;
    gint ret;
    
    session->bus_address = bus_address;
    gabriel_session_parse_bus_address (session);
    
    ssh_options = ssh_options_new ();
    ssh_options_set_host (ssh_options, host);
    ssh_options_set_username (ssh_options, username);
    ssh_options_set_ssh_dir (ssh_options, "%s/.ssh");
    ssh_options_set_identity (ssh_options, "id_dsa");

    session->ssh_session = ssh_new ();
    if (!session->ssh_session) {
	g_critical ("Failed to create ssh session\n");
	goto finland;
    }
    ssh_set_options (session->ssh_session, ssh_options);

    ret = ssh_connect (session->ssh_session);

    if (ret) {
	g_critical ("Failed to open ssh connection to %s\n", host);
	goto finland;
    }

    ret = ssh_userauth_autopubkey (session->ssh_session);
    
    if (ret != SSH_AUTH_SUCCESS) {
	if (ret == SSH_AUTH_DENIED) {
	    g_warning ("Public key method didn't work out, "
                     "trying password method..\n");
        }
    
	if (ret == SSH_AUTH_DENIED || ret == SSH_AUTH_PARTIAL) {
            if (password == NULL) {
               password = getpass ("Password: ");

               if (password == NULL) {
                   g_critical ("%s\n", strerror (errno));
                   goto finland;
               }
            }

	    ret = ssh_userauth_password (session->ssh_session, username, password);
            /* Get rid of the passwd string ASAP */
            bzero (password, strlen (password));

	    if (ret != SSH_AUTH_SUCCESS) {
		g_critical ("Failed to authenticate to host: %s\n", host);
		goto finland;
	    }
	}

	else {
	    g_critical ("Failed to authenticate to host %s\n", host);
	    goto finland;
	}
    }

    return session;

finland:
    gabriel_session_free (session);
    return NULL;
}

