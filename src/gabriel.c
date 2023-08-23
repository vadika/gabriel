/*
 * gabriel.c
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

#include "gabriel.h"
#include "gabriel-client.h"

extern gboolean shutting_down;

static gint
gabriel_create_unix_server (Gabriel * gabriel,
                            gchar * bind_address,
                            gboolean abstract)
{
    gint ret;
    gint unix_server_sock;
    struct sockaddr_un addr;
    gchar *bind_addr;
    gint addr_len;
    struct stat sb;

    if (bind_address) {
        bind_addr = bind_address;
    }

    else {
        bind_addr = DEFAULT_UNIX_ADDRESS;
    }

    /* Now the client side */
    unix_server_sock = socket (PF_UNIX, SOCK_STREAM, 0);
    if (unix_server_sock < 0) {
        g_critical ("%s\n", strerror (errno));
        return unix_server_sock;
    }

    memset (&addr, 0, sizeof (struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    addr_len = strlen (bind_addr);

    if (abstract) {
        addr.sun_path[0] = '\0';
        addr_len++;

        strncpy (&addr.sun_path[1], bind_addr, addr_len);
    }

    else {
        strncpy (addr.sun_path, bind_addr, addr_len);

        /* Delete the socket file if it already exists */
        if (g_file_test (bind_addr, G_FILE_TEST_EXISTS)) {
            g_remove (bind_addr);
        }
    }

    ret = bind (unix_server_sock,
                (struct sockaddr *) &addr,
                G_STRUCT_OFFSET (struct sockaddr_un, sun_path) + addr_len);
    if (ret != 0) {
        g_critical ("%s\n", strerror (errno));
        goto beach;
    }

    ret = listen (unix_server_sock, 1024);
    if (ret != 0) {
        if (!shutting_down) {
            g_critical ("%s\n", strerror (errno));
        }
        goto beach;
    }

    g_print ("Listening to D-Bus clients on: ");

    if (abstract) {
        g_print ("\"unix:abstract=%s\"\n", bind_addr);
    }

    else {
        g_print ("\"unix:path=%s\"\n", bind_addr);
    }

    return unix_server_sock;

  beach:
    close (unix_server_sock);
    return -1;
}

static gint
gabriel_create_tcp_server (Gabriel * gabriel,
                           gchar * bind_address,
                           gint tcp_port)
{
    gint ret;
    gint tcp_server_sock;
    struct sockaddr_in addr;
    gchar *bind_addr;

    if (bind_address) {
        bind_addr = bind_address;
    }

    else {
        bind_addr = DEFAULT_TCP_ADDRESS;
    }

    /* Now the client side */
    tcp_server_sock = socket (PF_INET, SOCK_STREAM, 0);
    if (tcp_server_sock < 0) {
        g_critical ("%s\n", strerror (errno));
        return tcp_server_sock;
    }

    memset (&addr, 0, sizeof (struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons (tcp_port);
    inet_aton (bind_addr, &(addr.sin_addr));

    ret = bind (tcp_server_sock,
                (struct sockaddr *) &addr, sizeof (struct sockaddr_in));
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
             bind_addr, tcp_port);

    return tcp_server_sock;

  beach:
    close (tcp_server_sock);
    return -1;
}

void
gabriel_handle_clients (Gabriel * gabriel,
                        gchar * transport_method,
                        gchar * bind_address,
                        gint tcp_port)
{
    gint ret;
    gint server_socket;

    if (transport_method == NULL) {
        transport_method = DEFAULT_DBUS_TRANSPORT;
    }

    if (strcmp (transport_method, "tcp") == 0) {
        server_socket =
            gabriel_create_tcp_server (gabriel, bind_address, tcp_port);
    }

    else if (strcmp (transport_method, "unix") == 0) {
        server_socket =
            gabriel_create_unix_server (gabriel, bind_address, FALSE);
    }

    else if (strcmp (transport_method, "abstract-unix") == 0) {
#ifndef HAVE_ABSTRACT_SOCKETS
        g_critical ("abstract unix sockets not supported on your platform");
        return;
#else
        server_socket =
            gabriel_create_unix_server (gabriel, bind_address, TRUE);
#endif
    }

    else {
        g_critical
            ("%s transport method not supported yet, you must specify"
             " either of these: tcp, unix and abstract.\n",
             transport_method);
        return;
    }

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

        client = gabriel_client_new (gabriel, client_sock);
        gabriel_handle_client (client);
        gabriel_client_free (client);
    }

  beach:
    close (server_socket);
}

void
gabriel_free (Gabriel * gabriel)
{
    if (gabriel) {
        if (gabriel->ssh_session) {
            ssh_disconnect (gabriel->ssh_session);
        }

        if (gabriel->socat_address) {
            g_free (gabriel->socat_address);
        }

        g_free (gabriel);
    }
}

static gboolean
gabriel_parse_bus_address (Gabriel * gabriel)
{
    gboolean dbus_ret;
    DBusAddressEntry **entries;
    gint num_entries;
    DBusError error;
    const gchar *method;

    dbus_error_init (&error);
    dbus_ret = dbus_parse_address (gabriel->bus_address,
                                   &entries, &num_entries, &error);
    if (!dbus_ret || num_entries < 1) {
        if (dbus_error_is_set (&error)) {
            g_critical ("%s\n", strerror (errno));
        }

        else {
            g_critical ("Failed to parse D-Bus bus address: %s\n",
                        gabriel->bus_address);
        }

        return FALSE;
    }

    /* We are only concerned with the first entry */
    method = dbus_address_entry_get_method (entries[0]);

    if (strcmp ("unix", method) == 0) {
        const gchar *address =
            dbus_address_entry_get_value (entries[0], "abstract");

        if (address != NULL) {
            gabriel->socat_address =
                g_strjoin (":", "ABSTRACT-CONNECT", address, NULL);
        }

        else {
            const gchar *address =
                dbus_address_entry_get_value (entries[0], "path");

            if (address != NULL) {
                gabriel->socat_address =
                    g_strjoin (":", "UNIX-CONNECT", address, NULL);
            }

            else {
                g_critical ("Failed to parse D-Bus bus address: %s\n",
                            gabriel->bus_address);
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
                        gabriel->bus_address);
            return FALSE;
        }

        else {
            gabriel->socat_address = g_strjoin (":", "TCP4", host, port, NULL);
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


int verify_knownhost(ssh_session session)
{
    enum ssh_known_hosts_e state;
    unsigned char *hash = NULL;
    ssh_key srv_pubkey = NULL;
    size_t hlen;
    char buf[10];
    char *hexa;
    char *p;
    int cmp;
    int rc;
    rc = ssh_get_server_publickey(session, &srv_pubkey);
    if (rc < 0) {
        return -1;
    }
    rc = ssh_get_publickey_hash(srv_pubkey,
                                SSH_PUBLICKEY_HASH_SHA1,
                                &hash,
                                &hlen);
    ssh_key_free(srv_pubkey);
    if (rc < 0) {
        return -1;
    }
    state = ssh_session_is_known_server(session);
    switch (state) {
        case SSH_KNOWN_HOSTS_OK:
            /* OK */
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
            g_critical ( "Host key for server changed: it is now:\n");
            ssh_print_hexa("Public key hash", hash, hlen);
            g_critical ( "For security reasons, connection will be stopped\n");
            ssh_clean_pubkey_hash(&hash);
            return -1;
        case SSH_KNOWN_HOSTS_OTHER:
            g_critical ( "The host key for this server was not found but an other"
                    "type of key exists.\n");
            g_critical ( "An attacker might change the default server key to"
                    "confuse your client into thinking the key does not exist\n");
            ssh_clean_pubkey_hash(&hash);
            return -1;
        case SSH_KNOWN_HOSTS_NOT_FOUND:
            g_critical ( "Could not find known host file.\n");
            g_critical ( "If you accept the host key here, the file will be"
                    "automatically created.\n");
            /* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */
        case SSH_KNOWN_HOSTS_UNKNOWN:
            hexa = ssh_get_hexa(hash, hlen);
            g_critical ("The server is unknown. Do you trust the host key?\n");
            g_critical ( "Public key hash: %s\n", hexa);
            ssh_string_free_char(hexa);
            ssh_clean_pubkey_hash(&hash);
            p = fgets(buf, sizeof(buf), stdin);
            if (p == NULL) {
                return -1;
            }
            cmp = strncasecmp(buf, "yes", 3);
            if (cmp != 0) {
                return -1;
            }
            rc = ssh_session_update_known_hosts(session);
            if (rc < 0) {
                g_critical ("Error %s\n", strerror(errno));
                return -1;
            }
            break;
        case SSH_KNOWN_HOSTS_ERROR:
            g_critical ("Error %s", ssh_get_error(session));
            ssh_clean_pubkey_hash(&hash);
            return -1;
    }
    ssh_clean_pubkey_hash(&hash);
    return 0;
}



Gabriel *
gabriel_create (gchar * host,
                        gchar * bus_address,
                        gchar * username,
                        gchar * password)
{
    Gabriel *gabriel = g_new0 (Gabriel, 1);
    gint ret;

    gabriel->bus_address = bus_address;
    gabriel_parse_bus_address (gabriel);

    //SSH API changes... now options are part of a session
    gabriel->ssh_session = ssh_new ();
    if (!gabriel->ssh_session) {
        g_critical ("Failed to create ssh session\n");
        goto finland;
    }
    g_critical ("Connecting to %s\n", host);
    g_critical ("Using username %s\n", username);
    ssh_options_set (gabriel->ssh_session, SSH_OPTIONS_HOST, host);
    ssh_options_set (gabriel->ssh_session, SSH_OPTIONS_USER, username);

    ret = ssh_connect (gabriel->ssh_session);

    if (ret!=SSH_OK) {
        g_critical ("Failed to open ssh connection to %s -- %s\n", host, ssh_get_error (gabriel->ssh_session));
        goto finland;
    }

    // Verify the server's identity
    ret=verify_knownhost(gabriel->ssh_session);

    if (ret < 0)
    {
      ssh_disconnect(gabriel->ssh_session);
      ssh_free(gabriel->ssh_session);
      goto finland;
    }

    if(!password)
        password=getpass("Password: ");

    ret = ssh_userauth_password (gabriel->ssh_session, NULL, password);
    if (ret!=SSH_AUTH_SUCCESS) {
        g_critical ("Failed to authenticate user %s -- %s\n", username, ssh_get_error (gabriel->ssh_session));
    }

    ret = ssh_userauth_publickey_auto(gabriel->ssh_session, NULL, NULL);

    if (ret == SSH_AUTH_ERROR)
    {
     g_critical( "PK Authentication failed: %s\n",
       ssh_get_error(gabriel->ssh_session));
    goto finland;
    }

    return gabriel;

  finland:
    gabriel_free (gabriel);
    return NULL;
}
