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
 * GNU Robots is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Robots; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <libssh/libssh.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <glib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

#define DEFAULT_TCP_PORT 1337
#define DEFAULT_ADDRESS "localhost"

gboolean shutting_down;

static void
signal_handler (gint sig_num)
{
    struct sigaction sig_action;

    switch (sig_num) {
        case SIGINT:
            /* reset the unix signals */
            bzero (&sig_action, sizeof (sig_action));
            sig_action.sa_handler = SIG_DFL;
            sigaction (SIGINT, &sig_action, NULL);
            shutting_down = TRUE;
            break;
        default:
            break;
    }
}

CHANNEL *
gabriel_channel_create (SSH_SESSION * ssh_session)
{
    CHANNEL *channel = NULL;
    gint ret;

    channel = channel_new (ssh_session);
    if (!channel) {
	g_critical ("Failed to create an ssh channel\n");
	goto beach;
    }

    ret = channel_open_session (channel);
    if (ret) {
	g_critical ("Failed to open ssh session channel\n");
	goto finland;
    }

    ret = channel_request_exec (channel,
                                "socat - UNIX-CONNECT:/tmp/gabriel");
    if (ret) {
	g_critical ("Failed to start socat on the remote\n");
	goto finland;
    }

beach:
   return channel;

finland:
    channel_free (channel);
    return NULL;
}

void
gabriel_channel_free (CHANNEL * channel)
{
    channel_free (channel);
}

typedef struct
{
    SSH_SESSION *ssh_session;
    gint sock;
} GabrielClient;

GabrielClient *
gabriel_client_new (SSH_SESSION * ssh_session, gint sock)
{
    GabrielClient *client = g_malloc (sizeof (GabrielClient));
    client->ssh_session = ssh_session;
    client->sock = sock;

    return client;
}

void
gabriel_client_free (GabrielClient * client)
{
  close (client->sock);
  free (client);
}

void gabriel_handle_client (GabrielClient * client)
{
    fd_set fds;
    struct timeval timeout;
    gchar buffer[10];
    BUFFER *readbuf = buffer_new ();
    CHANNEL *channels[] = {NULL, NULL};
    CHANNEL *outchannel[2];
    CHANNEL *channel;
    gint lus;
    gint eof = 0;
    gint ret;

    channel = channels[0] = gabriel_channel_create (client->ssh_session);

    if (channel == NULL) {
        goto beach;
    }
   
    while (channel_is_open (channel) && !eof) {
        do {
            FD_ZERO (&fds);
            if (!eof)
                FD_SET (client->sock, &fds);
            timeout.tv_sec = 30;
            timeout.tv_usec = 0;
            ret = ssh_select (channels, outchannel, client->sock + 1, &fds, &timeout);
        } while (ret == SSH_EINTR && !shutting_down);

        if (shutting_down) {
           goto near_beach;
        }

        if (FD_ISSET (client->sock, &fds)) {
            lus = read (client->sock, buffer, 10);
            if (lus) {
                channel_write (channel, buffer, lus);
            }
            else {
                eof = 1;
                continue;
            }
        }

        if (outchannel[0]) {
            while (channel_poll (outchannel[0], 0)) {
                lus = channel_read (outchannel[0], readbuf, 0, 0);

                if(lus == -1) {
                    g_critical ("%s\n", ssh_get_error (client->ssh_session));
                    goto near_beach;
                }

                if (lus == 0) {
                    g_message ("EOF received from the server\n");
                    eof = 1;
                    break;
                } 
                
                else {
                    write (client->sock, buffer_get (readbuf), lus);
                }
            }
        }
    }

near_beach:
    gabriel_channel_free (channel);
beach:
    buffer_free (readbuf);
}

void gabriel_handle_clients (SSH_SESSION * ssh_session,
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
	return;
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

    while (!shutting_down) {
	GabrielClient *client;
        gint client_sock;

        client_sock = accept (tcp_server_sock, NULL, NULL);
        if (client_sock < 0) {
            if (!shutting_down) {
                g_critical ("%s\n", strerror (errno));
            }
            goto beach;
        }

	client = gabriel_client_new (ssh_session, client_sock);
        gabriel_handle_client (client);
	gabriel_client_free (client);
    }

beach:
    close (tcp_server_sock);
}

SSH_SESSION *
gabriel_session_create (gchar * host,
                        gchar * username,
                        gchar * password)
{
    SSH_SESSION *ssh_session;
    SSH_OPTIONS *ssh_options;
    gint ret;
    
    ssh_options = ssh_options_new ();
    ssh_options_set_host (ssh_options, host);
    ssh_options_set_username (ssh_options, username);
    ssh_options_set_ssh_dir (ssh_options, "%s/.ssh");
    ssh_options_set_identity (ssh_options, "id_dsa");

    ssh_session = ssh_new ();
    if (!ssh_session) {
	g_critical ("Failed to create ssh session\n");
	return NULL;
    }
    ssh_set_options (ssh_session, ssh_options);

    ret = ssh_connect (ssh_session);

    if (ret) {
	g_critical ("Failed to open ssh connection to %s\n", host);
	goto finland;
    }

    ret = ssh_userauth_autopubkey (ssh_session);
    
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

	    ret = ssh_userauth_password (ssh_session, username, password);
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

    return ssh_session;

finland:
    ssh_disconnect (ssh_session);
    return NULL;
}

gint
main (gint argc, gchar **argv)
{
    struct sigaction sig_action;
    SSH_SESSION *ssh_session;
    GOptionContext *context;
    GError *error = NULL;
    gchar *host = DEFAULT_ADDRESS;
    gchar *username = NULL;
    gchar *password = NULL;
    gchar *local_address = DEFAULT_ADDRESS;
    gint tcp_port = DEFAULT_TCP_PORT;

    GOptionEntry entries[] = {
	{"host", 'h', 0, G_OPTION_ARG_STRING, &host,
	 "Hostname or IP of the remote host", "HOSTNAME"},
	{"username", 'u', 0, G_OPTION_ARG_STRING, &username,
	 "Username on the remote host", "USERNAME"},
	{"password", 'p', 0, G_OPTION_ARG_STRING, &password,
	 "Password on the remote host", "PASSWORD"},
	{"bind", 'b', 0, G_OPTION_ARG_STRING, &local_address,
	 "The address to listen for DBus client connections on", "LOCALHOST"},
	{"port", 't', 0, G_OPTION_ARG_INT, &tcp_port,
	 "The TCP port to listen for DBus client connections on", "PORT"},
	{NULL}
    };

    context = g_option_context_new ("- Gabriel");
    g_option_context_add_main_entries (context, entries, NULL);
    g_option_context_parse (context, &argc, &argv, &error);

    if (username == NULL) {
        username = (gchar *) g_get_user_name ();
    }

    /* set the unix signals */
    bzero (&sig_action, sizeof (sig_action));
    sig_action.sa_handler = signal_handler;
    sigaction (SIGINT, &sig_action, NULL);
   
    ssh_session = gabriel_session_create (host, username, password);
    if (ssh_session == NULL) {
        goto beach;
    }
   
    shutting_down = FALSE;
    gabriel_handle_clients (ssh_session, local_address, tcp_port);

    ssh_disconnect (ssh_session);

beach:
    g_print ("exiting gracefully\n");
    return 0;
}
