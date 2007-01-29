/*
 * gabriel-client.c
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

#define SELECT_TIMEOUT 3

extern gboolean shutting_down;

static gint
gabriel_channel_create_bridge (GabrielClient *client, CHANNEL *channel)
{
    gint ret;
    gchar *socat_cmd =
            g_strjoin (" - ", "socat", client->session->socat_address, NULL);

    ret = channel_open_session (channel);
    if (ret) {
	g_critical ("Failed to open ssh session channel\n");
	goto beach;
    }

    ret = channel_request_exec (channel, socat_cmd);
    if (ret) {
	g_critical ("Failed to start socat on the remote\n");
	goto beach;
    }

beach:
    g_free (socat_cmd);
    return ret;
}

static CHANNEL *
gabriel_channel_create (GabrielClient * client)
{
    CHANNEL *channel = NULL;
    gint ret;

    channel = channel_new (client->session->ssh_session);
    if (!channel) {
	g_critical ("Failed to create an ssh channel\n");
	goto beach;
    }

    ret = gabriel_channel_create_bridge (client, channel);
    if (ret) {
	goto finland;
    }

beach:
   return channel;

finland:
    channel_free (channel);
    return NULL;
}

static void
gabriel_channel_free (CHANNEL * channel)
{
    channel_free (channel);
}

GabrielClient *
gabriel_client_new (GabrielSession * session, gint sock)
{
    GabrielClient *client = g_new0 (GabrielClient, 1);
    client->session = session;
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

    channel = channels[0] = gabriel_channel_create (client);

    if (channel == NULL) {
        goto beach;
    }
   
    while (channel_is_open (channel) && !eof) {
        do {
            FD_ZERO (&fds);
            if (!eof)
                FD_SET (client->sock, &fds);
	    /* We need a timeout for the unfortunate case of getting SIGINT before 
	     * select gets called, in which case it would happily block forever
	     * if there is no timeout provided to it.
 	     */
            timeout.tv_sec = SELECT_TIMEOUT;
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
                    g_critical ("%s\n", ssh_get_error (client->session->ssh_session));
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

