/*
 * Copyright (C) 2006 by Latchesar Ionkov <lucho@ionkov.net>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * LATCHESAR IONKOV AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include "spfs.h"
#include "spfsimpl.h"

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <arpa/inet.h>

#include <poll.h>

typedef struct Spethconn2 Spethconn2;
struct Spethconn2 {
	struct sockaddr_ll saddr;
	int fd;		// for interface monitoring only
	Spfd *spfd;
};

static void sp_ethconn2_notify(Spfd *spfd, void *aux);
//static int sp_ethconn2_read(Spconn *conn);
static void sp_ethconn2_write(Spconn *conn);
static int sp_ethconn2_shutdown(Spconn *conn);
static void sp_ethconn2_dataout(Spconn *conn, Spreq *req);

Spconn*
sp_ethconn2_create(Spsrv *srv, void *sap)
{
	Spconn *conn = sp_conn_create(srv);
	if (!conn)
		return NULL;

	Spethconn2 *ethconn = sp_malloc(sizeof(*ethconn));
	if (!ethconn)
		goto error1;

	ethconn->saddr = *(struct sockaddr_ll *)sap;
	int fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (fd < 0)
		goto error1;

	if (bind(fd, (struct sockaddr *)&ethconn->saddr, sizeof(ethconn->saddr)) < 0)
		goto error2;

	ethconn->fd = fd;

	ethconn->spfd = spfd_add(fd, sp_ethconn2_notify, conn);
	if (!ethconn->spfd)
		goto error2;

	conn->caux = ethconn;
	conn->shutdown = sp_ethconn2_shutdown;
	conn->dataout = sp_ethconn2_dataout;
	sp_srv_add_conn(srv, conn);
	return conn;

error2:
	close(fd);
error1:
	sp_conn_destroy(conn);
	free(ethconn);
	return NULL;
}

static int
sp_ethconn2_shutdown(Spconn *conn)
{
	Spethconn2 *ethconn = conn->caux;

	close(ethconn->fd);
	spfd_remove(ethconn->spfd);
	free(ethconn);

	return 1;
}

static void
sp_ethconn2_dataout(Spconn *conn, Spreq *req)
{
	Spethconn2 *ethconn = conn->caux;

	if (req != conn->oreqs)
		return;

	if (spfd_can_write(ethconn->spfd))
		sp_ethconn2_write(conn);
}

static void
sp_ethconn2_notify(Spfd *spfd, void *aux)
{
	int n = 0;
	Spconn *conn = aux;

	if (spfd_can_write(spfd))
		sp_ethconn2_write(conn);

	if (n || spfd_has_error(spfd))
	{
		if (conn->srv->debuglevel > 0)
			fprintf(stderr, "sp_ethconn2_notify: error, shutdown conn\n");
		sp_conn_shutdown(conn);
	}
}

static void
sp_ethconn2_write(Spconn *conn)
{
	int n;
	Spfcall *rc;
	Spreq *req;
	//Spsrv *srv = conn->srv;
	Spethconn2 *ethconn = conn->caux;

	if (!conn->oreqs)
		return;

	spfd_write(ethconn->spfd, 0, 0);	// reset events

	req = conn->oreqs;
	rc = req->rcall;
	if (conn->srv->debuglevel) {
		fprintf(stderr, ">>> (%p) ", conn);
		sp_printfcall(stderr, rc, conn->dotu);
		fprintf(stderr, "\n");
	}

	n = sendto(ethconn->fd, rc->pkt, rc->size, 0,
			(struct sockaddr *)&ethconn->saddr, sizeof(ethconn->saddr));
	if (n <= 0)
		return;

	conn->oreqs = req->next;
	sp_conn_free_incall(conn, req->tcall);
	sp_req_free(req);
	free(rc);
}

//EOF
