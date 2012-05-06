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

#include <arpa/inet.h>

#include <poll.h>

typedef struct Spethconn Spethconn;
struct Spethconn {
	struct sockaddr_ll saddr;
	int fd;
	Spfd*		spfd;
};

static void sp_ethconn_notify(Spfd *spfd, void *aux);
static int sp_ethconn_read(Spconn *conn);
static void sp_ethconn_write(Spconn *conn);
static int sp_ethconn_shutdown(Spconn *conn);
static void sp_ethconn_dataout(Spconn *conn, Spreq *req);

Spconn*
sp_ethconn_create(Spsrv *srv, int fd)
{
	Spconn *conn = sp_conn_create(srv);
	if (!conn)
		return NULL;

	Spethconn *ethconn = sp_malloc(sizeof(*ethconn));
	if (!ethconn)
		goto error;

	ethconn->fd = fd;

	ethconn->spfd = spfd_add(fd, sp_ethconn_notify, conn);
	if (!ethconn->spfd)
		goto error;

	conn->caux = ethconn;
	conn->shutdown = sp_ethconn_shutdown;
	conn->dataout = sp_ethconn_dataout;
	sp_srv_add_conn(srv, conn);
	return conn;

error:
	free(ethconn);
	sp_conn_destroy(conn);
	return NULL;
}

static int
sp_ethconn_shutdown(Spconn *conn)
{
	Spethconn *ethconn = conn->caux;

	close(ethconn->fd);
	spfd_remove(ethconn->spfd);
	free(ethconn);

	return 1;
}

static void
sp_ethconn_dataout(Spconn *conn, Spreq *req)
{
	//Spethconn *ethconn = conn->caux;

	if (req != conn->oreqs)
		return;

	sp_ethconn_write(conn);
}

static void
sp_ethconn_notify(Spfd *spfd, void *aux)
{
	int n = 0;
	Spconn *conn = aux;

	int cr = spfd_can_read(spfd);
	if (conn->srv->debuglevel > 0)
		fprintf(stderr, "sp_ethconn_notify: fd readable %d\n", cr);

	if (spfd_can_read(spfd))
		n = sp_ethconn_read(conn);

	if (n || spfd_has_error(spfd))
	{
		if (conn->srv->debuglevel > 0)
			fprintf(stderr, "sp_ethconn_notify: error, shutdown conn\n");
		sp_conn_shutdown(conn);
	}
}

static int
sp_ethconn_read(Spconn *conn)
{
	Spsrv *srv = conn->srv;
	Spfcall *fc;
	Spreq *req;
	Spethconn *ethconn = conn->caux;

	/* if we are sending Enomem error back, block all reading */
	if (srv->enomem)
		return 0;

	if (!conn->ireqs) {
		fc = sp_conn_new_incall(conn);
		if (!fc)
			return 0;

		fc->size = 0;
		conn->ireqs = sp_req_alloc(conn, fc);
		if (!conn->ireqs)
			return 0;
	}
		
	fc = conn->ireqs->tcall;

	//
	// ethconn->saddr is later reused for sending. This is safe as 9P connection
	// is initated by the client.
	//

	socklen_t sa_len = sizeof(ethconn->saddr);
	spfd_read(ethconn->spfd, 0, 0);
	int n = recvfrom(ethconn->fd, fc->pkt, conn->msize, 0,
			(struct sockaddr *)&ethconn->saddr, &sa_len);
	if (srv->debuglevel > 1)
		fprintf(stderr, "sp_ethconn_read: recvfrom returns %d\n", n);
	if (n == 0)
		return 0;	// 0 would signify eof of a tcp socket
	else if (n < 0)
	{
		if (srv->debuglevel > 0)
			fprintf(stderr, "sp_ethconn_read: recvfrom error: %s\n", strerror(errno));
		return 0;
	}

	// packets of other protocols may still be visible on the interface
	if (ethconn->saddr.sll_protocol != htons(EXP_9P_ETH))
		return 0;

	if (n < 4)
		return 0;

	int exp_size = fc->pkt[0] | (fc->pkt[1]<<8) | (fc->pkt[2]<<16) | (fc->pkt[3]<<24);
	if (srv->debuglevel > 1)
		fprintf(stderr, "sp_ethconn_read: expected size %d\n", exp_size);
	if (exp_size != n -4) 	// +4: csum field
		return 0;

	fc->size = exp_size;

	if (!sp_deserialize(fc, fc->pkt, conn->dotu)) {
		fprintf(stderr, "error while deserializing\n");
		close(ethconn->fd);
		return 0;
	}

	if (srv->debuglevel > 0) {
		fprintf(stderr, "<<< (%p) ", conn);
		sp_printfcall(stderr, fc, conn->dotu);
		fprintf(stderr, "\n");
	}

	req = conn->ireqs;
	req->tag = req->tcall->tag;
	conn->ireqs = NULL;
	sp_srv_process_req(req);

	return 0;
}

static void
sp_ethconn_write(Spconn *conn)
{
	int n;
	Spfcall *rc;
	Spreq *req;
	Spsrv *srv = conn->srv;
	Spethconn *ethconn = conn->caux;

	if (srv->debuglevel > 0)
		fprintf(stderr, "sp_ethconn_write: entered\n");

	if (!conn->oreqs)
		return;

	req = conn->oreqs;
	rc = req->rcall;
	if (conn->srv->debuglevel) {
		fprintf(stderr, ">>> (%p) ", conn);
		sp_printfcall(stderr, rc, conn->dotu);
		fprintf(stderr, "\n");
	}

	n = sendto(ethconn->fd, rc->pkt, rc->size, 0,
			(struct sockaddr *)&ethconn->saddr, sizeof(ethconn->saddr));
	if (srv->debuglevel > 0)
		fprintf(stderr, "sp_ethconn_write: sendto returned %d\n", n);
	if (n <= 0)
		return;

	conn->oreqs = req->next;
	sp_conn_free_incall(conn, req->tcall);
	sp_req_free(req);
	if (rc==srv->rcenomem || rc==srv->rcenomemu) {
		/* unblock reading and read some messages if we can */
		srv->enomem = 0;
		if (spfd_can_read(ethconn->spfd))
			sp_ethconn_read(conn);
	} else
		free(rc);
}

//EOF
