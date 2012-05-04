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

typedef struct Spfdconn Spfdconn;
struct Spfdconn {
	int		fdin;
	int		fdout;
	Spfd*		spfdin;
	Spfd*		spfdout;
};

static void sp_fdconn_notify(Spfd *spfd, void *aux);
static int sp_fdconn_read(Spconn *conn);
static void sp_fdconn_write(Spconn *conn);
static int sp_fdconn_shutdown(Spconn *conn);
static void sp_fdconn_dataout(Spconn *conn, Spreq *req);

Spconn*
sp_fdconn_create(Spsrv *srv, int fdin, int fdout)
{
	Spconn *conn;
	Spfdconn *fdconn;

	conn = sp_conn_create(srv);
	if (!conn)
		return NULL;

	fdconn = sp_malloc(sizeof(*fdconn));
	if (!fdconn)
		goto error;

	fdconn->fdin = fdin;
	fdconn->fdout = fdout;

	fdconn->spfdin = spfd_add(fdin, sp_fdconn_notify, conn);
	if (!fdconn->spfdin)
		goto error;

	if (fdin == fdout)
		fdconn->spfdout = fdconn->spfdin;
	else {
		fdconn->spfdout = spfd_add(fdout, sp_fdconn_notify, conn);
		if (!fdconn->spfdout) {
			spfd_remove(fdconn->spfdin);
			goto error;
		}
	}

	conn->caux = fdconn;
	conn->shutdown = sp_fdconn_shutdown;
	conn->dataout = sp_fdconn_dataout;
	sp_srv_add_conn(srv, conn);
	return conn;

error:
	free(fdconn);
	sp_conn_destroy(conn);
	return NULL;
}

static int
sp_fdconn_shutdown(Spconn *conn)
{
	Spfdconn *fdconn;

	fdconn = conn->caux;
	close(fdconn->fdin);
	if (fdconn->fdout != fdconn->fdin)
		close(fdconn->fdin);

	spfd_remove(fdconn->spfdin);
	if (fdconn->spfdout != fdconn->spfdin)
		spfd_remove(fdconn->spfdout);
	free(fdconn);

	return 1;
}

static void
sp_fdconn_dataout(Spconn *conn, Spreq *req)
{
	Spfdconn *fdconn;

	if (req != conn->oreqs)
		return;

	fdconn = conn->caux;
	if (spfd_can_write(fdconn->spfdout))
		sp_fdconn_write(conn);
}

static void
sp_fdconn_notify(Spfd *spfd, void *aux)
{
	int n;
	Spconn *conn;

	conn = aux;
	n = 0;
	if (spfd_can_read(spfd))
		n = sp_fdconn_read(conn);

	if (!n && spfd_can_write(spfd))
		sp_fdconn_write(conn);

	if (n || spfd_has_error(spfd))
		sp_conn_shutdown(conn);
}

static int
sp_fdconn_read(Spconn *conn)
{
	int n, size;
	Spsrv *srv;
	Spfcall *fc;
	Spreq *req;
	Spfdconn *fdconn;

	srv = conn->srv;
	fdconn = conn->caux;

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
	n = spfd_read(fdconn->spfdin, fc->pkt + fc->size, conn->msize - fc->size);
	if (n == 0)
		return -1;
	else if (n < 0)
		return 0;

	fc->size += n;

again:
	n = fc->size;
	if (n < 4)
		return 0;

	size = fc->pkt[0] | (fc->pkt[1]<<8) | (fc->pkt[2]<<16) | (fc->pkt[3]<<24);
	if (n < size)
		return 0;

	if (size > conn->msize) {
		fprintf(stderr, "error: packet too big\n");
		close(fdconn->fdin);
		if (fdconn->fdout != fdconn->fdin)
			close(fdconn->fdout);
		return 0;
	}

	if (!sp_deserialize(fc, fc->pkt, conn->dotu)) {
		fprintf(stderr, "error while deserializing\n");
		close(fdconn->fdin);
		if (fdconn->fdout != fdconn->fdin)
			close(fdconn->fdout);
		return 0;
	}

	if (srv->debuglevel) {
		fprintf(stderr, "<<< (%p) ", conn);
		sp_printfcall(stderr, fc, conn->dotu);
		fprintf(stderr, "\n");
	}

	req = conn->ireqs;
	req->tag = req->tcall->tag;
	conn->ireqs = NULL;
	if (n > size) {
		fc = sp_conn_new_incall(conn);
		if (!fc)
			return 0;

		fc->size = 0;
		conn->ireqs = sp_req_alloc(conn, fc);
		if (!req)
			return 0;

		memmove(fc->pkt, req->tcall->pkt + size, n - size);
		fc->size = n - size;
	}

	sp_srv_process_req(req);
	if (conn->ireqs) {
		fc = conn->ireqs->tcall;
		goto again;
	}

	return 0;
}

static void
sp_fdconn_write(Spconn *conn)
{
	int n;
	u32 pos;
	Spfcall *rc;
	Spreq *req;
	Spsrv *srv;
	Spfdconn *fdconn;

	if (!conn->oreqs)
		return;

	srv = conn->srv;
	fdconn = conn->caux;
	req = conn->oreqs;
	rc = req->rcall;
	pos = (int) req->caux;
	if (conn->srv->debuglevel && pos==0) {
		fprintf(stderr, ">>> (%p) ", conn);
		sp_printfcall(stderr, rc, conn->dotu);
		fprintf(stderr, "\n");
	}

	n = spfd_write(fdconn->spfdout, rc->pkt + pos, rc->size - pos);
	if (n <= 0)
		return;

	pos += n;
	req->caux = (void *) pos;
	if (pos == rc->size) {
		conn->oreqs = req->next;
		sp_conn_free_incall(conn, req->tcall);
		sp_req_free(req);
		if (rc==srv->rcenomem || rc==srv->rcenomemu) {
			/* unblock reading and read some messages if we can */
			srv->enomem = 0;
			if (spfd_can_read(fdconn->spfdin))
				sp_fdconn_read(conn);
		} else
			free(rc);
	}
}
