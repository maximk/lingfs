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

Spconn*
sp_conn_create(Spsrv *srv)
{
	Spconn *conn;

	conn = sp_malloc(sizeof(*conn));
	if (!conn)
		return NULL;

	conn->srv = srv;
	conn->address = NULL;
	conn->msize = srv->msize;
	conn->dotu = srv->dotu;
	conn->flags = 0;
	conn->ireqs = NULL;
	conn->oreqs = NULL;
	conn->caux = NULL;
	conn->fidpool = NULL;
	conn->freercnum = 0;
	conn->freerclist = NULL;
	conn->reset = NULL;
	conn->shutdown = NULL;
	conn->dataout = NULL;

	return conn;
}

void
sp_conn_destroy(Spconn *conn)
{
	free(conn->address);
	free(conn);
}

void
sp_conn_shutdown(Spconn *conn)
{
	sp_srv_remove_conn(conn->srv, conn);
	sp_conn_reset(conn, 0, 0);
	conn->flags |= Cshutdown;
	if (conn->flags & Creset)
		return;

	if (conn->shutdown && !(*conn->shutdown)(conn)) {
		conn->flags |= Cshutdown;
		return;
	}

	sp_conn_destroy(conn);
}

void
sp_conn_reset(Spconn *conn, u32 msize, int dotu)
{
	char buf[32];
	Spsrv *srv;
	Spreq *req, *req1, *vreq;
	Spfcall *fc, *fc1, *rc;

	srv = conn->srv;
	conn->flags |= Creset;
	vreq = NULL;

	/* flush all working requests */
	/* if there are pending requests, the server should define flush, 
	   otherwise we loop forever */
again:
	req = conn->srv->workreqs;
	while (req != NULL) {
		if (req->conn == conn) {
			if (msize>0 && req->tcall->type==Tversion)
				vreq = req;
			else {
				if (srv->flush)
					rc = (*srv->flush)(req);
				else
					rc = NULL;

				free(rc);
				goto again;
			}
		}

		req = req->next;
	}

	if (conn->reset)
		(*conn->reset)(conn);
	else {
		req = conn->ireqs;
		conn->ireqs = NULL;
		while (req != NULL) {
			req1 = req->next;
			sp_conn_free_incall(conn, req->tcall);
			free(req->rcall);
			sp_req_free(req);
			req = req1;
		}

		req = conn->oreqs;
		conn->oreqs = NULL;
		while (req != NULL) {
			req1 = req->next;
			sp_conn_free_incall(conn, req->tcall);
			free(req->rcall);
			sp_req_free(req);
			req = req1;
		}
	}

	conn->msize = msize;
	if (conn->ireqs || conn->oreqs)
		return;

	/* free old pool of fcalls */	
	fc = conn->freerclist;
	conn->freerclist = NULL;
	while (fc != NULL) {
		fc1 = fc->next;
		free(fc);
		fc = fc1;
	}

	if (conn->fidpool) {
		sp_fidpool_destroy(conn->fidpool);
		conn->fidpool = NULL;
	}

	if (msize) {
		conn->dotu = dotu;
		conn->fidpool = sp_fidpool_create();
	}
	conn->flags &= ~Creset;

	/* if msize > 0, the reset was caused by Tversion, send the response back */
	if (vreq) {
		sprintf(buf, "9P2000%s", dotu?".u":"");
		rc = sp_create_rversion(conn->msize, buf);
		sp_respond(vreq, rc);
	}
}

void
sp_conn_respond(Spconn *conn, Spreq *req)
{
	Spreq *preq;

	if (!req->rcall) {
		sp_conn_free_incall(conn, req->tcall);
		sp_req_free(req);
		return;
	}

	sp_set_tag(req->rcall, req->tcall->tag);
	if (conn->oreqs) {
		for(preq = conn->oreqs; preq->next != NULL; preq = preq->next)
			;

		req->next = preq->next;
		preq->next = req;
	} else {
		conn->oreqs = req;
		req->next = NULL;
	}

	if (conn->dataout)
		(*conn->dataout)(conn, req);
}

Spfcall *
sp_conn_new_incall(Spconn *conn)
{
	Spfcall *fc;

	if (conn->freerclist) {
		fc = conn->freerclist;
		conn->freerclist = fc->next;
		conn->freercnum--;
	} else
		fc = sp_malloc(sizeof(*fc) + conn->msize);

	if (!fc)
		return NULL;

	fc->pkt = (u8*) fc + sizeof(*fc);
	return fc;
}

void
sp_conn_free_incall(Spconn* conn, Spfcall *rc)
{
	Spfcall *r;

	if (!rc)
		return;

	for(r = conn->freerclist; r != NULL; r = r->next)
		if (rc == r)
			abort();

	if (conn->freercnum < 64) {
		rc->next = conn->freerclist;
		conn->freerclist = rc;
		rc = NULL;
	}

	if (rc)
		free(rc);
}
