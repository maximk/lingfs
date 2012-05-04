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
#include <errno.h>
#include <assert.h>
#include "spfs.h"
#include "spfsimpl.h"

struct Reqpool {
	int		reqnum;
	Spreq*		reqlist;
} reqpool = { 0, NULL };

static Spfcall* sp_default_version(Spconn *, u32, Spstr *);
static Spfcall* sp_default_attach(Spfid *, Spfid *, Spstr *, Spstr *);
static Spfcall* sp_default_flush(Spreq *);
static int sp_default_clone(Spfid *, Spfid *);
static int sp_default_walk(Spfid *, Spstr*, Spqid *);
static Spfcall* sp_default_open(Spfid *, u8);
static Spfcall* sp_default_create(Spfid *, Spstr*, u32, u8, Spstr*);
static Spfcall* sp_default_read(Spfid *, u64, u32, Spreq *);
static Spfcall* sp_default_write(Spfid *, u64, u32, u8*, Spreq *);
static Spfcall* sp_default_clunk(Spfid *);
static Spfcall* sp_default_remove(Spfid *);
static Spfcall* sp_default_stat(Spfid *);
static Spfcall* sp_default_wstat(Spfid *, Spstat *);

Spsrv*
sp_srv_create()
{
	Spsrv *srv;

	srv = sp_malloc(sizeof(*srv));
	if (!srv)
		return NULL;

	srv->msize = 8216;
	srv->dotu = 1;
	srv->srvaux = NULL;
	srv->treeaux = NULL;
	srv->auth = NULL;

	srv->start = NULL;
	srv->shutdown = NULL;
	srv->destroy = NULL;
	srv->connopen = NULL;
	srv->connclose = NULL;
	srv->fiddestroy = NULL;

	srv->version = sp_default_version;
	srv->attach = sp_default_attach;
	srv->flush = sp_default_flush;
	srv->clone = sp_default_clone;
	srv->walk = sp_default_walk;
	srv->open = sp_default_open;
	srv->create = sp_default_create;
	srv->read = sp_default_read;
	srv->write = sp_default_write;
	srv->clunk = sp_default_clunk;
	srv->remove = sp_default_remove;
	srv->stat = sp_default_stat;
	srv->wstat = sp_default_wstat;

	srv->conns = NULL;
	srv->workreqs = NULL;
	srv->debuglevel = 0;

	srv->enomem = 0;
	srv->rcenomem = sp_create_rerror(Enomem, ENOMEM, 0);
	srv->rcenomemu = sp_create_rerror(Enomem, ENOMEM, 1);

	if (!srv->rcenomem || !srv->rcenomemu) {
		free(srv);
		return NULL;
	}

	return srv;
}

void
sp_srv_start(Spsrv *srv)
{
	(*srv->start)(srv);
}

int
sp_srv_add_conn(Spsrv *srv, Spconn *conn)
{
	int ret;

	ret = 0;
	conn->srv = srv;
	conn->next = srv->conns;
	srv->conns = conn;

	if (srv->connopen)
		(*srv->connopen)(conn);

	return ret;
}

void
sp_srv_remove_conn(Spsrv *srv, Spconn *conn)
{
	Spconn *c, *pc;

	for(pc=NULL, c=srv->conns; c!=NULL; pc=c, c=c->next)
		if (c == conn) {
			if (pc)
				pc->next = c->next;
			else
				srv->conns = c->next;

			break;
		}

	if (srv->connclose)
		(*srv->connclose)(conn);
}

void
sp_srv_add_workreq(Spsrv *srv, Spreq *req)
{
	if (srv->workreqs)
		srv->workreqs->prev = req;

	req->next = srv->workreqs;
	srv->workreqs = req;
	req->prev = NULL;
}

void
sp_srv_remove_workreq(Spsrv *srv, Spreq *req)
{
	if (req->prev)
		req->prev->next = req->next;
	else
		srv->workreqs = req->next;

	if (req->next)
		req->next->prev = req->prev;
}

typedef Spfcall* (*sp_fcall)(Spreq *, Spfcall *);
static sp_fcall sp_fcalls[] = {
	sp_version,
	sp_auth,
	sp_attach,
	NULL,
	sp_flush,
	sp_walk,
	sp_open,
	sp_create,
	sp_read,
	sp_write,
	sp_clunk,
	sp_remove,
	sp_stat,
	sp_wstat,
};

Spfcall *
sp_srv_get_enomem(Spsrv *srv, int dotu)
{
	Spfcall *rc;

	if (dotu)
		rc = srv->rcenomemu;
	else
		rc = srv->rcenomem;

	srv->enomem = 1;
	return rc;
}

void
sp_srv_put_enomem(Spsrv *srv)
{
	srv->enomem = 0;
}

void
sp_srv_process_req(Spreq *req)
{
	int ecode;
	char *ename;
	Spfcall *tc, *rc;
	Spconn *conn;
	sp_fcall f;

	conn = req->conn;
	sp_srv_add_workreq(conn->srv, req);

	tc = req->tcall;
	f = NULL;
	if (tc->type<Tfirst && tc->type>Rlast)
		sp_werror("unknown message type", ENOSYS);
	else
		f = sp_fcalls[(tc->type-Tfirst)/2];

	sp_werror(NULL, 0);
	if (f)
		rc = (*f)(req, tc);
	else
		sp_werror("unsupported message", ENOSYS);

	sp_rerror(&ename, &ecode);
	if (ename != NULL) {
		if (rc)
			free(rc);

		/* if there is not enough memory, use one of the 
		   preallocated error responses */
		if (ename == Enomem) 
			rc = sp_srv_get_enomem(conn->srv, conn->dotu);
		else
			rc = sp_create_rerror(ename, ecode, conn->dotu);
	}
	sp_werror(NULL, 0);

	if (rc)
		sp_respond(req, rc);
}

void
sp_respond(Spreq *req, Spfcall *rc)
{
	Spsrv *srv;
	Spreq *freq, *freq1;

	srv = req->conn->srv;
	req->rcall = rc;
	sp_srv_remove_workreq(srv, req);
	for(freq = req->flushreq; freq != NULL; freq = freq->flushreq)
		sp_srv_remove_workreq(srv, freq);

	if (req->rcall && req->rcall->type==Rread && req->fid->type&Qtdir)
		req->fid->diroffset = req->tcall->offset + req->rcall->count;

	if (req->fid != NULL) {
		sp_fid_decref(req->fid);
		req->fid = NULL;
	}

	freq = req->flushreq;
	sp_conn_respond(req->conn, req);

	while (freq != NULL) {
		freq->rcall = sp_create_rflush();
		/* TODO: handle ENOMEM while creating Rflush */
		freq1 = freq->flushreq;
		sp_conn_respond(freq->conn, freq);
		freq = freq1;
	}
}

void
sp_respond_error(Spreq *req, char *ename, int ecode)
{
	Spfcall *rc;

	rc = sp_create_rerror(ename, ecode, req->conn->dotu);
	sp_respond(req, rc);
}

static Spfcall*
sp_default_version(Spconn *conn, u32 msize, Spstr *version) 
{
	int dotu;

	if (msize > conn->srv->msize)
		msize = conn->srv->msize;

	dotu = 0;
	if (sp_strcmp(version, "9P2000.u")==0 && conn->srv->dotu)
		dotu = 1;
	else if (sp_strncmp(version, "9P2000", 6) == 0)
		dotu = 0;
	else {
		sp_werror("unsupported 9P version", EIO);
		return NULL;
	}

	if (msize < IOHDRSZ) {
		sp_werror("msize too small", EIO);
		return NULL;
	}

	sp_conn_reset(conn, msize, dotu);
	return NULL;
}

static Spfcall*
sp_default_attach(Spfid *fid, Spfid *afid, Spstr *uname, Spstr *aname)
{
	sp_werror(Enotimpl, EIO);
	return NULL;
}

static Spfcall*
sp_default_flush(Spreq *req)
{
	return 0;
}

static int
sp_default_clone(Spfid *fid, Spfid *newfid)
{
	return 0;
}

static int
sp_default_walk(Spfid *fid, Spstr* wname, Spqid *wqid)
{
	sp_werror(Enotimpl, ENOSYS);
	return 0;
}

static Spfcall*
sp_default_open(Spfid *fid, u8 perm)
{
	sp_werror(Enotimpl, ENOSYS);
	return NULL;
}

static Spfcall*
sp_default_create(Spfid *fid, Spstr *name, u32 mode, u8 perm, Spstr *extension)
{
	sp_werror(Enotimpl, ENOSYS);
	return NULL;
}

static Spfcall*
sp_default_read(Spfid *fid, u64 offset, u32 count, Spreq *req)
{
	sp_werror(Enotimpl, ENOSYS);
	return NULL;
}

static Spfcall*
sp_default_write(Spfid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	sp_werror(Enotimpl, ENOSYS);
	return NULL;
}

static Spfcall*
sp_default_clunk(Spfid *fid)
{
	sp_werror(Enotimpl, ENOSYS);
	return NULL;
}

static Spfcall*
sp_default_remove(Spfid *fid)
{
	sp_werror(Enotimpl, ENOSYS);
	return NULL;
}

static Spfcall*
sp_default_stat(Spfid *fid)
{
	sp_werror(Enotimpl, ENOSYS);
	return NULL;
}

static Spfcall*
sp_default_wstat(Spfid *fid, Spstat *stat)
{
	sp_werror(Enotimpl, ENOSYS);
	return NULL;
}

Spreq *sp_req_alloc(Spconn *conn, Spfcall *tc) {
	Spreq *req;

	if (reqpool.reqlist) {
		req = reqpool.reqlist;
		reqpool.reqlist = req->next;
		reqpool.reqnum--;
	} else {
		req = sp_malloc(sizeof(*req));
		if (!req)
			return NULL;
	}

	req->conn = conn;
	req->tag = tc?tc->tag:NOTAG;
	req->tcall = tc;
	req->rcall = NULL;
	req->responded = 0;
	req->flushreq = NULL;
	req->next = NULL;
	req->prev = NULL;
	req->fid = NULL;
	req->caux = NULL;

	return req;
}

void
sp_req_free(Spreq *req)
{
	if (reqpool.reqnum < 64) {
		req->next = reqpool.reqlist;
		reqpool.reqlist = req;
		reqpool.reqnum++;
	} else
		free(req);
}
