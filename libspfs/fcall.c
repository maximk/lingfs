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

char *Eunknownfid = "unknown fid";
char *Enoauth = "no authentication required";
char *Enotimpl = "not implemented";
char *Einuse = "fid already exists";
char *Ebadusefid = "bad use of fid";
char *Enotdir = "not a directory";
char *Etoomanywnames = "too many wnames";
char *Eperm = "permission denied";
char *Etoolarge = "i/o count too large";
char *Ebadoffset = "bad offset in directory read";
char *Edirchange = "cannot convert between files and directories";
char *Enotfound = "file not found";
char *Eopen = "file alread exclusively opened";
char *Eexist = "file or directory already exists";
char *Enotempty = "directory not empty";
char *Eunknownuser = "unknown user";

Spfcall *
sp_version(Spreq *req, Spfcall *tc)
{
	if (tc->msize < IOHDRSZ + 1) {
		sp_werror("msize too small", EIO);
		return NULL;
	}

	return (*req->conn->srv->version)(req->conn, tc->msize, &tc->version);
}

Spfcall *
sp_auth(Spreq *req, Spfcall *tc)
{
	int n;
	char *uname, *aname;
	Spconn *conn;
	Spfid *afid;
	Spfcall *rc;
	Spuser *user;
	Spqid aqid;

	rc = NULL;
	aname = NULL;
	conn = req->conn;
	afid = sp_fid_find(conn, tc->afid);
	if (afid) {
		sp_werror(Einuse, EIO);
		goto done;
	}

	afid = sp_fid_create(conn, tc->afid, NULL);
	if (!afid) 
		goto done;
	else
		sp_fid_incref(afid);

	if (tc->uname.len && !tc->n_uname) {
		uname = sp_strdup(&tc->uname);
		if (!uname) 
			goto done;

		user = sp_uname2user(uname);
		free(uname);
		if (!user)
			goto done;
		tc->n_uname = user->uid;
	} else {
		user = sp_uid2user(tc->n_uname);
		if (!user)
			goto done;
	}

	if (tc->aname.len) {
		aname = sp_strdup(&tc->aname);
		if (!aname)
			goto done;
	} else
		aname = NULL;

	afid->user = user;
	afid->type = Qtauth;
	if (conn->srv->auth && conn->srv->auth->startauth)
		n = (*conn->srv->auth->startauth)(afid, aname, &aqid);
	else
		n = 0;

	if (n) {
		assert((aqid.type & Qtauth) != 0);
		rc = sp_create_rauth(&aqid);
	} else
		sp_werror(Enoauth, EIO);
done:
	free(aname);
	sp_fid_decref(afid);
	return rc;
}

Spfcall *
sp_attach(Spreq *req, Spfcall *tc)
{
	char *uname, *aname;
	Spconn *conn;
	Spfid *fid, *afid;
	Spfcall *rc;
	Spuser *user;

	rc = NULL;
	aname = NULL;
	conn = req->conn;
	afid = NULL;
	fid = sp_fid_find(conn, tc->fid);
	if (fid) {
		sp_werror(Einuse, EIO);
		goto done;
	}

	fid = sp_fid_create(conn, tc->fid, NULL);
	if (!fid)
		goto done;
	else 
		sp_fid_incref(fid);

	req->fid = fid;
	afid = sp_fid_find(conn, tc->afid);
	if (!afid) {
		if (tc->afid!=NOFID) {
			sp_werror(Eunknownfid, EINVAL);
			goto done;
		}

		if (!(afid->type&Qtauth)) {
			sp_werror(Ebadusefid, EINVAL);
			goto done;
		}
	} else 
		sp_fid_incref(afid);

	if (tc->uname.len && tc->n_uname==~0) {
		uname = sp_strdup(&tc->uname);
		if (!uname) 
			goto done;

		user = sp_uname2user(uname);
		free(uname);
		if (!user)
			goto done;
		tc->n_uname = user->uid;
	} else {
		user = sp_uid2user(tc->n_uname);
		if (!user)
			goto done;
	}

	fid->user = user;
	if (tc->aname.len) {
		aname = sp_strdup(&tc->aname);
		if (!aname)
			goto done;
	} else
		aname = NULL;

	if (conn->srv->auth && conn->srv->auth->checkauth
	&& !(*conn->srv->auth->checkauth)(fid, afid, aname))
		goto done;

	rc = (*conn->srv->attach)(fid, afid, &tc->uname, &tc->aname, tc->n_uname);

done:
	free(aname);
	sp_fid_decref(afid);
	return rc;
}

Spfcall *
sp_flush(Spreq *req, Spfcall *tc)
{
	u16 oldtag;
	Spreq *creq;
	Spconn *conn;
	Spsrv *srv;
	Spfcall *ret;

	ret = NULL;
	conn = req->conn;
	srv = conn->srv;
	oldtag = tc->oldtag;

	for(creq = srv->workreqs; creq != NULL; creq = creq->next)
		if (creq->conn==conn && creq->tag==oldtag) {
			if (!creq->flushreq && srv->flush) {
				ret = (*srv->flush)(creq);
			}

			if (!ret) {
				req->flushreq = creq->flushreq;
				creq->flushreq = req;
			}

			goto done;
		}

	// if not found, return Rflush
	ret = sp_create_rflush();

done:
	return ret;
}

Spfcall *
sp_walk(Spreq *req, Spfcall *tc)
{
	int i;
	Spconn *conn;
	Spfid *fid, *newfid;
	Spfcall *rc;
	Spqid wqids[MAXWELEM];

	rc = NULL;
	conn = req->conn;
	newfid = NULL;
	fid = sp_fid_find(conn, tc->fid);
	if (!fid) {
		sp_werror(Eunknownfid, EIO);
		goto done;
	} else 
		sp_fid_incref(fid);

	req->fid = fid;
	if (!(fid->type&Qtdir)) {
		sp_werror(Enotdir, ENOTDIR);
		goto done;
	}

	if (fid->omode != (u16) ~0) {
		sp_werror(Ebadusefid, EIO);
		goto done;
	}

	if (tc->nwname > MAXWELEM) {
		sp_werror(Etoomanywnames, EIO);
		goto done;
	}

	if (tc->fid != tc->newfid) {
		newfid = sp_fid_find(conn, tc->newfid);
		if (newfid) {
			sp_werror(Einuse, EIO);
			goto done;
		}
		newfid = sp_fid_create(conn, tc->newfid, NULL);
		if (!newfid)
			goto done;

		if (!(*conn->srv->clone)(fid, newfid))
			goto done;

		newfid->user = fid->user;
		newfid->type = fid->type;
	} else
		newfid = fid;

	sp_fid_incref(newfid);
	for(i = 0; i < tc->nwname;) {
		if (!(*conn->srv->walk)(newfid, &tc->wnames[i], &wqids[i]))
			break;

		newfid->type = wqids[i].type;
		i++;

		if (i<(tc->nwname) && !(newfid->type&Qtdir))
			break;
	}

	if (i==0 && tc->nwname!=0)
		goto done;

	sp_werror(NULL, 0);
	if (tc->fid != tc->newfid)
		sp_fid_incref(newfid);
	rc = sp_create_rwalk(i, wqids);

done:
	sp_fid_decref(newfid);
	return rc;
}

Spfcall *
sp_open(Spreq *req, Spfcall *tc)
{
	Spconn *conn;
	Spfid *fid;
	Spfcall *rc;

	rc = NULL;
	conn = req->conn;
	fid = sp_fid_find(conn, tc->fid);
	if (!fid) {
		sp_werror(Eunknownfid, EIO);
		goto done;
	} else 
		sp_fid_incref(fid);

	req->fid = fid;
	if (fid->omode != (u16)~0) {
		sp_werror(Ebadusefid, EIO);
		goto done;
	}

	if (fid->type&Qtdir && tc->mode != Oread) {
		sp_werror(Eperm, EPERM);
		goto done;
	}

	rc = (*conn->srv->open)(fid, tc->mode);
	fid->omode = tc->mode;
done:
//	sp_fid_decref(fid);
	return rc;
}

Spfcall *
sp_create(Spreq *req, Spfcall *tc)
{
	Spconn *conn;
	Spfid *fid;
	Spfcall *rc;

	rc = NULL;
	conn = req->conn;
	fid = sp_fid_find(conn, tc->fid);
	if (!fid) {
		sp_werror(Eunknownfid, EIO);
		goto done;
	} else 
		sp_fid_incref(fid);

	req->fid = fid;
	if (fid->omode != (u16)~0) {
		sp_werror(Ebadusefid, EIO);
		goto done;
	}

	if (!(fid->type&Qtdir)) {
		sp_werror(Enotdir, ENOTDIR);
		goto done;
	}

	if (tc->perm&Dmdir && tc->mode!=Oread) {
		sp_werror(Eperm, EPERM);
		goto done;
	}

	if (tc->perm&(Dmnamedpipe|Dmsymlink|Dmlink|Dmdevice|Dmsocket)
	&& !fid->conn->dotu) {
		sp_werror(Eperm, EPERM);
		goto done;
	}

	rc = (*conn->srv->create)(fid, &tc->name, tc->perm, tc->mode, 
		&tc->extension);
	if (rc && rc->type == Rcreate) {
		fid->omode = tc->mode;
		fid->type = rc->qid.type;
	}

done:
//	sp_fid_decref(fid);
	return rc;
}

Spfcall *
sp_read(Spreq *req, Spfcall *tc)
{
	int n;
	Spconn *conn;
	Spfid *fid;
	Spfcall *rc;

	rc = NULL;
	conn = req->conn;
	fid = sp_fid_find(conn, tc->fid);
	if (!fid) {
		sp_werror(Eunknownfid, EIO);
		goto done;
	} else 
		sp_fid_incref(fid);

	req->fid = fid;
	if (tc->count+IOHDRSZ > conn->msize) {
		sp_werror(Etoolarge, EIO);
		goto done;
	}

	if (fid->type&Qtauth) {
		if (conn->srv->auth) {
			rc = sp_alloc_rread(tc->count);
			if (!rc)
				goto done;

			n = conn->srv->auth->read(fid, tc->offset, tc->count, rc->data);
			if (n >= 0) 
				sp_set_rread_count(rc, n);
			else {
				free(rc);
				rc = NULL;
			}
		} else
			sp_werror(Ebadusefid, EIO);

		goto done;
	}

	if (fid->omode==(u16)~0 || (fid->omode&3)==Owrite) {
		sp_werror(Ebadusefid, EIO);
		goto done;
	}

	if (fid->type&Qtdir && tc->offset != fid->diroffset) {
		sp_werror(Ebadoffset, EIO);
		goto done;
	}
		
	rc = (*conn->srv->read)(fid, tc->offset, tc->count, req);

/*
	if (rc && rc->id==Rread && fid->type&Qtdir) {
		fid->diroffset = tc->offset + rc->count;
	}
*/

done:
	return rc;
}

Spfcall *
sp_write(Spreq *req, Spfcall *tc)
{
	int n;
	Spconn *conn;
	Spfid *fid;
	Spfcall *rc;

	rc = NULL;
	conn = req->conn;
	fid = sp_fid_find(conn, tc->fid);
	if (!fid) {
		sp_werror(Eunknownfid, EIO);
		goto done;
	} else 
		sp_fid_incref(fid);

	req->fid = fid;
	if (fid->type&Qtauth) {
		if (conn->srv->auth) {
			n = conn->srv->auth->write(fid, tc->offset,
				tc->count, tc->data);
			if (n >= 0)
				rc = sp_create_rwrite(n);

			goto done;
		} else {
			sp_werror(Ebadusefid, EIO);
			goto done;
		}
	}

	if (fid->omode==(u16)~0 || fid->type&Qtdir || (fid->omode&3)==Oread) {
		sp_werror(Ebadusefid, EIO);
		goto done;
	}

	if (tc->count+IOHDRSZ > conn->msize) {
		sp_werror(Etoolarge, EIO);
		goto done;
	}

	rc = (*conn->srv->write)(fid, tc->offset, tc->count, tc->data, req);

done:
	return rc;
}

Spfcall *
sp_clunk(Spreq *req, Spfcall *tc)
{
	int n;
	Spconn *conn;
	Spfid *fid;
	Spfcall *rc;

	rc = NULL;
	conn = req->conn;
	fid = sp_fid_find(conn, tc->fid);
	if (!fid) {
		sp_werror(Eunknownfid, EIO);
		goto done;
	} else 
		sp_fid_incref(fid);

	req->fid = fid;
	if (fid->type&Qtauth) {
		if (conn->srv->auth) {
			n = conn->srv->auth->clunk(fid);
			if (n)
				rc = sp_create_rclunk();
		} else
			sp_werror(Ebadusefid, EIO);

		goto done;
	}

	if (fid->omode!=(u16)~0 && fid->omode==Orclose) {
		rc = (*conn->srv->remove)(fid);
		if (rc->type == Rerror)
			goto done;
		free(rc);
		rc = sp_create_rclunk();
	} else
		rc = (*conn->srv->clunk)(fid);

	if (rc && rc->type == Rclunk)
		sp_fid_decref(fid);

done:
	return rc;
}

Spfcall *
sp_remove(Spreq *req, Spfcall *tc)
{
	Spconn *conn;
	Spfid *fid;
	Spfcall *rc;

	rc = NULL;
	conn = req->conn;
	fid = sp_fid_find(conn, tc->fid);
	if (!fid) {
		sp_werror(Eunknownfid, EIO);
		goto done;
	} else 
		sp_fid_incref(fid);

	req->fid = fid;
	rc = (*conn->srv->remove)(fid);
	if (rc && rc->type == Rremove)
		sp_fid_decref(fid);

done:
	return rc;
}

Spfcall *
sp_stat(Spreq *req, Spfcall *tc)
{
	Spconn *conn;
	Spfid *fid;
	Spfcall *rc;

	rc = NULL;
	conn = req->conn;
	fid = sp_fid_find(conn, tc->fid);
	if (!fid) {
		sp_werror(Eunknownfid, EIO);
		goto done;
	} else 
		sp_fid_incref(fid);

	req->fid = fid;
	rc = (*conn->srv->stat)(fid);

done:
//	sp_fid_decref(fid);
	return rc;
}

Spfcall *
sp_wstat(Spreq *req, Spfcall *tc)
{
	Spconn *conn;
	Spfid *fid;
	Spfcall *rc;
	Spstat *stat;

	rc = NULL;
	conn = req->conn;
	stat = &tc->stat;
	fid = sp_fid_find(conn, tc->fid);
	if (!fid) {
		sp_werror(Eunknownfid, EIO);
		goto done;
	} else 
		sp_fid_incref(fid);

	req->fid = fid;
	if (stat->type != (u16)~0 || stat->dev != (u32)~0
	|| stat->qid.version != (u32)~0
	|| stat->qid.path != (u64)~0 ) {
                sp_werror(Eperm, EPERM);
                goto done;
        }

	if (((fid->type&Qtdir) && !(stat->mode&Dmdir))
	|| (!(fid->type&Qtdir) && (stat->mode&Dmdir))) {
		sp_werror(Edirchange, EPERM);
		goto done;
	}

	rc = (*conn->srv->wstat)(fid, &tc->stat);
done:
//	sp_fid_decref(fid);
	return rc;
}
