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
#include <limits.h>
#include <time.h>
#include "spfs.h"
#include "spfsimpl.h"

Spfile*
spfile_alloc(Spfile *parent, char *name, u32 mode, u64 qpath,
	void *ops, void *aux)
{
	Spfile *f;

	f = sp_malloc(sizeof(*f));
	if (!f)
		return NULL;

	f->refcount = 0;
	f->parent = parent;
	f->qid.type = mode>>24;
	f->qid.version = 0;
	f->qid.path = qpath;
	f->mode = mode;
	f->atime = 0;
	f->mtime = 0;
	f->length = 0;
	f->name = strdup(name);
	if (!f->name) {
		sp_werror(Enomem, ENOMEM);
		free(f);
		return NULL;
	}

	f->uid = NULL;
	f->gid = NULL;
	f->muid = NULL;
	f->excl = 0;
	f->extension = NULL;
	f->ops = ops;
	f->aux = aux;
	f->next = NULL;
	f->prev = NULL;
	f->dirfirst = NULL;
	f->dirlast = NULL;

	if (parent) {
		spfile_incref(parent);
		f->atime = parent->atime;
		f->mtime = parent->mtime;
		f->uid = parent->uid;
		f->gid = parent->gid;
		f->muid = f->uid;
	}

	return f;
}

void
spfile_incref(Spfile *f)
{
	if (!f)
		return;

	assert(f->refcount >= 0);
	f->refcount++;
}

int
spfile_decref(Spfile *f)
{
	int ret;
	Spfileops *fops;
	Spdirops *dops;

	if (!f)
		return 0;

	assert(f->refcount > 0);
	ret = --f->refcount;
	if (!ret) {
		if (f->ops) {
			if (f->mode & Dmdir) {
				dops = f->ops;
				if (dops->destroy)
					(*dops->destroy)(f);
			} else {
				fops = f->ops;
				if (fops->destroy)
					(*fops->destroy)(f);
			}
		}

		free(f->name);
		free(f->extension);
		free(f);
	} 

	return ret;
}

static void
spfile_ref(Spfile *file, Spfilefid *fid)
{
	Spfileops *fops;
	Spdirops *dops;

	if (file->ops) {
		if (file->mode & Dmdir) {
			dops = file->ops;
			if (dops->ref)
				(*dops->ref)(file, fid);
		} else {
			fops = file->ops;
			if (fops->ref)
				(*fops->ref)(file, fid);
		}
	}
}

static void
spfile_unref(Spfile *file, Spfilefid *fid)
{
	Spfileops *fops;
	Spdirops *dops;

	if (file->ops) {
		if (file->mode & Dmdir) {
			dops = file->ops;
			if (dops->unref)
				(*dops->unref)(file, fid);
		} else {
			fops = file->ops;
			if (fops->unref)
				(*fops->unref)(file, fid);
		}
	}
}

Spfile *
spfile_find(Spfile *dir, char *name)
{
	Spfile *f;
	Spdirops *dops;

	if (strcmp(name, "..") == 0)
		return dir->parent;

	dops = dir->ops;
	if (!dops->first || !dops->next) {
		sp_werror(Eperm, EPERM);
		return NULL;
	}

	for(f = (*dops->first)(dir); f != NULL; 
		f = (*dops->next)(dir, f)) {

		if (strcmp(name, f->name) == 0)
			break;
		spfile_decref(f);
	}

	return f;
}

static int
check_perm(u32 fperm, Spuser *fuid, Spgroup *fgid, Spuser *user, u32 perm)
{
	int i, n;
	Spgroup *group;
	gid_t *gids;

	if (!user)
		goto error;

	perm &= 7;
	if (!perm)
		return 1;

	if ((fperm&7) & perm)
		return 1;

	if (fuid==user && ((fperm>>6)&7) & perm)
		return 1;

	if (((fperm>>3)&7) & perm) {
		n = sp_usergroups(user, &gids);
		for(i = 0; i < n; i++) {
			group = sp_gid2group(gids[i]);
			if (fgid == group)
				return 1;
		}
	}

error:
	sp_werror(Eperm, EPERM);
	return 0;
}

static void
file2wstat(Spfile *file, Spwstat *wstat)
{
	wstat->size = 0;
	wstat->type = 0;
	wstat->dev = 0;
	wstat->qid = file->qid;
	wstat->mode = file->mode;
	wstat->atime = file->atime;
	wstat->mtime = file->mtime;
	wstat->length = file->length;
	wstat->name = file->name;
	wstat->uid = file->uid->uname;
	wstat->gid = file->gid->gname;
	wstat->muid = file->muid->uname;
	wstat->extension = file->extension;
	wstat->n_uid = file->uid->uid;
	wstat->n_gid = file->gid->gid;
	wstat->n_muid = file->muid->uid;
}

static void
blank_stat(Spstat *stat)
{
	stat->size = 0;
	stat->type = ~0;
	stat->dev = ~0;
	stat->qid.type = ~0;
	stat->qid.version = ~0;
	stat->qid.path = ~0;
	stat->mode = ~0;
	stat->atime = ~0;
	stat->mtime = ~0;
	stat->length = ~0;
	stat->name.len = 0;
	stat->uid.len = 0;
	stat->gid.len = 0;
	stat->muid.len = 0;
	stat->extension.len = 0;
	stat->n_uid = ~0;
	stat->n_gid = ~0;
	stat->n_muid = ~0;
}

int
spfile_checkperm(Spfile *file, Spuser *user, int perm)
{
	return check_perm(file->mode, file->uid, file->gid, user, perm);
}

static void
spfile_modified(Spfile *f, Spuser *u)
{
	// you better have the file locked ...
	f->muid = u;
	f->mtime = time(NULL);
	f->atime = f->mtime;
	f->qid.version++;
}

static Spfilefid*
spfile_fidalloc(Spfile *file, Spfid *fid) {
	Spfilefid *f;

	f = sp_malloc(sizeof(*f));
	if (!f)
		return NULL;

	f->omode = ~0;
	f->fid = fid;
	/* aux, diroffset and dirent can be non-zero only for open fids */
	f->aux = 0;
	f->diroffset = 0;
	f->dirent = NULL;
	f->file = file;
	spfile_incref(f->file);
	spfile_ref(file, f);

	return f;
}

void
spfile_fiddestroy(Spfid *fid)
{
	Spfilefid *f;
	Spfile *file;
	Spfileops *fops;

//	if (fid->conn->srv->debuglevel)
//		fprintf(stderr, "destroy fid %d\n", fid->fid);

	f = fid->aux;
	if (!f)
		return;

	file = f->file;
	if (f->omode != ~0) {
		if (!(file->mode&Dmdir)) {
			fops = file->ops;
			if (fops->closefid)
				(*fops->closefid)(f);
		}

		if (f->dirent)
			spfile_decref(f->dirent);
	}

	spfile_unref(file, f);
	spfile_decref(file);
	free(f);
}

Spfcall*
spfile_attach(Spfid *fid, Spfid *afid, Spstr *uname, Spstr *aname)
{
	Spfile *root;
	Spfilefid *f;
	char *u;
	Spuser *user;

	root = (Spfile*) fid->conn->srv->treeaux;

	u = sp_strdup(uname);
	if (!u)
		return NULL;

	user = sp_uname2user(u);
	free(u);
	if (!user) {
		sp_werror(Eunknownuser, EIO);
		return NULL;
	}

	if (!spfile_checkperm(root, user, 4)) 
		return NULL;

	fid->user = user;
	f = spfile_fidalloc(root, fid);
	if (!f)
		return NULL;

	fid->user = user;
	fid->aux = f;
	sp_fid_incref(fid);

	return sp_create_rattach(&root->qid);
}

int
spfile_clone(Spfid *fid, Spfid *newfid)
{
	Spfilefid *f, *nf;

	f = fid->aux;
	nf = spfile_fidalloc(f->file, newfid);
	if (!nf)
		return 0;

	newfid->aux = nf;

	return 1;
}

int
spfile_walk(Spfid *fid, Spstr *wname, Spqid *wqid)
{
	Spfilefid *f;
	Spfile *dir, *nfile;
	char *name;

	f = fid->aux;
	dir = f->file;

	if (!spfile_checkperm(dir, fid->user, 1))
		return 0;

	name = sp_strdup(wname);
	if (!name)
		return 0;

	nfile = spfile_find(dir, name);
	free(name);
	if (nfile) {
		spfile_unref(dir, f);
		f->file = nfile;
		spfile_decref(dir);
		spfile_ref(nfile, f);

		*wqid = nfile->qid;
	} else if (!sp_haserror())
		sp_werror(Enotfound, ENOENT);
		
	return nfile != NULL;
}

static int
mode2perm(int mode)
{
	int m;

	m = 0;
	switch (mode & 3) {
	case Oread:
		m = 4;
		break;

	case Owrite:
		m = 2;
		break;

	case Ordwr:
		m = 6;
		break;

	case Oexec:
		m = 1;
		break;
	}

	if (mode & Otrunc)
		m |= 2;

	return m;
}

Spfcall*
spfile_open(Spfid *fid, u8 mode)
{
	int m;
	Spfilefid *f;
	Spfile *file;
	Spfcall *ret;
	Spfileops *fops;
	Spstat stat;

	ret = NULL;
	f = fid->aux;
	file = f->file;
	m = mode2perm(mode);
	if (!spfile_checkperm(file, fid->user, m)) {
		return NULL;
	}

	if (mode & Oexcl) {
		if (file->excl) {
			sp_werror(Eopen, EPERM);
			return NULL;
		}

		file->excl = 1;
	}

	f->omode = mode;
	if (file->mode & Dmdir) {
		f->diroffset = 0;
		f->dirent = NULL;
	} else {
		fops = file->ops;

		if (mode & Otrunc) {
			if (!fops->wstat) {
				sp_werror(Eperm, EPERM);
				goto done;
			}

			blank_stat(&stat);
			stat.length = 0;
			if (!(*fops->wstat)(file, &stat))
				goto done;
		}

		if (fops->openfid && !(*fops->openfid)(f))
			goto done;
	}

	ret = sp_create_ropen(&file->qid, 0);

done:
	if (!ret && mode&Oexcl)
		file->excl = 1;

	return ret;

}

Spfcall*
spfile_create(Spfid *fid, Spstr* name, u32 perm, u8 mode, Spstr* extension)
{
	int m;
	Spfilefid *f;
	Spfile *dir, *file, *nf;
	Spdirops *dops;
	Spfileops *fops;
	char *sname, *sext;
	Spfcall *ret;

	ret = NULL;
	sname = NULL;
	file = NULL;

	f = fid->aux;
	dir = f->file;
	sname = sp_strdup(name);
	if (!sname)
		return NULL;

	sext = sp_strdup(extension);
	if (!sext) {
		free(sname);
		return NULL;
	}

	nf = spfile_find(dir, sname);
	if (sp_haserror())
		goto done;
	else if (nf) {
		sp_werror(Eexist, EEXIST);
		goto done;
	}

	if (!strcmp(sname, ".") || !strcmp(sname, "..")) {
		sp_werror(Eexist, EEXIST);
		goto done;
	}

	if (!spfile_checkperm(dir, fid->user, 2))
		goto done;

	if (perm & Dmsymlink)
		perm |= 0777;

	if (perm & Dmdir)
		perm &= ~0777 | (dir->mode & 0777);
	else 
		perm &= ~0666 | (dir->mode & 0666);

	m = mode2perm(mode);
	if (!check_perm(perm, fid->user, dir->gid, fid->user, m))
		goto done;

	dops = dir->ops;
	if (!dops->create) {
		sp_werror(Eperm, EPERM);
		goto done;
	}

	file = (*dops->create)(dir, sname, perm, fid->user, dir->gid, sext);
	if (!file)
		goto done;

	spfile_modified(dir, fid->user);
	f->file = file;
	f->omode = mode;

	if (mode & Oexcl)
		file->excl = 1;

	if (file->mode & Dmdir) {
		f->diroffset = 0;
		f->dirent = NULL;
	} else {
		fops = file->ops;
		if (fops->openfid)
			(*fops->openfid)(f);
	}

	f->omode = mode;
	ret = sp_create_rcreate(&file->qid, 0);

done:
	free(sname);
	free(sext);
	return ret;
}

Spfcall*
spfile_read(Spfid *fid, u64 offset, u32 count, Spreq *req)
{
	int i, n;
	Spfilefid *f;
	Spfile *file, *cf, *cf1;
	Spdirops *dops;
	Spfileops *fops;
	Spfcall *ret;
	Spwstat wstat;

	ret = NULL;
	f = fid->aux;
	ret = sp_alloc_rread(count);
	if (!ret)
		goto done;

	file = f->file;
	if (file->mode & Dmdir) {
		dops = file->ops;
		if (!dops->first || !dops->next) {
			sp_werror(Eperm, EPERM);
			goto done;
		}
			
		if (offset == 0) {
			if (f->dirent)
				spfile_decref(f->dirent);
			f->dirent = (*dops->first)(file);
			f->diroffset = 0;
		}

		n = 0;
		cf = f->dirent;
		while (n<count && cf!=NULL) {
			file2wstat(cf, &wstat);
			i = sp_serialize_stat(&wstat, ret->data + n, count - n - 1,
				fid->conn->dotu);

			if (i==0)
				break;

			n += i;
			cf1 = (dops->next)(file, cf);
			spfile_decref(cf);
			cf = cf1;
		}

		f->diroffset += n;
		f->dirent = cf;
		file->atime = time(NULL);
	} else {
		fops = file->ops;
		if (!fops->read) {
			sp_werror(Eperm, EPERM);
			goto done;
		}
		n = (*fops->read)(f, offset, count, ret->data, req);
		if (n < 0) {
			free(ret);
			ret = NULL;
		}

		file->atime = time(NULL);
	}

	if (ret)
		sp_set_rread_count(ret, n);

done:
	return ret;
}

Spfcall*
spfile_write(Spfid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	int n, ecode;
	Spfcall *ret;
	Spfilefid *f;
	Spfile *file;
	Spfileops *fops;
	char *ename;

	ret = NULL;
	f = fid->aux;
	file = f->file;
	if (f->omode & Oappend)
		offset = file->length;

	fops = file->ops;
	if (!fops->write) {
		sp_werror(Eperm, EPERM);
		goto done;
	}

	n = (*fops->write)(f, offset, count, data, req);

	sp_rerror(&ename, &ecode);
	if (!ename)
		spfile_modified(file, fid->user);

	if (n >= 0)
		ret = sp_create_rwrite(n);

done:
	return ret;
}

Spfcall*
spfile_clunk(Spfid *fid)
{
//	sp_fid_decref(fid);
	return sp_create_rclunk();
}

Spfcall*
spfile_remove(Spfid *fid)
{
	Spfilefid *f;
	Spfile *file, *cf, *parent;
	Spfcall *ret;
	Spdirops *dops;

	ret = NULL;
	f = fid->aux;
	file = f->file;
	if (file->mode&Dmdir) {
		dops = file->ops;
		if (!dops->first) {
			sp_werror(Eperm, EPERM);
			goto done;
		}

		cf = (*dops->first)(file);
		if (cf) {
			spfile_decref(cf);
			sp_werror(Enotempty, EIO);
			goto done;
		}
	}

	parent = file->parent;
	if (!spfile_checkperm(parent, fid->user, 2)) 
		return NULL;

	dops = parent->ops;
	if (!dops->remove) {
		sp_werror(Eperm, EPERM);
		goto done;
	}

	if ((*dops->remove)(parent, file)) {
		spfile_modified(parent, fid->user);
		spfile_decref(file);
		spfile_decref(parent);
		ret = sp_create_rremove();
	} 

done:
	return ret;
}

Spfcall*
spfile_stat(Spfid *fid)
{
	Spfilefid *f;
	Spfile *file;
	Spwstat wstat;

	f = fid->aux;
	file = f->file;
	file2wstat(file, &wstat);

	return sp_create_rstat(&wstat, fid->conn->dotu);
}

Spfcall*
spfile_wstat(Spfid *fid, Spstat *stat)
{
	int n;
	Spfilefid *f;
	Spfile *file;
	Spfileops *fops;
	Spdirops *dops;
	Spfcall *ret;

	ret = NULL;
	f = fid->aux;
	file = f->file;

	if (stat->name.len!=0 && !spfile_checkperm(file->parent, fid->user, 2))
		goto done;

	if (stat->length!=(u64)~0 && !spfile_checkperm(file, fid->user, 2))
		goto done;

	if (stat->mode!=(u32)~0 && file->uid!=fid->user) {
		sp_werror(Eperm, EPERM);
		goto done;
	}

	if (stat->mtime!=(u32)~0 && !spfile_checkperm(file, fid->user, 2)) {
		sp_werror(Eperm, EPERM);
		goto done;
	}

	if (file->mode & Dmdir) {
		dops = file->ops;
		if (!dops->wstat) {
			sp_werror(Eperm, EPERM);
			goto done;
		}
		n = (*dops->wstat)(file, stat);
	} else {
		fops = file->ops;
		if (!fops->wstat) {
			sp_werror(Eperm, EPERM);
			goto done;
		}
		n = (*fops->wstat)(file, stat);
	}

	if (!n)
		goto done;

	ret = sp_create_rwstat();

done:
	return ret;
}

void
spfile_init_srv(Spsrv *srv, Spfile *root)
{
	srv->dotu = 1;
	srv->attach = spfile_attach;
	srv->clone = spfile_clone;
	srv->walk = spfile_walk;
	srv->open = spfile_open;
	srv->create = spfile_create;
	srv->read = spfile_read;
	srv->write = spfile_write;
	srv->clunk = spfile_clunk;
	srv->remove = spfile_remove;
	srv->stat = spfile_stat;
	srv->wstat = spfile_wstat;
	srv->fiddestroy = spfile_fiddestroy;
	srv->treeaux = root;
	if (srv->msize > INT_MAX)
		srv->msize = INT_MAX;
}
