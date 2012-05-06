/*
 * Copyright (C) 2005 by Latchesar Ionkov <lucho@ionkov.net>
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
 * PRECISION INSIGHT AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

//#define _XOPEN_SOURCE 500
#define _BSD_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <utime.h>
#include <sys/mman.h>
#include "spfs.h"

#undef NPFS_USE_AIO

#define NELEM(x)	(sizeof(x)/sizeof((x)[0]))

typedef struct Fid Fid;

struct Fid {
	char*		path;
	int		omode;
	int		fd;
	DIR*		dir;
	int		diroffset;
	char*		direntname;
	void*		aux;		/* for mmapread */
	struct stat	stat;
};

Spsrv *srv;
int debuglevel = 0;
int sameuser;
int mmapreads;

char *Estatfailed = "stat failed";
char *Ebadfid = "fid unknown or out of range";
char *Enoextension = "empty extension while creating special file";
char *Eformat = "incorrect extension format";
char *Ecreatesocket = "cannot create socket";
//char *E = "";

static int fidstat(Fid *fid);
static void ustat2qid(struct stat *st, Spqid *qid);
static u8 ustat2qidtype(struct stat *st);
static u32 umode2npmode(mode_t umode, int dotu);
static mode_t npstat2umode(Spstat *st, int dotu);
static void ustat2npwstat(char *path, struct stat *st, Spwstat *wstat, int dotu);

static Spfcall* npfs_attach(Spfid *fid, Spfid *afid, Spstr *uname, Spstr *aname, u32 n_uname);
static int npfs_clone(Spfid *fid, Spfid *newfid);
static int npfs_walk(Spfid *fid, Spstr *wname, Spqid *wqid);
static Spfcall* npfs_open(Spfid *fid, u8 mode);
static Spfcall* npfs_create(Spfid *fid, Spstr *name, u32 perm, u8 mode, 
	Spstr *extension);
static Spfcall* npfs_read(Spfid *fid, u64 offset, u32 count, Spreq *);
static Spfcall* npfs_write(Spfid *fid, u64 offset, u32 count, u8 *data, Spreq *);
static Spfcall* npfs_clunk(Spfid *fid);
static Spfcall* npfs_remove(Spfid *fid);
static Spfcall* npfs_stat(Spfid *fid);
static Spfcall* npfs_wstat(Spfid *fid, Spstat *stat);

static void npfs_fiddestroy(Spfid *fid);

void
usage()
{
	fprintf(stderr, "npfs: -d -s [-x | -p port] -w nthreads\n");
	exit(-1);
}

int
main(int argc, char **argv)
{
	int c;
	int port, nwthreads;
	char *s;

	int use_tcp = 0;
	int use_eth = 0;

	port = 564;
	nwthreads = 16;
	while ((c = getopt(argc, argv, "dsmxp:w:")) != -1) {
		switch (c) {
		case 'd':
			debuglevel++;
			break;

		case 'x':
			if (use_tcp)
				usage();
			use_eth = 1;
			break;

		case 'p':
			if (use_eth)
				usage();
			port = strtol(optarg, &s, 10);
			if (*s != '\0')
				usage();
			use_tcp = 1;
			break;

		case 'w':
			nwthreads = strtol(optarg, &s, 10);
			if (*s != '\0')
				usage();
			break;

		case 's':
			sameuser = 1;
			break;

		case 'm':
			mmapreads = 1;
			break;

		default:
			usage();
		}
	}

	if (!use_tcp && !use_eth)
		use_tcp = 1;

	srv = (use_tcp)
		?sp_socksrv_create_tcp(&port)
		:sp_ethsrv_create();

	if (!srv)
		return -1;

	srv->dotu = 1;
	srv->attach = npfs_attach;
	srv->clone = npfs_clone;
	srv->walk = npfs_walk;
	srv->open = npfs_open;
	srv->create = npfs_create;
	srv->read = npfs_read;
	srv->write = npfs_write;
	srv->clunk = npfs_clunk;
	srv->remove = npfs_remove;
	srv->stat = npfs_stat;
	srv->wstat = npfs_wstat;
	srv->fiddestroy = npfs_fiddestroy;
	srv->debuglevel = debuglevel;

	sp_srv_start(srv);
	sp_poll_loop();
	return 0;
}

static int
fidstat(Fid *fid)
{
	if (lstat(fid->path, &fid->stat) < 0)
		return errno;

	if (S_ISDIR(fid->stat.st_mode))
		fid->stat.st_size = 0;

	return 0;
}

static Fid*
npfs_fidalloc() {
	Fid *f;

	f = malloc(sizeof(*f));

	f->path = NULL;
	f->omode = -1;
	f->fd = -1;
	f->dir = NULL;
	f->diroffset = 0;
	f->direntname = NULL;

	return f;
}

static void
npfs_fiddestroy(Spfid *fid)
{
	Fid *f;

	f = fid->aux;
	if (!f)
		return;

	if (f->fd != -1)
		close(f->fd);

	if (f->dir)
		closedir(f->dir);

	free(f->path);
	free(f);
}

static void
create_rerror(int ecode)
{
	char buf[256];

	strerror_r(ecode, buf, sizeof(buf));
	sp_werror(buf, ecode);
}

static int
omode2uflags(u8 mode)
{
	int ret;

	ret = 0;
	switch (mode & 3) {
	case Oread:
		ret = O_RDONLY;
		break;

	case Ordwr:
		ret = O_RDWR;
		break;

	case Owrite:
		ret = O_WRONLY;
		break;

	case Oexec:
		ret = O_RDONLY;
		break;
	}

	if (mode & Otrunc)
		ret |= O_TRUNC;

	if (mode & Oappend)
		ret |= O_APPEND;

	if (mode & Oexcl)
		ret |= O_EXCL;

	return ret;
}

static void
ustat2qid(struct stat *st, Spqid *qid)
{
	int n;

	qid->path = 0;
	n = sizeof(qid->path);
	if (n > sizeof(st->st_ino))
		n = sizeof(st->st_ino);
	memmove(&qid->path, &st->st_ino, n);
	qid->version = st->st_mtime ^ (st->st_size << 8);
	qid->type = ustat2qidtype(st);
}

static u8
ustat2qidtype(struct stat *st)
{
	u8 ret;

	ret = 0;
	if (S_ISDIR(st->st_mode))
		ret |= Qtdir;

	if (S_ISLNK(st->st_mode))
		ret |= Qtsymlink;

	return ret;
}

static u32
umode2npmode(mode_t umode, int dotu)
{
	u32 ret;

	ret = umode & 0777;
	if (S_ISDIR(umode))
		ret |= Dmdir;

	if (dotu) {
		if (S_ISLNK(umode))
			ret |= Dmsymlink;
		if (S_ISSOCK(umode))
			ret |= Dmsocket;
		if (S_ISFIFO(umode))
			ret |= Dmnamedpipe;
		if (S_ISBLK(umode))
			ret |= Dmdevice;
		if (S_ISCHR(umode))
			ret |= Dmdevice;
		if (umode & S_ISUID)
			ret |= Dmsetuid;
		if (umode & S_ISGID)
			ret |= Dmsetgid;
	}

	return ret;
}

static mode_t
np2umode(u32 mode, Spstr *extension, int dotu)
{
	mode_t ret;

	ret = mode & 0777;
	if (mode & Dmdir)
		ret |= S_IFDIR;

	if (dotu) {
		if (mode & Dmsymlink)
			ret |= S_IFLNK;
		if (mode & Dmsocket)
			ret |= S_IFSOCK;
		if (mode & Dmnamedpipe)
			ret |= S_IFIFO;
		if (mode & Dmdevice) {
			if (extension && extension->str[0] == 'c')
				ret |= S_IFCHR;
			else
				ret |= S_IFBLK;
		}
	}

	if (!(ret&~0777))
		ret |= S_IFREG;

	if (mode & Dmsetuid)
		ret |= S_ISUID;
	if (mode & Dmsetgid)
		ret |= S_ISGID;

	return ret;
}

static mode_t
npstat2umode(Spstat *st, int dotu)
{
	return np2umode(st->mode, &st->extension, dotu);
}

static void
ustat2npwstat(char *path, struct stat *st, Spwstat *wstat, int dotu)
{
	int err;
	Spuser *u;
	Spgroup *g;
	char *s, ext[256];

	memset(wstat, 0, sizeof(*wstat));
	ustat2qid(st, &wstat->qid);
	wstat->mode = umode2npmode(st->st_mode, dotu);
	wstat->atime = st->st_atime;
	wstat->mtime = st->st_mtime;
	wstat->length = st->st_size;

	u = sp_uid2user(st->st_uid);
	g = sp_gid2group(st->st_gid);
	
	wstat->uid = u?u->uname:"???";
	wstat->gid = g?g->gname:"???";
	wstat->muid = "";

	wstat->extension = NULL;
	if (dotu) {
		wstat->n_uid = st->st_uid;
		wstat->n_gid = st->st_gid;

		if (wstat->mode & Dmsymlink) {
			err = readlink(path, ext, sizeof(ext) - 1);
			if (err < 0)
				err = 0;

			ext[err] = '\0';
		} else if (wstat->mode & Dmdevice) {
			snprintf(ext, sizeof(ext), "%c %u %u", 
				S_ISCHR(st->st_mode)?'c':'b',
				major(st->st_rdev), minor(st->st_rdev));
		} else {
			ext[0] = '\0';
		}

		wstat->extension = strdup(ext);
	}

	s = strrchr(path, '/');
	if (s)
		wstat->name = s + 1;
	else
		wstat->name = path;
}

static inline void
npfs_change_user(Spuser *user)
{
	if (!sameuser)
		sp_change_user(user);
}

static Spfcall*
npfs_attach(Spfid *nfid, Spfid *nafid, Spstr *uname, Spstr *aname, u32 n_uname)
{
	int err;
	Spfcall* ret;
	Fid *fid;
	Spqid qid;
	char *user;

	user = NULL;
	ret = NULL;

	if (nafid != NULL) {
		sp_werror(Enoauth, EIO);
		goto done;
	}

	fid = npfs_fidalloc();
	fid->omode = -1;
	npfs_change_user(nfid->user);

	fid->omode = -1;
	if (aname->len==0 || *aname->str!='/')
		fid->path = strdup("/");
	else
		fid->path = sp_strdup(aname);
	
	nfid->aux = fid;
	err = fidstat(fid);
	if (err < 0) {
		create_rerror(err);
		goto done;
	}

	ustat2qid(&fid->stat, &qid);
	ret = sp_create_rattach(&qid);
	sp_fid_incref(nfid);

done:
	return ret;
}

static int
npfs_clone(Spfid *fid, Spfid *newfid)
{
	Fid *f, *nf;

	f = fid->aux;
	nf = npfs_fidalloc();
	nf->path = strdup(f->path);
	newfid->aux = nf;

	return 1;	
}


static int
npfs_walk(Spfid *fid, Spstr* wname, Spqid *wqid)
{
	int n;
	Fid *f;
	struct stat st;
	char *path;

	f = fid->aux;
	npfs_change_user(fid->user);
	n = fidstat(f);
	if (n < 0)
		create_rerror(n);

	n = strlen(f->path);
	path = malloc(n + wname->len + 2);
	memcpy(path, f->path, n);
	path[n] = '/';
	memcpy(path + n + 1, wname->str, wname->len);
	path[n + wname->len + 1] = '\0';

	if (lstat(path, &st) < 0) {
		free(path);
		create_rerror(errno);
		return 0;
	}

	free(f->path);
	f->path = path;
	ustat2qid(&st, wqid);

	return 1;
}

static Spfcall*
npfs_open(Spfid *fid, u8 mode)
{
	int err;
	Fid *f;
	Spqid qid;

	f = fid->aux;
	npfs_change_user(fid->user);
	if ((err = fidstat(f)) < 0)
		create_rerror(err);

	if (S_ISDIR(f->stat.st_mode)) {
		f->dir = opendir(f->path);
		if (!f->dir)
			create_rerror(errno);
	} else {
		f->fd = open(f->path, omode2uflags(mode));
		if (f->fd < 0)
			create_rerror(errno);
	}

	err = fidstat(f);
	if (err < 0)
		create_rerror(err);

	f->omode = mode;
	ustat2qid(&f->stat, &qid);
	return sp_create_ropen(&qid, 0);
}

static int
npfs_create_special(Spfid *fid, char *path, u32 perm, Spstr *extension)
{
	int nfid, err;
	int nmode, major, minor;
	char ctype;
	mode_t umode;
	Spfid *ofid;
	Fid *f, *of;
	char *ext;

	f = fid->aux;
	if (!perm&Dmnamedpipe && !extension->len) {
		sp_werror(Enoextension, EIO);
		return -1;
	}

	umode = np2umode(perm, extension, fid->conn->dotu);
	ext = sp_strdup(extension);
	if (perm & Dmsymlink) {
		if (symlink(ext, path) < 0) {
			err = errno;
			fprintf(stderr, "symlink %s %s %d\n", ext, path, err);
			create_rerror(err);
			goto error;
		}
	} else if (perm & Dmlink) {
		if (sscanf(ext, "%d", &nfid) == 0) {
			sp_werror(Eformat, EIO);
			goto error;
		}

		ofid = sp_fid_find(fid->conn, nfid);
		if (!ofid) {
			sp_werror(Eunknownfid, EIO);
			goto error;
		}

		of = ofid->aux;
		if (link(of->path, path) < 0) {
			create_rerror(errno);
			goto error;
		}
	} else if (perm & Dmdevice) {
		if (sscanf(ext, "%c %u %u", &ctype, &major, &minor) != 3) {
			sp_werror(Eformat, EIO);
			goto error;
		}

		nmode = 0;
		switch (ctype) {
		case 'c':
			nmode = S_IFCHR;
			break;

		case 'b':
			nmode = S_IFBLK;
			break;

		default:
			sp_werror(Eformat, EIO);
			goto error;
		}

		nmode |= perm & 0777;
		if (mknod(path, nmode, makedev(major, minor)) < 0) {
			create_rerror(errno);
			goto error;
		}
	} else if (perm & Dmnamedpipe) {
		if (mknod(path, S_IFIFO | (umode&0777), 0) < 0) {
			create_rerror(errno);
			goto error;
		}
	}

	f->omode = 0;
	if (!perm&Dmsymlink && chmod(path, umode)<0) {
		create_rerror(errno);
		goto error;
	}

	free(ext);
	return 0;

error:
	free(ext);
	return -1;
}


static Spfcall*
npfs_create(Spfid *fid, Spstr *name, u32 perm, u8 mode, Spstr *extension)
{
	int n, err, omode;
	Fid *f;
	Spfcall *ret;
	Spqid qid;
	char *npath;
	struct stat st;

	ret = NULL;
	omode = mode;
	f = fid->aux;
	if ((err = fidstat(f)) < 0)
		create_rerror(err);

	n = strlen(f->path);
	npath = malloc(n + name->len + 2);
	memmove(npath, f->path, n);
	npath[n] = '/';
	memmove(npath + n + 1, name->str, name->len);
	npath[n + name->len + 1] = '\0';

	if (lstat(npath, &st)==0 || errno!=ENOENT) {
		sp_werror(Eexist, EEXIST);
		goto out;
	}

	if (perm & Dmdir) {
		if (mkdir(npath, perm & 0777) < 0) {
			create_rerror(errno);
			goto out;
		}

		if (lstat(npath, &f->stat) < 0) {
			create_rerror(errno);
			rmdir(npath);
			goto out;
		}
		
		f->dir = opendir(npath);
		if (!f->dir) {
			create_rerror(errno);
			remove(npath);
			goto out;
		}
	} else if (perm & (Dmnamedpipe|Dmsymlink|Dmlink|Dmdevice)) {
		if (npfs_create_special(fid, npath, perm, extension) < 0)
			goto out;

		if (lstat(npath, &f->stat) < 0) {
			create_rerror(errno);
			remove(npath);
			goto out;
		}
	} else {
		f->fd = open(npath, O_CREAT|omode2uflags(mode), 
			perm & 0777);
		if (f->fd < 0) {
			create_rerror(errno);
			goto out;
		}

		if (lstat(npath, &f->stat) < 0) {
			create_rerror(errno);
			remove(npath);
			goto out;
		}
	}

	free(f->path);
	f->path = npath;
	f->omode = omode;
	npath = NULL;
	ustat2qid(&f->stat, &qid);
	ret = sp_create_rcreate(&qid, 0);

out:
	free(npath);
	return ret;
}

static u32
npfs_read_dir(Fid *f, u8* buf, u64 offset, u32 count, int dotu)
{
	int i, n, plen;
	char *dname, *path;
	struct dirent *dirent;
	struct stat st;
	Spwstat wstat;

	if (offset == 0) {
		rewinddir(f->dir);
		f->diroffset = 0;
	}

	plen = strlen(f->path);
	n = 0;
	dirent = NULL;
	dname = f->direntname;
	while (n < count) {
		if (!dname) {
			dirent = readdir(f->dir);
			if (!dirent)
				break;

			if (strcmp(dirent->d_name, ".") == 0
			|| strcmp(dirent->d_name, "..") == 0)
				continue;

			dname = dirent->d_name;
		}

		path = malloc(plen + strlen(dname) + 2);
		sprintf(path, "%s/%s", f->path, dname);
		
		if (lstat(path, &st) < 0) {
			free(path);
			create_rerror(errno);
			return 0;
		}

		ustat2npwstat(path, &st, &wstat, dotu);
		i = sp_serialize_stat(&wstat, buf + n, count - n - 1, dotu);
		free(wstat.extension);
		free(path);
		path = NULL;
		if (i==0)
			break;

		dname = NULL;
		n += i;
	}

	if (f->direntname) {
		free(f->direntname);
		f->direntname = NULL;
	}

	if (dirent)
		f->direntname = strdup(dirent->d_name);

	f->diroffset += n;
	return n;
}

static Spfcall*
npfs_read(Spfid *fid, u64 offset, u32 count, Spreq *req)
{
	int n;
	Fid *f;
	Spfcall *ret;

	f = fid->aux;
	ret = sp_alloc_rread(count);
	npfs_change_user(fid->user);
	if (f->dir)
		n = npfs_read_dir(f, ret->data, offset, count, fid->conn->dotu);
	else {
		if(mmapreads) {
			struct stat s;
			n = count;
			if(!f->aux) {
				fstat(f->fd, &s);
				f->aux=mmap(0, s.st_size, PROT_READ, 
						MAP_SHARED, f->fd, 0);
				if(f->aux < 0) {
					create_rerror(errno);
					goto error;	
				}
			}
			if(offset+count > s.st_size)
				n = s.st_size-offset;
			if(n>0)
				memcpy(ret->data, f->aux+offset, n);
			else 
				n = 0;
		} else {
			n = pread(f->fd, ret->data, count, offset);
			if (n < 0)
				create_rerror(errno);
		}
	}

error:
	if (sp_haserror()) {
		free(ret);
		ret = NULL;
	} else
		sp_set_rread_count(ret, n);

	return ret;
}

static Spfcall*
npfs_write(Spfid *fid, u64 offset, u32 count, u8 *data, Spreq *req)
{
	int n;
	Fid *f;

	f = fid->aux;
	npfs_change_user(fid->user);

	n = pwrite(f->fd, data, count, offset);
	if (n < 0)
		create_rerror(errno);

	return sp_create_rwrite(n);
}

static Spfcall*
npfs_clunk(Spfid *fid)
{
	Fid *f;
	Spfcall *ret;

	f = fid->aux;
	ret = sp_create_rclunk();
//	sp_fid_decref(fid);
	return ret;
}

static Spfcall*
npfs_remove(Spfid *fid)
{
	Fid *f;
	Spfcall *ret;

	ret = NULL;
	f = fid->aux;
	npfs_change_user(fid->user);
	if (remove(f->path) < 0) {
		create_rerror(errno);
		goto out;
	}

	ret = sp_create_rremove();

out:
//	sp_fid_decref(fid);
	return ret;

}

static Spfcall*
npfs_stat(Spfid *fid)
{
	int err;
	Fid *f;
	Spfcall *ret;
	Spwstat wstat;

	f = fid->aux;
	npfs_change_user(fid->user);
	err = fidstat(f);
	if (err < 0)
		create_rerror(err);

	ustat2npwstat(f->path, &f->stat, &wstat, fid->conn->dotu);

	ret = sp_create_rstat(&wstat, fid->conn->dotu);
	free(wstat.extension);

	return ret;
}

static Spfcall*
npfs_wstat(Spfid *fid, Spstat *stat)
{
	int err;
	Fid *f;
	Spfcall *ret;
	uid_t uid;
	gid_t gid;
	char *npath, *p, *s;
	Spuser *user;
	Spgroup *group;
	struct utimbuf tb;

	ret = NULL;
	f = fid->aux;
	npfs_change_user(fid->user);
	err = fidstat(f);
	if (err < 0) {
		create_rerror(err);
		goto out;
	}

	if (fid->conn->dotu) {
		uid = stat->n_uid;
		gid = stat->n_gid;
	} else {
		uid = (uid_t) -1;
		gid = (gid_t) -1;
	}

	if (uid == -1 && stat->uid.len) {
		s = sp_strdup(&stat->uid);
		user = sp_uname2user(s);
		free(s);
		if (!user) {
			sp_werror(Eunknownuser, EIO);
			goto out;
		}

		uid = user->uid;
	}

	if (gid == -1 && stat->gid.len) {
		s = sp_strdup(&stat->gid);
		group = sp_gname2group(s);
		free(s);
		if (!group) {
			sp_werror(Eunknownuser, EIO);
			goto out;
		}

		gid = group->gid;
	}

	if (stat->mode != (u32)~0) {
		if (stat->mode&Dmdir && !S_ISDIR(f->stat.st_mode)) {
			sp_werror(Edirchange, EIO);
			goto out;
		}

		if (chmod(f->path, npstat2umode(stat, fid->conn->dotu)) < 0) {
			create_rerror(errno);
			goto out;
		}
	}

	if (stat->mtime != (u32)~0) {
		tb.actime = 0;
		tb.modtime = stat->mtime;
		if (utime(f->path, &tb) < 0) {
			create_rerror(errno);
			goto out;
		}
	}

	if (gid != -1) {
		if (chown(f->path, uid, gid) < 0) {
			create_rerror(errno);
			goto out;
		}
	}

	if (stat->name.len != 0) {
		p = strrchr(f->path, '/');
		if (!p)
			p = f->path + strlen(f->path);

		npath = malloc(stat->name.len + (p - f->path) + 2);
		memcpy(npath, f->path, p - f->path);
		npath[p - f->path] = '/';
		memcpy(npath + (p - f->path) + 1, stat->name.str, stat->name.len);
		npath[(p - f->path) + 1 + stat->name.len] = 0;
		if (strcmp(npath, f->path) != 0) {
			if (rename(f->path, npath) < 0) {
				create_rerror(errno);
				goto out;
			}

			free(f->path);
			f->path = npath;
		}
	}

	if (stat->length != ~0) {
		if (truncate(f->path, stat->length) < 0) {
			create_rerror(errno);
			goto out;
		}
	}
	ret = sp_create_rwstat();
	
out:
	return ret;
}
