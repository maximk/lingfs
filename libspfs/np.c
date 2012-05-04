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
 * LATCHESAR IONKOV AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>
#include "spfs.h"
#include "spfsimpl.h"

struct cbuf {
	unsigned char *sp;
	unsigned char *p;
	unsigned char *ep;
};

static inline void
buf_init(struct cbuf *buf, void *data, int datalen)
{
	buf->sp = buf->p = data;
	buf->ep = data + datalen;
}

static inline int
buf_check_overflow(struct cbuf *buf)
{
	return buf->p > buf->ep;
}

static inline int
buf_check_end(struct cbuf *buf)
{
	return buf->p == buf->ep;
}

static inline int
buf_check_size(struct cbuf *buf, int len)
{
	if (buf->p+len > buf->ep) {
		if (buf->p < buf->ep)
			buf->p = buf->ep + 1;

		return 0;
	}

	return 1;
}

static inline void *
buf_alloc(struct cbuf *buf, int len)
{
	void *ret = NULL;

	if (buf_check_size(buf, len)) {
		ret = buf->p;
		buf->p += len;
	}

	return ret;
}

static inline void
buf_put_int8(struct cbuf *buf, u8 val, u8* pval)
{
	if (buf_check_size(buf, 1)) {
		buf->p[0] = val;
		buf->p++;

		if (pval)
			*pval = val;
	}
}

static inline void
buf_put_int16(struct cbuf *buf, u16 val, u16 *pval)
{
	if (buf_check_size(buf, 2)) {
		buf->p[0] = val;
		buf->p[1] = val >> 8;
		buf->p += 2;

		if (pval)
			*pval = val;

	}
}

static inline void
buf_put_int32(struct cbuf *buf, u32 val, u32 *pval)
{
	if (buf_check_size(buf, 4)) {
		buf->p[0] = val;
		buf->p[1] = val >> 8;
		buf->p[2] = val >> 16;
		buf->p[3] = val >> 24;
		buf->p += 4;

		if (pval)
			*pval = val;
	}
}

static inline void
buf_put_int64(struct cbuf *buf, u64 val, u64 *pval)
{
	if (buf_check_size(buf, 8)) {
		buf->p[0] = val;
		buf->p[1] = val >> 8;
		buf->p[2] = val >> 16;
		buf->p[3] = val >> 24;
		buf->p[4] = val >> 32;
		buf->p[5] = val >> 40;
		buf->p[6] = val >> 48;
		buf->p[7] = val >> 56;
		buf->p += 8;

		if (pval)
			*pval = val;
	}
}

static inline void
buf_put_str(struct cbuf *buf, char *s, Spstr *ps)
{
	int slen = 0;

	if (s)
		slen = strlen(s);

	if (buf_check_size(buf, 2+slen)) {
		ps->len = slen;
		buf_put_int16(buf, slen, NULL);
		ps->str = buf_alloc(buf, slen);
		memmove(ps->str, s, slen);
	}
}

static inline void
buf_put_qid(struct cbuf *buf, Spqid *qid, Spqid *pqid)
{
	buf_put_int8(buf, qid->type, &pqid->type);
	buf_put_int32(buf, qid->version, &pqid->version);
	buf_put_int64(buf, qid->path, &pqid->path);
}

static inline void
buf_put_wstat(struct cbuf *bufp, Spwstat *wstat, Spstat* stat, int statsz, int dotu)
{
	buf_put_int16(bufp, statsz, &stat->size);
	buf_put_int16(bufp, wstat->type, &stat->type);
	buf_put_int32(bufp, wstat->dev, &stat->dev);
	buf_put_qid(bufp, &wstat->qid, &stat->qid);
	buf_put_int32(bufp, wstat->mode, &stat->mode);
	buf_put_int32(bufp, wstat->atime, &stat->atime);
	buf_put_int32(bufp, wstat->mtime, &stat->mtime);
	buf_put_int64(bufp, wstat->length, &stat->length);

	buf_put_str(bufp, wstat->name, &stat->name);
	buf_put_str(bufp, wstat->uid, &stat->uid);
	buf_put_str(bufp, wstat->gid, &stat->gid);
	buf_put_str(bufp, wstat->muid, &stat->muid);

	if (dotu) {
		buf_put_str(bufp, wstat->extension, &stat->extension);
		buf_put_int32(bufp, wstat->n_uid, &stat->n_uid);
		buf_put_int32(bufp, wstat->n_gid, &stat->n_gid);
		buf_put_int32(bufp, wstat->n_muid, &stat->n_muid);
	}
}

static inline u8
buf_get_int8(struct cbuf *buf)
{
	u8 ret = 0;

	if (buf_check_size(buf, 1)) {
		ret = buf->p[0];
		buf->p++;
	}

	return ret;
}

static inline u16
buf_get_int16(struct cbuf *buf)
{
	u16 ret = 0;

	if (buf_check_size(buf, 2)) {
		ret = buf->p[0] | (buf->p[1] << 8);
		buf->p += 2;
	}

	return ret;
}

static inline u32
buf_get_int32(struct cbuf *buf)
{
	u32 ret = 0;

	if (buf_check_size(buf, 4)) {
		ret = buf->p[0] | (buf->p[1] << 8) | (buf->p[2] << 16) | 
			(buf->p[3] << 24);
		buf->p += 4;
	}

	return ret;
}

static inline u64
buf_get_int64(struct cbuf *buf)
{
	u64 ret = 0;

	if (buf_check_size(buf, 8)) {
		ret = (u64) buf->p[0] | 
			((u64) buf->p[1] << 8) |
			((u64) buf->p[2] << 16) | 
			((u64) buf->p[3] << 24) |
			((u64) buf->p[4] << 32) | 
			((u64) buf->p[5] << 40) |
			((u64) buf->p[6] << 48) | 
			((u64) buf->p[7] << 56);
		buf->p += 8;
	}

	return ret;
}

static inline void
buf_get_str(struct cbuf *buf, Spstr *str)
{
	str->len = buf_get_int16(buf);
	str->str = buf_alloc(buf, str->len);
}

static inline void
buf_get_qid(struct cbuf *buf, Spqid *qid)
{
	qid->type = buf_get_int8(buf);
	qid->version = buf_get_int32(buf);
	qid->path = buf_get_int64(buf);
}

static inline void
buf_get_stat(struct cbuf *buf, Spstat *stat, int dotu)
{
	stat->size = buf_get_int16(buf);
	stat->type = buf_get_int16(buf);
	stat->dev = buf_get_int32(buf);
	buf_get_qid(buf, &stat->qid);
	stat->mode = buf_get_int32(buf);
	stat->atime = buf_get_int32(buf);
	stat->mtime = buf_get_int32(buf);
	stat->length = buf_get_int64(buf);
	buf_get_str(buf, &stat->name);
	buf_get_str(buf, &stat->uid);
	buf_get_str(buf, &stat->gid);
	buf_get_str(buf, &stat->muid);

	if (dotu) {
		buf_get_str(buf, &stat->extension);
		stat->n_uid = buf_get_int32(buf);
		stat->n_gid = buf_get_int32(buf);
		stat->n_muid = buf_get_int32(buf);
	} else {
		stat->extension.len = 0;
		stat->n_uid = ~0;
		stat->n_gid = ~0;
		stat->n_muid = ~0;
	}

}

static int
size_wstat(Spwstat *wstat, int dotu)
{
	int size = 0;

	if (wstat == NULL)
		return 0;

	size = 2 + 4 + 13 + 4 +  /* type[2] dev[4] qid[13] mode[4] */
		4 + 4 + 8 + 	 /* atime[4] mtime[4] length[8] */
		8;		 /* name[s] uid[s] gid[s] muid[s] */

	if (wstat->name)
		size += strlen(wstat->name);
	if (wstat->uid)
		size += strlen(wstat->uid);
	if (wstat->gid)
		size += strlen(wstat->gid);
	if (wstat->muid)
		size += strlen(wstat->muid);

	if (dotu) {
		size += 4 + 4 + 4 + 2; /* n_uid[4] n_gid[4] n_muid[4] extension[s] */
		if (wstat->extension)
			size += strlen(wstat->extension);
	}

	return size;
}

char *
sp_strdup(Spstr *str)
{
	char *ret;

	ret = sp_malloc(str->len + 1);
	if (!ret)
		return NULL;

	memmove(ret, str->str, str->len);
	ret[str->len] = '\0';

	return ret;
}

int
sp_strcmp(Spstr *str, char *cs)
{
	int ret;

	ret = strncmp(str->str, cs, str->len);
	if (!ret && cs[str->len])
		ret = 1;

	return ret;
}

int
sp_strncmp(Spstr *str, char *cs, int len)
{
	int ret;

	if (str->len >= len)
		ret = strncmp(str->str, cs, len);
	else
		ret = sp_strcmp(str, cs);

	return ret;
}

void
sp_set_tag(Spfcall *fc, u16 tag)
{
	fc->tag = tag;
	fc->pkt[5] = tag;
	fc->pkt[6] = tag >> 8;
}

static Spfcall *
sp_create_common(struct cbuf *bufp, u32 size, u8 id)
{
	Spfcall *fc;

	size += 4 + 1 + 2; /* size[4] id[1] tag[2] */
	fc = sp_malloc(sizeof(Spfcall) + size);
	if (!fc)
		return NULL;

	memset(fc, 0, sizeof(*fc));
	fc->pkt = (u8 *) fc + sizeof(*fc);
	buf_init(bufp, (char *) fc->pkt, size);
	buf_put_int32(bufp, size, &fc->size);
	buf_put_int8(bufp, id, &fc->type);
	buf_put_int16(bufp, NOTAG, &fc->tag);

	return fc;
}

static Spfcall *
sp_post_check(Spfcall *fc, struct cbuf *bufp)
{
	if (buf_check_overflow(bufp)) {
		fprintf(stderr, "buffer overflow\n");
		return NULL;
	}

//	fprintf(stderr, "serialize dump: ");
//	dumpdata(fc->pkt, fc->size);
	return fc;
}

Spfcall *
sp_create_tversion(u32 msize, char *version)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 4 + 2 + strlen(version); /* msize[4] version[s] */
	fc = sp_create_common(bufp, size, Tversion);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, msize, &fc->msize);
	buf_put_str(bufp, version, &fc->version);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rversion(u32 msize, char *version)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 4 + 2 + strlen(version); /* msize[4] version[s] */
	fc = sp_create_common(bufp, size, Rversion);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, msize, &fc->msize);
	buf_put_str(bufp, version, &fc->version);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_tauth(u32 fid, char *uname, char *aname, u32 n_uname, int dotu)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 4 + 2 + 2; /* fid[4] uname[s] aname[s] */
	if (uname)
		size += strlen(uname);

	if (aname)
		size += strlen(aname);

	if (dotu)
		size += 4;	/* n_uname[4] */

	fc = sp_create_common(bufp, size, Tauth);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, fid, &fc->fid);
	buf_put_str(bufp, uname, &fc->uname);
	buf_put_str(bufp, aname, &fc->aname);
	if (dotu)
		buf_put_int32(bufp, fid, &fc->n_uname);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rauth(Spqid *aqid)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 13; /* aqid[13] */
	fc = sp_create_common(bufp, size, Rauth);
	if (!fc)
		return NULL;

	buf_put_qid(bufp, aqid, &fc->qid);
	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rerror(char *ename, int ecode, int dotu)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 2 + strlen(ename); /* ename[s] */
	if (dotu)
		size += 4; /* ecode[4] */

	fc = sp_create_common(bufp, size, Rerror);
	if (!fc)
		return NULL;

	buf_put_str(bufp, ename, &fc->ename);
	if (dotu)
		buf_put_int32(bufp, ecode, &fc->ecode);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rerror1(Spstr *ename, int ecode, int dotu)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 2 + ename->len + (dotu?4:0); /* ename[s] ecode[4] */
	fc = sp_create_common(bufp, size, Rerror);
	if (!fc)
		return NULL;

	fc->ename.len = ename->len;
	fc->ename.str = buf_alloc(bufp, ename->len);
	memmove(fc->ename.str, ename->str, ename->len);
	if (dotu)
		buf_put_int32(bufp, ecode, &fc->ecode);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_tflush(u16 oldtag)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 2;
	fc = sp_create_common(bufp, size, Tflush);
	if (!fc)
		return NULL;

	buf_put_int16(bufp, oldtag, &fc->oldtag);
	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rflush(void)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 0;
	fc = sp_create_common(bufp, size, Rflush);
	if (!fc)
		return NULL;

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_tattach(u32 fid, u32 afid, char *uname, char *aname, u32 n_uname, int dotu)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 4 + 4 + 2 + 2; /* fid[4] afid[4] uname[s] aname[s] */
	if (uname)
		size += strlen(uname);

	if (aname)
		size += strlen(aname);

	if (dotu)
		size += 4; /* n_uname[4] */

	fc = sp_create_common(bufp, size, Tattach);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, fid, &fc->fid);
	buf_put_int32(bufp, afid, &fc->afid);
	buf_put_str(bufp, uname, &fc->uname);
	buf_put_str(bufp, aname, &fc->aname);

	if (dotu)
		buf_put_int32(bufp, n_uname, &fc->n_uname);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rattach(Spqid *qid)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 13; /* qid[13] */
	fc = sp_create_common(bufp, size, Rattach);
	if (!fc)
		return NULL;

	buf_put_qid(bufp, qid, &fc->qid);
	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_twalk(u32 fid, u32 newfid, u16 nwname, char **wnames)
{
	int i, size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	if (nwname > MAXWELEM) {
		fprintf(stderr, "nwqid > MAXWELEM\n");
		return NULL;
	}

	bufp = &buffer;
	size = 4 + 4 + 2 + nwname * 2; /* fid[4] newfid[4] nwname[2] nwname*wname[s] */
	for(i = 0; i < nwname; i++)
		size += strlen(wnames[i]);

	fc = sp_create_common(bufp, size, Twalk);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, fid, &fc->fid);
	buf_put_int32(bufp, newfid, &fc->newfid);
	buf_put_int16(bufp, nwname, &fc->nwname);
	for(i = 0; i < nwname; i++)
		buf_put_str(bufp, wnames[i], &fc->wnames[i]);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rwalk(int nwqid, Spqid *wqids)
{
	int i, size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	if (nwqid > MAXWELEM) {
		fprintf(stderr, "nwqid > MAXWELEM\n");
		return NULL;
	}

	bufp = &buffer;
	size = 2 + nwqid*13; /* nwqid[2] nwqid*wqid[13] */
	fc = sp_create_common(bufp, size, Rwalk);
	if (!fc)
		return NULL;

	buf_put_int16(bufp, nwqid, &fc->nwqid);
	for(i = 0; i < nwqid; i++) {
		buf_put_qid(bufp, &wqids[i], &fc->wqids[i]);
	}

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_topen(u32 fid, u8 mode)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 4 + 1; /* fid[4] mode[1] */
	fc = sp_create_common(bufp, size, Topen);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, fid, &fc->fid);
	buf_put_int8(bufp, mode, &fc->mode);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_ropen(Spqid *qid, u32 iounit)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 13 + 4; /* qid[13] iounit[4] */
	fc = sp_create_common(bufp, size, Ropen);
	if (!fc)
		return NULL;

	buf_put_qid(bufp, qid, &fc->qid);
	buf_put_int32(bufp, iounit, &fc->iounit);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_tcreate(u32 fid, char *name, u32 perm, u8 mode, char *extension, int dotu)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 4 + 2 + strlen(name) + 4 + 1; /* fid[4] name[s] perm[4] mode[1] */
	if (dotu)
		size += 2 + (extension?strlen(extension):0);

	fc = sp_create_common(bufp, size, Tcreate);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, fid, &fc->fid);
	buf_put_str(bufp, name, &fc->name);
	buf_put_int32(bufp, perm, &fc->perm);
	buf_put_int8(bufp, mode, &fc->mode);
	if (dotu)
		buf_put_str(bufp, extension, &fc->extension);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rcreate(Spqid *qid, u32 iounit)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 13 + 4; /* qid[13] iounit[4] */
	fc = sp_create_common(bufp, size, Rcreate);
	if (!fc)
		return NULL;

	buf_put_qid(bufp, qid, &fc->qid);
	buf_put_int32(bufp, iounit, &fc->iounit);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_tread(u32 fid, u64 offset, u32 count)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 4 + 8 + 4; /* fid[4] offset[8] count[4] */
	fc = sp_create_common(bufp, size, Tread);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, fid, &fc->fid);
	buf_put_int64(bufp, offset, &fc->offset);
	buf_put_int32(bufp, count, &fc->count);
	return sp_post_check(fc, bufp);
}

Spfcall *
sp_alloc_rread(u32 count)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;
	void *p;

	bufp = &buffer;
	size = 4 + count; /* count[4] data[count] */
	fc = sp_create_common(bufp, size, Rread);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, count, &fc->count);
	p = buf_alloc(bufp, count);
	fc->data = p;

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rread(u32 count, u8* data)
{
	Spfcall *fc;

	fc = sp_alloc_rread(count);
	if (fc->data)
		memmove(fc->data, data, count);

	return fc;
}

void
sp_set_rread_count(Spfcall *fc, u32 count)
{
	int size;
	struct cbuf buffer;
	struct cbuf *bufp;

	assert(count <= fc->count);
	bufp = &buffer;
	size = 4 + 1 + 2 + 4 + count; /* size[4] id[1] tag[2] count[4] data[count] */

	buf_init(bufp, (char *) fc->pkt, size);
	buf_put_int32(bufp, size, &fc->size);
	buf_init(bufp, (char *) fc->pkt + 7, size - 7);
	buf_put_int32(bufp, count, &fc->count);
}

Spfcall *
sp_create_twrite(u32 fid, u64 offset, u32 count, u8 *data)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;
	void *p;

	bufp = &buffer;
	size = 4 + 8 + 4 + count; /* fid[4] offset[8] count[4] data[count] */
	fc = sp_create_common(bufp, size, Twrite);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, fid, &fc->fid);
	buf_put_int64(bufp, offset, &fc->offset);
	buf_put_int32(bufp, count, &fc->count);
	p = buf_alloc(bufp, count);
	fc->data = p;
	if (fc->data)
		memmove(fc->data, data, count);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rwrite(u32 count)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 4; /* count[4] */
	fc = sp_create_common(bufp, size, Rwrite);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, count, &fc->count);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_tclunk(u32 fid)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 4;	/* fid[4] */
	fc = sp_create_common(bufp, size, Tclunk);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, fid, &fc->fid);
	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rclunk(void)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 0;
	fc = sp_create_common(bufp, size, Rclunk);
	if (!fc)
		return NULL;

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_tremove(u32 fid)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 4;	/* fid[4] */
	fc = sp_create_common(bufp, size, Tremove);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, fid, &fc->fid);
	return sp_post_check(fc, bufp);
}
Spfcall *
sp_create_rremove(void)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 0;
	fc = sp_create_common(bufp, size, Rremove);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_tstat(u32 fid)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 4;	/* fid[4] */
	fc = sp_create_common(bufp, size, Tstat);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, fid, &fc->fid);
	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rstat(Spwstat *wstat, int dotu)
{
	int size, statsz;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;

	statsz = size_wstat(wstat, dotu);
	size = 2 + 2 + statsz; /* stat[n] */
	fc = sp_create_common(bufp, size, Rstat);
	if (!fc)
		return NULL;

	buf_put_int16(bufp, statsz + 2, NULL);
	buf_put_wstat(bufp, wstat, &fc->stat, statsz, dotu);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_twstat(u32 fid, Spwstat *wstat, int dotu)
{
	int size, statsz;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;

	statsz = size_wstat(wstat, dotu);
	size = 4 + 2 + 2 + statsz; /* fid[4] stat[n] */
	fc = sp_create_common(bufp, size, Twstat);
	if (!fc)
		return NULL;

	buf_put_int32(bufp, fid, &fc->fid);
	buf_put_int16(bufp, statsz + 2, NULL);
	buf_put_wstat(bufp, wstat, &fc->stat, statsz, dotu);

	return sp_post_check(fc, bufp);
}

Spfcall *
sp_create_rwstat(void)
{
	int size;
	Spfcall *fc;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	size = 0;
	fc = sp_create_common(bufp, size, Rwstat);

	return sp_post_check(fc, bufp);
}

int
sp_deserialize(Spfcall *fc, u8 *data, int dotu)
{
	int i;
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	buf_init(bufp, data, 4);
	fc->size = buf_get_int32(bufp);

//	fprintf(stderr, "deserialize dump: ");
//	dumpdata(data, fc->size);

	buf_init(bufp, data + 4, fc->size - 4);
	fc->type = buf_get_int8(bufp);
	fc->tag = buf_get_int16(bufp);
	fc->fid = fc->afid = fc->newfid = NOFID;

	switch (fc->type) {
	default:
		goto error;

	case Tversion:
		fc->msize = buf_get_int32(bufp);
		buf_get_str(bufp, &fc->version);
		break;

	case Rversion:
		fc->msize = buf_get_int32(bufp);
		buf_get_str(bufp, &fc->version);
		break;

	case Tauth:
		fc->afid = buf_get_int32(bufp);
		buf_get_str(bufp, &fc->uname);
		buf_get_str(bufp, &fc->aname);
		if (dotu && !buf_check_end(bufp)) {
			fprintf(stderr, "-----\n");
			fc->n_uname = buf_get_int32(bufp);
		} else
			fc->n_uname = ~0;
		break;

	case Rauth:
		buf_get_qid(bufp, &fc->qid);
		break;

	case Tflush:
		fc->oldtag = buf_get_int16(bufp);
		break;

	case Tattach:
		fc->fid = buf_get_int32(bufp);
		fc->afid = buf_get_int32(bufp);
		buf_get_str(bufp, &fc->uname);
		buf_get_str(bufp, &fc->aname);
		if (dotu && !buf_check_end(bufp)) {
			fprintf(stderr, "-----\n");
			fc->n_uname = buf_get_int32(bufp);
		} else
			fc->n_uname = ~0;
		break;

	case Rattach:
		buf_get_qid(bufp, &fc->qid);
		break;

	case Rerror:
		buf_get_str(bufp, &fc->ename);
		if (dotu)
			fc->ecode = buf_get_int32(bufp);
		else
			fc->ecode = 0;
		break;

	case Twalk:
		fc->fid = buf_get_int32(bufp);
		fc->newfid = buf_get_int32(bufp);
		fc->nwname = buf_get_int16(bufp);
		if (fc->nwname > MAXWELEM)
			goto error;

		for(i = 0; i < fc->nwname; i++) {
			buf_get_str(bufp, &fc->wnames[i]);
		}
		break;

	case Rwalk:
		fc->nwqid = buf_get_int16(bufp);
		if (fc->nwqid > MAXWELEM)
			goto error;
		for(i = 0; i < fc->nwqid; i++)
			buf_get_qid(bufp, &fc->wqids[i]);
		break;

	case Topen:
		fc->fid = buf_get_int32(bufp);
		fc->mode = buf_get_int8(bufp);
		break;

	case Ropen:
	case Rcreate:
		buf_get_qid(bufp, &fc->qid);
		fc->iounit = buf_get_int32(bufp);
		break;

	case Tcreate:
		fc->fid = buf_get_int32(bufp);
		buf_get_str(bufp, &fc->name);
		fc->perm = buf_get_int32(bufp);
		fc->mode = buf_get_int8(bufp);
		fc->extension.len = 0;
		fc->extension.str = NULL;
		if (dotu)
			buf_get_str(bufp, &fc->extension);
		break;

	case Tread:
		fc->fid = buf_get_int32(bufp);
		fc->offset = buf_get_int64(bufp);
		fc->count = buf_get_int32(bufp);
		break;

	case Rread:
		fc->count = buf_get_int32(bufp);
		fc->data = buf_alloc(bufp, fc->count);
		break;

	case Twrite:
		fc->fid = buf_get_int32(bufp);
		fc->offset = buf_get_int64(bufp);
		fc->count = buf_get_int32(bufp);
		fc->data = buf_alloc(bufp, fc->count);
		break;

	case Rwrite:
		fc->count = buf_get_int32(bufp);
		break;

	case Tclunk:
	case Tremove:
	case Tstat:
		fc->fid = buf_get_int32(bufp);
		break;

	case Rflush:
	case Rclunk:
	case Rremove:
	case Rwstat:
		break;

	case Rstat:
		buf_get_int16(bufp);
		buf_get_stat(bufp, &fc->stat, dotu);
		break;

	case Twstat:
		fc->fid = buf_get_int32(bufp);
		buf_get_int16(bufp);
		buf_get_stat(bufp, &fc->stat, dotu);
		break;

	}

	if (buf_check_overflow(bufp))
		goto error;

	return fc->size;

error:
	return 0;
}

int 
sp_serialize_stat(Spwstat *wstat, u8* buf, int buflen, int dotu)
{
	int statsz;
	struct cbuf buffer;
	struct cbuf *bufp;
	Spstat stat;

	statsz = size_wstat(wstat, dotu);

	if (statsz > buflen)
		return 0;

	bufp = &buffer;
	buf_init(bufp, buf, buflen);

	buf_put_wstat(bufp, wstat, &stat, statsz, dotu);

	if (buf_check_overflow(bufp))
		return 0;

	return bufp->p - bufp->sp;
}

int 
sp_deserialize_stat(Spstat *stat, u8* buf, int buflen, int dotu)
{
	struct cbuf buffer;
	struct cbuf *bufp;

	bufp = &buffer;
	buf_init(bufp, buf, buflen);

	buf_get_stat(bufp, stat, dotu);

	if (buf_check_overflow(bufp))
		return 0;

	return bufp->p - bufp->sp;
}
