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
#include "spfs.h"
#include "spfsimpl.h"

static int
sp_printperm(FILE *f, int perm)
{
	int n;
	char b[10];

	n = 0;
	if (perm & Dmdir)
		b[n++] = 'd';
	if (perm & Dmappend)
		b[n++] = 'a';
	if (perm & Dmauth)
		b[n++] = 'A';
	if (perm & Dmexcl)
		b[n++] = 'l';
	if (perm & Dmtmp)
		b[n++] = 't';
	if (perm & Dmdevice)
		b[n++] = 'D';
	if (perm & Dmsocket)
		b[n++] = 'S';
	if (perm & Dmnamedpipe)
		b[n++] = 'P';
        if (perm & Dmsymlink)
                b[n++] = 'L';
        b[n] = '\0';

        return fprintf(f, "%s%03o", b, perm&0777);
}             

static int
sp_printqid(FILE *f, Spqid *q)
{
	int n;
	char buf[10];

	n = 0;
	if (q->type & Qtdir)
		buf[n++] = 'd';
	if (q->type & Qtappend)
		buf[n++] = 'a';
	if (q->type & Qtauth)
		buf[n++] = 'A';
	if (q->type & Qtexcl)
		buf[n++] = 'l';
	if (q->type & Qttmp)
		buf[n++] = 't';
	if (q->type & Qtsymlink)
		buf[n++] = 'L';
	buf[n] = '\0';

	return fprintf(f, " (%.16llx %x '%s')", (long long unsigned int) q->path, q->version, buf);
}

int
sp_printstat(FILE *f, Spstat *st, int dotu)
{
	int n;

	n = fprintf(f, "'%.*s' '%.*s' '%.*s' '%.*s' q ", 
		st->name.len, st->name.str, st->uid.len, st->uid.str,
		st->gid.len, st->gid.str, st->muid.len, st->muid.str);

	n += sp_printqid(f, &st->qid);
	n += fprintf(f, " m ");
	n += sp_printperm(f, st->mode);
	n += fprintf(f, " at %d mt %d l %lld t %d d %d",
		st->atime, st->mtime, (long long unsigned int) st->length, st->type, st->dev);
	if (dotu)
		n += fprintf(f, " ext '%.*s'", st->extension.len, 
			st->extension.str);

	return n;
}

int
sp_dump(FILE *f, u8 *data, int datalen)
{
	int i, n;

	i = n = 0;
	while (i < datalen) {
		n += fprintf(f, "%02x", data[i]);
		if (i%4 == 3)
			n += fprintf(f, " ");
		if (i%32 == 31)
			n += fprintf(f, "\n");

		i++;
	}
	n += fprintf(f, "\n");

	return n;
}

static int
sp_printdata(FILE *f, u8 *buf, int buflen)
{
	return sp_dump(f, buf, buflen<64?buflen:64);
}

int
sp_dumpdata(u8 *buf, int buflen)
{
	return sp_dump(stderr, buf, buflen);
}

int
sp_printfcall(FILE *f, Spfcall *fc, int dotu) 
{
	int i, ret, type, fid, tag;

	if (!fc)
		return fprintf(f, "NULL");

	type = fc->type;
	fid = fc->fid;
	tag = fc->tag;

	ret = 0;
	switch (type) {
	case Tversion:
		ret += fprintf(f, "Tversion tag %u msize %u version '%.*s'", 
			tag, fc->msize, fc->version.len, fc->version.str);
		break;

	case Rversion:
		ret += fprintf(f, "Rversion tag %u msize %u version '%.*s'", 
			tag, fc->msize, fc->version.len, fc->version.str);
		break;

	case Tauth:
		ret += fprintf(f, "Tauth tag %u afid %d uname %.*s aname %.*s",
			tag, fc->afid, fc->uname.len, fc->uname.str, 
			fc->aname.len, fc->aname.str);
		if (dotu)
			ret += fprintf(f, " nuname %d", fc->n_uname);
		break;

	case Rauth:
		ret += fprintf(f, "Rauth tag %u qid ", tag); 
		sp_printqid(f, &fc->qid);
		break;

	case Tattach:
		ret += fprintf(f, "Tattach tag %u fid %d afid %d uname %.*s aname %.*s",
			tag, fid, fc->afid, fc->uname.len, fc->uname.str, 
			fc->aname.len, fc->aname.str);
		if (dotu)
			ret += fprintf(f, " nuname %d", fc->n_uname);
		break;

	case Rattach:
		ret += fprintf(f, "Rattach tag %u qid ", tag); 
		sp_printqid(f, &fc->qid);
		break;

	case Rerror:
		ret += fprintf(f, "Rerror tag %u ename %.*s", tag, 
			fc->ename.len, fc->ename.str);
		if (dotu)
			ret += fprintf(f, " ecode %d", fc->ecode);
		break;

	case Tflush:
		ret += fprintf(f, "Tflush tag %u oldtag %u", tag, fc->oldtag);
		break;

	case Rflush:
		ret += fprintf(f, "Rflush tag %u", tag);
		break;

	case Twalk:
		ret += fprintf(f, "Twalk tag %u fid %d newfid %d nwname %d", 
			tag, fid, fc->newfid, fc->nwname);
		for(i = 0; i < fc->nwname; i++)
			ret += fprintf(f, " '%.*s'", fc->wnames[i].len, 
				fc->wnames[i].str);
		break;
		
	case Rwalk:
		ret += fprintf(f, "Rwalk tag %u nwqid %d", tag, fc->nwqid);
		for(i = 0; i < fc->nwqid; i++)
			ret += sp_printqid(f, &fc->wqids[i]);
		break;
		
	case Topen:
		ret += fprintf(f, "Topen tag %u fid %d mode %d", tag, fid, 
			fc->mode);
		break;
		
	case Ropen:
		ret += fprintf(f, "Ropen tag %u", tag);
		ret += sp_printqid(f, &fc->qid);
		ret += fprintf(f, " iounit %d", fc->iounit);
		break;
		
	case Tcreate:
		ret += fprintf(f, "Tcreate tag %u fid %d name %.*s perm ",
			tag, fid, fc->name.len, fc->name.str);
		ret += sp_printperm(f, fc->perm);
		ret += fprintf(f, " mode %d", fc->mode);
		if (dotu)
			ret += fprintf(f, " ext %.*s", fc->extension.len,
				fc->extension.str);
		break;
		
	case Rcreate:
		ret += fprintf(f, "Rcreate tag %u", tag);
		ret += sp_printqid(f, &fc->qid);
		ret += fprintf(f, " iounit %d", fc->iounit);
		break;
		
	case Tread:
		ret += fprintf(f, "Tread tag %u fid %d offset %lld count %u", 
			tag, fid, (long long int) fc->offset, fc->count);
		break;
		
	case Rread:
		ret += fprintf(f, "Rread tag %u count %u data ", tag, fc->count);
		ret += sp_printdata(f, fc->data, fc->count);
		break;
		
	case Twrite:
		ret += fprintf(f, "Twrite tag %u fid %d offset %lld count %u data ",
			tag, fid, (long long int) fc->offset, fc->count);
		ret += sp_printdata(f, fc->data, fc->count);
		break;
		
	case Rwrite:
		ret += fprintf(f, "Rwrite tag %u count %u", tag, fc->count);
		break;
		
	case Tclunk:
		ret += fprintf(f, "Tclunk tag %u fid %d", tag, fid);
		break;
		
	case Rclunk:
		ret += fprintf(f, "Rclunk tag %u", tag);
		break;
		
	case Tremove:
		ret += fprintf(f, "Tremove tag %u fid %d", tag, fid);
		break;
		
	case Rremove:
		ret += fprintf(f, "Rremove tag %u", tag);
		break;
		
	case Tstat:
		ret += fprintf(f, "Tstat tag %u fid %d", tag, fid);
		break;
		
	case Rstat:
		ret += fprintf(f, "Rstat tag %u ", tag);
		ret += sp_printstat(f, &fc->stat, dotu);
		break;
		
	case Twstat:
		ret += fprintf(f, "Twstat tag %u fid %d ", tag, fid);
		ret += sp_printstat(f, &fc->stat, dotu);
		break;
		
	case Rwstat:
		ret += fprintf(f, "Rwstat tag %u", tag);
		break;

	default:
		ret += fprintf(f, "unknown type %d", type);
		break;
	}

	return ret;
}
