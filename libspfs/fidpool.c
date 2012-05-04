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

Spfid**
sp_fidpool_create(void)
{
	Spfid **ret;

	return calloc(FID_HTABLE_SIZE, sizeof(*ret));
}

void
sp_fidpool_destroy(Spfid **pool)
{
	int i;
	Spfid *f, *ff;

	for(i = 0; i < FID_HTABLE_SIZE; i++) {
		f = pool[i];
		while (f != NULL) {
			ff = f->next;
			if (f->conn->srv->fiddestroy)
				(*f->conn->srv->fiddestroy)(f);
			free(f);
			f = ff;
		}
	}

	free(pool);
}

Spfid*
sp_fid_find(Spconn *conn, u32 fid)
{
	int hash;
	Spfid **htable, *f, **prevp;

	hash = fid % FID_HTABLE_SIZE;
	htable = conn->fidpool;
	if (!htable)
		return NULL;

	prevp = &htable[hash];
	f = *prevp;
	while (f != NULL) {
		if (f->fid == fid) {
			*prevp = f->next;
			f->next = htable[hash];
			htable[hash] = f;
			break;
		}

		prevp = &f->next;
		f = *prevp;
	}
	return f;
}

Spfid*
sp_fid_create(Spconn *conn, u32 fid, void *aux)
{
	int hash;
	Spfid **htable, *f;

	hash = fid % FID_HTABLE_SIZE;
	htable = conn->fidpool;
	if (!htable)
		return NULL;

	f = sp_fid_find(conn, fid);
	if (f)
		return NULL;

	f = sp_malloc(sizeof(*f));
	if (!f)
		return NULL;

	f->fid = fid;
	f->conn = conn;
	f->refcount = 0;
	f->omode = ~0;
	f->type = 0;
	f->diroffset = 0;
	f->dev = 0;
	f->user = NULL;
	f->aux = aux;

	f->next = htable[hash];
	htable[hash] = f;

	return f;
}

int
sp_fid_destroy(Spfid *fid)
{
	int hash;
	Spconn *conn;
	Spfid **htable, *f, **prevp;

	conn = fid->conn;
	hash = fid->fid % FID_HTABLE_SIZE;
	htable = conn->fidpool;
	if (!htable)
		return 0;

	prevp = &htable[hash];
	f = *prevp;
	while (f != NULL) {
		if (f->fid == fid->fid) {
			*prevp = f->next;
			if (f->conn->srv->fiddestroy)
				(*f->conn->srv->fiddestroy)(f);
			free(f);
			break;
		}

		prevp = &f->next;
		f = *prevp;
	}
	return f != NULL;
}

void
sp_fid_incref(Spfid *fid)
{
	if (!fid)
		return;

	fid->refcount++;
}

void
sp_fid_decref(Spfid *fid)
{
	if (!fid)
		return;

	fid->refcount--;

	if (!fid->refcount)
		sp_fid_destroy(fid);
}
