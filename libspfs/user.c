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
#include <unistd.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include "spfs.h"
#include "spfsimpl.h"

struct Usercache {
	int		init;
	int		hsize;
	Spuser**	htable;
} usercache = { 0 };

struct Spgroupcache {
	int		init;
	int		hsize;
	Spgroup**	htable;
} groupcache = { 0 };

Spuser *currentUser;

static void
initusercache(void)
{
	if (!usercache.init) {
		usercache.hsize = 64;
		usercache.htable = calloc(usercache.hsize, sizeof(Spuser *));
		usercache.init = 1;
	}
}

Spuser*
sp_uid2user(int uid)
{
	int n, i;
	Spuser *u;
	struct passwd pw, *pwp;
	int bufsize;
	char *buf;

	if (!usercache.init)
		initusercache();

	n = uid % usercache.hsize;
	for(u = usercache.htable[n]; u != NULL; u = u->next)
		if (u->uid == uid)
			break;

	if (u)
		return u;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize < 256)
		bufsize = 256;

	buf = sp_malloc(bufsize);
	if (!buf)
		return NULL;

	i = getpwuid_r(uid, &pw, buf, bufsize, &pwp);
	if (i) {
		sp_uerror(i);
		free(buf);
		return NULL;
	}

	u = sp_malloc(sizeof(*u) + strlen(pw.pw_name) + 1);
	if (!u) {
		free(buf);
		return NULL;
	}

	u->uid = uid;
	u->uname = (char *)u + sizeof(*u);
	strcpy(u->uname, pw.pw_name);
	u->dfltgroup = sp_gid2group(pw.pw_gid);

	u->ngroups = 0;
	u->groups = NULL;

	u->next = usercache.htable[n];
	usercache.htable[n] = u;

	free(buf);
	return u;
}

Spuser*
sp_uname2user(char *uname)
{
	int i, n;
	struct passwd pw, *pwp;
	int bufsize;
	char *buf;
	Spuser *u;

	if (!usercache.init)
		initusercache();

	for(i = 0; i<usercache.hsize; i++)
		for(u = usercache.htable[i]; u != NULL; u = u->next)
			if (strcmp(uname, u->uname) == 0)
				return u;

	bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize < 256)
		bufsize = 256;

	buf = sp_malloc(bufsize);
	if (!buf)
		return NULL;

	i = getpwnam_r(uname, &pw, buf, bufsize, &pwp);
	if (i) {
		sp_uerror(i);
		free(buf);
		return NULL;
	}

	if (!pw.pw_name) {
		free(buf);
		return NULL;
	}

	u = sp_malloc(sizeof(*u) + strlen(pw.pw_name) + 1);
	if (!u) {
		free(buf);
		return NULL;
	}

	u->uid = pw.pw_uid;
	u->uname = (char *)u + sizeof(*u);
	strcpy(u->uname, pw.pw_name);
	u->dfltgroup = sp_gid2group(pw.pw_gid);

	u->ngroups = 0;
	u->groups = NULL;

	n = u->uid % usercache.hsize;
	u->next = usercache.htable[n];
	usercache.htable[n] = u;

	free(buf);
	return u;
}

int
sp_usergroups(Spuser *u, gid_t **gids)
{
	int n;
	gid_t *grps;

	if (!u->groups) {
		n = 0;
		getgrouplist(u->uname, u->dfltgroup->gid, NULL, &n);
		grps = sp_malloc(sizeof(*grps) * n);
		if (!grps)
			return -1;

		getgrouplist(u->uname, u->dfltgroup->gid, grps, &n);
		u->groups = grps;
		u->ngroups = n;
	}

	*gids = u->groups;
	return u->ngroups;
}

static void
initgroupcache(void)
{
	if (!groupcache.init) {
		groupcache.hsize = 64;
		groupcache.htable = calloc(groupcache.hsize, sizeof(Spuser *));
		if (!groupcache.htable) {
			sp_werror(Enomem, ENOMEM);
			return;
		}
		groupcache.init = 1;
	}
}

Spgroup*
sp_gid2group(gid_t gid)
{
	int n, err;
	Spgroup *g;
	struct group grp, *pgrp;
	int bufsize;
	char *buf;

	if (!groupcache.init)
		initgroupcache();

	n = gid % groupcache.hsize;
	for(g = groupcache.htable[n]; g != NULL; g = g->next)
		if (g->gid == gid)
			break;

	if (g)
		return g;

	bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (bufsize < 256)
		bufsize = 256;

	buf = sp_malloc(bufsize);
	if (!buf)
		return NULL;

	err = getgrgid_r(gid, &grp, buf, bufsize, &pgrp);
	if (err) {
		sp_uerror(err);
		free(buf);
		return NULL;
	}

	g = sp_malloc(sizeof(*g) + strlen(grp.gr_name) + 1);
	if (!g) {
		free(buf);
		return NULL;
	}

	g->gid = grp.gr_gid;
	g->gname = (char *)g + sizeof(*g);
	strcpy(g->gname, grp.gr_name);

	g->next = groupcache.htable[n];
	groupcache.htable[n] = g;

	free(buf);
	return g;
}

Spgroup*
sp_gname2group(char *gname)
{
	int i, n, bufsize;
	Spgroup *g;
	struct group grp, *pgrp;
	char *buf;

	if (!groupcache.init)
		initgroupcache();

	for(i = 0; i < groupcache.hsize; i++) 
		for(g = groupcache.htable[i]; g != NULL; g = g->next)
			if (strcmp(g->gname, gname) == 0)
				return g;

	bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (bufsize < 256)
		bufsize = 256;

	buf = sp_malloc(bufsize);
	if (!buf)
		return NULL;

	i = getgrnam_r(gname, &grp, buf, bufsize, &pgrp);
	if (i) {
		sp_uerror(i);
		free(buf);
		return NULL;
	}

	g = malloc(sizeof(*g) + strlen(grp.gr_name) + 1);
	if (!g) {
		free(buf);
		return NULL;
	}

	g->gid = grp.gr_gid;
	g->gname = (char *)g + sizeof(*g);
	strcpy(g->gname, grp.gr_name);

	n = g->gid % groupcache.hsize;
	g->next = groupcache.htable[n];
	groupcache.htable[n] = g;

	free(buf);
	return g;
}

int
sp_change_user(Spuser *u)
{
	int n;
	gid_t *gids;

	if (currentUser == u)
		return 0;

	if (setreuid(0, 0) < 0) 
		goto error;

	n = sp_usergroups(u, &gids);
	if (n < 0)
		return -1;

	setgroups(n, gids);
	if (setregid(-1, u->dfltgroup->gid) < 0)
		goto error;

	if (setreuid(-1, u->uid) < 0)
		goto error;

	currentUser = u;
	return 0;

error:
	sp_uerror(errno);
	return -1;
}
