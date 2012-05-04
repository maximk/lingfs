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
#include <fcntl.h>
#include <sys/poll.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include "spfs.h"
#include "spfsimpl.h"

enum {
	TblModified	= 1,
	ChunkSize	= 4,
};

enum {
	Readable	= 1,
	Writable	= 2,
	Error		= 4,

	Removed		= 64,
};

typedef struct Spolltbl Spolltbl;
struct Spolltbl {
	int		shutdown;
	int		looping;
	int		flags;
	int		fdnum;
	int		fdsize;
	Spfd**		spfds;
	struct pollfd*	fds;
	Spfd*		pend_spfds;
};

struct Spfd {
	int		fd;
	int		flags;
	void*		aux;
	void		(*notify)(Spfd *, void *);

	struct pollfd*	pfd;
	Spfd*		next;	/* list of the fds pending addition */
};

static Spolltbl ptbl;

/*
void
check_fds(void)
{
	int i;
	Spfd *spfd;

	for(i = 0; i < ptbl.fdnum; i++)
		assert(ptbl.fds[i].fd==INT_MAX || ptbl.fds[i].fd<100);

	for(spfd = ptbl.pend_spfds; spfd != NULL; spfd = spfd->next)
		assert(spfd->fd==INT_MAX || spfd->fd<100);
}
*/

void
sp_poll_stop()
{
	ptbl.shutdown = 1;
}

int
sp_poll_looping()
{
	return ptbl.looping;
}

Spfd *
spfd_add(int fd, void (*notify)(Spfd *, void *), void *aux)
{
	Spfd *spfd;

//	fprintf(stderr, "spfd_add fd %d\n", fd);
	spfd = sp_malloc(sizeof(*spfd));
	if (!spfd)
		return NULL;

	fcntl(fd, F_SETFL, O_NONBLOCK);
	spfd->fd = fd;
	spfd->flags = 0;
	spfd->aux = aux;
	spfd->notify = notify;
	spfd->pfd = NULL;
	spfd->next = NULL;

	spfd->next = ptbl.pend_spfds;
	ptbl.pend_spfds = spfd;

	ptbl.flags |= TblModified;

	return spfd;
}

void
spfd_remove(Spfd *spfd)
{
//	fprintf(stderr, "spfd_remove fd %d\n", spfd->fd);
	spfd->flags |= Removed;
	ptbl.flags |= TblModified;
}

void
spfd_remove_all()
{
	int i;

	for(i = 0; i < ptbl.fdnum; i++)
		ptbl.spfds[i]->flags |= Removed;

	ptbl.flags |= TblModified;
}

int
spfd_can_read(Spfd *spfd)
{
	return spfd->flags & Readable;
}

int
spfd_can_write(Spfd *spfd)
{
	return spfd->flags & Writable;
}

int
spfd_has_error(Spfd *spfd)
{
	return spfd->flags & Error;
}

int
spfd_read(Spfd *spfd, void *buf, int buflen)
{
	int n, ret;

	if (buflen)
		ret = read(spfd->fd, buf, buflen);
	else
		ret = 0;

	spfd->flags &= ~Readable;
	spfd->pfd->events |= POLLIN;

	if (ret < 0) {
		n = errno;
		if (n != EAGAIN)
			sp_uerror(n);
	}

	return ret;
}

int
spfd_write(Spfd *spfd, void *buf, int buflen)
{
	int n, ret;

	if (buflen)
		ret = write(spfd->fd, buf, buflen);
	else
		ret = 0;

	spfd->flags &= ~Writable;
	spfd->pfd->events |= POLLOUT;

	if (ret < 0) {
		n = errno;
		if (n != EAGAIN)
			sp_uerror(n);
	}

	return ret;
}

static void
sp_poll_update_table()
{
	int i, n, m;
	struct pollfd *tfds;
	struct Spfd **tspfd, *pspfd, *spfd, *spfd1;

	/* get rid of the disconnected fds */
	for(i = 0; i < ptbl.fdnum; i++) {
		if (ptbl.spfds[i] && ptbl.spfds[i]->flags & Removed) {
			free(ptbl.spfds[i]);
			ptbl.spfds[i] = NULL;
		}
	}

	/* remove the disconnected fds that are still in the pending queue */
	pspfd = NULL;
	spfd = ptbl.pend_spfds;
	while (spfd != NULL) {
		if (spfd->flags & Removed) {
			if (pspfd)
				pspfd->next = spfd->next;
			else
				ptbl.pend_spfds = spfd->next;

			spfd1 = spfd->next;
			free(spfd);
			spfd = spfd1;
		} else {
			pspfd = spfd;
			spfd = spfd->next;
		}
	}

	/* try to fill the holes with pending fds */
	for(i = 0, pspfd = ptbl.pend_spfds; pspfd && i < ptbl.fdsize; i++) {
		if (!ptbl.spfds[i]) {
			ptbl.spfds[i] = pspfd;
			ptbl.spfds[i]->pfd = &ptbl.fds[i];
			ptbl.fds[i].fd = pspfd->fd;
			ptbl.fds[i].events = POLLIN | POLLOUT;
			pspfd = pspfd->next;
		}
	}

	/* if there are still holes, move some elements to fill them */
	for(n = i; i < ptbl.fdnum; i++) {
		if (!ptbl.spfds[i])
			continue;

		if (i != n) {
			ptbl.spfds[n] = ptbl.spfds[i];
			ptbl.spfds[n]->pfd = &ptbl.fds[n];
			ptbl.fds[n] = ptbl.fds[i];
			ptbl.spfds[i] = NULL;
		}
		n++;
	}

	/* find out the number of still pending fds */
	for(i = 0, spfd=pspfd; spfd != NULL; spfd = spfd->next, i++)
		;
	

	/* increase the array if we have to */
	m = n + i + ChunkSize - ((n+i)%ChunkSize);
	if (ptbl.fdsize < m) {
		tfds = realloc(ptbl.fds, sizeof(struct pollfd) * m);
		if (tfds)
			ptbl.fds = tfds;

		tspfd = realloc(ptbl.spfds, sizeof(Spfd *) * m);
		if (tspfd) {
			for(i = 0; i < n; i++)
				tspfd[i]->pfd = &ptbl.fds[i];

			for(i = ptbl.fdsize; i < m; i++)
				tspfd[i] = NULL;
			ptbl.spfds = tspfd;
		}

		if (tfds && tspfd)
			ptbl.fdsize = m;
	}

	/* put the remaining pending fds in place */
	for(i = n; i < ptbl.fdsize && pspfd != NULL; i++, pspfd = pspfd->next) {
		ptbl.spfds[i] = pspfd;
		ptbl.spfds[i]->pfd = &ptbl.fds[i];
		ptbl.fds[i].fd = pspfd->fd;
		ptbl.fds[i].events = POLLIN | POLLOUT;
	}

	ptbl.pend_spfds = pspfd;
	ptbl.fdnum = i;
	ptbl.flags &= ~TblModified;
}

void
sp_poll_once()
{
	int i, n, flags;
	struct pollfd *pfd;
	struct Spfd *spfd;

	if (ptbl.flags & TblModified)
		sp_poll_update_table();

	n = poll(ptbl.fds, ptbl.fdnum, 300000);
//		fprintf(stderr, "sp_poll_loop fdnum %d result %d\n", ptbl.fdnum, n);

	if (n < 0)
		return;

	for(i = ptbl.fdnum - 1; i>=0 && n>0; i--) {
		spfd = ptbl.spfds[i];
		pfd = &ptbl.fds[i];

		if (!spfd || spfd->flags&Removed || !pfd->revents)
			continue;

		if (!(pfd->revents & (POLLERR |  POLLHUP | POLLNVAL)))
			continue;

		flags = spfd->flags | Error;
		if (pfd->revents & POLLIN) {
			pfd->events &= ~POLLIN;
			flags |= Readable;
		}

		if (pfd->revents & POLLOUT) {
			pfd->events &= ~POLLOUT;
			flags |= Writable;
		}

		n--;
		pfd->revents = 0;
		spfd->flags = flags;
		(*spfd->notify)(spfd, spfd->aux);
	}

	for(i = ptbl.fdnum - 1; i>=0 && n>0; i--) {
		spfd = ptbl.spfds[i];
		pfd = &ptbl.fds[i];

		if (!spfd || spfd->flags&Removed || !pfd->revents)
			continue;

		flags = spfd->flags;

		if (pfd->revents & POLLIN) {
			pfd->events &= ~POLLIN;
			flags |= Readable;
		}

		if (pfd->revents & POLLOUT) {
			pfd->events &= ~POLLOUT;
			flags |= Writable;
		}

		n--;
		if (spfd->flags != flags) {
			spfd->flags = flags;
			(*spfd->notify)(spfd, spfd->aux);
		}
	}

	if (ptbl.flags & TblModified)
		sp_poll_update_table();
}

void
sp_poll_loop()
{
	ptbl.shutdown = 0;
	ptbl.looping = 1;
	while (!ptbl.shutdown) 
		sp_poll_once();
	ptbl.looping = 0;
}
