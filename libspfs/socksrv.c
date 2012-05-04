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
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include "spfs.h"
#include "spfsimpl.h"

typedef struct Socksrv Socksrv;

struct Socksrv {
	int			domain;
	int			type;
	int			proto;
	struct sockaddr*	saddr;
	int			saddrlen;
	
	int			sock;
	int			shutdown;
	Spfd*			spfd;
};

static void sp_socksrv_notify(Spfd *spfd, void *aux);
static void sp_socksrv_start(Spsrv *srv);
static void sp_socksrv_shutdown(Spsrv *srv);
static void sp_socksrv_destroy(Spsrv *srv);

static Socksrv*
sp_socksrv_create_common(int domain, int type, int proto)
{
	Socksrv *ss;
	int flag = 1;

	ss = sp_malloc(sizeof(*ss));
	if (!ss) 
		return NULL;

	ss->domain = domain;
	ss->type = type;
	ss->proto = proto;
	ss->shutdown = 0;
	ss->sock = socket(domain, type, proto);
	if (ss->sock < 0) {
		sp_suerror("cannot create socket", errno);
		free(ss);
		return NULL;
	}

	setsockopt(ss->sock, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(int));

	return ss;
}

static int
sp_socksrv_connect(Socksrv *ss)
{
	ss->sock = socket(ss->domain, ss->type, ss->proto);
	if (ss->sock < 0) {
		sp_suerror("cannot connect socket", errno);
		return -1;
	}

	fcntl(ss->sock, F_SETFD, FD_CLOEXEC);
	if (bind(ss->sock, ss->saddr, ss->saddrlen) < 0) {
		sp_suerror("cannot bind socket", errno);
		return -1;
	}

	if (listen(ss->sock, 1) < 0) {
		sp_suerror("cannot listen on socket", errno);
		return -1;
	}

	return 0;
}

Spsrv*
sp_socksrv_create_tcp(int *port)
{
	socklen_t n;
	Spsrv *srv;
	Socksrv *ss;
	struct sockaddr_in* saddr;

	ss = sp_socksrv_create_common(PF_INET, SOCK_STREAM, 0);
	if (!ss)
		return NULL;

	saddr = sp_malloc(sizeof(*saddr));
	if (!saddr)
		return NULL;

	ss->saddr = (struct sockaddr *) saddr;
	ss->saddrlen = sizeof(*saddr);

	saddr->sin_family = AF_INET;
	saddr->sin_port = htons(*port);
	saddr->sin_addr.s_addr = htonl(INADDR_ANY);
	if (sp_socksrv_connect(ss) < 0) {
		free(saddr);
		free(ss);
		return NULL;
	}

	saddr->sin_port = 4242;
	n = sizeof(*saddr);
	if (getsockname(ss->sock, ss->saddr, &n) < 0) {
		sp_suerror("cannot get socket address", errno);
		free(saddr);
		free(ss);
		return NULL;
	}

	*port = ntohs(saddr->sin_port);

	srv = sp_srv_create();
	if (!srv) {
		free(ss->saddr);
		free(ss);
		return NULL;
	}

	srv->srvaux = ss;
	srv->start = sp_socksrv_start;
	srv->shutdown = sp_socksrv_shutdown;
	srv->destroy = sp_socksrv_destroy;

	return srv;
}


static void
sp_socksrv_start(Spsrv *srv)
{
	Socksrv *ss;

	ss = srv->srvaux;

	ss->spfd = spfd_add(ss->sock, sp_socksrv_notify, srv);
}

static void
sp_socksrv_shutdown(Spsrv *srv)
{
	Socksrv *ss;

	ss = srv->srvaux;
	ss->shutdown = 1;
	spfd_remove(ss->spfd);
	close(ss->sock);
}

static void
sp_socksrv_destroy(Spsrv *srv)
{
	Socksrv *ss;

	ss = srv->srvaux;
	free(ss);
	srv->srvaux = NULL;
}

static void
sp_socksrv_notify(Spfd *spfd, void *aux)
{
	int csock;
	Spsrv *srv;
	Spconn *conn;
	Socksrv *ss;
	struct sockaddr_in caddr;
	socklen_t caddrlen;
	char buf[64];

	srv = aux;
	ss = srv->srvaux;

	if (!spfd_can_read(spfd))
		return;

	spfd_read(spfd, buf, 0);
	caddrlen = sizeof(caddr);
	csock = accept(ss->sock, (struct sockaddr *) &caddr, &caddrlen);
	if (csock<0) {
		if (!ss->shutdown)
			return;

		close(ss->sock);
		if (sp_socksrv_connect(ss) < 0)
			fprintf(stderr, "error while reconnecting: %d\n", errno);
		return;
	}

	fcntl(csock, F_SETFD, FD_CLOEXEC);
	if (!(conn = sp_fdconn_create(srv, csock, csock)))
		close(csock);

	snprintf(buf, sizeof(buf), "%s!%d", inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));
	conn->address = strdup(buf);
}
