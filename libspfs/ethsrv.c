//
//
//

#include <stdlib.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <arpa/inet.h>

#include "spfs.h"

#define EXP_9P_ETH	0x885b

typedef struct Ethsrv Ethsrv;

struct Ethsrv {
	int	nl_sock;	// NETLINK socket to get notified when a new Ethernet is added

	Spfd *spfd;
};

static void sp_ethsrv_notify(Spfd *spfd, void *aux);
static void sp_ethsrv_start(Spsrv *srv);
static void sp_ethsrv_shutdown(Spsrv *srv);
static void sp_ethsrv_destroy(Spsrv *srv);

Spsrv*
sp_ethsrv_create(char *intf_name)
{
	struct Ethsrv *es = malloc(sizeof(*es));
	if (es == NULL)
		return NULL;

	es->nl_sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (es->nl_sock < 0)
		goto fail;

	struct sockaddr_nl saddr = {
		.nl_family = AF_NETLINK,
		.nl_pid = getpid(),
		.nl_groups = RTNLGRP_LINK | RTNLGRP_NOTIFY,
	};

	if (bind(es->nl_sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
		goto fail;

	Spsrv *srv = sp_srv_create();
	if (srv == 0)
		goto fail;

	srv->srvaux = es;
	srv->start = sp_ethsrv_start;
	srv->shutdown = sp_ethsrv_shutdown;
	srv->destroy = sp_ethsrv_destroy;

	return srv;

fail:
	free(es);
	return NULL;
}

static void
sp_ethsrv_start(Spsrv *srv)
{
	Ethsrv *es = srv->srvaux;

	es->spfd = spfd_add(es->nl_sock, sp_ethsrv_notify, srv);
}

static void
sp_ethsrv_shutdown(Spsrv *srv)
{
	Ethsrv *es = srv->srvaux;

	spfd_remove(es->spfd);
	close(es->nl_sock);
}

static void
sp_ethsrv_destroy(Spsrv *srv)
{
	Ethsrv *es = srv->srvaux;

	free(es);
	srv->srvaux = NULL;
}

static void
sp_ethsrv_notify(Spfd *spfd, void *aux)
{
	Spsrv *srv = aux;
	Ethsrv *es = srv->srvaux;

	if (!spfd_can_read(spfd))
		return;

	uint8_t buf[4096];
	spfd_read(spfd, buf, 0);
	int len = recv(es->nl_sock, buf, sizeof(buf), 0);
	struct nlmsghdr *hdr = (struct nlmsghdr *)buf;

	int fd;
	while (NLMSG_OK(hdr, len))
	{
		struct ifinfomsg *ifi = NLMSG_DATA(hdr);

		//
		// Multiple RTM_NEWLINK messages may be received. It seems only the
		// first one has ifi_change field set to 0xffffffff
		//

		if (hdr->nlmsg_type == RTM_NEWLINK && ifi->ifi_change == 0xffffffff)
		{
			//
			// Open a RAW socket listening on the new network interface and
			// create a 9P connection associated with the interface
			//

			fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
			if (fd < 0)
				goto fail1;

			struct sockaddr_ll sa = {
				.sll_family = AF_PACKET,
				.sll_protocol = htons(EXP_9P_ETH),
				.sll_ifindex = ifi->ifi_index,
			};
			if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
				goto fail2;

			Spconn *conn = sp_ethconn_create(srv, fd);
			if (conn == 0)
				goto fail2;
		}
		hdr = NLMSG_NEXT(hdr, len);
	}

	return;

fail2:
	close(fd);
fail1:
	perror("sp_ethsrv_notify");
}

//EOF
