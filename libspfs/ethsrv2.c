//
//
//

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <string.h>
#include <errno.h>

#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <arpa/inet.h>

#include "spfs.h"
#include "spfsimpl.h"

typedef struct Ethsrv2 Ethsrv2;

#define MAX_CONNS	256

struct Ethsrv2 {
	int fd;
	Spfd *spfd;

	struct {
		uint8_t haddr[ETH_ALEN];
		Spconn *conn;
	} addr_to_conn[MAX_CONNS];
	int nr_conns;
};

static void sp_ethsrv2_notify(Spfd *spfd, void *aux);
static void sp_ethsrv2_start(Spsrv *srv);
static void sp_ethsrv2_shutdown(Spsrv *srv);
static void sp_ethsrv2_destroy(Spsrv *srv);

Spsrv*
sp_ethsrv2_create(char *ifname)
{
	struct Ethsrv2 *es = malloc(sizeof(*es));
	if (es == NULL)
		return NULL;

	es->fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (es->fd < 0)
		goto error1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	if (ioctl(es->fd, SIOCGIFINDEX, &ifr) < 0)
		goto error2;

	struct sockaddr_ll saddr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(EXP_9P_ETH),
		.sll_ifindex = ifr.ifr_ifindex,
	};
	if (bind(es->fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
		goto error2;

	es->nr_conns = 0;

	Spsrv *srv = sp_srv_create();
	if (srv == 0)
		goto error2;

	srv->srvaux = es;
	srv->start = sp_ethsrv2_start;
	srv->shutdown = sp_ethsrv2_shutdown;
	srv->destroy = sp_ethsrv2_destroy;

	return srv;

error2:
	close(es->fd);
error1:
	free(es);
	return NULL;
}

static void
sp_ethsrv2_start(Spsrv *srv)
{
	Ethsrv2 *es = srv->srvaux;

	es->spfd = spfd_add(es->fd, sp_ethsrv2_notify, srv);
}

static void
sp_ethsrv2_shutdown(Spsrv *srv)
{
	Ethsrv2 *es = srv->srvaux;

	spfd_remove(es->spfd);
	close(es->fd);
}

static void
sp_ethsrv2_destroy(Spsrv *srv)
{
	Ethsrv2 *es = srv->srvaux;

	free(es);
	srv->srvaux = NULL;
}

static void
sp_ethsrv2_notify(Spfd *spfd, void *aux)
{
	Spsrv *srv = aux;
	Ethsrv2 *es = srv->srvaux;

	Spfcall *fc;
	Spreq *req;

	if (!spfd_can_read(spfd))
		return;

	if (srv->enomem)
		return;

	spfd_read(spfd, 0, 0);	// reset POLLIN event

	struct sockaddr_ll saddr;
	socklen_t sa_len = sizeof(saddr);

	uint8_t buf[srv->msize];
	int len = recvfrom(es->fd, buf, srv->msize, 0,
			(struct sockaddr *)&saddr, &sa_len);
	if (len < 0)
		return;

	if (len < 4)
		return;
	int exp_len = buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
	if (exp_len != len -4)	// -4: csum field
		return;

	uint8_t mac1 = saddr.sll_addr[0];
	uint8_t mac2 = saddr.sll_addr[1];
	uint8_t mac3 = saddr.sll_addr[2];
	uint8_t mac4 = saddr.sll_addr[3];
	uint8_t mac5 = saddr.sll_addr[4];
	uint8_t mac6 = saddr.sll_addr[5];

	if (mac1 != 0x00 || mac2 != 0x16 || mac3 != 0x3e)
		return;

	Spconn *conn = 0;
	int i;
	for (i = 0; i < es->nr_conns; i++)
	{
		if (mac4 == es->addr_to_conn[i].haddr[3] &&
			mac5 == es->addr_to_conn[i].haddr[4] &&
			mac6 == es->addr_to_conn[i].haddr[5])
		{
			conn = es->addr_to_conn[i].conn;
			break;
		}
	}

	if (conn == 0)
	{
		assert(es->nr_conns < MAX_CONNS);

		//
		// An unknown client sends the first message; create a new connection.
		//
		
		conn = sp_ethconn2_create(srv, &saddr);

		memcpy(es->addr_to_conn[es->nr_conns].haddr, saddr.sll_addr, ETH_ALEN);
		es->addr_to_conn[es->nr_conns].conn = conn;
		es->nr_conns++;

		fprintf(stderr, "A new connection to %02x:%02x:%02x:%02x:%02x:%02x added\n",
									mac1, mac2, mac3, mac4, mac5, mac6);
	}

	fc = sp_conn_new_incall(conn);
	if (fc == 0)
		return;
	req = sp_req_alloc(conn, fc);
	if (req == 0)
		return;
	fc = req->tcall;

	if (sp_deserialize(fc, buf, conn->dotu) == 0)
   	{
		fprintf(stderr, "error while deserializing\n");
		return;
	}

	if (srv->debuglevel > 0)
	{
		fprintf(stderr, "<<< (%p) ", conn);
		sp_printfcall(stderr, fc, conn->dotu);
		fprintf(stderr, "\n");
	}

	sp_srv_process_req(req);
}

//EOF
