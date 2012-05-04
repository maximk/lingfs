
//
//
//

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <net/if.h>

#include <string.h>
#include <assert.h>

#define VIF_NAME	"eth0"
#define EXP_9P_ETH	0x885b

int main(int ac, char *av[])
{
	printf("Allocating RAW socket\n");
	int sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (sock < 0)
		goto fail;
	printf("RAW socket allocated [%d]\n", sock);

	printf("Retrieving interface index for %s\n", VIF_NAME);
	struct ifreq ifr = {
		.ifr_name = VIF_NAME
	};
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
		goto fail;
	printf("Interface index retrieved [%d]\n", ifr.ifr_ifindex);

	printf("Binding socket to the interface\n");
	struct sockaddr_ll sa = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(EXP_9P_ETH),
		//.sll_protocol = htons(ETH_P_ALL),
		.sll_ifindex = ifr.ifr_ifindex,
		//.sll_halen = 6,
		//.sll_addr = {0x00, 0x16, 0x3e, 0xaa, 0xbb, 0xcc},
	};
	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		goto fail;
	printf("Interface bound successfully\n");

	printf("Receiving messages from %s...\n", VIF_NAME);
	while (1)
	{
		uint8_t buf[4096];
		socklen_t sa_len = sizeof(sa);
		int sz = recvfrom(sock, buf, sizeof(buf),
					0, (struct sockaddr *)&sa, &sa_len);
		if (sz < 0)
			goto fail;
		uint8_t *mac = sa.sll_addr;
		printf("recv: %d from %02x:%02x:%02x:%02x:%02x:%02x\n",
			buf[4], mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

		assert(sa.sll_family == AF_PACKET);
		assert(sa.sll_halen == ETH_ALEN);
		assert(sa.sll_ifindex == ifr.ifr_ifindex);
		assert(sa.sll_protocol == htons(EXP_9P_ETH));

		//
		// Always reply with a successful Rversion
		//
		uint8_t reply[] = {19,0,0,0,
						   101,
						   0,0,
						   0xdc,5,0,0,
						   6,0,'9','P','2','0','0','0'};

		if (sendto(sock, reply, 19, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
			goto fail;
	}

	exit(0);

fail:
	perror("*** error");
	exit(1);
}

//EOF

================================================================================














#define EXP_9P_ETH	0x885b

typedef struct Ethsrv Ethsrv;

struct Ethsrv {
	struct sockaddr_sll saddr;	// the address the raw socket is bound to

	int	raw_sock;

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

	es->raw_sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
	if (es->raw_sock < 0)
		goto fail1;

	struct ifreq ifr = {
		.ifr_name = VIF_NAME
	};
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
		goto fail1;

	es->saddr.sll_family = AF_PACKET;
	es->saddr.sll_protocol = htons(EXP_9P_ETH);
	es->saddr.sll_ifindex = ifr.ifr_ifindex;

	if (bind(es->raw_sock, (struct sockaddr *)&es->saddr, sizeof(es->saddr)) < 0)
		goto fail1;

	srv = sp_srv_create();
	if (srv == 0)
		goto fail1;

	srv->srvaux = es;
	srv->start = sp_ethsrv_start;
	srv->shutdown = sp_ethsrv_shutdown;
	srv->destroy = sp_ethsrv_destroy;

	return srv;

fail1:
	free(es);
	return NULL;
}

static void
sp_ethsrv_start(Spsrv *srv)
{
	Ethsrv *es = srv->srvaux;

	es->spfd = spfd_add(es->sock, sp_ethsrv_notify, srv);
}

static void
sp_ethsrv_shutdown(Spsrv *srv)
{
	Ethsrv *es = srv->srvaux;

	spfd_remove(es->spfd);
	close(es->sock);
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

	srv = aux;
	es = srv->srvaux;

	if (!spfd_can_read(spfd))
		return;

	spfd_read(spfd, buf, 0);


	XXX


	caddrlen = sizeof(caddr);
	csock = accept(es->sock, (struct sockaddr *) &caddr, &caddrlen);
	if (csock<0) {
		if (!es->shutdown)
			return;

		close(es->sock);
		if (sp_ethsrv_connect(es) < 0)
			fprintf(stderr, "error while reconnecting: %d\n", errno);
		return;
	}

	fcntl(csock, F_SETFD, FD_CLOEXEC);
	if (!(conn = sp_fdconn_create(srv, csock, csock)))
		close(csock);

	snprintf(buf, sizeof(buf), "%s!%d", inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));
	conn->addrees = strdup(buf);
}

//EOF
