//
//
//

#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <netpacket/packet.h>
#include <net/ethernet.h>
//#include <net/if.h>
#include <linux/if.h>

#include <arpa/inet.h>

#include "spfs.h"
#include "spfsimpl.h"

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

	uint8_t buf[1024];
	spfd_read(spfd, buf, 0);
	int len = recv(es->nl_sock, buf, sizeof(buf), 0);

	//
	// The analysis of real netlink traffic tells us that we need to wait for
	// RTM_NEW_LINK messages with IFF_UP and IFF_RUNNING bits set, attribute
	// IFLA_OPERSTATE set to 0 or 6, and attribute IFLA_PROTINFO set to 3.
	// Moreover, multiple such messages may be received. Magic, I say.
	//

	int fd;
	struct nlmsghdr *hdr = (struct nlmsghdr *)buf;
	while (NLMSG_OK(hdr, len))
	{
		struct ifinfomsg *ifi = NLMSG_DATA(hdr);

		if (hdr->nlmsg_type == RTM_NEWLINK &&
				(ifi->ifi_flags & IFF_UP) != 0 &&
				(ifi->ifi_flags & IFF_RUNNING) != 0)
		{
			struct rtattr *rta = (void *)ifi + sizeof(*ifi);
			int rta_len = len -sizeof(*ifi);

			int oper_state_ok = 0;
			int protinfo_ok = 0;
			while (RTA_OK(rta, rta_len))
			{
				int dlen = RTA_PAYLOAD(rta);
				if (rta->rta_type == IFLA_OPERSTATE && dlen == 1)
				{
					uint8_t oper_state = *(uint8_t *)RTA_DATA(rta);
					oper_state_ok = (oper_state == IF_OPER_UP) ||
									(oper_state == IF_OPER_UNKNOWN);
				}
				else if (rta->rta_type == IFLA_PROTINFO && dlen == 1)
					protinfo_ok = *(uint8_t *)RTA_DATA(rta) == 3;	// magic

				rta = RTA_NEXT(rta, rta_len);
			}

			if (oper_state_ok && protinfo_ok)
			{
				if (srv->debuglevel > 0)
					fprintf(stderr, "sp_ethsrv_notify: RTM_NEW_LINK msg recv [%d]\n", ifi->ifi_index);

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

				if (srv->debuglevel > 0)
					fprintf(stderr, "sp_ethsrv_notify: ethconn added [%d]\n", ifi->ifi_index);
			}
		}

		hdr = NLMSG_NEXT(hdr, len);
	}

	return;

fail2:
	close(fd);
fail1:
	perror("sp_ethsrv_notify");
}

//	struct nlmsghdr *hdr = (struct nlmsghdr *)buf;
//	while (NLMSG_OK(hdr, len))
//	{
//		struct ifinfomsg *ifi = NLMSG_DATA(hdr);
//
//		if (hdr->nlmsg_type == RTM_NEWLINK)
//		{
//			printf("NLMSG: RTM_NEW_LINK idindex %d change %d\n",
//									ifi->ifi_index, ifi->ifi_change);
//			printf("\tflags: %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n",
//					(ifi->ifi_flags & IFF_UP) ?"IFF_UP" :"",
//					(ifi->ifi_flags & IFF_BROADCAST) ?"IFF_BROADCAST" :"",
//					(ifi->ifi_flags & IFF_DEBUG) ?"IFF_DEBUG" :"",
//					(ifi->ifi_flags & IFF_LOOPBACK) ?"IFF_LOOPBACK" :"",
//					(ifi->ifi_flags & IFF_POINTOPOINT) ?"IFF_POINTOPOINT" :"",
//					(ifi->ifi_flags & IFF_NOTRAILERS) ?"IFF_NOTRAILERS" :"",
//					(ifi->ifi_flags & IFF_RUNNING) ?"IFF_RUNNING" :"",
//					(ifi->ifi_flags & IFF_NOARP) ?"IFF_NOARP" :"",
//					(ifi->ifi_flags & IFF_PROMISC) ?"IFF_PROMISC" :"",
//					(ifi->ifi_flags & IFF_ALLMULTI) ?"IFF_ALLMULTI" :"",
//					(ifi->ifi_flags & IFF_MASTER) ?"IFF_MASTER" :"",
//					(ifi->ifi_flags & IFF_SLAVE) ?"IFF_SLAVE" :"",
//					(ifi->ifi_flags & IFF_MULTICAST) ?"IFF_MULTICAST" :"",
//					(ifi->ifi_flags & IFF_PORTSEL) ?"IFF_PORTSEL" :"",
//					(ifi->ifi_flags & IFF_AUTOMEDIA) ?"IFF_AUTOMEDIA" :"",
//					(ifi->ifi_flags & IFF_DYNAMIC) ?"IFF_DYNAMIC" :"");
//
//			// assume no padding between ifi and the first attribute
//			struct rtattr *rta = (void *)ifi + sizeof(*ifi);
//			int rta_len = len -sizeof(*ifi);
//
//			while (RTA_OK(rta, rta_len))
//			{
//				int dlen = RTA_PAYLOAD(rta);
//				if (rta->rta_type == IFLA_UNSPEC)
//					printf("\tattr: IFLA_UNSPEC [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_ADDRESS)
//				{
//					assert(dlen == 6);
//					uint8_t *mac = RTA_DATA(rta);
//					printf("\tattr: IFLA_ADDRESS %02x:%02x:%02x:%02x:%02x:%02x\n",
//									mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
//				}
//				else if (rta->rta_type == IFLA_BROADCAST)
//				{
//					assert(dlen == 6);
//					uint8_t *mac = RTA_DATA(rta);
//					printf("\tattr: IFLA_BROADCAST %02x:%02x:%02x:%02x:%02x:%02x\n",
//									mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
//				}
//				else if (rta->rta_type == IFLA_IFNAME)
//					printf("\tattr: IFLA_IFNAME [%s]\n", (char *)RTA_DATA(rta));
//				else if (rta->rta_type == IFLA_MTU)
//				{
//					assert(dlen == 4);
//					uint32_t mtu = *(uint32_t *)RTA_DATA(rta);
//					printf("\tattr: IFLA_MTU (%d)\n", mtu);
//				}
//				else if (rta->rta_type == IFLA_QDISC)
//					printf("\tattr: IFLA_QDISC [%s]\n", (char *)RTA_DATA(rta));
//				else if (rta->rta_type == IFLA_STATS)
//					printf("\tattr: IFLA_STATS [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_COST)
//					printf("\tattr: IFLA_COST [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_PRIORITY)
//					printf("\tattr: IFLA_PRIORITY [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_MASTER)
//				{
//					assert(dlen == 4);
//					uint32_t master = *(uint32_t *)RTA_DATA(rta);
//					printf("\tattr: IFLA_MASTER (%d)\n", master);
//				}
//				else if (rta->rta_type == IFLA_WIRELESS)
//					printf("\tattr: IFLA_WIRELESS [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_PROTINFO)
//				{
//					assert(dlen == 1);
//					uint8_t protinfo = *(uint8_t *)RTA_DATA(rta);
//					printf("\tattr: IFLA_PROTINFO (%d)\n", protinfo);
//				}
//				else if (rta->rta_type == IFLA_TXQLEN)
//					printf("\tattr: IFLA_TXQLEN [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_MAP)
//					printf("\tattr: IFLA_MAP [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_WEIGHT)
//					printf("\tattr: IFLA_WEIGHT [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_OPERSTATE)
//				{
//					assert(dlen == 1);
//					uint8_t oper_state = *(uint8_t *)RTA_DATA(rta);
//					printf("\tattr: IFLA_OPERSTATE (%d)\n", oper_state);
//				}
//				else if (rta->rta_type == IFLA_LINKMODE)
//					printf("\tattr: IFLA_LINKMODE [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_LINKINFO)
//					printf("\tattr: IFLA_LINKINFO [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_NET_NS_PID)
//					printf("\tattr: IFLA_NET_NS_PID [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_IFALIAS)
//					printf("\tattr: IFLA_IFALIAS [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_NUM_VF)
//					printf("\tattr: IFLA_NUM_VF [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_VFINFO_LIST)
//					printf("\tattr: IFLA_VFINFO_LIST [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_STATS64)
//					printf("\tattr: IFLA_STATS64 [%d]\n", dlen);
//				else if (rta->rta_type == IFLA_VF_PORTS)
//					printf("\tattr: IFLA_VF_PORTS [%d]\n", dlen);
//				else
//				{
//					assert(rta->rta_type == IFLA_PORT_SELF);
//					printf("\tattr: IFLA_PORT_SELF [%d]\n", dlen);
//				}
//
//				rta = RTA_NEXT(rta, rta_len);
//			}
//		}
//		else
//		{
//			printf("NLMSG: type %d, ignored\n", hdr->nlmsg_type);
//		}
//
//		hdr = NLMSG_NEXT(hdr, len);
//	}

//EOF
