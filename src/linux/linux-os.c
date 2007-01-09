/*
 * MIPv6, an IPv6 mobility framework
 *
 * Copyright (C) 2006, 2007 Hugo Santos
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the version 2 of the GNU General Public License
 * as published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author:  Hugo Santos <hugo@fivebits.net>
 */

#include <stdint.h>
#include <unistd.h>
#include <fcntl.h> /* for fcntl() */
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <net/if.h>

#include <netinet/ip6.h>
#include <netinet/ip6mh.h>

#include <mblty/events.h>
#include <mblty/tunnel.h>
#include <mblty/router.h>
#include <mblty/base-defs.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>
#include <mblty/sock-support.h>

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/neighbour.h>

#include "linux-def.h"

/* from linux/if_tunnel.h */
#define SIOCGETTUNNEL   (SIOCDEVPRIVATE + 0)
#define SIOCADDTUNNEL   (SIOCDEVPRIVATE + 1)
#define SIOCDELTUNNEL   (SIOCDEVPRIVATE + 2)
#define SIOCCHGTUNNEL   (SIOCDEVPRIVATE + 3)

/* derived from linux/ip6_tunnel.h */
#define IP6_TNL_F_IGN_ENCAP_LIMIT	0x01
#define IP6_TNL_F_USE_ORIG_TCLASS	0x02
#define IP6_TNL_F_USE_ORIG_FLOWLABEL	0x04
#define IP6_TNL_F_MIP6_DEV		0x08
#define IP6_TNL_F_RCV_DSCP_COPY		0x10

#ifndef IFA_F_HOME_ADDRESS
#define IFA_F_HOME_ADDRESS 0x02
#endif

#ifndef IFA_F_MANAGED
#define IFA_F_MANAGED	0x10
#endif

/* BSD does RECV.., old Linuxes do not */
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

#ifndef IPV6_RECVDSTOPTS
#define IPV6_RECVDSTOPTS IPV6_DSTOPTS
#endif

#ifndef IPV6_RECVRTHDR
#define IPV6_RECVRTHDR IPV6_RTHDR
#endif

#ifndef IPV6_UNSPECSOURCE
/* Linux only */
#define IPV6_UNSPECSOURCE 80
#endif

#ifndef IPV6_RECVNETWORKHDRS
/* these are our kernel's only modifications */
#define IPV6_RECVNETWORKHDRS	81
#define IPV6_NETWORKHDRS	82
#endif

struct ip6_tnl_parm {
	char name[IFNAMSIZ];
	int link;
	uint8_t proto;
	uint8_t encap_limit;
	uint8_t hop_limit;
	uint32_t flowinfo;
	uint32_t flags;
	struct in6_addr laddr;
	struct in6_addr raddr;
};

struct ip6sock_msgctl {
	struct msghdr *h;
	struct cmsghdr *chdr;
	int ctllen;
};

static struct nl_handle *nl_events;
static struct nl_cache *links;

static LIST_DEF(pending_msgs);
static LIST_DEF(interfaces);

/* we must keep different control buffers for sent
 * and received messages as we may be clearing data
 * which is requiring to send for instance */
static uint8_t _msg_inctlbuf[256], _msg_outctlbuf[256];

static const char *linux_intf_desc(mblty_os_intf_t *, int, char *, size_t);
static int linux_intf_get_type(mblty_os_intf_t *);
static int linux_intf_get_address(mblty_os_intf_t *, uint8_t *, size_t);
static int linux_intf_get_flags(mblty_os_intf_t *, uint32_t *);
static int linux_intf_set_up(mblty_os_intf_t *, int);
static int linux_intf_neigh_update(linux_intf_t *, int type, struct in6_addr *,
				   uint8_t *, size_t);
static int linux_intf_eth_neigh_update(mblty_os_intf_t *, struct in6_addr *,
				       uint8_t *, size_t);
static int linux_intf_cap_enable(mblty_os_intf_t *, mblty_os_intf_cap_t);
static int linux_intf_cap_disable(mblty_os_intf_t *, mblty_os_intf_cap_t);

static mblty_os_intf_ops_t linux_intf_base_ops = {
	.description = linux_intf_desc,
	.get_type = linux_intf_get_type,
	.get_address = linux_intf_get_address,
	.get_flags = linux_intf_get_flags,
	.set_up = linux_intf_set_up,
	.neigh_update = NULL,
	.enable = linux_intf_cap_enable,
	.disable = linux_intf_cap_disable,
};

static mblty_os_intf_ops_t linux_intf_eth_ops = {
	.description = linux_intf_desc,
	.get_type = linux_intf_get_type,
	.get_address = linux_intf_get_address,
	.get_flags = linux_intf_get_flags,
	.set_up = linux_intf_set_up,
	.neigh_update = linux_intf_eth_neigh_update,
	.enable = linux_intf_cap_enable,
	.disable = linux_intf_cap_disable,
};

static int os_sk_send(supsocket_t *, struct in6_addr *, void *, int,
		      supsocket_txopt_t *);
static int os_sk_recv(supsocket_t *, void *, int, supsocket_rxparm_t *);
static int os_sk_enable(supsocket_t *, supsocket_cap_t);
static int os_sk_disable(supsocket_t *, supsocket_cap_t);
static int os_sk_join_mc(supsocket_t *, mblty_os_intf_t *, struct in6_addr *);
static int os_sk_leave_mc(supsocket_t *, mblty_os_intf_t *, struct in6_addr *);
static int os_sk_join_anycast(supsocket_t *, mblty_os_intf_t *,
			      struct in6_addr *);
static int os_sk_leave_anycast(supsocket_t *, mblty_os_intf_t *,
			       struct in6_addr *);

static supsocket_ops_t linux_sk_ops = {
	.send = os_sk_send,
	.recv = os_sk_recv,
	.enable = os_sk_enable,
	.disable = os_sk_disable,
	.join_mc = os_sk_join_mc,
	.leave_mc = os_sk_leave_mc,
	.join_anycast = os_sk_join_anycast,
	.leave_anycast = os_sk_leave_anycast,
};

static linux_intf_t *
linux_deep_get_intf(int ifindex, int maycreate, int *created)
{
	char buf[IFNAMSIZ];
	linux_intf_t *li;

	(*created) = 1;

	list_for_each_entry (li, &interfaces, entry) {
		if (li->ifindex == ifindex) {
			(*created) = 0;
			return li;
		}
	}

	if (!maycreate)
		return NULL;

	if (if_indextoname(ifindex, buf) == NULL)
		return NULL;

	li = allocate_object(linux_intf_t);
	if (li == NULL)
		return NULL;

	li->ifindex = ifindex;
	strncpy(li->osh.name, buf, IFNAMSIZ);

	list_init(&li->addresses);

	switch (linux_intf_get_type(&li->osh)) {
	case ARPHRD_ETHER:
		li->osh.ops = &linux_intf_eth_ops;
		break;
	case ARPHRD_LOOPBACK:
	case ARPHRD_TUNNEL6:
	default:
		li->osh.ops = &linux_intf_base_ops;
		break;
	}

	list_add_tail(&li->entry, &interfaces);

	return li;
}

static linux_intf_t *
linux_get_intf(int ifindex, int maycreate)
{
	int tmp;
	return linux_deep_get_intf(ifindex, maycreate, &tmp);
}

static linux_intf_t *
linux_event_get_intf(int ifindex, int maycreate)
{
	linux_intf_t *li;
	int created;

	li = linux_deep_get_intf(ifindex, maycreate, &created);
	if (li == NULL)
		return NULL;

	if (created)
		mblty_found_interface(&li->osh);

	return li;
}

static void
linux_lost_interface(linux_intf_t *li)
{
	debug_log(7, "[Linux] Lost interface %s.\n", li->osh.name);

	mblty_lost_interface(&li->osh);

	list_del(&li->entry);
	free_object(li);
}

static const char *
linux_intf_desc(mblty_os_intf_t *osh, int type, char *buf, size_t len)
{
	if (type == 0)
		snprintf(buf, len, "%s", osh->name);
	else
		snprintf(buf, len, "%s [%i]", osh->name, INTF(osh)->ifindex);

	return buf;
}

static int
perform_intf_ioctl(linux_intf_t *intf, int type, struct ifreq *ifr)
{
	int fd, res;

	memset(ifr, 0, sizeof(struct ifreq));
	strncpy(ifr->ifr_name, intf->osh.name, sizeof(ifr->ifr_name));
	ifr->ifr_ifindex = intf->ifindex;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	res = ioctl(fd, type, &ifr);
	close(fd);

	return res;
}

static int
linux_intf_get_type(mblty_os_intf_t *osh)
{
	int ifindex = INTF(osh)->ifindex;
	struct rtnl_link *l;
	int res;

	l = rtnl_link_get(links, ifindex);
	if (l == NULL) {
		struct ifreq ifr;
		if (perform_intf_ioctl(INTF(osh), SIOCGIFHWADDR, &ifr) < 0)
			return -1;
		return ifr.ifr_hwaddr.sa_family;
	}

	res = rtnl_link_get_arptype(l);
	rtnl_link_put(l);

	return res;
}

static int
linux_intf_get_address(mblty_os_intf_t *osh, uint8_t *lladdr, size_t len)
{
	int ifindex = INTF(osh)->ifindex;
	struct nl_addr *addr;
	struct rtnl_link *l;
	int addrlen;

	l = rtnl_link_get(links, ifindex);
	if (l == NULL)
		return -1;

	addr = rtnl_link_get_addr(l);
	addrlen = nl_addr_get_len(addr);

	if (addrlen <= (int)len)
		memcpy(lladdr, nl_addr_get_binary_addr(addr), addrlen);
	else
		addrlen = -1;

	rtnl_link_put(l);

	return addrlen;
}

static int
linux_intf_get_flags(mblty_os_intf_t *osh, uint32_t *flags)
{
	int ifindex = INTF(osh)->ifindex;
	struct rtnl_link *l;

	l = rtnl_link_get(links, ifindex);
	if (l == NULL) {
		struct ifreq ifr;

		if (perform_intf_ioctl(INTF(osh), SIOCGIFFLAGS, &ifr) < 0)
			return -1;

		*flags = ifr.ifr_flags;
	} else {
		*flags = rtnl_link_get_flags(l);
		rtnl_link_put(l);
	}

	return 0;
}

static int
linux_intf_set_up(mblty_os_intf_t *osh, int on)
{
	int ifindex = INTF(osh)->ifindex;
	struct ifreq ifr;
	int fd, res;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, osh->name, sizeof(ifr.ifr_name));

	ifr.ifr_ifindex = ifindex;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0)
		return -1;

	if (on)
		ifr.ifr_flags |=  (IFF_UP | IFF_RUNNING);
	else
		ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);

	res = ioctl(fd, SIOCSIFFLAGS, &ifr);
	close(fd);

	return res;
}

static struct nl_addr *
_get_addr(struct in6_addr *addr)
{
	return nl_addr_build(AF_INET6, addr, 16);
}

static int
linux_intf_neigh_update(linux_intf_t *li, int type, struct in6_addr *address,
			uint8_t *_lladdr, size_t addrlen)
{
	struct nl_addr *addr, *lladdr;
	struct rtnl_neigh *neigh;
	int res = 0;

	lladdr = nl_addr_build(type, _lladdr, addrlen);
	addr = _get_addr(address);
	neigh = rtnl_neigh_alloc();

	if (addr && lladdr && neigh) {
		rtnl_neigh_set_ifindex(neigh, li->ifindex);
		rtnl_neigh_set_dst(neigh, addr);
		rtnl_neigh_set_lladdr(neigh, lladdr);
		rtnl_neigh_set_state(neigh, NUD_REACHABLE);

		rtnl_neigh_add(nl_events, neigh, NLM_F_REPLACE);
	} else {
		res = -1;
	}

	if (neigh)
		rtnl_neigh_put(neigh);
	if (lladdr)
		nl_addr_put(lladdr);
	if (addr)
		nl_addr_put(addr);

	return res;
}

static int
linux_intf_eth_neigh_update(mblty_os_intf_t *osh, struct in6_addr *addr,
			    uint8_t *lladdr, size_t len)
{
	return linux_intf_neigh_update(INTF(osh), AF_LLC, addr, lladdr, len);
}

static int
linux_do_sysctl(const char *path, const char *intf, int on, int *was)
{
	const char *op = on ? "1\n" : "0\n";
	char wpath[256];
	int fd, res;
	char tmp;

	snprintf(wpath, sizeof(wpath), path, intf);

	fd = open(wpath, O_RDWR);
	if (fd < 0)
		return fd;

	if (read(fd, &tmp, 1) < 0) {
		close(fd);
		return -1;
	}

	tmp = tmp - '0';

	if (was) {
		*was = tmp;
	}

	res = write(fd, op, strlen(op));
	if (res > 0) {
		debug_log(5, "%s: %i -> %i\n", wpath, (int)tmp, on);
	}

	close(fd);

	return 0;
}

#define AUTOCONF_PATH	"/proc/sys/net/ipv6/conf/%s/autoconf"
#define ACCEPT_RA_PATH	"/proc/sys/net/ipv6/conf/%s/accept_ra"
#define FORWARDING_PATH	"/proc/sys/net/ipv6/conf/%s/forwarding"

static int
kern_conf_autoconfiguration(const char *name, int on)
{
	int was;

	if (linux_do_sysctl(AUTOCONF_PATH, name, on, &was) < 0)
		return -1;

	if (linux_do_sysctl(ACCEPT_RA_PATH, name, on, NULL) < 0)
		linux_do_sysctl(AUTOCONF_PATH, name, was, NULL);

	return 0;
}

static int
kern_enable_ipv6_forwarding(const char *name, int on)
{
	return linux_do_sysctl(FORWARDING_PATH, name, on, NULL);
}

static int
linux_intf_cap_enable(mblty_os_intf_t *osh, mblty_os_intf_cap_t cap)
{
	switch (cap) {
	case MBLTY_OS_INTF_CAP_FORWARDING:
		return kern_enable_ipv6_forwarding(osh->name, 1);
	case MBLTY_OS_INTF_CAP_AUTOCONF:
		return kern_conf_autoconfiguration(osh->name, 1);
	}

	return -1;
}

static int
linux_intf_cap_disable(mblty_os_intf_t *osh, mblty_os_intf_cap_t cap)
{
	switch (cap) {
	case MBLTY_OS_INTF_CAP_FORWARDING:
		return kern_enable_ipv6_forwarding(osh->name, 0);
	case MBLTY_OS_INTF_CAP_AUTOCONF:
		return kern_conf_autoconfiguration(osh->name, 0);
	}

	return -1;
}

mblty_os_intf_t *
mblty_os_intf_get_by_name(const char *name)
{
	linux_intf_t *li;

	list_for_each_entry (li, &interfaces, entry) {
		if (strcmp(li->osh.name, name) == 0)
			return &li->osh;
	}

	return NULL;
}

mblty_os_intf_t *
mblty_os_intf_get_loopback()
{
	linux_intf_t *li = linux_get_intf(1, 1);
	if (li)
		return &li->osh;
	return NULL;
}

int mblty_os_intf_is_loopback(mblty_os_intf_t *osh)
{
	uint32_t flags;

	if (mblty_os_intf_get_flags(osh, &flags) < 0)
		return 0;

	return flags & IFF_LOOPBACK;
}

static void
linux_handle_link_event(struct nl_msg *msg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct ifinfomsg *ifi;
	struct rtnl_link *l;
	linux_intf_t *li;

	ifi = nlmsg_data(hdr);

	l = rtnl_link_update_cache_from_msg(links, hdr);
	if (l == NULL)
		return;

	li = linux_event_get_intf(ifi->ifi_index,
				  hdr->nlmsg_type == RTM_NEWLINK);

	if (hdr->nlmsg_type == RTM_NEWLINK)
		mblty_interface_flags_changed(&li->osh,
					      rtnl_link_get_flags(l));
	else if (hdr->nlmsg_type == RTM_DELLINK) {
		/* Linux's IPv6 signals DELLINK with family AF_INET6
		 * when all of the addresses are removed. we ignore
		 * that event. */
		if (li && ifi->ifi_family != AF_INET6)
			linux_lost_interface(li);
	}

	rtnl_link_put(l);
}

static void
linux_handle_addr_event(struct nl_msg *msg)
{
	struct rtnl_addr *addr = rtnl_addr_alloc_from_msg(msg);
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	struct nl_addr *local;

	if (addr == NULL)
		return;

	local = rtnl_addr_get_local(addr);

	if (nl_addr_get_family(local) == AF_INET6) {
		linux_intf_t *li = linux_get_intf(rtnl_addr_get_ifindex(addr),
						  0);
		int prefixlen = rtnl_addr_get_prefixlen(addr);
		struct in6_prefix addrpfx;
		struct in6_addr *in6a;

		in6a = (struct in6_addr *)nl_addr_get_binary_addr(local);
		in6_addr_copy(&addrpfx.address, in6a);
		addrpfx.prefixlen = prefixlen;

		if (hdr->nlmsg_type == RTM_NEWADDR)
			mblty_address_added(&li->osh, &addrpfx);
		else
			mblty_address_removed(&li->osh, &addrpfx);
	}

	rtnl_addr_put(addr);
}

static int
linux_nl_event(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);

	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		linux_handle_link_event(msg);
		break;

	case RTM_NEWADDR:
	case RTM_DELADDR:
		linux_handle_addr_event(msg);
		break;
	}

	return NL_PROCEED;
}

static void
linux_free_pending_msg(struct linux_pending_msg *pmsg)
{
	nlmsg_free(pmsg->msg);

	list_del(&pmsg->entry);
	free_object(pmsg);
}

static void
linux_handle_nl_ack(int err, struct linux_pending_msg *pmsg)
{
	if (pmsg->cb)
		pmsg->cb(err, pmsg->param);

	linux_free_pending_msg(pmsg);
}

struct linux_pending_msg *
linux_get_request(kern_addremove_callback cb, void *param)
{
	struct linux_pending_msg *pmsg;

	list_for_each_entry (pmsg, &pending_msgs, entry) {
		if (pmsg->cb == cb && pmsg->param == param)
			return pmsg;
	}

	return NULL;
}

static void
linux_handle_error(uint32_t pid, uint32_t seq, int error)
{
	struct linux_pending_msg *pmsg;
	struct nlmsghdr *pendhdr;

	list_for_each_entry (pmsg, &pending_msgs, entry) {
		pendhdr = nlmsg_hdr(pmsg->msg);

		if (pendhdr->nlmsg_pid == pid &&
		    pendhdr->nlmsg_seq == seq) {
			linux_handle_nl_ack(error, pmsg);
			break;
		}
	}
}

static int
linux_nl_ack(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);
	int error = 0;

	debug_log(7, "linux_nl_ack(%i, %i)\n", (int)hdr->nlmsg_pid,
		  hdr->nlmsg_seq);

	if (hdr->nlmsg_type == NLMSG_ERROR)
		error = ((struct nlmsgerr *)nlmsg_data(hdr))->error;

	linux_handle_error(hdr->nlmsg_pid, hdr->nlmsg_seq, error);

	return NL_PROCEED;
}

static int
linux_nl_err(struct sockaddr_nl *sal, struct nlmsgerr *err, void *arg)
{
	linux_handle_error(err->msg.nlmsg_pid, err->msg.nlmsg_seq, err->error);
	return NL_PROCEED;
}

static int
nl_events_waiting(supsocket_t *sock)
{
	nl_recvmsgs_def(nl_events);
	return 0;
}

static void
linux_alloc_initial_intf(struct nl_object *obj, void *arg)
{
	struct rtnl_link *rl = (struct rtnl_link *)obj;

	linux_get_intf(rtnl_link_get_ifindex(rl), 1);
}

void
os_internal_init()
{
	supsocket_t *sock;

	nl_debug = 0;

	nl_events = nl_handle_alloc();

	nl_disable_sequence_check(nl_events);
	/* handle normal messages */
	nl_cb_set(nl_handle_get_cb(nl_events), NL_CB_VALID, NL_CB_CUSTOM,
		  linux_nl_event, NULL);
	/* handle ACKs */
	nl_cb_set(nl_handle_get_cb(nl_events), NL_CB_ACK, NL_CB_CUSTOM,
		  linux_nl_ack, NULL);
	nl_cb_err(nl_handle_get_cb(nl_events), NL_CB_CUSTOM,
		  linux_nl_err, NULL);
	nl_join_groups(nl_events, ~0);

	if (nl_connect(nl_events, NETLINK_ROUTE) < 0)
		perform_shutdown(NULL, "Failed to connect NETLINK_ROUTE");

	links = rtnl_link_alloc_cache(nl_events);
	if (links == NULL)
		perform_shutdown(NULL, "Failed to allocate link cache");
	nl_cache_mngt_provide(links);
	nl_cache_foreach(links, linux_alloc_initial_intf, NULL);

	/* set nl events sock to non-blocking mode */
	fcntl(nl_handle_get_fd(nl_events), F_SETFL, O_NONBLOCK);

	sock = support_register_socket(nl_handle_get_fd(nl_events),
				       nl_events_waiting, NULL, NULL);
	sock->mode = SUPSOCKET_READ;
}

void
os_internal_shutdown()
{
	support_unregister_socket(nl_handle_get_fd(nl_events));

	nl_cache_free(links);
	links = NULL;

	nl_close(nl_events);

	nl_handle_destroy(nl_events);
	nl_events = NULL;
}

static void
msgctl_init(struct ip6sock_msgctl *msgctl, struct msghdr *h)
{
	msgctl->h = h;
	msgctl->chdr = CMSG_FIRSTHDR(h);
	msgctl->ctllen = 0;
}

static void
msgctl_finalize(struct ip6sock_msgctl *msgctl)
{
	msgctl->h->msg_controllen = msgctl->ctllen;
}

static void
build_msghdr(struct msghdr *h, struct sockaddr_in6 *name,
	     struct iovec *v, void *buf, int buflen,
	     void *control, int controllen)
{
	memset(h, 0, sizeof(struct msghdr));

	h->msg_name = name;
	h->msg_namelen = sizeof(struct sockaddr_in6);
	h->msg_iov = v;
	h->msg_iovlen = 1;

	v->iov_base = (char *)buf;
	v->iov_len = buflen;

	h->msg_control = control;
	h->msg_controllen = controllen;
	h->msg_flags = 0;
}

static int
sendmsg_retry(int fd, struct msghdr *h, int flags)
{
	int res;

	while (1) {
		res = sendmsg(fd, h, flags);
		if (res < 0 && errno == EINTR)
			continue;
		break;
	}

	return res;
}

static int
set_recvpktinfo(int fd, int on)
{
	return setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
}

static int
add_pktinfo(struct ip6sock_msgctl *msgctl, int ifindex, struct in6_addr *addr)
{
	struct cmsghdr *chdr = msgctl->chdr;
	char buf1[INET6_ADDRSTRLEN];
	struct in6_pktinfo *info;

	if (chdr == NULL)
		return -1;

	debug_log(15, "add_pktinfo(%p, %i, %s)\n", msgctl, ifindex,
		  format_addr(buf1, addr));

	chdr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_PKTINFO;

	info = (struct in6_pktinfo *)CMSG_DATA(chdr);

	info->ipi6_ifindex = ifindex;
	if (addr)
		in6_addr_copy(&info->ipi6_addr, addr);
	else
		in6_addr_copy(&info->ipi6_addr, &in6addr_any);

	msgctl->ctllen += CMSG_SPACE(sizeof(struct in6_pktinfo));
	msgctl->chdr = CMSG_NXTHDR(msgctl->h, chdr);

	return 0;
}

static int
set_recvdstopts(int fd, int on)
{
	return setsockopt(fd, IPPROTO_IPV6, IPV6_RECVDSTOPTS, &on, sizeof(on));
}

static int
add_dstopts_hoa(struct ip6sock_msgctl *msgctl, struct in6_addr *hoa)
{
	struct cmsghdr *chdr = msgctl->chdr;
	struct in6_addr *addr;
	uint8_t *buf;

	if (chdr == NULL)
		return -1;

	chdr->cmsg_len = CMSG_LEN(24);
	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_DSTOPTS;

	buf = CMSG_DATA(chdr);
	buf[0] = 0;
	buf[1] = 2; /* length = (2 + 1) * 8 = 24 */
	buf[2] = IP6OPT_PADN;
	buf[3] = 2; /* length, 4 bytes of padding */
	buf[4] = 0;
	buf[5] = 0;
	buf[6] = IP6OPT_HOME_ADDRESS;
	buf[7] = 16; /* length */
	addr = (struct in6_addr *)(buf + 8);
	in6_addr_copy(addr, hoa);

	msgctl->ctllen += CMSG_SPACE(24);
	msgctl->chdr = CMSG_NXTHDR(msgctl->h, chdr);

	return 0;
}

static int
set_recvrthdr(int fd, int on)
{
	return setsockopt(fd, IPPROTO_IPV6, IPV6_RECVRTHDR, &on, sizeof(on));
}

static int
add_unspec_source(struct ip6sock_msgctl *msgctl)
{
	struct cmsghdr *chdr = msgctl->chdr;

	debug_assert(chdr, "chdr");

	chdr->cmsg_len = CMSG_LEN(0);
	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_UNSPECSOURCE;

	msgctl->ctllen += CMSG_SPACE(0);
	msgctl->chdr = CMSG_NXTHDR(msgctl->h, chdr);

	return 0;
}

static int
add_hoplimit(struct ip6sock_msgctl *msgctl, int hoplimit)
{
	struct cmsghdr *chdr = msgctl->chdr;

	if (chdr == NULL)
		return -1;

	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_HOPLIMIT;
	chdr->cmsg_len = CMSG_LEN(sizeof(int));
	*((int *)CMSG_DATA(chdr)) = hoplimit;

	msgctl->ctllen += CMSG_SPACE(sizeof(int));
	msgctl->chdr = CMSG_NXTHDR(msgctl->h, chdr);

	return 0;
}

static void
add_rthdr(struct ip6sock_msgctl *msgctl, int type, struct in6_addr *addr)
{
	struct cmsghdr *chdr = msgctl->chdr;
	struct ip6_rthdr0 *rt0;

	debug_assert(chdr, "Not enough control space");

	chdr->cmsg_len = CMSG_LEN(sizeof(struct ip6_rthdr0));
	chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_RTHDR;

	rt0 = (struct ip6_rthdr0 *)CMSG_DATA(chdr);
	memset(rt0, 0, sizeof(struct ip6_rthdr0));

	rt0->ip6r0_len = 2;
	rt0->ip6r0_type = type;
	rt0->ip6r0_segleft = 1;

	in6_addr_copy(&rt0->ip6r0_addr[0], addr);

	msgctl->ctllen += CMSG_SPACE(sizeof(struct ip6_rthdr0));
	msgctl->chdr = CMSG_NXTHDR(msgctl->h, chdr);
}

static int
os_sk_send(supsocket_t *sock, struct in6_addr *destination, void *buf,
	   int length, supsocket_txopt_t *txopt)
{
	struct ip6sock_msgctl msgctl;
	struct sockaddr_in6 dst;
	struct msghdr h;
	struct iovec v;

	memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	in6_addr_copy(&dst.sin6_addr, destination);

	build_msghdr(&h, &dst, &v, buf, length, _msg_outctlbuf,
		     sizeof(_msg_outctlbuf));

	memset(_msg_outctlbuf, 0, sizeof(_msg_outctlbuf));

	msgctl_init(&msgctl, &h);

	if (txopt) {
		if (txopt->flags & SUPSTXO_SOURCE_ADDR) {
			if (IN6_IS_ADDR_UNSPECIFIED(txopt->src))
				add_unspec_source(&msgctl);
			else if (txopt->flags & SUPSTXO_SOURCE_INTF)
				add_pktinfo(&msgctl,
					    INTF(txopt->intf)->ifindex,
					    txopt->src);
			else
				add_pktinfo(&msgctl, 0, txopt->src);
		} else if (txopt->flags & SUPSTXO_SOURCE_INTF) {
			add_pktinfo(&msgctl, INTF(txopt->intf)->ifindex, NULL);
		}

		if (txopt->flags & SUPSTXO_SOURCE_INTF)
			dst.sin6_scope_id = INTF(txopt->intf)->ifindex;

		if (txopt->flags & SUPSTXO_HOP_LIMIT ||
		    txopt->hoplimit > 0)
			add_hoplimit(&msgctl, txopt->hoplimit);

		if (txopt->flags & SUPSTXO_SOURCE_HOA)
			add_dstopts_hoa(&msgctl, txopt->hoa);

		if (txopt->flags & SUPSTXO_DEST_INDIR_RT)
			add_rthdr(&msgctl, txopt->rttype, txopt->dst);
	}

	msgctl_finalize(&msgctl);

	return sendmsg_retry(sock->fd, &h, 0);
}

static int
os_sk_recv(supsocket_t *sock, void *buf, int length, supsocket_rxparm_t *rxp)
{
	struct in6_pktinfo *pkti;
	struct cmsghdr *c;
	struct msghdr h;
	struct iovec v;
	int res = -1;

	memset(&rxp->p_src, 0, sizeof(rxp->p_src));
	rxp->p_src.sin6_family = AF_INET6;

	build_msghdr(&h, &rxp->p_src, &v, buf, length, _msg_inctlbuf,
		     sizeof(_msg_inctlbuf));

	do {
		res = recvmsg(sock->fd, &h, 0);
		if (res <= 0 && errno != EINTR)
			return res;
	} while (res <= 0);

	rxp->src = &rxp->p_src.sin6_addr;
	rxp->flags = 0;

	for (c = CMSG_FIRSTHDR(&h); c; c = CMSG_NXTHDR(&h, c)) {
		if (c->cmsg_level != IPPROTO_IPV6)
			continue;

		switch (c->cmsg_type) {
		case IPV6_PKTINFO:
			if (c->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
				pkti = (struct in6_pktinfo *)CMSG_DATA(c);

				rxp->dst = &pkti->ipi6_addr;
				rxp->intf =
					&linux_get_intf(pkti->ipi6_ifindex,
							0)->osh;
				rxp->flags |= SUPSRXP_RECV_INFO;
			}
			break;

		case IPV6_RTHDR:
			if (c->cmsg_len >= CMSG_LEN(sizeof(struct ip6_rthdr) +
						    sizeof(struct in6_addr))) {
				/* must have at least one segment */
				rxp->rthdr = (struct ip6_rthdr *)CMSG_DATA(c);
				rxp->flags |= SUPSRXP_RTHDR_INFO;
			}
			break;

		case IPV6_DSTOPTS:
			if (c->cmsg_len >= CMSG_LEN(sizeof(struct ip6_dest))) {
				rxp->dsthdr = (struct ip6_dest *)CMSG_DATA(c);
				if (CMSG_LEN((rxp->dsthdr->ip6d_len + 1) * 8)
						<= c->cmsg_len)
					rxp->flags |= SUPSRXP_DSTOPS_INFO;
				else
					rxp->dsthdr = NULL;
			}
			break;

		case IPV6_NETWORKHDRS:
			debug_assert(c->cmsg_len >= CMSG_LEN(0),
				     "Malformed IPV6_NETWORKHDRS");

			rxp->ip6hdr = (struct ip6_hdr *)CMSG_DATA(c);
			rxp->ip6hdrlen = c->cmsg_len - CMSG_LEN(0);
			rxp->flags |= SUPSRXP_NETWRKHDRS_INFO;
			break;

		default:
			break;
		}
	}

	return res;
}

static int
enable_multicast_loop(int fd, int on)
{
	return setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
			  &on, sizeof(on));
}

static int
os_sk_enable(supsocket_t *sock, supsocket_cap_t cap)
{
	int on = 1;

	switch (cap) {
	case SUPSCAP_MULTICAST_LOOP:
		return enable_multicast_loop(sock->fd, 1);
	case SUPSCAP_RECV_INFO:
		return set_recvpktinfo(sock->fd, 1);
	case SUPSCAP_RTHDR_INFO:
		return set_recvrthdr(sock->fd, 1);
	case SUPSCAP_DSTOPTS_INFO:
		return set_recvdstopts(sock->fd, 1);
	case SUPSCAP_NETWRKHDRS_INFO:
		return setsockopt(sock->fd, IPPROTO_IPV6, IPV6_RECVNETWORKHDRS,
				  &on, sizeof(on));
	}

	return -1;
}

static int
os_sk_disable(supsocket_t *sock, supsocket_cap_t cap)
{
	int off = 0;

	switch (cap) {
	case SUPSCAP_MULTICAST_LOOP:
		return enable_multicast_loop(sock->fd, 0);
	case SUPSCAP_RECV_INFO:
		return set_recvpktinfo(sock->fd, 0);
	case SUPSCAP_RTHDR_INFO:
		return set_recvrthdr(sock->fd, 0);
	case SUPSCAP_DSTOPTS_INFO:
		return set_recvdstopts(sock->fd, 0);
	case SUPSCAP_NETWRKHDRS_INFO:
		return setsockopt(sock->fd, IPPROTO_IPV6, IPV6_RECVNETWORKHDRS,
				  &off, sizeof(off));
	}

	return -1;
}

static int
posix_sk_mc_op(supsocket_t *sock, int op, mblty_os_intf_t *osh,
	       struct in6_addr *addr)
{
	struct ipv6_mreq mreq = {
		.ipv6mr_interface = INTF(osh)->ifindex,
		.ipv6mr_multiaddr = *addr,
	};

	return setsockopt(sock->fd, IPPROTO_IPV6, op, &mreq,
			  sizeof(struct ipv6_mreq));
}

static int
os_sk_join_mc(supsocket_t *sock, mblty_os_intf_t *osh, struct in6_addr *mcaddr)
{
	return posix_sk_mc_op(sock, IPV6_JOIN_GROUP, osh, mcaddr);
}

static int
os_sk_leave_mc(supsocket_t *sock, mblty_os_intf_t *osh, struct in6_addr *mcaddr)
{
	return posix_sk_mc_op(sock, IPV6_LEAVE_GROUP, osh, mcaddr);
}

static int
os_sk_join_anycast(supsocket_t *sock, mblty_os_intf_t *osh,
		   struct in6_addr *mcaddr)
{
#ifdef IPV6_JOIN_ANYCAST
	return posix_sk_mc_op(sock, IPV6_JOIN_ANYCAST, osh, mcaddr);
#else
	return -1;
#endif
}

static int
os_sk_leave_anycast(supsocket_t *sock, mblty_os_intf_t *osh,
		    struct in6_addr *addr)
{
#ifdef IPV6_LEAVE_ANYCAST
	return posix_sk_mc_op(sock, IPV6_LEAVE_ANYCAST, osh, addr);
#else
	return -1;
#endif
}

int
os_create_socket(supsocket_t *sock, int domain, int type, int proto)
{
	sock->fd = socket(domain, type, proto);
	if (sock->fd < 0)
		return sock->fd;

	sock->ops = &linux_sk_ops;

	return 0;
}

int
os_close_socket(supsocket_t *sock)
{
	return close(sock->fd);
}

static void
kern_fill_ip6ip6_params(struct ip6_tnl_parm *params, struct in6_addr *local,
			struct in6_addr *remote)
{
	memset(params, 0, sizeof(struct ip6_tnl_parm));

	params->proto = IPPROTO_IPV6;
	params->flags = IP6_TNL_F_IGN_ENCAP_LIMIT |
		        IP6_TNL_F_USE_ORIG_TCLASS |
		        IP6_TNL_F_RCV_DSCP_COPY;
	params->hop_limit = 64;

	in6_addr_copy(&params->laddr, local);
	in6_addr_copy(&params->raddr, remote);
}

static int
kern_ip6ip6_ioctl(int type, const char *ifname, struct ip6_tnl_parm *params)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_ifru.ifru_data = (void *)params;

	return ioctl(nl_handle_get_fd(nl_events), type, &ifr);
}

static int
kern_update_ip6ip6_tunnel(struct mblty_tunnel *tun, struct in6_addr *local,
			  struct in6_addr *remote)
{
	struct ip6_tnl_parm params;

	kern_fill_ip6ip6_params(&params, local, remote);

	return kern_ip6ip6_ioctl(SIOCCHGTUNNEL, tun->osh->name, &params);
}

static void
kern_free_ip6ip6_tunnel(struct mblty_tunnel *tun)
{
	kern_ip6ip6_ioctl(SIOCDELTUNNEL, tun->osh->name, NULL);

	free_object(tun);
}

static mblty_tunnel_ops_t linux_ip6ip6_ops = {
	.update = kern_update_ip6ip6_tunnel,
	.destructor = kern_free_ip6ip6_tunnel,
};

static mblty_tunnel_t *
kern_alloc_ip6ip6_tunnel(mblty_tunnel_factory_t *factory,
			 struct in6_addr *local, struct in6_addr *remote)
{
	struct ip6_tnl_parm params;
	struct mblty_tunnel *tun;
	linux_intf_t *li;

	tun = allocate_object(struct mblty_tunnel);
	if (tun == NULL)
		return NULL;

	tun->ops = &linux_ip6ip6_ops;

	kern_fill_ip6ip6_params(&params, local, remote);

	if (kern_ip6ip6_ioctl(SIOCGETTUNNEL, "ip6tnl0", &params) < 0) {
		kern_fill_ip6ip6_params(&params, local, remote);
		if (kern_ip6ip6_ioctl(SIOCADDTUNNEL, "ip6tnl0", &params) < 0) {
			free_object(tun);
			return NULL;
		}
	}

	li = linux_get_intf(if_nametoindex(params.name), 1);
	if (li == NULL) {
		kern_ip6ip6_ioctl(SIOCDELTUNNEL, params.name, NULL);
		free_object(tun);
		return NULL;
	}

	tun->osh = &li->osh;

	return tun;
}

#define CALL_BACK(cb, arg, err) \
	if (cb) { (cb)(err, arg); }

static int
linux_do_request(struct nl_msg *msg, kern_addremove_callback cb,
		 void *arg)
{
	struct linux_pending_msg *pmsg;

	if (cb) {
		pmsg = allocate_object(struct linux_pending_msg);

		if (msg && pmsg) {
			pmsg->msg = msg;
			pmsg->cb = cb;
			pmsg->param = arg;

			if (nl_send_auto_complete(nl_events, pmsg->msg) >= 0) {
				list_add_tail(&pmsg->entry, &pending_msgs);

				return 0;
			}
		}

		if (pmsg)
			free_object(pmsg);
	} else if (msg) {
		int res = nl_send_auto_complete(nl_events, msg);
		nlmsg_free(msg);
		return res;
	}

	if (msg)
		nlmsg_free(msg);

	CALL_BACK(cb, arg, -1);
	return -1;
}

static int
linux_do_request_type(int type, struct nl_msg *msg,
		      kern_addremove_callback cb, void *arg)
{
	struct nlmsghdr *hdr = nlmsg_hdr(msg);

	hdr->nlmsg_type = type;

	return linux_do_request(msg, cb, arg);
}

static void
linux_route_addremove(int type, int flags, struct in6_prefix *dst,
		      struct in6_addr *src, struct in6_addr *gw,
		      mblty_os_intf_t *oif, int prio, uint32_t rtfl,
		      kern_addremove_callback cb, void *arg)
{

	struct nl_addr *dstaddr = NULL, *srcaddr = NULL, *gwaddr = NULL;
	struct rtnl_route *rt = rtnl_route_alloc();
	struct nl_msg *msg;

	dstaddr = _get_addr(&dst->address);
	if (dstaddr == NULL) {
		CALL_BACK(cb, arg, -1);
		return;
	}

	nl_addr_set_prefixlen(dstaddr, dst->prefixlen);

	if (src) {
		srcaddr = _get_addr(src);
		if (srcaddr == NULL) {
			nl_addr_put(dstaddr);
			CALL_BACK(cb, arg, -1);
			return;
		}
	}

	if (gw) {
		gwaddr = _get_addr(gw);
		if (gwaddr == NULL) {
			if (srcaddr)
				nl_addr_put(srcaddr);
			nl_addr_put(dstaddr);
			CALL_BACK(cb, arg, -1);
			return;
		}
	}

	rtnl_route_set_dst(rt, dstaddr);
	nl_addr_put(dstaddr);

	if (srcaddr) {
		rtnl_route_set_src(rt, srcaddr);
		nl_addr_put(srcaddr);
	}

	if (gwaddr) {
		rtnl_route_set_gateway(rt, gwaddr);
		nl_addr_put(gwaddr);
	}

	if (prio >= 0)
		rtnl_route_set_prio(rt, prio);

	if (oif)
		rtnl_route_set_oif(rt, INTF(oif)->ifindex);

	if (rtfl & MBLTY_POLICY_F_NOTIFY)
		rtnl_route_set_flags(rt, RTM_F_NOTIFY);

	msg = rtnl_route_build_request(rt, flags);
	rtnl_route_put(rt);

	linux_do_request_type(type, msg, cb, arg);
}

void
linux_route_add(struct in6_prefix *dst, struct in6_addr *src,
	        struct in6_addr *gw, mblty_os_intf_t * oif, int prio,
	        uint32_t rtfl, kern_addremove_callback cb, void *arg)
{
	linux_route_addremove(RTM_NEWROUTE, NLM_F_CREATE|NLM_F_EXCL,
			      dst, src, gw, oif, prio, rtfl, cb, arg);
}

void
linux_route_delete(struct in6_prefix *dst, struct in6_addr *src,
		   struct in6_addr *gw, mblty_os_intf_t *oif, int prio,
		   kern_addremove_callback cb, void *arg)
{
	linux_route_addremove(RTM_DELROUTE, 0, dst, src, gw, oif,
			      prio, 0, cb, arg);
}

static void
linux_address_action(int add, int ifindex, struct in6_addr *newa,
		     uint32_t flags, linux_intf_addr_cb_t cb, void *arg)
{
	struct nl_addr *nla = _get_addr(newa);
	uint32_t nlflags = 0, rtnlflags = 0;
	struct rtnl_addr *addr;
	struct nl_msg *msg;
	int res;

	addr = rtnl_addr_alloc();

	if (nla == NULL || addr == NULL) {
		if (nla)
			nl_addr_put(nla);
		if (addr)
			rtnl_addr_put(addr);
		CALL_BACK(cb, arg, -1);
		return;
	}

	res = rtnl_addr_set_local(addr, nla);
	nl_addr_put(nla);

	if (res < 0) {
		rtnl_addr_put(addr);
		CALL_BACK(cb, arg, -1);
		return;
	}

	rtnl_addr_set_ifindex(addr, ifindex);

	if (flags & KERN_ADDR_F_MANAGED)
		rtnlflags |= IFA_F_MANAGED;

	if (flags & KERN_ADDR_F_PERMANENT)
		rtnlflags |= IFA_F_PERMANENT;

	if (flags & KERN_ADDR_F_TENTATIVE)
		rtnlflags |= IFA_F_TENTATIVE;

	if (flags & KERN_ADDR_F_DEPRECATED)
		rtnlflags |= IFA_F_DEPRECATED;

	if (flags & KERN_ADDR_F_HOME_ADDRESS)
		rtnlflags |= IFA_F_HOME_ADDRESS;

	rtnl_addr_set_flags(addr, rtnlflags);

	if (flags & KERN_ADDR_F_REPLACE)
		nlflags |= NLM_F_REPLACE;

	if (add)
		msg = rtnl_addr_build_add_request(addr, nlflags);
	else
		msg = rtnl_addr_build_delete_request(addr, nlflags);

	rtnl_addr_put(addr);

	linux_do_request(msg, cb, arg);
}

void
linux_intf_address_add(mblty_os_intf_t *osh, struct in6_addr *address,
			  uint32_t f, linux_intf_addr_cb_t cb, void *arg)
{
	linux_address_action(1, INTF(osh)->ifindex, address, f, cb, arg);
}

void
linux_intf_address_remove(mblty_os_intf_t *osh, struct in6_addr *address,
			  linux_intf_addr_cb_t cb, void *arg)
{
	linux_address_action(0, INTF(osh)->ifindex, address, 0, cb, arg);
}

void
linux_cancel_request(void *param)
{
	struct linux_pending_msg *pmsg, *tmp;

	list_for_each_entry_safe (pmsg, tmp, &pending_msgs, entry) {
		if (pmsg->param == param)
			linux_free_pending_msg(pmsg);
	}
}

void
linux_intf_cancel_addr_op(mblty_os_intf_t *osh, void *param)
{
	linux_cancel_request(param);
}

static void
kern_remove_one_address(struct nl_object *obj, void *arg)
{
	struct rtnl_addr *addr = (struct rtnl_addr *)obj;
	char buf1[INET6_ADDRSTRLEN];
	linux_intf_t *intf = arg;
	struct in6_addr *in6a;
	struct nl_addr *local;
	int prefixlen;

	if (rtnl_addr_get_ifindex(addr) != intf->ifindex)
		return;

	local = rtnl_addr_get_local(addr);
	if (local == NULL)
		return;

	if (nl_addr_get_family(local) != AF_INET6)
		return;

	in6a = (struct in6_addr *)nl_addr_get_binary_addr(local);

	if (!(rtnl_addr_get_flags(addr) & IFA_F_MANAGED)) {
		if (rtnl_addr_get_flags(addr) & IFA_F_PERMANENT)
			if (!IN6_IS_ADDR_LINKLOCAL(in6a))
				return;
	}

	prefixlen = rtnl_addr_get_prefixlen(addr);

	debug_log(4, "Linux, removing %s (%i) from %s\n",
		  format_addr(buf1, in6a), prefixlen, intf->osh.name);

	rtnl_addr_delete(nl_events, addr, 0);

	if (prefixlen < 128) {
		struct in6_prefix pfx;

		in6_addr_copy(&pfx.address, in6a);
		pfx.prefixlen = prefixlen;
		in6_prefix_apply(&pfx);

		linux_route_delete(&pfx, NULL, NULL, &intf->osh, -1,
				   NULL, NULL);
	}
}

static void
generic_foreach_action(void (*cb)(struct nl_object *, void *), void *param,
		       struct nl_cache *(*alloc_cache)(struct nl_handle *))
{
	struct nl_cache *cache = NULL;

	cache = alloc_cache(nl_events);
	if (cache == NULL) {
		debug_log(4, "Failed to allocate requested cache.\n");
	} else {
		nl_cache_mngt_provide(cache);
		nl_cache_foreach(cache, cb, param);
		nl_cache_free(cache);
	}
}

static void
kern_foreach_address_action(void (*cb)(struct nl_object *, void *), void *arg)
{
	generic_foreach_action(cb, arg, rtnl_addr_alloc_cache);
}

static void
kern_foreach_route_action(void (*cb)(struct nl_object *, void *), void *arg)
{
	generic_foreach_action(cb, arg, rtnl_route_alloc_cache);
}

struct kern_get_addr_ctx {
	mblty_os_intf_t *intf;
	void (*cb)(mblty_os_intf_t *, struct in6_prefix *, void *);
	void *arg;
};

static void
kern_give_one_address(struct nl_object *obj, void *arg)
{
	struct rtnl_addr *addr = (struct rtnl_addr *)obj;
	struct kern_get_addr_ctx *ctx = arg;

	if (rtnl_addr_get_ifindex(addr) == INTF(ctx->intf)->ifindex) {
		struct nl_addr *local = rtnl_addr_get_local(addr);
		struct in6_addr *in6a;
		struct in6_prefix pfx;

		if (local == NULL || nl_addr_get_family(local) != AF_INET6)
			return;

		in6a = (struct in6_addr *)nl_addr_get_binary_addr(local);

		in6_addr_copy(&pfx.address, in6a);
		pfx.prefixlen = nl_addr_get_prefixlen(local);

		ctx->cb(ctx->intf, &pfx, ctx->arg);
	}
}

void
mblty_os_intf_get_addresses(mblty_os_intf_t *osh, void (*cb)(mblty_os_intf_t *,
			    struct in6_prefix *pfx, void *arg), void *arg)
{
	struct kern_get_addr_ctx ctx;

	ctx.intf = osh;
	ctx.cb = cb;
	ctx.arg = arg;

	kern_foreach_address_action(kern_give_one_address, &ctx);
}

void
mblty_os_intf_remove_kernel_addresses(mblty_os_intf_t *osh)
{
	kern_foreach_address_action(kern_remove_one_address, INTF(osh));
}

static void
_rtnl_route_delete(struct rtnl_route *rt)
{
	struct nl_msg *msg;

	msg = rtnl_route_build_request(rt, 0);
	if (msg == NULL)
		return;

	linux_do_request_type(RTM_DELROUTE, msg, NULL, NULL);
}

static void
kern_remove_kernel_route(struct nl_object *obj, void *arg)
{
	struct rtnl_route *route = (struct rtnl_route *)obj;
	mblty_os_intf_t *osh = arg;

	if (rtnl_route_get_oif(route) != INTF(osh)->ifindex)
		return;

	if (rtnl_route_get_protocol(route) != RTPROT_KERNEL)
		return;

	_rtnl_route_delete(route);
}

void
mblty_os_intf_remove_kernel_routes(mblty_os_intf_t *intf)
{
	kern_foreach_route_action(kern_remove_kernel_route, intf);
}

static int
kern_check_ip6ip6_availability()
{
	struct rtnl_link *l = rtnl_link_get_by_name(links, "ip6tnl0");
	if (l == NULL)
		return -1;
	rtnl_link_put(l);
	return 0;
}

static mblty_tunnel_factory_t linux_ip6ip6_factory = {
	.allocate = kern_alloc_ip6ip6_tunnel,
};

mblty_tunnel_factory_t *
mblty_obtain_tunnel_factory(mblty_tunnel_type_t type)
{
	switch (type) {
	case MBLTY_TUN_TYPE_IP6IP6:
		if (kern_check_ip6ip6_availability() < 0)
			return NULL;
		return &linux_ip6ip6_factory;
	}

	return NULL;
}

void
mblty_return_tunnel_factory(mblty_tunnel_factory_t *factory)
{
	/* empty */
}

