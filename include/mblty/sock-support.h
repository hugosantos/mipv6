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

#ifndef _SOCK_SUPPORT_H_
#define _SOCK_SUPPORT_H_

#include <sys/types.h>
#include <netinet/in.h>

#include <mblty/base-support.h>

struct mblty_os_intf;

typedef struct sup_socket supsocket_t;
typedef struct sup_socket_ops supsocket_ops_t;
typedef struct sup_socket_rx_params supsocket_rxparm_t;
typedef struct sup_socket_tx_options supsocket_txopt_t;

typedef int (*sup_socket_cb_t)(struct sup_socket *);

struct sup_socket_tx_options {
#define SUPSTXO_SOURCE_ADDR	0x0001
#define SUPSTXO_SOURCE_INTF	0x0002
#define SUPSTXO_SOURCE		(SUPSTXO_SOURCE_ADDR | SUPSTXO_SOURCE_INTF)
#define SUPSTXO_HOP_LIMIT	0x0004
#define SUPSTXO_SOURCE_HOA	0x0008
#define SUPSTXO_DEST_INDIR_RT	0x0010
	uint32_t flags;

	/* SOURCE_ADDR */
	struct in6_addr *src;
	/* SOURCE_INTF */
	struct mblty_os_intf *intf;
	/* HOP_LIMIT */
	int hoplimit;
	/* SOURCE_HOA */
	struct in6_addr *hoa;
	/* DEST_INDIR_RT */
	struct in6_addr *dst;
	int rttype;
};

#define SUPSOCK_EMPTY_TXOPT { \
	.flags = 0, \
	.src = NULL, \
	.intf = NULL, \
	.hoplimit = 0, \
	.hoa = NULL, \
	.dst = NULL, \
	.rttype = 0, \
}

typedef enum {
	SUPSCAP_MULTICAST_LOOP	= 1,
	SUPSCAP_RECV_INFO	= 2,
	SUPSCAP_RTHDR_INFO	= 3,
	SUPSCAP_DSTOPTS_INFO	= 4,
	SUPSCAP_NETWRKHDRS_INFO	= 5,
} supsocket_cap_t;

struct sup_socket_rx_params {
#define SUPSRXP_RECV_INFO	(1 << SUPSCAP_RECV_INFO)
#define SUPSRXP_RTHDR_INFO	(1 << SUPSCAP_RTHDR_INFO)
#define SUPSRXP_DSTOPS_INFO	(1 << SUPSCAP_DSTOPTS_INFO)
#define SUPSRXP_NETWRKHDRS_INFO	(1 << SUPSCAP_NETWRKHDRS_INFO)
	uint32_t flags;

	struct in6_addr *src, *dst;
	struct mblty_os_intf *intf;

	/* RTHDR_INFO */
	struct ip6_rthdr *rthdr;

	/* DSTOPT_INFO */
	struct ip6_dest *dsthdr;

	/* NETWRKHDRS_INFO */
	struct ip6_hdr *ip6hdr;
	size_t ip6hdrlen;

	/* private */
	struct sockaddr_in6 p_src;
};

struct sup_socket_ops {
	int (*send)(supsocket_t *, struct in6_addr *destination,
		    void *buf, int length, supsocket_txopt_t *);
	int (*recv)(supsocket_t *, void *buf, int maxlen,
		    supsocket_rxparm_t *);

	int (*enable)(supsocket_t *, supsocket_cap_t);
	int (*disable)(supsocket_t *, supsocket_cap_t);

	int (*join_mc)(supsocket_t *, struct mblty_os_intf *,
		       struct in6_addr *);
	int (*leave_mc)(supsocket_t *, struct mblty_os_intf *,
			struct in6_addr *);
	int (*join_anycast)(supsocket_t *, struct mblty_os_intf *,
			    struct in6_addr *);
	int (*leave_anycast)(supsocket_t *, struct mblty_os_intf *,
			     struct in6_addr *);
};

struct sup_socket {
	supsocket_ops_t *ops;

	int fd;

#define SUPSOCKET_READ	0x1
#define SUPSOCKET_WRITE	0x2
#define SUPSOCKET_ERROR	0x4
	int mode;

	sup_socket_cb_t cbs[3];
};

supsocket_t *mblty_create_socket(int domain, int type, int protocol,
				 sup_socket_cb_t r_cb, sup_socket_cb_t w_cb,
				 sup_socket_cb_t e_cb);
void mblty_close_socket(supsocket_t *);

int mblty_sk_send(supsocket_t *, struct in6_addr *, void *, int,
		  supsocket_txopt_t *);
int mblty_sk_recv(supsocket_t *, void *, int, supsocket_rxparm_t *);
int mblty_sk_enable(supsocket_t *, supsocket_cap_t);
int mblty_sk_disable(supsocket_t *, supsocket_cap_t);
int mblty_sk_join_mc(supsocket_t *, struct mblty_os_intf *, struct in6_addr *);
int mblty_sk_leave_mc(supsocket_t *, struct mblty_os_intf *, struct in6_addr *);
int mblty_sk_join_anycast(supsocket_t *, struct mblty_os_intf *, struct in6_addr *);
int mblty_sk_leave_anycast(supsocket_t *, struct mblty_os_intf *, struct in6_addr *);

/* register_socket never fails, just asserts if there
 * are no more slots */
supsocket_t *support_register_socket(int fd, sup_socket_cb_t r_cb,
				     sup_socket_cb_t w_cb,
				     sup_socket_cb_t e_cb);
supsocket_t *support_get_socket(int fd);
void support_unregister_socket(int fd);

int os_create_socket(struct sup_socket *, int domain, int type, int proto);
int os_close_socket(struct sup_socket *);

#endif /* _SOCK_SUPPORT_H_ */

