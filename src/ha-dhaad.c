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

#include <errno.h>

#include <mblty/icmpv6.h>
#include <mblty/router.h>
#include <mblty/address.h>
#include <mblty/interface.h>
#include <mblty/base-support.h>
#include <mblty/sock-support.h>

#include <mipv6/ha.h>

#include <netinet/ip6mh.h> /* for DHAAD definitions */

void mipv6_dhaad_init();
void mipv6_dhaad_handle_prefix(struct mipv6_home_prefix *);

extern supsocket_t *mipv6_sock;

static void
join_home_pfx_anycast(struct mipv6_home_prefix *p)
{
	struct in6_addr addr;

	mipv6_build_homepfx_anycast(&addr, &p->pfx);

	if (mblty_sk_join_anycast(mipv6_sock, p->intf->osh, &addr) < 0) {
		debug_log(1, "Failed to join Home-Agents subnet anycast "
			      "address: %s.\n", strerror(errno));
	}
}

static int
is_home_pfx_anycast(struct in6_addr *p)
{
	return p->s6_addr[ 8] == 0xfe && p->s6_addr[ 9] == 0xff &&
	       p->s6_addr[10] == 0xff && p->s6_addr[11] == 0xff &&
	       p->s6_addr[12] == 0xff && p->s6_addr[13] == 0xff &&
	       p->s6_addr[14] == 0xff && p->s6_addr[15] == 0xfe;
}

static void
ha_reply_haad_req(struct mipv6_home_prefix *hp, struct mip6_dhaad_req *req,
		  struct in6_addr *from)
{
	struct {
		struct mip6_dhaad_rep h;
		uint8_t addrbuf[1280 - sizeof(struct mip6_dhaad_rep)];
	} msg;
	struct in6_addr *addrs = (struct in6_addr *)msg.addrbuf, *lastaddr;
	mblty_intf_prefix_t *pfx;

	lastaddr = addrs + (sizeof(msg.addrbuf) / sizeof(struct in6_addr));

	memset(&msg.h, 0, sizeof(struct mip6_dhaad_rep));

	msg.h.mip6_dhrep_type = MIP6_HA_DISCOVERY_REPLY;
	msg.h.mip6_dhrep_id = req->mip6_dhreq_id;

	in6_addr_copy(addrs, &hp->ha_addr);
	addrs++;

	pfx = mblty_retrieve_intf_prefix(hp->intf, &hp->pfx);
	if (pfx) {
		mblty_router_prefix_t *netpfx;
		mblty_router_name_t *name;
		mblty_router_t *rtr;

		list_for_each_entry (netpfx, &pfx->instances, instance) {
			rtr = mblty_pfx_router(netpfx);

			if (!(rtr->flags & MBLTY_ROUTER_HOME_AGENT))
				continue;

			list_for_each_entry (name, &rtr->names, name_entry) {
				if (addrs >= lastaddr)
					break;
				in6_addr_copy(addrs, &name->address);
				addrs++;
			}
		}
	}

	icmpv6_send(from, &hp->ha_addr, NULL, -1, &msg.h.mip6_dhrep_hdr,
		    sizeof(msg));
}

static void
ha_haad_req_handler(struct icmp6_hdr *hdr, int length, supsocket_rxparm_t *rxp)
{
	struct mip6_dhaad_req *req = (struct mip6_dhaad_req *)hdr;
	struct mipv6_home_prefix *hp;

	if (!is_home_pfx_anycast(rxp->dst))
		return;

	hp = mipv6_matching_home_prefix(rxp->dst);
	if (hp == NULL)
		return;

	ha_reply_haad_req(hp, req, rxp->src);
}

void
mipv6_dhaad_handle_prefix(struct mipv6_home_prefix *p)
{
	join_home_pfx_anycast(p);
}

static void
mipv6_dhaad_shutdown()
{
	icmpv6_register_handler(MIP6_HA_DISCOVERY_REQUEST,
				ha_haad_req_handler, 0);

}

static struct mblty_shutdown_entry dhaad_shutdown = {
	.handler = mipv6_dhaad_shutdown,
};

void
mipv6_dhaad_init()
{
	icmpv6_register_handler(MIP6_HA_DISCOVERY_REQUEST,
				ha_haad_req_handler, 1);

	mblty_register_shutdown(&dhaad_shutdown);
}

