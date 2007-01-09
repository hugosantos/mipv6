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

#include <mblty/icmpv6.h>
#include <mblty/base-support.h>

#include <mipv6/mipv6.h>
#include <mipv6/mn-hoa.h>

#include <netinet/ip6mh.h> /* for DHAAD definitions */

void mipv6_mn_dhaad_init();

struct tentative_address {
	struct in6_prefix home_pfx;
	struct in6_addr hoa;

	uint16_t identifier;

	suptimer_t rtx;
	struct list_entry entry;
};

static LIST_DEF(tentative_list);
static uint16_t tentative_id_seq;

static void
dhaad_request(struct tentative_address *addr)
{
	struct mip6_dhaad_req req;
	struct in6_addr to;

	addr->identifier = tentative_id_seq++;

	mipv6_build_homepfx_anycast(&to, &addr->home_pfx);

	memset(&req, 0, sizeof(struct mip6_dhaad_req));
	req.mip6_dhreq_type = MIP6_HA_DISCOVERY_REQUEST;
	req.mip6_dhreq_id = htons(addr->identifier);

	icmpv6_send(&to, NULL, NULL, -1, &req.mip6_dhreq_hdr, sizeof(req));
}

static void
do_dhaad_request(suptimer_t *tmr, void *arg)
{
	struct tentative_address *addr = arg;

	dhaad_request(addr);

	timer_add(tmr, 60000);
}

void
mipv6_mn_tentative_hoa(struct in6_prefix *homepfx, struct in6_addr *hoa)
{
	struct tentative_address *tent;

	tent = allocate_object(struct tentative_address);
	debug_assert(tent, "Failed to instantiate tentative address");

	in6_prefix_copy_applied(&tent->home_pfx, homepfx);
	in6_addr_copy(&tent->hoa, hoa);
	tent->identifier = 0;
	timer_init(&tent->rtx, "tentative address rtx");
	tent->rtx.cb = do_dhaad_request;
	tent->rtx.cb_arg = tent;

	list_add(&tent->entry, &tentative_list);

	/* start asking right away */
	timer_add(&tent->rtx, 500);
}

static struct tentative_address *
tentative_get_by_id(uint16_t id)
{
	struct tentative_address *iter;

	list_for_each_entry (iter, &tentative_list, entry) {
		if (iter->identifier == id)
			return iter;
	}

	return NULL;
}

static void
tentative_got_ha(struct tentative_address *tent, struct in6_addr *ha)
{
	timer_remove(&tent->rtx);
	list_del(&tent->entry);

	mipv6_mn_allocate_hoa(ha, &tent->home_pfx, &tent->hoa, 0);

	free_object(tent);
}

static void
dhaad_handle_reply(struct icmp6_hdr *hdr, int length, supsocket_rxparm_t *rxp)
{
	struct mip6_dhaad_rep *rep = (struct mip6_dhaad_rep *)hdr;
	int num_addr = (length - sizeof(struct icmp6_hdr)) / 16;
	struct tentative_address *tent;

	if (num_addr <= 0)
		return;

	tent = tentative_get_by_id(ntohs(rep->mip6_dhrep_id));
	if (tent == NULL)
		return;

	tentative_got_ha(tent, (struct in6_addr *)(hdr + 1));
}

static void
mipv6_mn_dhaad_shutdown()
{
	icmpv6_register_handler(MIP6_HA_DISCOVERY_REPLY,
				dhaad_handle_reply, 0);
}

static struct mblty_shutdown_entry mn_dhaad_shutdown = {
	.handler = mipv6_mn_dhaad_shutdown,
};

void
mipv6_mn_dhaad_init()
{
	tentative_id_seq = mipv6_generate_rand_uint16();

	icmpv6_register_handler(MIP6_HA_DISCOVERY_REPLY,
				dhaad_handle_reply, 1);

	mblty_register_shutdown(&mn_dhaad_shutdown);
}

