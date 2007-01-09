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

#include <stdio.h>
#include <mblty/timers.h>
#include <mblty/interface.h>
#include <mipv6/os.h>
#include <mipv6/mn-hoa.h>
#include <mipv6/console.h>

const char *mipv6_console_path = "/var/run/mipv6-mn-console";

extern int rc_show_timers(struct mipv6_rconsole_client *);
extern int rc_show_routers(struct mipv6_rconsole_client *);
extern int rc_show_prefixes(struct mipv6_rconsole_client *);
extern int rc_show_addresses(struct mipv6_rconsole_client *);
extern int rc_show_interfaces(struct mipv6_rconsole_client *);
extern int rc_show_binding_cache(struct mipv6_rconsole_client *);

static int
print_hoa_info(struct mipv6_mn_hoa *hoa, void *arg)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN],
	     buf3[INET6_ADDRSTRLEN], d[64];
	struct mipv6_rconsole_client *cli = arg;
	struct mblty_network_address *coa;
	struct mipv6_mn_individual *ind;
	struct mipv6_mn_ha_router *ha_r;
	struct mipv6_mn_ha *ha;

	char last_bu[32] = "Never";
	char next_bu[32] = "Won't send";

	coa = mipv6_mn_hoa_active_coa(hoa);
	ha_r = mipv6_get_hoa_ha_router(hoa);
	ha = mipv6_get_hoa_ha(hoa);

	con_printf(cli, "HoA %s\n", format_addr(buf1, mblty_get_addr(&hoa->a)));
	con_printf(cli, "  HA: %s\n", ha ?
		   format_addr(buf2, &ha->address) : NULL);
	con_printf(cli, "  HA Tunnel: %s\n",
		   mblty_os_intf_desc(ha_r->tunnel->osh, 1, d, sizeof(d)));
	con_printf(cli, "  Primary CoA: %s (%s)\n",
		   coa ? format_addr(buf3, mblty_get_addr(coa)) : NULL,
		   coa ? mblty_addr_intf(coa)->osh->name : "none");

	if (hoa->binding_ctx.ts_bu_last_sent) {
		snprintf(last_bu, sizeof(last_bu), "%u secs ago",
			 (uint32_t)((support_get_sys_timestamp() -
				hoa->binding_ctx.ts_bu_last_sent) / 1000));
	}

	if (hoa->binding_ctx.flags & MIPV6_BCTX_SCHEDULED_BU) {
		uint64_t secs;

		secs = timer_remaining_time(&hoa->binding_ctx.trans);
		snprintf(next_bu, sizeof(next_bu), "Will send in %u secs",
			 (uint32_t)(secs / 1000));
	}

	con_printf(cli, "  Last BU sent: %s (%s)\n", last_bu, next_bu);

	if (list_empty(&hoa->individual_ctxs))
		return 0; /* continue iteration */

	con_printf(cli, "  Individuals:\n");

	list_for_each_entry (ind, &hoa->individual_ctxs, entry) {
		con_printf(cli, "   To %s (%sauthenticated%s)\n",
			   format_addr(buf1, &ind->remote),
			   mipv6_auth_data_is_valid(&ind->binding_ctx) ?
				"" : "not ",
			   ind->flags & MIPV6_MN_IND_AUTHERR ?
				", auth err" : "");
		if (!mipv6_auth_data_is_valid(&ind->binding_ctx))
			con_printf(cli, "    Last required %u secs ago.\n",
				   (uint32_t)(support_get_sys_timestamp()
					- ind->last_required) / 1000);
#if 0
		con_printf(cli, "   Last update %u secs ago, value is %u.\n",
			   (uint32_t)(support_get_sys_timestamp()
				      - ind->st_last_update),
			   ind->st_last_value);
#endif
	}

	return 0; /* continue iteration */
}

static void
dump_stat_tx(struct mipv6_rconsole_client *cli, const char *desc,
	     struct mipv6_msg_stat_tx *tx)
{
	con_printf(cli, "  %17s %10u %10u\n", desc, tx->tx, tx->failed);
}

static void
dump_stat_rx(struct mipv6_rconsole_client *cli, const char *desc,
	     struct mipv6_msg_stat_rx *rx)
{
	con_printf(cli, "  %17s %10u %10u\n", desc, rx->rx, rx->dscrd);
}

static int
print_hoa_stats(struct mipv6_mn_hoa *hoa, void *arg)
{
	struct mipv6_msg_stats *stats = &hoa->binding_ctx.stats;
	struct mipv6_rconsole_client *cli = arg;
	char buf1[INET6_ADDRSTRLEN];

	con_printf(cli, "HoA %s\n", format_addr(buf1, mblty_get_addr(&hoa->a)));

	con_printf(cli, "  %17s %10s %10s\n", " ", "Sent", "Failed");
	con_printf(cli, "  ----------------------------------------\n");

	dump_stat_tx(cli, "Binding Update", &stats->bu);
	dump_stat_tx(cli, "Home Test Init", &stats->hoti);
	dump_stat_tx(cli, "Care-of Test Init", &stats->coti);

	con_printf(cli, "\n");
	con_printf(cli, "  %17s %10s %10s\n", " ", "Received", "Discarded");
	con_printf(cli, "  ----------------------------------------\n");

	dump_stat_rx(cli, "Binding Ack", &stats->back);
	dump_stat_rx(cli, "Binding Ref Req", &stats->brr);
	dump_stat_rx(cli, "Binding Error", &stats->berr);
	dump_stat_rx(cli, "Home Test", &stats->hot);
	dump_stat_rx(cli, "Care-of Test", &stats->cot);

	return 0; /* continue iteration */
}

static int
show_info(struct mipv6_rconsole_client *cli)
{
	mipv6_mn_foreach_hoa(print_hoa_info, cli);
	return 0;
}

static int
show_stats(struct mipv6_rconsole_client *cli)
{
	mipv6_mn_foreach_hoa(print_hoa_stats, cli);
	return 0;
}

static int
print_bctx(struct mipv6_binding_context *ctx, void *arg)
{
	char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN],
	     buf3[INET6_ADDRSTRLEN];
	struct mipv6_rconsole_client *cli = arg;
	uint32_t flags = ctx->flags;

	con_printf(cli, "HoA %s to %s%s\n  via CoA %s lifetime: %us seq: %u\n",
		   format_addr(buf1, mblty_get_addr(ctx->hoa)),
		   format_addr(buf3, ctx->destination),
		   mipv6_auth_data_is_valid(ctx) ? " [A]" : "",
		   ctx->coa ? format_addr(buf2, &ctx->coa->address) : NULL,
		   (uint32_t)ctx->lifetime, (uint32_t)ctx->sequence);

	if (flags == 0)
		return 0;

	con_printf(cli, "  flags:");

#define DO_FLAG(desc,flag) if (flags & flag) { con_printf(cli, " %s", desc); flags &= ~(flag); }

	DO_FLAG("scheduled-bu", MIPV6_BCTX_SCHEDULED_BU);
	DO_FLAG("want-ack", MIPV6_BCTX_WANT_ACK);
	DO_FLAG("home-reg", MIPV6_BCTX_HOMEREG);
	DO_FLAG("waiting-ack", MIPV6_BCTX_WAITING_ACK);
	DO_FLAG("active-reg", MIPV6_BCTX_ACTIVE_REG);
	DO_FLAG("no-send-bu", MIPV6_BCTX_NO_SEND_BU);
	DO_FLAG("use-alt-coa", MIPV6_BCTX_USE_ALT_COA);
	DO_FLAG("failed", MIPV6_BCTX_FAILED);
	DO_FLAG("has-nai", MIPV6_BCTX_HAS_NAI);
	DO_FLAG("expired", MIPV6_BCTX_EXPIRED);
	DO_FLAG("pending-new-reg", MIPV6_BCTX_PENDING_NEW_REG);

#undef DO_FLAG

	if (flags)
		con_printf(cli, " others(0x%x)\n", flags);
	else
		con_printf(cli, "\n");

	return 0;
}

static int
show_bul(struct mipv6_rconsole_client *cli)
{
	mipv6_foreach_binding_context(print_bctx, cli);
	return 0;
}

struct mipv6_console_cmd mipv6_console_cmds[] = {
	{ "^exit$", mipv6_rconsole_exit },
	{ "^show[ \t]+info$", show_info },
	{ "^show[ \t]+stats$", show_stats },
	{ "^show[ \t]+timers$", rc_show_timers },
	{ "^show[ \t]+routers$", rc_show_routers },
	{ "^show[ \t]+prefixes$", rc_show_prefixes },
	{ "^show[ \t]+addresses$", rc_show_addresses },
	{ "^show[ \t]+interfaces$", rc_show_interfaces },
	{ "^show[ \t]+binding cache$", rc_show_binding_cache },
	{ "^show[ \t]+binding contexts$", show_bul },
	{ NULL, NULL }
};

