/*
 * lib/route/sch/prio.c		PRIO Qdisc/Class
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup qdisc
 * @defgroup prio (Fast) Prio
 * @brief
 *
 * @par 1) Typical PRIO configuration
 * @code
 * // Specify the maximal number of bands to be used for this PRIO qdisc.
 * rtnl_qdisc_prio_set_bands(qdisc, QDISC_PRIO_DEFAULT_BANDS);
 *
 * // Provide a map assigning each priority to a band number.
 * uint8_t map[] = QDISC_PRIO_DEFAULT_PRIOMAP;
 * rtnl_qdisc_prio_set_priomap(qdisc, map, sizeof(map));
 * @endcode
 * @{
 */

#include <netlink-local.h>
#include <netlink-tc.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/qdisc-modules.h>
#include <netlink/route/sch/prio.h>

/** @cond SKIP */
#define SCH_PRIO_ATTR_BANDS	1
#define SCH_PRIO_ATTR_PRIOMAP	2
/** @endcond */

static inline struct rtnl_prio *prio_qdisc(struct rtnl_qdisc *qdisc)
{
	return (struct rtnl_prio *) qdisc->q_subdata;
}

static inline struct rtnl_prio *prio_alloc(struct rtnl_qdisc *qdisc)
{
	if (!qdisc->q_subdata)
		qdisc->q_subdata = calloc(1, sizeof(struct rtnl_prio));

	return prio_qdisc(qdisc);
}

static int prio_msg_parser(struct rtnl_qdisc *qdisc)
{
	struct rtnl_prio *prio;
	struct tc_prio_qopt *opt;

	if (qdisc->q_opts->d_size < sizeof(*opt))
		return nl_error(EINVAL, "prio specific option size mismatch");

	prio = prio_alloc(qdisc);
	if (!prio)
		return nl_errno(ENOMEM);

	opt = (struct tc_prio_qopt *) qdisc->q_opts->d_data;
	prio->qp_bands = opt->bands;
	memcpy(prio->qp_priomap, opt->priomap, sizeof(prio->qp_priomap));
	prio->qp_mask = (SCH_PRIO_ATTR_BANDS | SCH_PRIO_ATTR_PRIOMAP);
	
	return 0;
}

static void prio_free_data(struct rtnl_qdisc *qdisc)
{
	free(qdisc->q_subdata);
}

static int prio_dump_brief(struct rtnl_qdisc *qdisc,
			   struct nl_dump_params *p, int line)
{
	struct rtnl_prio *prio = prio_qdisc(qdisc);

	if (prio)
		dp_dump(p, " bands %u", prio->qp_bands);

	return line;
}

static int prio_dump_full(struct rtnl_qdisc *qdisc,
			  struct nl_dump_params *p, int line)
{
	struct rtnl_prio *prio = prio_qdisc(qdisc);
	int i, hp;

	if (!prio)
		goto ignore;

	dp_dump(p, "priomap [");
	
	for (i = 0; i <= TC_PRIO_MAX; i++)
		dp_dump(p, "%u%s", prio->qp_priomap[i],
			i < TC_PRIO_MAX ? " " : "");

	dp_dump(p, "]\n");
	dp_new_line(p, line++);

	hp = (((TC_PRIO_MAX/2) + 1) & ~1);

	for (i = 0; i < hp; i++) {
		char a[32];
		dp_dump(p, "    %18s => %u",
			rtnl_prio2str(i, a, sizeof(a)),
			prio->qp_priomap[i]);
		if (hp+i <= TC_PRIO_MAX) {
			dp_dump(p, " %18s => %u",
				rtnl_prio2str(hp+i, a, sizeof(a)),
				prio->qp_priomap[hp+i]);
			if (i < (hp - 1)) {
				dp_dump(p, "\n");
				dp_new_line(p, line++);
			}
		}
	}

ignore:
	return line;
}

static struct nl_msg *prio_get_opts(struct rtnl_qdisc *qdisc)
{
	struct rtnl_prio *prio;
	struct tc_prio_qopt opts;
	struct nl_msg *msg;

	prio = prio_qdisc(qdisc);
	if (!prio ||
	    !(prio->qp_mask & SCH_PRIO_ATTR_PRIOMAP))
		goto errout;

	opts.bands = prio->qp_bands;
	memcpy(opts.priomap, prio->qp_priomap, sizeof(opts.priomap));

	msg = nlmsg_build_no_hdr();
	if (!msg)
		goto errout;

	if (nlmsg_append(msg, &opts, sizeof(opts), 0) < 0) {
		nlmsg_free(msg);
		goto errout;
	}

	return msg;
errout:
	return NULL;
}

/**
 * @name Attribute Modification
 * @{
 */

/**
 * Set number of bands of PRIO qdisc.
 * @arg qdisc		PRIO qdisc to be modified.
 * @arg bands		New number of bands.
 * @return 0 on success or a negative error code.
 */
int rtnl_qdisc_prio_set_bands(struct rtnl_qdisc *qdisc, int bands)
{
	struct rtnl_prio *prio;
	
	prio = prio_alloc(qdisc);
	if (!prio)
		return nl_errno(ENOMEM);

	prio->qp_bands = bands;
	prio->qp_mask |= SCH_PRIO_ATTR_BANDS;

	return 0;
}

/**
 * Get number of bands of PRIO qdisc.
 * @arg qdisc		PRIO qdisc.
 * @return Number of bands or a negative error code.
 */
int rtnl_qdisc_prio_get_bands(struct rtnl_qdisc *qdisc)
{
	struct rtnl_prio *prio;

	prio = prio_qdisc(qdisc);
	if (prio && prio->qp_mask & SCH_PRIO_ATTR_BANDS)
		return prio->qp_bands;
	else
		return nl_errno(ENOMEM);
}

/**
 * Set priomap of the PRIO qdisc.
 * @arg qdisc		PRIO qdisc to be modified.
 * @arg priomap		New priority mapping.
 * @arg len		Length of priomap (# of elements).
 * @return 0 on success or a negative error code.
 */
int rtnl_qdisc_prio_set_priomap(struct rtnl_qdisc *qdisc, uint8_t priomap[],
				int len)
{
	struct rtnl_prio *prio;
	int i;

	prio = prio_alloc(qdisc);
	if (!prio)
		return nl_errno(ENOMEM);

	if (!(prio->qp_mask & SCH_PRIO_ATTR_BANDS))
		return nl_error(EINVAL, "Set number of bands first");

	if ((len / sizeof(uint8_t)) > (TC_PRIO_MAX+1))
		return nl_error(ERANGE, "priomap length out of bounds");

	for (i = 0; i <= TC_PRIO_MAX; i++) {
		if (priomap[i] > prio->qp_bands)
			return nl_error(ERANGE, "priomap element %d " \
			    "out of bounds, increase bands number");
	}

	memcpy(prio->qp_priomap, priomap, len);
	prio->qp_mask |= SCH_PRIO_ATTR_PRIOMAP;

	return 0;
}

/**
 * Get priomap of a PRIO qdisc.
 * @arg qdisc		PRIO qdisc.
 * @return Priority mapping as array of size TC_PRIO_MAX+1
 *         or NULL if an error occured.
 */
uint8_t *rtnl_qdisc_prio_get_priomap(struct rtnl_qdisc *qdisc)
{
	struct rtnl_prio *prio;

	prio = prio_qdisc(qdisc);
	if (prio && prio->qp_mask & SCH_PRIO_ATTR_PRIOMAP)
		return prio->qp_priomap;
	else {
		nl_errno(ENOENT);
		return NULL;
	}
}

/** @} */

/**
 * @name Priority Band Translations
 * @{
 */

static struct trans_tbl prios[] = {
	__ADD(TC_PRIO_BESTEFFORT,besteffort)
	__ADD(TC_PRIO_FILLER,filler)
	__ADD(TC_PRIO_BULK,bulk)
	__ADD(TC_PRIO_INTERACTIVE_BULK,interactive_bulk)
	__ADD(TC_PRIO_INTERACTIVE,interactive)
	__ADD(TC_PRIO_CONTROL,control)
};

/**
 * Convert priority to character string.
 * @arg prio		Priority.
 * @arg buf		Destination buffer
 * @arg size		Size of destination buffer.
 *
 * Converts a priority to a character string and stores the result in
 * the specified destination buffer.
 *
 * @return Name of priority as character string.
 */
char * rtnl_prio2str(int prio, char *buf, size_t size)
{
	return __type2str(prio, buf, size, prios, ARRAY_SIZE(prios));
}

/**
 * Convert character string to priority.
 * @arg name		Name of priority.
 *
 * Converts the provided character string specifying a priority
 * to the corresponding numeric value.
 *
 * @return Numeric priority or a negative value if no match was found.
 */
int rtnl_str2prio(const char *name)
{
	return __str2type(name, prios, ARRAY_SIZE(prios));
}

/** @} */

static struct rtnl_qdisc_ops prio_ops = {
	.qo_kind		= "prio",
	.qo_msg_parser		= prio_msg_parser,
	.qo_free_data		= prio_free_data,
	.qo_dump[NL_DUMP_BRIEF]	= prio_dump_brief,
	.qo_dump[NL_DUMP_FULL]	= prio_dump_full,
	.qo_get_opts		= prio_get_opts,
};

static struct rtnl_qdisc_ops pfifo_fast_ops = {
	.qo_kind		= "pfifo_fast",
	.qo_msg_parser		= prio_msg_parser,
	.qo_free_data		= prio_free_data,
	.qo_dump[NL_DUMP_BRIEF]	= prio_dump_brief,
	.qo_dump[NL_DUMP_FULL]	= prio_dump_full,
	.qo_get_opts		= prio_get_opts,
};

static void __init prio_init(void)
{
	rtnl_qdisc_register(&prio_ops);
	rtnl_qdisc_register(&pfifo_fast_ops);
}

static void __exit prio_exit(void)
{
	rtnl_qdisc_unregister(&prio_ops);
	rtnl_qdisc_unregister(&pfifo_fast_ops);
}

/** @} */
