/*
 * lib/route/sch/dsmark.c	DSMARK
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
 * @ingroup class
 * @defgroup dsmark Differentiated Services Marker (DSMARK)
 * @{
 */

#include <netlink-local.h>
#include <netlink-tc.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/qdisc-modules.h>
#include <netlink/route/class.h>
#include <netlink/route/class-modules.h>
#include <netlink/route/sch/dsmark.h>

/** @cond SKIP */
#define SCH_DSMARK_ATTR_INDICES		0x1
#define SCH_DSMARK_ATTR_DEFAULT_INDEX	0x2
#define SCH_DSMARK_ATTR_SET_TC_INDEX	0x4

#define SCH_DSMARK_ATTR_MASK		0x1
#define SCH_DSMARK_ATTR_VALUE		0x2
/** @endcond */

static inline struct rtnl_dsmark_qdisc *dsmark_qdisc(struct rtnl_qdisc *qdisc)
{
	return (struct rtnl_dsmark_qdisc *) qdisc->q_subdata;
}

static inline struct rtnl_dsmark_qdisc *
dsmark_qdisc_alloc(struct rtnl_qdisc *qdisc)
{
	if (!qdisc->q_subdata)
		qdisc->q_subdata = calloc(1, sizeof(struct rtnl_dsmark_qdisc));

	return dsmark_qdisc(qdisc);
}

static struct nla_policy dsmark_policy[TCA_DSMARK_MAX+1] = {
	[TCA_DSMARK_INDICES]		= { .type = NLA_U16 },
	[TCA_DSMARK_DEFAULT_INDEX]	= { .type = NLA_U16 },
	[TCA_DSMARK_SET_TC_INDEX]	= { .type = NLA_FLAG },
	[TCA_DSMARK_VALUE]		= { .type = NLA_U8 },
	[TCA_DSMARK_MASK]		= { .type = NLA_U8 },
};

static int dsmark_qdisc_msg_parser(struct rtnl_qdisc *qdisc)
{
	int err;
	struct nlattr *tb[TCA_DSMARK_MAX + 1];
	struct rtnl_dsmark_qdisc *dsmark;

	err = tca_parse(tb, TCA_DSMARK_MAX, (struct rtnl_tca *) qdisc,
			dsmark_policy);
	if (err < 0)
		return err;

	dsmark = dsmark_qdisc_alloc(qdisc);
	if (!dsmark)
		return nl_errno(ENOMEM);

	if (tb[TCA_DSMARK_INDICES]) {
		dsmark->qdm_indices = nla_get_u16(tb[TCA_DSMARK_INDICES]);
		dsmark->qdm_mask |= SCH_DSMARK_ATTR_INDICES;
	}

	if (tb[TCA_DSMARK_DEFAULT_INDEX]) {
		dsmark->qdm_default_index =
				nla_get_u16(tb[TCA_DSMARK_DEFAULT_INDEX]);
		dsmark->qdm_mask |= SCH_DSMARK_ATTR_DEFAULT_INDEX;
	}

	if (tb[TCA_DSMARK_SET_TC_INDEX]) {
		dsmark->qdm_set_tc_index = 1;
		dsmark->qdm_mask |= SCH_DSMARK_ATTR_SET_TC_INDEX;
	}

	return 0;
}

static inline struct rtnl_dsmark_class *dsmark_class(struct rtnl_class *class)
{
	return (struct rtnl_dsmark_class *) class->c_subdata;
}

static inline struct rtnl_dsmark_class *
dsmark_class_alloc(struct rtnl_class *class)
{
	if (!class->c_subdata)
		class->c_subdata = calloc(1, sizeof(struct rtnl_dsmark_class));

	return dsmark_class(class);
}

static int dsmark_class_msg_parser(struct rtnl_class *class)
{
	int err;
	struct nlattr *tb[TCA_DSMARK_MAX + 1];
	struct rtnl_dsmark_class *dsmark;

	err = tca_parse(tb, TCA_DSMARK_MAX, (struct rtnl_tca *) class,
			dsmark_policy);
	if (err < 0)
		return err;

	dsmark = dsmark_class_alloc(class);
	if (!dsmark)
		return nl_errno(ENOMEM);

	if (tb[TCA_DSMARK_MASK]) {
		dsmark->cdm_bmask = nla_get_u8(tb[TCA_DSMARK_MASK]);
		dsmark->cdm_mask |= SCH_DSMARK_ATTR_MASK;
	}

	if (tb[TCA_DSMARK_VALUE]) {
		dsmark->cdm_value = nla_get_u8(tb[TCA_DSMARK_VALUE]);
		dsmark->cdm_mask |= SCH_DSMARK_ATTR_VALUE;
	}

	return 0;
}

static int dsmark_qdisc_dump_brief(struct rtnl_qdisc *qdisc,
				   struct nl_dump_params *p, int line)
{
	struct rtnl_dsmark_qdisc *dsmark = dsmark_qdisc(qdisc);

	if (dsmark && (dsmark->qdm_mask & SCH_DSMARK_ATTR_INDICES))
		dp_dump(p, " indices 0x%04x", dsmark->qdm_indices);

	return line;
}

static int dsmark_qdisc_dump_full(struct rtnl_qdisc *qdisc,
				  struct nl_dump_params *p, int line)
{
	struct rtnl_dsmark_qdisc *dsmark = dsmark_qdisc(qdisc);

	if (!dsmark)
		goto ignore;

	if (dsmark->qdm_mask & SCH_DSMARK_ATTR_DEFAULT_INDEX)
		dp_dump(p, " default index 0x%04x", dsmark->qdm_default_index);

	if (dsmark->qdm_mask & SCH_DSMARK_ATTR_SET_TC_INDEX)
		dp_dump(p, " set-tc-index");

ignore:
	return line;
}

static int dsmark_class_dump_brief(struct rtnl_class *class,
				   struct nl_dump_params *p, int line)
{
	struct rtnl_dsmark_class *dsmark = dsmark_class(class);

	if (!dsmark)
		goto ignore;

	if (dsmark->cdm_mask & SCH_DSMARK_ATTR_VALUE)
		dp_dump(p, " value 0x%02x", dsmark->cdm_value);

	if (dsmark->cdm_mask & SCH_DSMARK_ATTR_MASK)
		dp_dump(p, " mask 0x%02x", dsmark->cdm_bmask);

ignore:
	return line;
}

static struct nl_msg *dsmark_qdisc_get_opts(struct rtnl_qdisc *qdisc)
{
	struct rtnl_dsmark_qdisc *dsmark = dsmark_qdisc(qdisc);
	struct nl_msg *msg;

	if (!dsmark)
		return NULL;

	msg = nlmsg_build_no_hdr();
	if (!msg)
		goto nla_put_failure;

	if (dsmark->qdm_mask & SCH_DSMARK_ATTR_INDICES)
		NLA_PUT_U16(msg, TCA_DSMARK_INDICES, dsmark->qdm_indices);

	if (dsmark->qdm_mask & SCH_DSMARK_ATTR_DEFAULT_INDEX)
		NLA_PUT_U16(msg, TCA_DSMARK_DEFAULT_INDEX,
			    dsmark->qdm_default_index);

	if (dsmark->qdm_mask & SCH_DSMARK_ATTR_SET_TC_INDEX)
		NLA_PUT_FLAG(msg, TCA_DSMARK_SET_TC_INDEX);

	return msg;

nla_put_failure:
	nlmsg_free(msg);
	return NULL;
}

static struct nl_msg *dsmark_class_get_opts(struct rtnl_class *class)
{
	struct rtnl_dsmark_class *dsmark = dsmark_class(class);
	struct nl_msg *msg;

	if (!dsmark)
		return NULL;

	msg = nlmsg_build_no_hdr();
	if (!msg)
		goto nla_put_failure;

	if (dsmark->cdm_mask & SCH_DSMARK_ATTR_MASK)
		NLA_PUT_U8(msg, TCA_DSMARK_MASK, dsmark->cdm_bmask);

	if (dsmark->cdm_mask & SCH_DSMARK_ATTR_VALUE)
		NLA_PUT_U8(msg, TCA_DSMARK_VALUE, dsmark->cdm_value);

	return msg;

nla_put_failure:
	nlmsg_free(msg);
	return NULL;
}

/**
 * @name Class Attribute Access
 * @{
 */

/**
 * Set bitmask of DSMARK class.
 * @arg class		DSMARK class to be modified.
 * @arg mask		New bitmask.
 * @return 0 on success or a negative error code.
 */
int rtnl_class_dsmark_set_bitmask(struct rtnl_class *class, uint8_t mask)
{
	struct rtnl_dsmark_class *dsmark;
	
	dsmark = dsmark_class(class);
	if (!dsmark)
		return nl_errno(ENOMEM);

	dsmark->cdm_bmask = mask;
	dsmark->cdm_mask |= SCH_DSMARK_ATTR_MASK;

	return 0;
}

/**
 * Get bitmask of DSMARK class.
 * @arg class		DSMARK class.
 * @return Bitmask or a negative error code.
 */
int rtnl_class_dsmark_get_bitmask(struct rtnl_class *class)
{
	struct rtnl_dsmark_class *dsmark;

	dsmark = dsmark_class(class);
	if (dsmark && dsmark->cdm_mask & SCH_DSMARK_ATTR_MASK)
		return dsmark->cdm_bmask;
	else
		return nl_errno(ENOENT);
}

/**
 * Set value of DSMARK class.
 * @arg class		DSMARK class to be modified.
 * @arg value		New value.
 * @return 0 on success or a negative errror code.
 */
int rtnl_class_dsmark_set_value(struct rtnl_class *class, uint8_t value)
{
	struct rtnl_dsmark_class *dsmark;

	dsmark = dsmark_class(class);
	if (!dsmark)
		return nl_errno(ENOMEM);

	dsmark->cdm_value = value;
	dsmark->cdm_mask |= SCH_DSMARK_ATTR_VALUE;

	return 0;
}

/**
 * Get value of DSMARK class.
 * @arg class		DSMARK class.
 * @return Value or a negative error code.
 */
int rtnl_class_dsmark_get_value(struct rtnl_class *class)
{
	struct rtnl_dsmark_class *dsmark;

	dsmark = dsmark_class(class);
	if (dsmark && dsmark->cdm_mask & SCH_DSMARK_ATTR_VALUE)
		return dsmark->cdm_value;
	else
		return nl_errno(ENOENT);
}

/** @} */

/**
 * @name Qdisc Attribute Access
 * @{
 */

/**
 * Set indices of DSMARK qdisc.
 * @arg qdisc		DSMARK qdisc to be modified.
 * @arg indices		New indices.
 */
int rtnl_qdisc_dsmark_set_indices(struct rtnl_qdisc *qdisc, uint16_t indices)
{
	struct rtnl_dsmark_qdisc *dsmark;

	dsmark = dsmark_qdisc(qdisc);
	if (!dsmark)
		return nl_errno(ENOMEM);

	dsmark->qdm_indices = indices;
	dsmark->qdm_mask |= SCH_DSMARK_ATTR_INDICES;

	return 0;
}

/**
 * Get indices of DSMARK qdisc.
 * @arg qdisc		DSMARK qdisc.
 * @return Indices or a negative error code.
 */
int rtnl_qdisc_dsmark_get_indices(struct rtnl_qdisc *qdisc)
{
	struct rtnl_dsmark_qdisc *dsmark;

	dsmark = dsmark_qdisc(qdisc);
	if (dsmark && dsmark->qdm_mask & SCH_DSMARK_ATTR_INDICES)
		return dsmark->qdm_indices;
	else
		return nl_errno(ENOENT);
}

/**
 * Set default index of DSMARK qdisc.
 * @arg qdisc		DSMARK qdisc to be modified.
 * @arg default_index	New default index.
 * @return 0 on success or a negative error code.
 */
int rtnl_qdisc_dsmark_set_default_index(struct rtnl_qdisc *qdisc,
					uint16_t default_index)
{
	struct rtnl_dsmark_qdisc *dsmark;

	dsmark = dsmark_qdisc(qdisc);
	if (!dsmark)
		return nl_errno(ENOMEM);

	dsmark->qdm_default_index = default_index;
	dsmark->qdm_mask |= SCH_DSMARK_ATTR_DEFAULT_INDEX;

	return 0;
}

/**
 * Get default index of DSMARK qdisc.
 * @arg qdisc		DSMARK qdisc.
 * @return Default index or a negative error code.
 */
int rtnl_qdisc_dsmark_get_default_index(struct rtnl_qdisc *qdisc)
{
	struct rtnl_dsmark_qdisc *dsmark;

	dsmark = dsmark_qdisc(qdisc);
	if (dsmark && dsmark->qdm_mask & SCH_DSMARK_ATTR_DEFAULT_INDEX)
		return dsmark->qdm_default_index;
	else
		return nl_errno(ENOENT);
}

/**
 * Set set-tc-index flag of DSMARK qdisc.
 * @arg qdisc		DSMARK qdisc to be modified.
 * @arg flag		Flag indicating whether to enable or disable.
 * @return 0 on success or a negative error code.
 */
int rtnl_qdisc_dsmark_set_set_tc_index(struct rtnl_qdisc *qdisc, int flag)
{
	struct rtnl_dsmark_qdisc *dsmark;

	dsmark = dsmark_qdisc(qdisc);
	if (!dsmark)
		return nl_errno(ENOMEM);

	dsmark->qdm_set_tc_index = !!flag;
	dsmark->qdm_mask |= SCH_DSMARK_ATTR_SET_TC_INDEX;

	return 0;
}

/**
 * Get set-tc-index flag of DSMARK qdisc.
 * @arg qdisc		DSMARK qdisc to be modified.
 * @return 1 or 0 to indicate wehther the flag is enabled or a negative
 *         error code.
 */
int rtnl_qdisc_dsmark_get_set_tc_index(struct rtnl_qdisc *qdisc)
{
	struct rtnl_dsmark_qdisc *dsmark;

	dsmark = dsmark_qdisc(qdisc);
	if (dsmark && dsmark->qdm_mask & SCH_DSMARK_ATTR_SET_TC_INDEX)
		return dsmark->qdm_set_tc_index;
	else
		return nl_errno(ENOENT);
}

/** @} */

static struct rtnl_qdisc_ops dsmark_qdisc_ops = {
	.qo_kind		= "dsmark",
	.qo_msg_parser		= dsmark_qdisc_msg_parser,
	.qo_dump[NL_DUMP_BRIEF]	= dsmark_qdisc_dump_brief,
	.qo_dump[NL_DUMP_FULL]	= dsmark_qdisc_dump_full,
	.qo_get_opts		= dsmark_qdisc_get_opts,
};

static struct rtnl_class_ops dsmark_class_ops = {
	.co_kind		= "dsmark",
	.co_msg_parser		= dsmark_class_msg_parser,
	.co_dump[NL_DUMP_BRIEF]	= dsmark_class_dump_brief,
	.co_get_opts		= dsmark_class_get_opts,
};

static void __init dsmark_init(void)
{
	rtnl_qdisc_register(&dsmark_qdisc_ops);
	rtnl_class_register(&dsmark_class_ops);
}

static void __exit dsmark_exit(void)
{
	rtnl_qdisc_unregister(&dsmark_qdisc_ops);
	rtnl_class_unregister(&dsmark_class_ops);
}

/** @} */
