/*
 * lib/attr.c		Netlink Attributes
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Copyright (c) 2003-2005 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup nl
 * @defgroup attr Netlink Attributes
 * Module to parse TLVs and append them to netlink messages.
 *
 * @par
 * Netlink attributes are chained together following each other:
 * @code
 *                 RTA_PAYLOAD(rta)
 *                   <--------->
 * +----------+- - -+- - - - - -+- - -+----------+- - -+- - - - - -
 * |  Header  | Pad |  Payload  | Pad |  Header  | Pad |  Payload
 * +----------+- - -+- - - - - -+- - -+----------+- - -+- - - - - -
 * RTA_DATA(rta)-----^                 ^
 * RTA_NEXT(rta, attrlen)--------------'
 * @endcode
 *
 * @par
 * The routing attribute header and payload must be aligned properly:
 * @code
 *  <---- RTA_ALIGN(hlen) ----> <---- RTA_ALIGN(len) --->
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 * |        Header       | Pad |     Payload       | Pad |
 * |    struct rtattr    |     |                   |     |
 * +---------------------+- - -+- - - - - - - - - -+- - -+
 *  <------- hlen ------>       <------ len ------>
 *  <--------------- RTA_LENGTH(len) ------------->
 *  <------------------ RTA_SPACE(len) ----------------->
 * @endcode
 *
 * @par Nested TLVs:
 * Nested TLVs are an array of TLVs nested into another TLV. This can be useful
 * to allow subsystems to have their own formatting rules without the need to
 * make the underlying layer be aware of it. It can also be useful to transfer
 * arrays, lists and flattened trees.
 * \code
 *  <-------------------- RTA_ALIGN(...) ------------------->
 * +---------------+- - - - - - - - - - - - - - - - - -+- - -+
 * |               |+---------+---------+- - -+-------+|     |
 * |  TLV Header   ||  TLV 1  |  TLV 2  |     | TLV n || Pad |
 * |               |+---------+---------+- - -+-------+|     |
 * +---------------+- - - - - - - - - - - - - - - - - -+- - -+
 *                  <------- RTA_PAYLOAD(rta) -------->
 * \endcode
 *
 * @par Example 1
 * @code
 * int param1 = 10;
 * char *param2 = "parameter text";
 * struct nlmsghdr hdr = {
 * 	.nlmsg_type = MY_ACTION,
 * };
 * struct nl_msg *m = nl_msg_build(&hdr);
 * nl_msg_append_tlv(m, 1, &param1, sizeof(param1));
 * nl_msg_append_tlv(m, 2, param2, strlen(param2));
 * 
 * nl_send_auto_complete(handle, nl_msg_get(m));
 * nl_msg_free(m);
 * @endcode
 *
 * @par Example 2 (Nested TLVs)
 * @code
 * struct nl_msg * nested_config(void)
 * {
 * 	int a = 5, int b = 10;
 * 	struct nl_msg *n = nl_msg_build(NULL);
 * 	nl_msg_append_tlv(n, 10, &a, sizeof(a));
 * 	nl_msg_append_tlv(n, 20, &b, sizeof(b));
 * 	return n;
 * }
 *
 * ...
 * struct nl_msg *m = nl_msg_build(&hdr);
 * struct nl_msg *nest = nested_config();
 * nl_msg_append_nested(m, 1, nest);
 *
 * nl_send_auto_complete(handle, nl_msg_get(m));
 * nl_msg_free(nest);
 * nl_msg_free(m);
 * @endcode
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/helpers.h>
#include <netlink/addr.h>
#include <netlink/route/rtattr.h>
#include <linux/socket.h>

/**
 * @name Building
 * @{
 */

/**
 * Append a TLV to a netlink message
 * @arg n		netlink message
 * @arg type		TLV type
 * @arg data		data of TLV
 * @arg len		length of data
 *
 * Extends the netlink message as needed and appends a new TLV of given
 * type at the tail of the message and encapsulates the data into the
 * TLV. The starting point of the TLV header is properly aligned which
 * means that there may be gap between the current data at the tail and
 * the begin of the TLV. The length of the TLV is properly aligned, a
 * possible gap between the end of the data and the end of the TLV
 * is left blank.
 *
 * @return 0 on success or a negative error code
 */
int nl_msg_append_tlv(struct nl_msg *n, int type, void *data, size_t len)
{
	int tlen;
	struct rtattr *rta;
	
	tlen = NLMSG_ALIGN(n->nmsg->nlmsg_len) + RTA_LENGTH(NLMSG_ALIGN(len));

	n->nmsg = realloc(n->nmsg, tlen);
	if (n->nmsg == NULL)
		return -ENOMEM;

	rta = (struct rtattr *) NLMSG_TAIL(n->nmsg);
	rta->rta_type = type;
	rta->rta_len = RTA_LENGTH(NLMSG_ALIGN(len));
	memcpy(RTA_DATA(rta), data, len);
	n->nmsg->nlmsg_len = tlen;
	
	return 0;
}

/**
 * Append a u32 value as TLV to a netlink message
 * @arg n		netlink message
 * @arg type		TLV type
 * @arg value		integer value
 * @see nl_msg_append_tlv
 * @return 0 on success or a negative error code
 */
int nl_msg_append_tlv_u32(struct nl_msg *n, int type, uint32_t value)
{
	return nl_msg_append_tlv(n, type, &value, sizeof(uint32_t));
}

/**
 * Append a u64 value as TLV to a netlink message
 * @arg n		netlink message
 * @arg type		TLV type
 * @arg value		integer value
 * @see nl_msg_append_tlv
 * @return 0 on success or a negative error code
 */
int nl_msg_append_tlv_u64(struct nl_msg *n, int type, uint64_t value)
{
	return nl_msg_append_tlv(n, type, &value, sizeof(uint64_t));
}

/**
 * Append a NUL terminated string as TLV to a netlink message
 * @arg n		netlink message
 * @arg type		TLV type
 * @arg str		NUL terminated string
 * @see nl_msg_append_tlv
 * @return 0 on success or a negative error code
 */
int nl_msg_append_tlv_string(struct nl_msg *n, int type, char *str)
{
	return nl_msg_append_tlv(n, type, str, strlen(str) + 1);
}

/**
 * Append a abstract address as TLV to a netlink message
 * @arg n		netlink message
 * @arg type		TLV type
 * @arg addr		abstract address
 * @see nl_msg_append_tlv
 * @return 0 on success or a negative error code
 */
int nl_msg_append_tlv_addr(struct nl_msg *n, int type, struct nl_addr *addr)
{
	return nl_msg_append_tlv(n, type,
				 nl_addr_get_binary_addr(addr),
				 nl_addr_get_len(addr));
}

/**
 * Append a nested TLV to a netlink message
 * @arg n		netlink message
 * @arg type		TLV type
 * @arg nested	netlink message to nest
 *
 * Extends the netlink message as needed and appends a new TLV of given
 * type at the tail of the message. The message pointed to by \a nested
 * gets its header cut off and gets encapsulated into the TLV. The starting
 * point of the TLV header is properly aligned which means that there may
 * be a gap between the current data at the tail and the begin of the TLV.
 * The length of the TLV is properly aligned, a possible gap between the
 * end of the data and the end of the TLV is left blank.
 *
 * @return 0 on success or a negative error code
 */
int nl_msg_append_nested(struct nl_msg *n, int type, struct nl_msg *nested)
{
	return nl_msg_append_tlv(n, type, nl_msg_payload(nested),
		nl_msg_payloadlen(nested));
}

/** @} */

/**
 * @name Parsing
 * @{
 */

/**
 * Parse and split a TLV block and store them in a array
 * @arg attr		destination rtattr array
 * @arg max		Maximal number of TLVs
 * @arg rta		rtattr to be split apart
 * @arg len		Length of attributes block
 *
 * Splits a block of TLVs and stores the start of every TLV into the
 * provided array \a attr using the TLV type as index, i.e. the TLV
 * array can be used to access the TLV by their type afterwards. Multiple
 * occurances of the same TLV type are overwritten and only the last
 * occurance will show up. TLV types exceeding \a max will be ignored.
 *
 * \b Example: 
 * @code
 *   netlink message
 *  +--------+---------------+---------------+----------------+
 *  | header | T=3 L=8 V=... | T=1 L=4 V=... | T=4 L=16 V=... |
 *  +--------+---------------+---------------+----------------+
 *             ^               ^               ^
 *             |       +-------+               |
 *             +-------|----------+    +-------+
 *                     |          |    |
 *     tb[] = { NULL, ptr, NULL, ptr, ptr, NULL };
 * @endcode
 * @return 0 on success or a negative error code.
 * @exception EINVAL Leftover while parsing the TLVs
 */
int nl_parse_rtattr(struct rtattr **attr, size_t max, struct rtattr *rta,
		    size_t len)
{
	memset(attr, 0, NL_TB_LENGTH(max + 1));

	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			attr[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, len);
	}

	if (len > 0)
		return nl_error(EINVAL, "Leftover while parsing TLVs");

	return 0;
}

/**
 * Split a netlink message into a TLV array
 * @arg tb		destination TLV array 
 * @arg max		size of TLV array (number of elements)
 * @arg n		netlink message
 *
 * Splits a netlink message and stores the start of every TLV into the
 * provided array \a tb using the TLV type as index, i.e. the TLV
 * array can be used to access TLV by their type afterwards. Multiple
 * occurances of the same TLV type are overwritten and only the last
 * occurance will show up. TLV types exceeding \a max will be ignored.
 *
 * @pre The message payload must contain a block of TLVs.
 * @see nl_parse_rtattr()
 * @return 0 on success or a negative error code.
 */
int nl_msg_parse_rtattr(struct rtattr **tb, int max, struct nl_msg *n)
{
	return nl_msg_parse_rtattr_off(tb, max, n, 0);
}

/**
 * Split a netlink message with raw data prefixed into a TLV array
 * @arg tb		destination TLV array 
 * @arg max		size of TLV array (number of elements)
 * @arg n		netlink message
 * @arg offset	length of data in bytes in front of the TLVs
 *
 * Splits a netlink message having raw data prefixed in front of the
 * TLVs and stores the start of every TLV into the provided array
 * \a tb using the TLV type as index, i.e. the TLV array can be used
 * to access TLV by their type afterwards. Multiple occurances of the
 * same TLV type are overwritten and only the last occurance will show
 * up. TLV types exceeding \a max will be ignored.
 *
 * @pre The message payload must contain a block of TLVs at the
 *      given \a offset.
 * @see nl_parse_rtattr()
 * @return 0 on success or a negative error code.
 */
int nl_msg_parse_rtattr_off(struct rtattr **tb, int max, struct nl_msg *n,
			    int offset)
{
	return nl_parse_rtattr(tb, max, nl_msg_payload(n) + offset,
	    nl_msg_payloadlen(n));
}

/** @} */

/**
 * @name Attribute Access Shortcuts
 * @{
 */

/**
 * Parse a TLV containing an address and build an abstract adress based on it
 * @arg family		address family
 * @arg prefixlen	length of prefix
 * @arg rta		source rtattr
 * @return Newly allocated abstract address or NULL
 */
struct nl_addr *nl_rta_parse_addr(int family, int prefixlen, struct rtattr *rta)
{
	struct nl_addr *addr = nl_addr_build(family, RTA_DATA(rta),
					     RTA_PAYLOAD(rta));

	if (addr)
		nl_addr_set_prefixlen(addr, prefixlen);

	return addr;
}

/**
 * Copy a routing attribute into a buffer
 * @arg dst		destination buffer
 * @arg len		length of destination buffer
 * @arg rta		routing attribute
 * @return 0 on success or a negative error code.
 */
int nl_copy_data(void *dst, size_t len, struct rtattr *rta)
{
	if (RTA_PAYLOAD(rta) > len)
		return nl_error(EINVAL, "TLV payload is too big to " \
		    "fit into the requested buffer.\n");

	memcpy(dst, RTA_DATA(rta), RTA_PAYLOAD(rta));

	return 0;
}

/**
 * Allocate a abstract data out of a routing attribute
 * @arg d		an abstract data
 * @arg rta		routing attribute
 * @return 0 on success or a negative error code
 */
int nl_alloc_data_from_rtattr(struct nl_data **d, struct rtattr *rta)
{
	if (*d)
		nl_data_free(*d);

	*d = nl_data_alloc(RTA_DATA(rta), RTA_PAYLOAD(rta));
	if (!*d)
		return -ENOMEM;

	return 0;
}

/** @} */
/** @} */
