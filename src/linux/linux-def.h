#ifndef _PRIV_LINUX_DEF_H_
#define _PRIV_LINUX_DEF_H_

#include <mblty/interface.h>

#define KERN_ADDR_F_PERMANENT		0x0001
#define KERN_ADDR_F_TENTATIVE		0x0002
#define KERN_ADDR_F_DEPRECATED		0x0004
#define KERN_ADDR_F_HOME_ADDRESS	0x0008
#define KERN_ADDR_F_MANAGED		0x0010
#define KERN_ADDR_F_REPLACE		0x1000

#define KERN_DEF_METRIC		1024

typedef void (*kern_addremove_callback)(int res, void *);
typedef void (*linux_intf_addr_cb_t)(int res, void *);

typedef struct linux_intf linux_intf_t;

struct linux_pending_msg {
	struct nl_msg *msg;

	kern_addremove_callback cb;
	void *param;

	struct list_entry entry;
};

struct linux_intf {
	mblty_os_intf_t osh;
	int ifindex;

	struct list_entry addresses;
	struct list_entry entry;
};

#define INTF(x)	container_of(x, linux_intf_t, osh)

void linux_intf_address_add(mblty_os_intf_t *, struct in6_addr *, uint32_t,
			    linux_intf_addr_cb_t, void *);
void linux_intf_address_remove(mblty_os_intf_t *, struct in6_addr *,
			       linux_intf_addr_cb_t, void *);
void linux_intf_cancel_addr_op(mblty_os_intf_t *, void *cookie);

void linux_route_add(struct in6_prefix *dst, struct in6_addr *src,
		     struct in6_addr *gw, struct mblty_os_intf *, int metric,
		     uint32_t flags, kern_addremove_callback, void *arg);
void linux_route_delete(struct in6_prefix *dst, struct in6_addr *src,
		        struct in6_addr *gw, struct mblty_os_intf *, int metric,
		        kern_addremove_callback, void *arg);

struct linux_pending_msg *linux_get_request(kern_addremove_callback, void *);
void linux_cancel_request(void *param);

#endif
