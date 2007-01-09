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

#ifndef _PRIV_LIST_SUPPORT_H_
#define _PRIV_LIST_SUPPORT_H_

#include <stddef.h>

/* original code from Linux's list handling code (include/linux/list.h) */

struct list_entry {
	struct list_entry *next, *prev;
};

#define LIST_DEF_INIT(name) { &(name), &(name) }

#define LIST_DEF(name) \
	struct list_entry name = LIST_DEF_INIT(name)

static inline void list_init(struct list_entry *head)
{
	head->next = head;
	head->prev = head;
}

static inline void __list_add(struct list_entry *new,
			      struct list_entry *prev,
			      struct list_entry *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_entry *new, struct list_entry *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_entry *new, struct list_entry *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_entry * prev, struct list_entry * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_entry *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}

static inline void list_move(struct list_entry *list, struct list_entry *head)
{
        __list_del(list->prev, list->next);
        list_add(list, head);
}

static inline void list_move_tail(struct list_entry *list,
				  struct list_entry *head)
{
        __list_del(list->prev, list->next);
        list_add_tail(list, head);
}

static inline int list_empty(const struct list_entry *head)
{
	return head->next == head;
}

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_get_entry(target, ptr, member) \
	(target = list_entry(ptr, typeof(*target), member))

#define list_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

#define list_for_each_prev(pos, head) \
	for (pos = (head)->prev; pos != (head); pos = pos->prev)

#define list_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
	     n = list_entry((pos)->member.next, typeof(*n), member);	\
	     &pos->member != (head);					\
	     pos = n, n = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))

#define list_head(head, type, member) \
	list_entry((head)->next, type, member)

#define list_get_head(target, head, member) \
	(target = (list_empty(head) ? \
		NULL : list_head(head, typeof(*target), member)))

static inline void
list_insert_sorted(struct list_entry *new, struct list_entry *head,
		   int (*comp)(struct list_entry *, struct list_entry *,
		   void *), void *arg)
{
	if (list_empty(head)) {
		list_add_tail(new, head);
	} else {
		struct list_entry *iter, *prev = NULL;

		list_for_each (iter, head) {
			if (comp(new, iter, arg) < 0)
				break;
			prev = iter;
		}

		list_add(new, prev ? prev : head);
	}
}

#endif /* _PRIV_LIST_SUPPORT_H_ */
