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

#ifndef _HEAP_SUPPORT_H_
#define _HEAP_SUPPORT_H_

#include <stddef.h>
#include <mblty/debug.h>

struct heap_item {
	int index;
};

struct heap {
	int size, count;
	struct heap_item **data;

	int (*compare)(struct heap *, struct heap_item *, struct heap_item *);
};

static inline int
heap_empty(struct heap *h)
{
	return h->count == 0;
}

static inline struct heap_item *
heap_top(struct heap *h)
{
	if (heap_empty(h))
		return NULL;
	return h->data[0];
}

void heap_init(struct heap *);
void heap_free(struct heap *);

void heap_push(struct heap *, struct heap_item *);
void heap_pop(struct heap *);

void heap_remove(struct heap *, struct heap_item *);
void heap_update(struct heap *, struct heap_item *);

void heap_foreach_item(struct heap *, void (*)(struct heap_item *, void *),
		       void *argument);
struct heap_item *heap_first_match(struct heap *,
				   int (*)(struct heap_item *, void *),
				   void *);

static inline struct heap_item *
heap_top_and_pop(struct heap *h)
{
	struct heap_item *p = heap_top(h);
	heap_pop(h);
	return p;
}

#endif /* _HEAP_SUPPORT_H_ */
