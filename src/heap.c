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
#include <stdlib.h>

#include <mblty/heap-support.h>

void
heap_init(struct heap *heap)
{
	heap->count = 0;
	heap->size = 0;
	heap->data = NULL;
	heap->compare = NULL;
}

void
heap_free(struct heap *heap)
{
	if (heap->data == NULL)
		return;

	free(heap->data);
	heap->data = NULL;
}

static void
heap_realloc(struct heap *heap)
{
	heap->data = realloc(heap->data, heap->size * sizeof(void *));
	/* debug_assert(heap->data, "Heap data allocation failed."); */
}

static void
heap_increase_size(struct heap *heap)
{
	heap->count++;

	if (heap->count > heap->size) {
		heap->size = 2 * (heap->size ? heap->size : 1);
		heap_realloc(heap);
	}
}

static void
heap_decrease_size(struct heap *heap)
{
	heap->count--;

	if (heap->count < (heap->size / 2)) {
		heap->size /= 2;
		heap_realloc(heap);
	}
}

static inline void
heap_swap_items(struct heap *heap, int a, int b)
{
	struct heap_item *tmp = heap->data[a];
	heap->data[a] = heap->data[b];
	heap->data[b] = tmp;

	heap->data[a]->index = a;
	heap->data[b]->index = b;
}

static inline int
heap_compare(struct heap *heap, int a, int b)
{
	return heap->compare(heap, heap->data[a], heap->data[b]);
}

static void
heap_fix(struct heap *heap, int i)
{
	int p;

	while (i > 0) {
		p = i / 2;

		if (heap_compare(heap, i, p) >= 0)
			break;

		heap_swap_items(heap, i, p);

		i = p;
	}
}

static void
push_to_root(struct heap *heap, int i)
{
	int p;

	while (i > 0) {
		p = i / 2;
		heap_swap_items(heap, i, p);
		i = p;
	}
}

static void
heap_fix_down(struct heap *heap, int p)
{
	int count = heap->count;
	int l, r;

	while (p < count) {
		l = p ? p * 2 : 1;
		r = l + 1;

		if (l >= count)
			break;

		if (r < count && heap_compare(heap, r, p) < 0
			      && heap_compare(heap, r, l) < 0) {
			heap_swap_items(heap, p, r);
			p = r;
		} else if (heap_compare(heap, l, p) < 0) {
			heap_swap_items(heap, p, l);
			p = l;
		} else {
			break;
		}
	}
}

void
heap_push(struct heap *heap, struct heap_item *item)
{
	int i = heap->count;

	heap_increase_size(heap);
	heap->data[i] = item;
	heap->data[i]->index = i;
	heap_fix(heap, i);
}

void
heap_pop(struct heap *heap)
{
	heap_swap_items(heap, 0, heap->count - 1);
	heap_decrease_size(heap);
	heap_fix_down(heap, 0);
}

void
heap_update(struct heap *heap, struct heap_item *item)
{
	int indx = item->index;

	if (indx > 0 && heap_compare(heap, indx, indx / 2) < 0)
		heap_fix(heap, indx);
	else
		heap_fix_down(heap, indx);
}

void
heap_remove(struct heap *heap, struct heap_item *item)
{
	push_to_root(heap, item->index);
	heap_pop(heap);
}

void
heap_foreach_item(struct heap *heap, void (*cb)(struct heap_item *, void *),
		  void *argument)
{
	int i;

	for (i = 0; i < heap->count; i++) {
		cb(heap->data[i], argument);
	}
}

struct heap_item *
heap_first_match(struct heap *heap, int (*cb)(struct heap_item *, void *),
		 void *argument)
{
	int i;

	for (i = 0; i < heap->count; i++) {
		if (cb(heap->data[i], argument) == 0)
			return heap->data[i];
	}

	return NULL;
}

