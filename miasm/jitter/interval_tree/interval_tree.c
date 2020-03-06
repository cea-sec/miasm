#include "interval_tree.h"

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

#include "interval_tree_generic.h"

INTERVAL_TREE_DEFINE(struct interval_tree_node, rb,
		     unsigned long, __subtree_last,
		     START, LAST,, interval_tree)


void
interval_tree_print(struct rb_root *root)
{
	struct interval_tree_node *node;
	struct rb_node *rb_node;

    printf("[");

    rb_node = rb_first(root);

    while(rb_node != NULL)
    {
        node = rb_entry(rb_node, struct interval_tree_node, rb);
        printf(" %lu-%lu ", node->interval.start, node->interval.last);
        rb_node = rb_next(rb_node);
    }
    printf("]\n");
}

void
interval_tree_free(struct rb_root *root)
{
	struct interval_tree_node *node;
	struct rb_node *rb_node;

    rb_node = rb_first(root);

    while(rb_node != NULL)
    {
        node = rb_entry(rb_node, struct interval_tree_node, rb);
        rb_node = rb_next(rb_node);
        interval_tree_remove(root, node);
        free(node);
    }
}

struct rb_root
interval_tree_new()
{
    struct rb_root interval_tree = { NULL };
    return interval_tree;
}

struct interval_tree_node *
interval_tree_alloc_new_node(struct interval interval)
{
    struct interval_tree_node *node = malloc(sizeof(*node));

    if (node == NULL)
    {
        fprintf(stderr, "INTERVAL: cannot alloc new node\n");
        return NULL;
    }

    node->interval = interval;

    return node;
}

void
interval_tree_insert_new_node(struct rb_root *root, struct interval interval)
{
    struct interval_tree_node *node = interval_tree_alloc_new_node(interval);

    interval_tree_insert(root, node);
}

unsigned long
interval_tree_search_interval(struct rb_root *root, struct interval interval)
{
	struct interval_tree_node *node;
	unsigned long results = 0;

	for (node = interval_tree_iter_first(root, interval.start, interval.last);
         node != NULL;
	     node = interval_tree_iter_next(node, interval.start,interval. last))
        results++;
	return results;
}

/*
 Remove nodes of interval tree root overlapping with interval [start, last]
 starting from node from.
 Return last removed node.
*/
struct interval
interval_tree_remove_from(struct rb_root *root,
                          struct interval interval,
                          struct interval_tree_node *from)
{
    struct interval last_interval;
	struct interval_tree_node *prev_node, *cur_node;

    cur_node = from;
    while(cur_node != NULL)
    {
        last_interval = cur_node->interval;

        prev_node = cur_node;
	    cur_node = interval_tree_iter_next(cur_node,
                                           interval.start,
                                           interval.last);

        interval_tree_remove(root, prev_node);
        free(prev_node);
    }

    return last_interval;
}

/*
 Add result of merge_function(a, b) to root.
 For example, merge_function can be interval_sub or interval_union from
 interval.h.
*/
void
interval_tree_add_merged(struct rb_root *root,
                         struct interval a,
                         struct interval b,
                         struct interval_result merge_function(struct interval,
                                                               struct interval))
{
    struct interval_result sub = merge_function(a, b);
    unsigned long index = 0;
    for(index = 0; index < sub.nb_results; index++)
        interval_tree_insert_new_node(root,
                                      sub.intervals[index]);
}

void
interval_tree_sub(struct rb_root *root, struct interval interval)
{
	struct interval_tree_node *first_node;
    struct interval first_interval, last_interval;

    first_node = interval_tree_iter_first(root, interval.start, interval.last);

    if (first_node == NULL)
        // Subtracted interval is not overlapping with any existing interval.
        return;

    first_interval = first_node->interval;

    last_interval = interval_tree_remove_from(root, interval, first_node);

    interval_tree_add_merged(root, first_interval, interval, interval_sub);
    if (!interval_eq(first_interval, last_interval))
    {
        interval_tree_add_merged(root, last_interval, interval, interval_sub);
    }
}

void
interval_tree_add(struct rb_root *root, struct interval interval)
{
    struct interval_result result_union;
    struct interval first_interval, last_interval;
	struct interval_tree_node *first_node;

    first_node = interval_tree_iter_first(root, interval.start, interval.last);

    if (first_node == NULL)
    {
        // New interval is not overlapping with any existing interval.
        // We can simply add it to our interval tree.
        interval_tree_insert_new_node(root, interval);
        return;
    }

    // Removing all intervals overlapping with the new interval.
    // First and last intervals are saved in order to be merged and inserted in
    // the interval tree later.
    first_interval = first_node->interval;

    last_interval = interval_tree_remove_from(root, interval, first_node);

    // First and last intervals overlapping with the new interval are merged
    // and inserted in the interval tree.
    // At this point we know that those three intervals are like this:
    // First: ----
    // New:     ----
    // Last:       ----
    // If First == Last we add First U New to our interval tree.
    // Else we add First U New U Last to our interval tree.

    if (interval_eq(first_interval, last_interval))
    {
        interval_tree_add_merged(root,
                                 first_interval,
                                 interval,
                                 interval_union);
    }
    else
    {
        result_union = interval_union(first_interval, interval);
        if (result_union.nb_results == 1)
        {
            interval_tree_add_merged(root,
                                     last_interval,
                                     result_union.intervals[0],
                                     interval_union);
        }
        else
        {
            fprintf(stderr, "INTERVAL: interval_union should always return one"
                            "interval here.\n");
        }
    }
}

struct rb_root
interval_tree_intersection(struct rb_root *root, struct interval interval)
{
	struct interval_tree_node *cur_node, *first_node, *last_node;
    struct interval first_interval, last_interval;

    struct rb_root intersection_tree = interval_tree_new();

    first_node = interval_tree_iter_first(root, interval.start, interval.last);

    if (first_node == NULL)
    {
        // Interval is not overlapping with any existing interval.
        return intersection_tree;
    }

    cur_node = first_node;
    while(cur_node)
    {
        interval_tree_insert_new_node(&intersection_tree, cur_node->interval);
        last_node = cur_node;
	    cur_node = interval_tree_iter_next(cur_node,
                                           interval.start,
                                           interval.last);
    }

    first_interval = first_node->interval;
    last_interval = last_node->interval;

    first_node = interval_tree_iter_first(&intersection_tree,
                                          first_node->interval.start,
                                          first_node->interval.last);
    interval_tree_remove(&intersection_tree, first_node);
    free(first_node);

    interval_tree_add_merged(&intersection_tree,
                             first_interval,
                             interval,
                             interval_intersection);

    if (!interval_eq(first_interval, last_interval))
    {
        last_node = interval_tree_iter_first(&intersection_tree,
                                             last_node->interval.start,
                                             last_node->interval.last);
        interval_tree_remove(&intersection_tree, last_node);
        free(last_node);

        interval_tree_add_merged(&intersection_tree,
                                 last_interval,
                                 interval,
                                 interval_intersection);
    }

    return intersection_tree;
}

