#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

#include "interval_tree.h"
#include "interval_tree_generic.h"

#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)

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
        printf(" %lu-%lu ", node->start, node->last);
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
        interval_tree_remove(node, root);
        free(node);
    }

    free(root);
}

struct interval_tree_node *
interval_tree_alloc_new_node(unsigned long start, unsigned long last)
{
    struct interval_tree_node *node = calloc(1, sizeof(*node));

    if (node == NULL)
    {
        printf("INTERVAL: cannot alloc new node\n");
        exit(EXIT_FAILURE);
    }

    node->start = start;
    node->last = last;

    return node;
}

void
interval_tree_insert_new_node(unsigned long start, unsigned long last, struct rb_root *root)
{
    struct interval_tree_node *node = interval_tree_alloc_new_node(start, last);

    interval_tree_insert(node, root);
}

unsigned long
interval_tree_search_interval(unsigned long start, unsigned long last, struct rb_root *root)
{
	struct interval_tree_node *node;
	unsigned long results = 0;

	for (node = interval_tree_iter_first(root, start, last); node;
	     node = interval_tree_iter_next(node, start, last))
		results++;
	return results;
}

struct interval
interval_tree_remove_from(unsigned long start,
                          unsigned long last,
                          struct interval_tree_node *from,
                          struct rb_root *root)
{
    struct interval last_interval;
	struct interval_tree_node *prev_node, *cur_node;

    cur_node = from;
    while(cur_node)
    {
        last_interval.start = cur_node->start;
        last_interval.last = cur_node->last;

        prev_node = cur_node;
	    cur_node = interval_tree_iter_next(cur_node, start, last);

        interval_tree_remove(prev_node, root);
        free(prev_node);
    }

    return last_interval;
}

bool
interval_overlap(struct interval a, struct interval b)
{
    if (a.start <= b.last && b.start <= a.last)
        return true;
    return false;
}

bool
interval_eq(struct interval a, struct interval b)
{
    if (a.start == b.start && b.last == a.last)
        return true;
    return false;
}

struct interval_result *
interval_union(struct interval a, struct interval b)
{
    struct interval_result *result = calloc(1, sizeof(*result));

    if (interval_overlap(a, b))
    {
        result->nb_results = 1;
        result->intervals[0].start = MIN(a.start, b.start);
        result->intervals[0].last = MAX(a.last, b.last);
    }
    else
    {
        result->nb_results = 2;
        result->intervals[0] = a;
        result->intervals[1] = b;
    }

    return result;
}

struct interval_result *
interval_sub(struct interval a, struct interval b)
{
    struct interval_result *result = calloc(1, sizeof(*result));

    if (interval_eq(a, b))
    {
        /*
            a: ----
            b: ----
            =
        */
        result->nb_results = 0;
    }
    else if (interval_overlap(a, b))
    {
        if (a.start >= b.start && a.last <= b.last)
            /*
                a: ?--?
                b: ----
                =
            */
            result->nb_results = 0;
        else if (b.start >= a.start && b.last <= a.last)
        {
            // b is included in a
            if (b.start == a.start)
            {
                /*
                    a: ----
                    b: ---
                    =     -
                */
                result->nb_results = 1;
                result->intervals[0].start = b.last + 1;
                result->intervals[0].last = a.last;
            }
            else if (b.last == a.last)
            {
                /*
                    a: ----
                    b:  ---
                    =  - 
                */
                result->nb_results = 1;
                result->intervals[0].start = a.start;
                result->intervals[0].last = b.start - 1;
            }
            else
            {
                /*
                    a: ----
                    b:  --
                    =  -  -
                */
                result->nb_results = 2;
                result->intervals[0].start = a.start;
                result->intervals[0].last = b.start - 1;
                result->intervals[1].start = b.last + 1;
                result->intervals[1].last = a.last;
            }
        }
        else if (a.start > b.start)
        {
            /*
                a:  ----
                b: ----
                =      -
            */
            result->nb_results = 1;
            result->intervals[0].start = b.last + 1;
            result->intervals[0].last = a.last;
        }
        else
        {
            /*
                a: ----
                b:  ----
                =  -
            */
            result->nb_results = 1;
            result->intervals[0].start = a.start;
            result->intervals[0].last = b.start - 1;
        }
    }
    else
    {
        /*
            a: ----
            b:       ----
            =  ----
        */
        result->nb_results = 1;
        result->intervals[0] = a;
    }
    
    return result;
}

struct interval_result *
interval_intersection(struct interval a, struct interval b)
{
    struct interval tmp1, tmp2;
    struct interval_result *result = calloc(1, sizeof(*result));

    if (result == NULL)
    {
        printf("INTERVAL: cannot alloc new interval_result\n");
        exit(EXIT_FAILURE);
    }

    if (interval_eq(a, b))
    {
        result->nb_results = 1;
        result->intervals[0] = a;
    }
    else if (!interval_overlap(a, b))
        result->nb_results = 0;
    else
    {
        // intersection(a, b) = a - (b - a)
        free(result);
        result = interval_sub(a, b);
        if (result->nb_results == 1)
        {
            tmp1 = result->intervals[0];
            free(result);
            result = interval_sub(a, tmp1); 
        }
        else if (result->nb_results == 2)
        {
            tmp1 = result->intervals[0];
            tmp2 = result->intervals[1];
            free(result);
            result = interval_sub(a, tmp1); 
            tmp1 = result->intervals[0];
            free(result);
            result = interval_sub(tmp1, tmp2); 
        }
        else
        {
            result->nb_results = 1;
            result->intervals[0] = a;
        }
    }

    return result;
}

void
interval_tree_add_merged(struct interval a,
                         struct interval b,
                         struct rb_root *root,
                         struct interval_result *merge_function(struct interval,
                                                                struct interval))
{
    struct interval_result *sub = merge_function(a, b);

    for(unsigned long index = 0; index < sub->nb_results; index++)
        interval_tree_insert_new_node(sub->intervals[index].start,
                                      sub->intervals[index].last,
                                      root);

    free(sub);
}

void
interval_tree_sub(unsigned long start, unsigned long last, struct rb_root *root)
{
	struct interval_tree_node *first_node;
    struct interval first_interval, last_interval, sub_interval;

    first_node = interval_tree_iter_first(root, start, last);

    if (first_node == NULL)
        // Substracted interval is not overlapping with any existing interval.
        return;

    first_interval.start = first_node->start;
    first_interval.last = first_node->last;

    last_interval = interval_tree_remove_from(start, last, first_node, root);

    sub_interval.start = start;
    sub_interval.last = last;
    interval_tree_add_merged(first_interval, sub_interval, root, interval_sub);
    if (!interval_eq(first_interval, last_interval))
    {
        interval_tree_add_merged(last_interval, sub_interval, root, interval_sub);
    }
}

void
interval_tree_add(unsigned long start, unsigned long last, struct rb_root *root)
{
    struct interval_result *result_union;
    struct interval add_interval, first_interval, last_interval;
	struct interval_tree_node *first_node;

    first_node = interval_tree_iter_first(root, start, last);

    if (first_node == NULL)
    {
        // New interval is not overlapping with any existing interval.
        // We can simply add it to our interval tree.
        interval_tree_insert_new_node(start, last, root);
        return;
    }

    // Removing all intervals overlapping with the new interval.
    // First and last intervals are saved in order to be merged and inserted in
    // the interval tree later.
    first_interval.start = first_node->start;
    first_interval.last = first_node->last;

    last_interval = interval_tree_remove_from(start, last, first_node, root);

    // First and last intervals overlapping with the new interval are merged
    // and inserted in the interval tree.
    // At this point we know that those three intervals are like this:
    // First: ----
    // New:     ----
    // Last:       ----
    // If First == Last we add First U New to our interval tree.
    // Else we add First U New U Last to our interval tree.
    add_interval.start = start;
    add_interval.last = last;

    if (interval_eq(first_interval, last_interval))
    {
        interval_tree_add_merged(first_interval,
                                 add_interval,
                                 root,
                                 interval_union);
    }
    else
    {
        result_union = interval_union(first_interval, add_interval);
        if (result_union->nb_results == 1)
        {
            interval_tree_add_merged(last_interval,
                                     result_union->intervals[0],
                                     root,
                                     interval_union);
        }
        else
        {
            printf("INTERVAL: interval_union(first_interval, add_interval) \
should always return one interval here.\n");
        }
        free(result_union);
    }
}

struct rb_root *
interval_tree_intersection(unsigned long start,
                           unsigned long last,
                           struct rb_root *root)
{
	struct interval_tree_node *cur_node, *first_node, *last_node;
    struct interval intersection_interval, first_interval, last_interval;
    struct rb_root *intersection_tree = calloc(1, sizeof(*intersection_tree));

    if (intersection_tree == NULL)
    {
        printf("INTERVAL: cannot alloc new interval tree\n");
        exit(EXIT_FAILURE);
    }

    first_node = interval_tree_iter_first(root, start, last);

    if (first_node == NULL)
    {
        // Interval is not overlapping with any existing interval.
        return intersection_tree;
    }

    cur_node = first_node;
    while(cur_node)
    {
        interval_tree_insert_new_node(cur_node->start,
                                      cur_node->last,
                                      intersection_tree);
        last_node = cur_node;
	    cur_node = interval_tree_iter_next(cur_node, start, last);
    }

    first_interval.start = first_node->start;
    first_interval.last = first_node->last;
    last_interval.start = last_node->start;
    last_interval.last = last_node->last;
    intersection_interval.start = start;
    intersection_interval.last = last;

    first_node = interval_tree_iter_first(intersection_tree,
                                          first_node->start,
                                          first_node->last);
    interval_tree_remove(first_node, intersection_tree);
    free(first_node);

    interval_tree_add_merged(first_interval,
                             intersection_interval,
                             intersection_tree,
                             interval_intersection);

    if (!interval_eq(first_interval, last_interval))
    {
        last_node = interval_tree_iter_first(intersection_tree,
                                             last_node->start,
                                             last_node->last);
        interval_tree_remove(last_node, intersection_tree);
        free(last_node);

        interval_tree_add_merged(last_interval,
                                 intersection_interval,
                                 intersection_tree,
                                 interval_intersection);
    }

    return intersection_tree;
}

