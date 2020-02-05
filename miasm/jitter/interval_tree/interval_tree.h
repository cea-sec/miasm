#ifndef _LINUX_INTERVAL_TREE_H
#define _LINUX_INTERVAL_TREE_H

#include "rbtree.h"

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

struct interval {
	unsigned long start; /* Start of interval */
	unsigned long last;	 /* Last location _in_ interval */
};

/*
Union of two intervals can be:
- one interval if they overlap
- or two intervals if they don't
Subtraction of two intervals (a-b) can be:
- nothing if intervals are equals
- nothing if intervals overlap and a is included in b
- one interval if they overlap
- two intervals if they overlap and b is included in a
*/
struct interval_result {
    struct interval intervals[2]; 
    unsigned long nb_results;
};

struct interval_tree_node {
	struct rb_node rb;
	unsigned long start; /* Start of interval */
	unsigned long last;	/* Last location _in_ interval */
	unsigned long __subtree_last;
};

void
interval_tree_insert(struct interval_tree_node *node, struct rb_root *root);

void
interval_tree_remove(struct interval_tree_node *node, struct rb_root *root);

struct interval_tree_node *
interval_tree_iter_first(struct rb_root *root,
                         unsigned long start,
                         unsigned long last);

struct rb_root *
interval_tree_new();

struct interval_tree_node *
interval_tree_alloc_new_node(unsigned long start, unsigned long last);

void
interval_tree_insert_new_node(unsigned long start,
                              unsigned long last,
                              struct rb_root *root);

void
interval_tree_print(struct rb_root *root);

unsigned long
interval_tree_search_interval(unsigned long start,
                              unsigned long last,
                              struct rb_root *root);

void
interval_tree_free(struct rb_root *root);

// Remove nodes of interval tree root overlapping with [start, last] starting
// from node from.
// Return last removed node.
struct interval
interval_tree_remove_from(unsigned long start,
                          unsigned long last,
                          struct interval_tree_node *from,
                          struct rb_root *root);


// Add merge_function(a, b) to root
// For example, merge_function can be interval_sub or interval_union
void
interval_tree_add_merged(struct interval a,
                         struct interval b,
                         struct rb_root *root,
                         struct interval_result * merge_function(struct interval, 
                                                                 struct interval));

// Return a - b
struct interval_result *
interval_sub(struct interval a, struct interval b);

// Return a U b
struct interval_result *
interval_union(struct interval a, struct interval b);

// Return a ∩ b
struct interval_result *
interval_intersection(struct interval a, struct interval b);

// Return intersection between the interval [start, last] and the interval tree
// root.
// Return value is an interval tree.
struct rb_root *
interval_tree_intersection(unsigned long start,
                           unsigned long last,
                           struct rb_root *root);

// Add interval [start, last] to interval tree root.
// If the the new interval overlaps with existing intervals, they are broken up
// and merged.
void
interval_tree_add(unsigned long start,
                  unsigned long last,
                  struct rb_root *root);

// Remove interval [start, last] to interval tree root.
// If the the interval overlaps with existing intervals, they are broken up
// and merged.
void
interval_tree_sub(unsigned long start,
                  unsigned long last,
                  struct rb_root *root);


#endif	/* _LINUX_INTERVAL_TREE_H */
