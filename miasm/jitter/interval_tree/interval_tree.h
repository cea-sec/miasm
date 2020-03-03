#ifndef INTERVAL_TREE_H 
#define INTERVAL_TREE_H 

#include <stdbool.h>
#include "rbtree.h"
#include "interval.h"

#define START(node) ((node)->interval.start)
#define LAST(node)  ((node)->interval.last)

struct interval_tree_node {
	struct rb_node rb;
    struct interval interval;
	unsigned long __subtree_last;
};

void
interval_tree_insert_new_node(struct rb_root *root, struct interval interval);

void
interval_tree_print(struct rb_root *root);

struct rb_root
interval_tree_new();

void
interval_tree_free(struct rb_root *root);

/*
 Return intersection between the interval and the interval tree root.
 Return value is an interval tree.
*/
struct rb_root
interval_tree_intersection(struct rb_root *root, struct interval interval);

/*
 Add interval to interval tree root.
 If the new interval overlaps with existing intervals, they are broken up and
 merged.
*/
void
interval_tree_add(struct rb_root *root, struct interval interval);

/*
 Remove interval to interval tree root.
 If the the interval overlaps with existing intervals, they are broken up and
 merged.
*/
void
interval_tree_sub(struct rb_root *root, struct interval interval);

#endif
