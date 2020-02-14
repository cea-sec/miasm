#include <stdbool.h>

struct interval {
    unsigned long start;
    unsigned long last;	 /* Last location _in_ interval */
};

/*
Union result of two intervals can be:
- one interval if they overlap
- or two intervals if they don't
Subtraction of two intervals (a-b) can be:
- nothing if intervals are equals
- if intervals overlap:
    - nothing if a is included in b
    - two intervals if b is included in a
    - else one interval
Intersection result of two intervals can be:
- one interval if they overlap
- or nothing if they don't
*/
struct interval_result {
    struct interval intervals[2];
    unsigned long nb_results;
};

// Return a - b
struct interval_result
interval_sub(struct interval a, struct interval b);

// Return a u b
struct interval_result
interval_union(struct interval a, struct interval b);

// Return a ∩ b
struct interval_result
interval_intersection(struct interval a, struct interval b);

bool
interval_eq(struct interval a, struct interval b);

bool
interval_overlap(struct interval a, struct interval b);
