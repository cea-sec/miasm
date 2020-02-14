#include "interval.h"

#include <stdlib.h>
#include <stdio.h>

struct interval_result
interval_sub(struct interval a, struct interval b)
{
    struct interval_result result;

    if (interval_eq(a, b))
    {
        /*
            a: ----
            b: ----
            =
        */
        result.nb_results = 0;
    }
    else if (interval_overlap(a, b))
    {
        if (a.start >= b.start && a.last <= b.last)
            /*
                a: ?--?
                b: ----
                =
            */
            result.nb_results = 0;
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
                result.nb_results = 1;
                result.intervals[0].start = b.last + 1;
                result.intervals[0].last = a.last;
            }
            else if (b.last == a.last)
            {
                /*
                    a: ----
                    b:  ---
                    =  -
                */
                result.nb_results = 1;
                result.intervals[0].start = a.start;
                result.intervals[0].last = b.start - 1;
            }
            else
            {
                /*
                    a: ----
                    b:  --
                    =  -  -
                */
                result.nb_results = 2;
                result.intervals[0].start = a.start;
                result.intervals[0].last = b.start - 1;
                result.intervals[1].start = b.last + 1;
                result.intervals[1].last = a.last;
            }
        }
        else if (a.start > b.start)
        {
            /*
                a:  ----
                b: ----
                =      -
            */
            result.nb_results = 1;
            result.intervals[0].start = b.last + 1;
            result.intervals[0].last = a.last;
        }
        else
        {
            /*
                a: ----
                b:  ----
                =  -
            */
            result.nb_results = 1;
            result.intervals[0].start = a.start;
            result.intervals[0].last = b.start - 1;
        }
    }
    else
    {
        /*
            a: ----
            b:       ----
            =  ----
        */
        result.nb_results = 1;
        result.intervals[0] = a;
    }

    return result;
}

struct interval_result
interval_intersection(struct interval a, struct interval b)
{
    struct interval tmp1, tmp2;
    struct interval_result result;

    if (interval_eq(a, b))
    {
        result.nb_results = 1;
        result.intervals[0] = a;
    }
    else if (!interval_overlap(a, b))
        result.nb_results = 0;
    else
    {
        // intersection(a, b) = a - (b - a)
        result = interval_sub(a, b);
        if (result.nb_results == 1)
        {
            tmp1 = result.intervals[0];
            result = interval_sub(a, tmp1);
        }
        else if (result.nb_results == 2)
        {
            tmp1 = result.intervals[0];
            tmp2 = result.intervals[1];
            result = interval_sub(a, tmp1);
            tmp1 = result.intervals[0];
            result = interval_sub(tmp1, tmp2);
        }
        else
        {
            result.nb_results = 1;
            result.intervals[0] = a;
        }
    }

    return result;
}

struct interval_result
interval_union(struct interval a, struct interval b)
{
    struct interval_result result;

    if (interval_overlap(a, b))
    {
        result.nb_results = 1;
        result.intervals[0].start = a.start < b.start ? a.start : b.start; // MIN
        result.intervals[0].last = a.last > b.last ? a.last : b.last; // MAX
    }
    else
    {
        result.nb_results = 2;
        result.intervals[0] = a;
        result.intervals[1] = b;
    }

    return result;
}

bool
interval_eq(struct interval a, struct interval b)
{
    return a.start == b.start && b.last == a.last;
}


bool
interval_overlap(struct interval a, struct interval b)
{
    return a.start <= b.last && b.start <= a.last;
}
