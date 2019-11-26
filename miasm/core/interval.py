from __future__ import print_function

INT_EQ = 0      # Equivalent
INT_B_IN_A = 1  # B in A
INT_A_IN_B = -1 # A in B
INT_DISJOIN = 2 # Disjoint
INT_JOIN = 3    # Overlap
INT_JOIN_AB = 4 # B starts at the end of A
INT_JOIN_BA = 5 # A starts at the end of B


def cmp_interval(inter1, inter2):
    """Compare @inter1 and @inter2 and returns the associated INT_* case
    @inter1, @inter2: interval instance
    """
    if inter1 == inter2:
        return INT_EQ

    inter1_start, inter1_stop = inter1
    inter2_start, inter2_stop = inter2
    result = INT_JOIN
    if inter1_start <= inter2_start and inter1_stop >= inter2_stop:
        result = INT_B_IN_A
    if inter2_start <= inter1_start and inter2_stop >= inter1_stop:
        result = INT_A_IN_B
    if inter1_stop + 1 == inter2_start:
        result = INT_JOIN_AB
    if inter2_stop + 1 == inter1_start:
        result = INT_JOIN_BA
    if inter1_start > inter2_stop + 1 or inter2_start > inter1_stop + 1:
        result = INT_DISJOIN
    return result


class interval(object):
    """Stands for intervals with integer bounds

    Offers common methods to work with interval"""

    def __init__(self, bounds=None):
        """Instance an interval object
        @bounds: (optional) list of (int, int) and/or interval instance
        """
        if bounds is None:
            bounds = []
        elif isinstance(bounds, interval):
            bounds = bounds.intervals
        self.is_cannon = False
        self.intervals = bounds
        self.cannon()

    def __iter__(self):
        """Iterate on intervals"""
        for inter in self.intervals:
            yield inter

    @staticmethod
    def cannon_list(tmp):
        """
        Return a cannonizes list of intervals
        @tmp: list of (int, int)
        """
        tmp = sorted([x for x in tmp if x[0] <= x[1]])
        out = []
        if not tmp:
            return out
        out.append(tmp.pop())
        while tmp:
            x = tmp.pop()
            rez = cmp_interval(out[-1], x)

            if rez == INT_EQ:
                continue
            elif rez == INT_DISJOIN:
                out.append(x)
            elif rez == INT_B_IN_A:
                continue
            elif rez in [INT_JOIN, INT_JOIN_AB, INT_JOIN_BA, INT_A_IN_B]:
                u, v = x
                while out and cmp_interval(out[-1], (u, v)) in [
                    INT_JOIN, INT_JOIN_AB, INT_JOIN_BA, INT_A_IN_B]:
                    u = min(u, out[-1][0])
                    v = max(v, out[-1][1])
                    out.pop()
                out.append((u, v))
            else:
                raise ValueError('unknown state', rez)
        return out[::-1]

    def cannon(self):
        "Apply .cannon_list() on self contained intervals"
        if self.is_cannon is True:
            return
        self.intervals = interval.cannon_list(self.intervals)
        self.is_cannon = True

    def __repr__(self):
        if self.intervals:
            o = " U ".join(["[0x%X 0x%X]" % (x[0], x[1])
                           for x in self.intervals])
        else:
            o = "[]"
        return o

    def __contains__(self, other):
        if isinstance(other, interval):
            for intervalB in other.intervals:
                is_in = False
                for intervalA in self.intervals:
                    if cmp_interval(intervalA, intervalB) in [INT_EQ, INT_B_IN_A]:
                        is_in = True
                        break
                if not is_in:
                    return False
            return True
        else:
            for intervalA in self.intervals:
                if intervalA[0] <= other <= intervalA[1]:
                    return True
            return False

    def __eq__(self, i):
        return self.intervals == i.intervals

    def __ne__(self, other):
        return not self.__eq__(other)

    def union(self, other):
        """
        Return the union of intervals
        @other: interval instance
        """

        if isinstance(other, interval):
            other = other.intervals
        other = interval(self.intervals + other)
        return other

    def difference(self, other):
        """
        Return the difference of intervals
        @other: interval instance
        """

        to_test = self.intervals[:]
        i = -1
        to_del = other.intervals[:]
        while i < len(to_test) - 1:
            i += 1
            x = to_test[i]
            if x[0] > x[1]:
                del to_test[i]
                i -= 1
                continue

            while to_del and to_del[0][1] < x[0]:
                del to_del[0]

            for y in to_del:
                if y[0] > x[1]:
                    break
                rez = cmp_interval(x, y)
                if rez == INT_DISJOIN:
                    continue
                elif rez == INT_EQ:
                    del to_test[i]
                    i -= 1
                    break
                elif rez == INT_A_IN_B:
                    del to_test[i]
                    i -= 1
                    break
                elif rez == INT_B_IN_A:
                    del to_test[i]
                    i1 = (x[0], y[0] - 1)
                    i2 = (y[1] + 1, x[1])
                    to_test[i:i] = [i1, i2]
                    i -= 1
                    break
                elif rez in [INT_JOIN_AB, INT_JOIN_BA]:
                    continue
                elif rez == INT_JOIN:
                    del to_test[i]
                    if x[0] < y[0]:
                        to_test[i:i] = [(x[0], y[0] - 1)]
                    else:
                        to_test[i:i] = [(y[1] + 1, x[1])]
                    i -= 1
                    break
                else:
                    raise ValueError('unknown state', rez)
        return interval(to_test)

    def intersection(self, other):
        """
        Return the intersection of intervals
        @other: interval instance
        """

        out = []
        for x in self.intervals:
            if x[0] > x[1]:
                continue
            for y in other.intervals:
                rez = cmp_interval(x, y)

                if rez == INT_DISJOIN:
                    continue
                elif rez == INT_EQ:
                    out.append(x)
                    continue
                elif rez == INT_A_IN_B:
                    out.append(x)
                    continue
                elif rez == INT_B_IN_A:
                    out.append(y)
                    continue
                elif rez == INT_JOIN_AB:
                    continue
                elif rez == INT_JOIN_BA:
                    continue
                elif rez == INT_JOIN:
                    if x[0] < y[0]:
                        out.append((y[0], x[1]))
                    else:
                        out.append((x[0], y[1]))
                    continue
                else:
                    raise ValueError('unknown state', rez)
        return interval(out)


    def __add__(self, other):
        return self.union(other)

    def __and__(self, other):
        return self.intersection(other)

    def __sub__(self, other):
        return self.difference(other)

    def hull(self):
        "Return the first and the last bounds of intervals"
        if not self.intervals:
            return None, None
        return self.intervals[0][0], self.intervals[-1][1]


    @property
    def empty(self):
        """Return True iff the interval is empty"""
        return not self.intervals

    def show(self, img_x=1350, img_y=20, dry_run=False):
        """
        show image representing the interval
        """
        try:
            import Image
            import ImageDraw
        except ImportError:
            print('cannot import python PIL imaging')
            return

        img = Image.new('RGB', (img_x, img_y), (100, 100, 100))
        draw = ImageDraw.Draw(img)
        i_min, i_max = self.hull()

        print(hex(i_min), hex(i_max))

        addr2x = lambda addr: ((addr - i_min) * img_x) // (i_max - i_min)
        for a, b in self.intervals:
            draw.rectangle((addr2x(a), 0, addr2x(b), img_y), (200, 0, 0))

        if dry_run is False:
            img.show()

    @property
    def length(self):
        """
        Return the cumulated length of intervals
        """
        # Do not use __len__ because we may return a value > 32 bits
        return sum((stop - start + 1) for start, stop in self.intervals)
