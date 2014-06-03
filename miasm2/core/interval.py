INT_EQ = 0
INT_B_IN_A = 1
INT_A_IN_B = -1
INT_DISJOIN = 2
INT_JOIN = 3
INT_JOIN_AB = 4
INT_JOIN_BA = 5

# 0  => eq
# 1  => b in a
# -1 => a in b
# 2  => disjoin
# 3  => join
# 4  => join a,b touch
# 5  => join b,a touch


def cmp_interval(a, b):
    if a == b:
        return INT_EQ
    a1, a2 = a
    b1, b2 = b
    if a1 <= b1 and a2 >= b2:
        return INT_B_IN_A
    if b1 <= a1 and b2 >= a2:
        return INT_A_IN_B
    if a2 + 1 == b1:
        return INT_JOIN_AB
    if b2 + 1 == a1:
        return INT_JOIN_BA
    if a1 > b2 + 1 or b1 > a2 + 1:
        return INT_DISJOIN
    return INT_JOIN

# interval is: [a, b]


class interval:

    def __init__(self, a=None):
        if a is None:
            a = []
        if isinstance(a, interval):
            a = a.intervals
        self.is_cannon = False
        self.intervals = a
        self.cannon()

    def __iter__(self):
        for x in self.intervals:
            yield x

    @classmethod
    def cannon_list(cls, tmp):
        """
        Return a cannonizes list of intervals
        """
        tmp = sorted([x for x in tmp if x[0] <= x[1]])
        out = []
        if not tmp:
            return out
        out.append(tmp.pop())
        while tmp:
            x = tmp.pop()
            rez = cmp_interval(out[-1], x)
            # print out[-1], x, rez
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

    def __contains__(self, i):
        if isinstance(i, interval):
            for x in self.intervals:
                is_out = True
                for y in i.intervals:
                    if cmp_interval(x, y) in [INT_EQ, INT_B_IN_A]:
                        is_out = False
                        break
                if is_out:
                    return False
            return True
        else:
            for x in self.intervals:
                if x[0] <= i <= x[1]:
                    return True
            return False

    def __eq__(self, i):
        return self.intervals == i.intervals

    def __add__(self, i):
        if isinstance(i, interval):
            i = i.intervals
        i = interval(self.intervals + i)
        return i

    def __sub__(self, v):
        to_test = self.intervals[:]
        i = -1
        to_del = v.intervals[:]
        while i < len(to_test) - 1:
            i += 1
            x = to_test[i]
            if x[0] > x[1]:
                del(to_test[i])
                i -= 1
                continue

            while to_del and to_del[0][1] < x[0]:
                del(to_del[0])

            for y in to_del:
                if y[0] > x[1]:
                    break
                rez = cmp_interval(x, y)
                if rez == INT_DISJOIN:
                    continue
                elif rez == INT_EQ:
                    del(to_test[i])
                    i -= 1
                    break
                elif rez == INT_A_IN_B:
                    del(to_test[i])
                    i -= 1
                    break
                elif rez == INT_B_IN_A:
                    del(to_test[i])
                    i1 = (x[0], y[0] - 1)
                    i2 = (y[1] + 1, x[1])
                    to_test[i:i] = [i1, i2]
                    i -= 1
                    break
                elif rez in [INT_JOIN_AB, INT_JOIN_BA]:
                    continue
                elif rez == INT_JOIN:
                    del(to_test[i])
                    if x[0] < y[0]:
                        to_test[i:i] = [(x[0], y[0] - 1)]
                    else:
                        to_test[i:i] = [(y[1] + 1, x[1])]
                    i -= 1
                    break
                else:
                    raise ValueError('unknown state', rez)
        return interval(to_test)

    def __and__(self, v):
        out = []
        for x in self.intervals:
            # print "x", x
            if x[0] > x[1]:
                continue
            for y in v.intervals:
                # print 'y', y
                rez = cmp_interval(x, y)
                # print x, y, rez
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

    def hull(self):
        if not self.intervals:
            return None, None
        return self.intervals[0][0], self.intervals[-1][1]

    def show(self, img_x=1350, img_y=20, dry_run=False):
        """
        show image representing the itnerval
        """
        try:
            import Image
            import ImageDraw
        except ImportError:
            print 'cannot import python PIL imaging'
            return

        img = Image.new('RGB', (img_x, img_y), (100, 100, 100))
        draw = ImageDraw.Draw(img)
        i_min, i_max = self.hull()

        print hex(i_min), hex(i_max)

        def addr2x(addr):
            return (addr - i_min) * img_x / (i_max - i_min)
        for a, b in self.intervals:
            draw.rectangle((addr2x(a), 0, addr2x(b), img_y), (200, 0, 0))

        if dry_run is False:
            img.show()
