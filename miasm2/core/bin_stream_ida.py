from idc import Byte, SegEnd
from idautils import Segments

from miasm2.core.bin_stream import bin_stream_str


class bin_stream_ida(bin_stream_str):
    """
    bin_stream implementation for IDA

    Don't generate xrange using address computation:
    It can raise error on overflow 7FFFFFFF with 32 bit python
    """
    def getbytes(self, start, l=1):
        o = ""
        for ad in xrange(l):
            o += chr(Byte(ad + start - self.shift))
        return o

    def readbs(self, l=1):
        if self.offset + l > self.l:
            raise IOError("not enough bytes")
        o = self.getbytes(self.offset)
        self.offset += l
        return p

    def __str__(self):
        raise NotImplementedError('Not fully functional')

    def setoffset(self, val):
        self.offset = val

    def getlen(self):
        # Lazy version
        if hasattr(self, "_getlen"):
            return self._getlen
        max_addr = SegEnd(list(Segments())[-1]  - (self.offset + self.shift))
        self._getlen = max_addr
        return max_addr
