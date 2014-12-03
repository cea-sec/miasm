from idc import Byte

from miasm2.core.bin_stream import bin_stream_str


class bin_stream_ida(bin_stream_str):
    """
    bin_stream implementation for IDA

    IDA should provide Byte function

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
            raise IOError
        o = self.getbytes(self.offset)
        self.offset += l
        return p

    def writebs(self, l=1):
        raise ValueError('writebs unsupported')

    def __str__(self):
        raise NotImplementedError('Not fully functional')

    def setoffset(self, val):
        self.offset = val

    def __len__(self):
        return 0x7FFFFFFF

    def getlen(self):
        return 0x7FFFFFFF - self.offset - self.shift
