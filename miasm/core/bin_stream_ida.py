from builtins import range
from idc import get_wide_byte, get_segm_end
from idautils import Segments
from idaapi import is_mapped

from miasm.core.utils import int_to_byte
from miasm.core.bin_stream import bin_stream_str


class bin_stream_ida(bin_stream_str):
    """
    bin_stream implementation for IDA

    Don't generate xrange using address computation:
    It can raise error on overflow 7FFFFFFF with 32 bit python
    """
    def _getbytes(self, start, l=1):
        out = []
        for ad in range(l):
            offset = ad + start + self.base_address
            if not is_mapped(offset):
                raise IOError(f"not enough bytes @ offset {offset:x}")
            out.append(int_to_byte(get_wide_byte(offset)))
        return b''.join(out)

    def readbs(self, l=1):
        if self.offset + l > self.l:
            raise IOError("not enough bytes")
        content = self.getbytes(self.offset)
        self.offset += l
        return content

    def __str__(self):
        raise NotImplementedError('Not fully functional')

    def setoffset(self, val):
        self.offset = val

    def getlen(self):
        # Lazy version
        if hasattr(self, "_getlen"):
            return self._getlen
        max_addr = get_segm_end(list(Segments())[-1]  - (self.offset - self.base_address))
        self._getlen = max_addr
        return max_addr
