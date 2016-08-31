import random

from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.analysis.machine import Machine

myjit = Machine("x86_32").jitter()

base_addr = 0x13371337
page_size = 0x1000
data = "".join([chr(random.randint(0, 255)) for _ in xrange(page_size)])

for i, access_right in enumerate([0, PAGE_READ, PAGE_WRITE, PAGE_READ|PAGE_WRITE]):
    myjit.vm.add_memory_page(base_addr+i*page_size, access_right, data)

for i, access_right in enumerate([0, PAGE_READ, PAGE_WRITE, PAGE_READ|PAGE_WRITE]):
    assert myjit.vm.get_mem_access(base_addr+i*page_size) == access_right


for i, access_right in enumerate([PAGE_READ, 0, PAGE_READ|PAGE_WRITE, PAGE_WRITE]):
    myjit.vm.set_mem_access(base_addr+i*page_size, access_right)

for i, access_right in enumerate([PAGE_READ, 0, PAGE_READ|PAGE_WRITE, PAGE_WRITE]):
    assert myjit.vm.get_mem_access(base_addr+i*page_size) == access_right



