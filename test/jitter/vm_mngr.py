import sys
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

loc_db = LocationDB()
myjit = Machine("x86_32").jitter(loc_db, sys.argv[1])

base_addr = 0x13371337
page_size = 0x1000
data = b"\x00" * page_size
rights = [0, PAGE_READ, PAGE_WRITE, PAGE_READ|PAGE_WRITE]
shuffled_rights = [PAGE_READ, 0, PAGE_READ|PAGE_WRITE, PAGE_WRITE]

# Add pages
for i, access_right in enumerate(rights):
    myjit.vm.add_memory_page(base_addr + i * page_size, access_right, data)

# Check rights
for i, access_right in enumerate(rights):
    assert myjit.vm.get_mem_access(base_addr + i * page_size) == access_right

# Modify rights
for i, access_right in enumerate(shuffled_rights):
    myjit.vm.set_mem_access(base_addr + i * page_size, access_right)

# Check for modification
for i, access_right in enumerate(shuffled_rights):
    assert myjit.vm.get_mem_access(base_addr + i * page_size) == access_right

# Remove pages
for i in range(len(rights)):
    myjit.vm.remove_memory_page(base_addr + i * page_size)

# Add pages again
for i, access_right in enumerate(rights):
    myjit.vm.add_memory_page(base_addr + i * page_size, access_right, data)
