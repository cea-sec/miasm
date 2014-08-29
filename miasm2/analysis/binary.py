from miasm2.core.bin_stream import *
import logging
from miasm2.jitter.jitload import vm_load_pe, vm_load_elf

log = logging.getLogger("binary")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.INFO)

class Container(object):
    def __init__(self, filename, vm = None, addr = None):
        data = open(filename).read()
        log.info('load binary')
        e, bs, ep = None, None, None

        if data.startswith('MZ'):
            try:
                if vm is not None:
                    e = vm_load_pe(vm, filename)
                else:
                    e = pe_init.PE(data)
                if e.isPE() and e.NTsig.signature_value == 0x4550:
                    bs = bin_stream_pe(e.virt)
                    ep = e.rva2virt(e.Opthdr.AddressOfEntryPoint)
            except:
                log.error('Cannot read PE!')
        elif data.startswith('\x7fELF'):
            try:
                if vm is not None:
                    e = vm_load_elf(vm, filename)
                else:
                    e = elf_init.ELF(data)
                bs = bin_stream_elf(e.virt)
                ep = e.Ehdr.entry
            except:
                log.error('Cannot read ELF!')
        else:
            bs = bin_stream_str(data)
            if vm is not None:
                if addr is None:
                    raise ValueError('set load addr')
                vm.vm_add_memory_page(addr,
                                      PAGE_READ,
                                      data)

        self.e, self.bs, self.ep = e, bs, ep
