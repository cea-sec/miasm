import logging

from miasm2.core.bin_stream import bin_stream_str, bin_stream_elf, bin_stream_pe
from miasm2.jitter.csts import PAGE_READ


log = logging.getLogger("binary")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("%(levelname)-5s: %(message)s"))
log.addHandler(console_handler)
log.setLevel(logging.ERROR)


# Container
## Exceptions
class ContainerSignatureException(Exception):
    "The container does not match the current container signature"


class ContainerParsingException(Exception):
    "Error during container parsing"


## Parent class
class Container(object):
    """Container abstraction layer

    This class aims to offer a common interface for abstracting container
    such as PE or ELF.
    """

    available_container = []  # Available container formats
    fallback_container = None # Fallback container format

    @classmethod
    def from_string(cls, data, vm=None, addr=None):
        """Instanciate a container and parse the binary
        @data: str containing the binary
        @vm: (optional) VmMngr instance to link with the executable
        @addr: (optional) Base address for the binary. If set,
               force the unknown format
        """
        log.info('Load binary')

        if not addr:
            addr = 0
        else:
            # Force fallback mode
            log.warning('Fallback to string input (offset=%s)' % hex(addr))
            return cls.fallback_container(data, vm, addr)

        # Try each available format
        for container_type in cls.available_container:
            try:
                return container_type(data, vm)
            except ContainerSignatureException:
                continue
            except ContainerParsingException, error:
                log.error(error)

        # Fallback mode
        log.warning('Fallback to string input (offset=%s)' % hex(addr))
        return cls.fallback_container(data, vm, addr)

    @classmethod
    def register_container(cls, container):
        "Add a Container format"
        cls.available_container.append(container)

    @classmethod
    def register_fallback(cls, container):
        "Set the Container fallback format"
        cls.fallback_container = container

    @classmethod
    def from_stream(cls, stream, *args, **kwargs):
        """Instanciate a container and parse the binary
        @stream: stream to use as binary
        @vm: (optional) VmMngr instance to link with the executable
        @addr: (optional) Shift to apply before parsing the binary. If set,
               force the unknown format
        """
        return Container.from_string(stream.read(), *args, **kwargs)

    def parse(self, data, *args, **kwargs):
        "Launch parsing of @data"
        raise NotImplentedError("Abstract method")

    def __init__(self, *args, **kwargs):
        "Alias for 'parse'"
        self.parse(*args, **kwargs)

    @property
    def bin_stream(self):
        "Return the BinStream instance corresponding to container content"
        return self._bin_stream

    @property
    def executable(self):
        "Return the abstract instance standing for parsed executable"
        return self._executable

    @property
    def entry_point(self):
        "Return the detected entry_point"
        return self._entry_point


## Format dependent classes
class ContainerPE(Container):
    "Container abstraction for PE"


    def parse(self, data, vm=None):
        from miasm2.jitter.loader.pe import vm_load_pe, preload_pe
        from elfesteem import pe_init

        # Parse signature
        if not data.startswith('MZ'):
            raise ContainerSignatureException()

        # Build executable instance
        try:
            if vm is not None:
                self._executable = vm_load_pe(vm, data)
            else:
                self._executable = pe_init.PE(data)
        except Exception, error:
            raise ContainerParsingException('Cannot read PE: %s' % error)

        # Check instance validity
        if not self._executable.isPE() or \
                self._executable.NTsig.signature_value != 0x4550:
            raise ContainerSignatureException()

        # Build the bin_stream instance and set the entry point
        try:
            self._bin_stream = bin_stream_pe(self._executable.virt)
            ep_detected = self._executable.Opthdr.AddressOfEntryPoint
            self._entry_point = self._executable.rva2virt(ep_detected)
        except Exception, error:
            raise ContainerParsingException('Cannot read PE: %s' % error)


class ContainerELF(Container):
    "Container abstraction for ELF"

    def parse(self, data, vm=None):
        from miasm2.jitter.loader.elf import vm_load_elf, preload_elf
        from elfesteem import elf_init

        # Parse signature
        if not data.startswith('\x7fELF'):
            raise ContainerSignatureException()

        # Build executable instance
        try:
            if vm is not None:
                self._executable = vm_load_elf(vm, data)
            else:
                self._executable = elf_init.ELF(data)
        except Exception, error:
            raise ContainerParsingException('Cannot read ELF: %s' % error)

        # Build the bin_stream instance and set the entry point
        try:
            self._bin_stream = bin_stream_elf(self._executable.virt)
            self._entry_point = self._executable.Ehdr.entry
        except Exception, error:
            raise ContainerParsingException('Cannot read ELF: %s' % error)


class ContainerUnknown(Container):
    "Container abstraction for unknown format"

    def parse(self, data, vm, addr):
        self._bin_stream = bin_stream_str(data, shift=addr)
        if vm is not None:
            vm.add_memory_page(addr,
                               PAGE_READ,
                               data)
        self._executable = None
        self._entry_point = 0


## Register containers
Container.register_container(ContainerPE)
Container.register_container(ContainerELF)
Container.register_fallback(ContainerUnknown)
