import logging
import warnings

from miasm.core.bin_stream import bin_stream_str, bin_stream_elf, bin_stream_pe
from miasm.jitter.csts import PAGE_READ


log = logging.getLogger("binary")
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter("[%(levelname)-8s]: %(message)s"))
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
    def from_string(cls, data, loc_db, *args, **kwargs):
        """Instantiate a container and parse the binary
        @data: str containing the binary
        @loc_db: LocationDB instance
        """
        log.info('Load binary')
        # Try each available format
        for container_type in cls.available_container:
            try:
                return container_type(data, loc_db, *args, **kwargs)
            except ContainerSignatureException:
                continue
            except ContainerParsingException as error:
                log.error(error)

        # Fallback mode
        log.warning('Fallback to string input')
        return cls.fallback_container(data, loc_db, *args, **kwargs)

    @classmethod
    def register_container(cls, container):
        "Add a Container format"
        cls.available_container.append(container)

    @classmethod
    def register_fallback(cls, container):
        "Set the Container fallback format"
        cls.fallback_container = container

    @classmethod
    def from_stream(cls, stream, loc_db, *args, **kwargs):
        """Instantiate a container and parse the binary
        @stream: stream to use as binary
        @vm: (optional) VmMngr instance to link with the executable
        @addr: (optional) Base address of the parsed binary. If set,
               force the unknown format
        """
        return Container.from_string(stream.read(), loc_db, *args, **kwargs)

    def parse(self, data, *args, **kwargs):
        """Launch parsing of @data
        @data: str containing the binary
        """
        raise NotImplementedError("Abstract method")

    def __init__(self, data, loc_db, **kwargs):
        "Alias for 'parse'"
        # Init attributes
        self._executable = None
        self._bin_stream = None
        self._entry_point = None
        self._arch = None
        self._loc_db = loc_db

        # Launch parsing
        self.parse(data, **kwargs)

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

    @property
    def arch(self):
        "Return the guessed architecture"
        return self._arch

    @property
    def loc_db(self):
        "LocationDB instance preloaded with container symbols (if any)"
        return self._loc_db

    @property
    def symbol_pool(self):
        "[DEPRECATED API]"
        warnings.warn("Deprecated API: use 'loc_db'")
        return self.loc_db

## Format dependent classes
class ContainerPE(Container):
    "Container abstraction for PE"

    def parse(self, data, vm=None, **kwargs):
        from miasm.jitter.loader.pe import vm_load_pe, guess_arch
        from miasm.loader import pe_init

        # Parse signature
        if not data.startswith(b'MZ'):
            raise ContainerSignatureException()

        # Build executable instance
        try:
            if vm is not None:
                self._executable = vm_load_pe(vm, data)
            else:
                self._executable = pe_init.PE(data)
        except Exception as error:
            raise ContainerParsingException('Cannot read PE: %s' % error)

        # Check instance validity
        if not self._executable.isPE() or \
                self._executable.NTsig.signature_value != 0x4550:
            raise ContainerSignatureException()

        # Guess the architecture
        self._arch = guess_arch(self._executable)

        # Build the bin_stream instance and set the entry point
        try:
            self._bin_stream = bin_stream_pe(self._executable)
            ep_detected = self._executable.Opthdr.AddressOfEntryPoint
            self._entry_point = self._executable.rva2virt(ep_detected)
        except Exception as error:
            raise ContainerParsingException('Cannot read PE: %s' % error)


class ContainerELF(Container):
    "Container abstraction for ELF"

    def parse(self, data, vm=None, addr=0, apply_reloc=False, **kwargs):
        """Load an ELF from @data
        @data: bytes containing the ELF bytes
        @vm (optional): VmMngr instance. If set, load the ELF in virtual memory
        @addr (optional): base address the ELF in virtual memory
        @apply_reloc (optional): if set, apply relocation during ELF loading

        @addr and @apply_reloc are only meaningful in the context of a
        non-empty @vm
        """
        from miasm.jitter.loader.elf import vm_load_elf, guess_arch, \
            fill_loc_db_with_symbols
        from miasm.loader import elf_init

        # Parse signature
        if not data.startswith(b'\x7fELF'):
            raise ContainerSignatureException()

        # Build executable instance
        try:
            if vm is not None:
                self._executable = vm_load_elf(
                    vm,
                    data,
                    loc_db=self.loc_db,
                    base_addr=addr,
                    apply_reloc=apply_reloc
                )
            else:
                self._executable = elf_init.ELF(data)
        except Exception as error:
            raise ContainerParsingException('Cannot read ELF: %s' % error)

        # Guess the architecture
        self._arch = guess_arch(self._executable)

        # Build the bin_stream instance and set the entry point
        try:
            self._bin_stream = bin_stream_elf(self._executable)
            self._entry_point = self._executable.Ehdr.entry + addr
        except Exception as error:
            raise ContainerParsingException('Cannot read ELF: %s' % error)

        if vm is None:
            # Add known symbols (vm_load_elf already does it)
            fill_loc_db_with_symbols(self._executable, self.loc_db, addr)



class ContainerUnknown(Container):
    "Container abstraction for unknown format"

    def parse(self, data, vm=None, addr=0, **kwargs):
        self._bin_stream = bin_stream_str(data, base_address=addr)
        if vm is not None:
            vm.add_memory_page(
                addr,
                PAGE_READ,
                data
            )
        self._executable = None
        self._entry_point = 0


## Register containers
Container.register_container(ContainerPE)
Container.register_container(ContainerELF)
Container.register_fallback(ContainerUnknown)
