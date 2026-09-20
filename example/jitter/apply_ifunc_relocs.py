from argparse import ArgumentParser
from pdb import pm
from miasm.analysis.binary import Container, ContainerELF
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB

if __name__ == "__main__":
    parser = ArgumentParser(description="x86 ELF ifunc relocs")
    parser.add_argument("filename", help="ELF to apply (ifunc) relocs to")
    parser.add_argument("-j", "--jitter",
                        help="Jitter engine (default is 'gcc')",
                        default="gcc")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose mode")
    args = parser.parse_args()
    loc_db = LocationDB()

    myjit = Machine("x86_64").jitter(loc_db, args.jitter)
    myjit.init_stack()

    with open(args.filename, 'rb') as f:
        elf: ContainerELF = Container.from_stream(f, loc_db=loc_db, apply_reloc=True, run_ifuncs=True)
        assert(isinstance(elf, ContainerELF))

    run_addr = elf._entry_point

    if args.verbose:
        myjit.set_trace_log()
    myjit.run(run_addr)
