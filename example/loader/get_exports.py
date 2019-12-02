from argparse import ArgumentParser
from miasm.jitter.loader.pe import get_export_name_addr_list
from miasm.analysis.binary import Container


parser = ArgumentParser(description="Retrieve exported functions of a DLL")
parser.add_argument("filename",
                    help="DLL filename")
args = parser.parse_args()


fdesc = open(args.filename, 'rb')
cont = Container.from_stream(fdesc)

exported_funcs = get_export_name_addr_list(cont.executable)

for name_or_ordinal, address in exported_funcs:
    print(name_or_ordinal, hex(address))
