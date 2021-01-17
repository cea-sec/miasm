from argparse import ArgumentParser
from miasm.analysis.binary import Container
from miasm.core.locationdb import LocationDB
from miasm.jitter.loader.pe import get_export_name_addr_list


parser = ArgumentParser(description="Retrieve exported functions of a DLL")
parser.add_argument("filename",
                    help="DLL filename")
args = parser.parse_args()


fdesc = open(args.filename, 'rb')
loc_db = LocationDB()
cont = Container.from_stream(fdesc, loc_db)

exported_funcs = get_export_name_addr_list(cont.executable)

for name_or_ordinal, address in exported_funcs:
    print(name_or_ordinal, hex(address))
