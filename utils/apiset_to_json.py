import sys
import json
import ctypes
from miasm.loader.pe_init import PE
from argparse import ArgumentParser


ULONG = ctypes.c_uint32


def extract_409_resource(res):
    """
    Find the first resource id 0x409
    """
    if res is None:
        return None
    for x in res.resentries:
        if x.data:
            if x.name == 0x409:
                return x.data.s
        if x.offsettosubdir:
            ret = extract_409_resource(x.subdir)
            if ret:
                return ret
    return None


class ApiSetWin10(object):
    def __init__(self, fname_apisetschema):
        self.pe = PE(open(fname_apisetschema, "rb").read())
        self.version = self.get_version()
        self.api_section = self.pe.getsectionbyname(".apiset").get_data()
        self.hash_factor = self.get_hash_factor()
        self.hash_entries = self.get_hash_entries()
        self.redirections = self.get_redirection_by_name()

    def get_version(self):
        res = self.pe.DirRes.resdesc

        data = extract_409_resource(res)
        token = "ProductVersion\x00".encode("utf-16le")
        index_start = data.find(token)
        assert index_start > 0
        index_start += len(token)
        index_stop = data.find(b"\x00\x00", index_start)
        assert index_start > 0
        data = data[index_start : index_stop + 1]
        data = data.decode("utf-16le")
        return data

    class ApiSetHeader(ctypes.Structure):
        _fields_ = [
            ("Version", ULONG),
            ("Size", ULONG),
            ("Flags", ULONG),
            ("Count", ULONG),
            ("EntryOffset", ULONG),
            ("HashOffset", ULONG),
            ("HashFactor", ULONG),
        ]

    class ApiSetHashEntry(ctypes.Structure):
        _fields_ = [
            ("NumberOfEntries", ULONG),
        ]

    class ApiSetHosts_win10(ctypes.Structure):
        _fields_ = [
            ("Hash", ULONG),
            ("Index", ULONG),
        ]

    class ApiSetNameSpaceEntry(ctypes.Structure):
        _fields_ = [
            ("Flags", ULONG),
            ("NameOffset", ULONG),
            ("NameLength", ULONG),
            ("HashedLength", ULONG),
            ("ValueOffset", ULONG),
            ("ValueCount", ULONG),
        ]

    class ApiSetValueEntry(ctypes.Structure):
        _fields_ = [
            ("Flags", ULONG),
            ("NameOffset", ULONG),
            ("NameLength", ULONG),
            ("ValueOffset", ULONG),
            ("ValueLength", ULONG),
        ]

    def get_hash_factor(self):
        hdr = self.ApiSetHeader.from_buffer_copy(
            self.api_section[0 : ctypes.sizeof(self.ApiSetHeader)]
        )
        # Windows 10
        assert hdr.Version >= 5
        return hdr.HashFactor

    def get_redirection_by_name(self):
        hdr = self.ApiSetHeader.from_buffer_copy(
            self.api_section[0 : ctypes.sizeof(self.ApiSetHeader)]
        )
        # Windows 10
        assert hdr.Version >= 5
        redirections = {}
        for i in range(hdr.Count):
            addr = hdr.EntryOffset + i * ctypes.sizeof(self.ApiSetNameSpaceEntry)
            entry = self.ApiSetNameSpaceEntry.from_buffer_copy(
                self.api_section[addr : addr + ctypes.sizeof(self.ApiSetNameSpaceEntry)]
            )
            addr = entry.NameOffset
            redir_name = self.api_section[addr : addr + entry.NameLength]
            redir_name = redir_name.decode("utf-16le")

            addr_descs = entry.ValueOffset

            host_out = {}
            for i in range(entry.ValueCount):
                addr = addr_descs + i * ctypes.sizeof(self.ApiSetValueEntry)
                host = self.ApiSetValueEntry.from_buffer_copy(
                    self.api_section[addr : addr + ctypes.sizeof(self.ApiSetValueEntry)]
                )
                if host.NameOffset != 0:
                    addr = host.NameOffset
                    importName = self.api_section[addr : addr + host.NameLength]
                    importName = importName.decode("utf-16le")
                else:
                    importName = ""

                addr = host.ValueOffset
                hostName = self.api_section[addr : addr + host.ValueLength]
                hostName = hostName.decode("utf-16le")
                host_out[importName] = hostName
            redirections[redir_name.lower()] = host_out

        return redirections

    # hash func can be found in ntdll!ApiSetpSearchForApiSet
    def compute_hash(self, apiset_lib_name, hashf):
        hashk = 0
        for c in apiset_lib_name:
            hashk = (hashk * hashf + c) & ((1 << 32) - 1)
        return hashk

    def get_hash_entries(self):
        hash_entries = {}
        hdr = self.ApiSetHeader.from_buffer_copy(
            self.api_section[: ctypes.sizeof(self.ApiSetHeader)]
        )
        # Windows 10
        assert hdr.Version >= 5
        for i in range(0, hdr.Count):
            offset = hdr.HashOffset + i * ctypes.sizeof(self.ApiSetHosts_win10)
            hash_entry = self.ApiSetHosts_win10.from_buffer_copy(
                self.api_section[
                    offset : offset + ctypes.sizeof(self.ApiSetHosts_win10)
                ]
            )
            offset = hdr.EntryOffset + hash_entry.Index * ctypes.sizeof(
                self.ApiSetNameSpaceEntry
            )
            namespace_entry = self.ApiSetNameSpaceEntry.from_buffer_copy(
                self.api_section[
                    offset : offset + ctypes.sizeof(self.ApiSetNameSpaceEntry)
                ]
            )
            hashed_name = self.api_section[
                namespace_entry.NameOffset : namespace_entry.NameOffset
                + namespace_entry.HashedLength
            ]
            hashed_name = hashed_name.decode("utf-16le")
            entries = []
            for c in range(0, namespace_entry.ValueCount):
                offset = namespace_entry.ValueOffset + c * ctypes.sizeof(
                    self.ApiSetValueEntry
                )
                value_entry = self.ApiSetValueEntry.from_buffer_copy(
                    self.api_section[
                        offset : offset + ctypes.sizeof(self.ApiSetValueEntry)
                    ]
                )
                value_name = self.api_section[
                    value_entry.NameOffset : value_entry.NameOffset
                    + value_entry.NameLength
                ]
                value_data = self.api_section[
                    value_entry.ValueOffset : value_entry.ValueOffset
                    + value_entry.ValueLength
                ]
                name = value_name.decode("utf-16le")
                data = value_data.decode("utf-16le")
                entries.append((name, data))
            hash_entries[hashed_name] = dict(entries)
        return hash_entries


parser = ArgumentParser("Extract information from windows apiset dll")
parser.add_argument("filename", help="Windows ApiSet schema dll")
args = parser.parse_args()

apiset = ApiSetWin10(args.filename)
apiset.get_redirection_by_name()

export_obj = {}
export_obj["version"] = apiset.version
export_obj["hashes"] = apiset.hash_entries

open("%s.json" % apiset.version, "w").write(json.dumps(export_obj))
