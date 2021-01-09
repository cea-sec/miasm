"""Example of DynamicSymbolicExecution engine use

This example should run on the compiled ELF x86 64bits version of
"dse_crackme.c"

"""
from __future__ import print_function

#### This part is only related to the run of the sample, without DSE ####
from builtins import range
import os
import subprocess
import platform
from collections import namedtuple
from pdb import pm
from tempfile import NamedTemporaryFile
from future.utils import viewitems

from miasm.core.utils import int_to_byte
from miasm.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm.analysis.sandbox import Sandbox_Linux_x86_64
from miasm.expression.expression import *
from miasm.os_dep.win_api_x86_32 import get_win_str_a
from miasm.core.locationdb import LocationDB

is_win = platform.system() == "Windows"

# File "management"
my_FILE_ptr = 0x11223344
FInfo = namedtuple("FInfo", ["path", "fdesc"])
FILE_to_info = {}
TEMP_FILE = NamedTemporaryFile(delete = False)

def xxx_fopen(jitter):
    '''
    #include <stdio.h>

    FILE *fopen(const char *path, const char *mode);
    '''
    global my_FILE_ptr
    ret_addr, args = jitter.func_args_systemv(['path', 'mode'])
    fname = get_win_str_a(jitter, args.path)
    FILE_to_info[my_FILE_ptr] = FInfo(fname, open(fname, "rb"))
    my_FILE_ptr += 1
    return jitter.func_ret_stdcall(ret_addr, my_FILE_ptr - 1)

def xxx_fread(jitter):
    '''
    #include <stdio.h>

    size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
    '''
    ret_addr, args = jitter.func_args_systemv(['ptr', 'size', 'nmemb', 'stream'])
    info = FILE_to_info[args.stream]
    data = info.fdesc.read(args.size * args.nmemb)
    jitter.vm.set_mem(args.ptr, data)
    return jitter.func_ret_stdcall(ret_addr, len(data))

def xxx_fclose(jitter):
    '''
    #include <stdio.h>

    int fclose(FILE *stream);
    '''
    ret_addr, args = jitter.func_args_systemv(['stream'])
    del FILE_to_info[args.stream]
    return jitter.func_ret_stdcall(ret_addr, 0)

# Create sandbox
parser = Sandbox_Linux_x86_64.parser(description="ELF sandboxer")
parser.add_argument("filename", help="ELF Filename")
parser.add_argument("--strategy",
                    choices=["code-cov", "branch-cov", "path-cov"],
                    help="Strategy to use for solution creation",
                    default="code-cov")
options = parser.parse_args()
options.mimic_env = True
options.command_line = ["%s" % TEMP_FILE.name]
loc_db = LocationDB()
sb = Sandbox_Linux_x86_64(loc_db, options.filename, options, globals())

# Init segment
sb.jitter.lifter.do_stk_segm = True
sb.jitter.lifter.do_ds_segm = True
sb.jitter.lifter.do_str_segm = True
sb.jitter.lifter.do_all_segm = True
FS_0_ADDR = 0x7ff70000
sb.jitter.cpu.FS = 0x4
sb.jitter.cpu.set_segm_base(sb.jitter.cpu.FS, FS_0_ADDR)
sb.jitter.vm.add_memory_page(
    FS_0_ADDR + 0x28,
    PAGE_READ,
    b"\x42\x42\x42\x42\x42\x42\x42\x42",
    "Stack canary FS[0x28]"
)

# Prepare the execution
sb.jitter.init_run(sb.entry_point)


#### This part handle the DSE ####
from miasm.analysis.dse import DSEPathConstraint
from miasm.analysis.machine import Machine


# File "management"

class SymbolicFile(object):
    """Symbolic file with read operation, returning symbolic bytes"""

    def __init__(self, fname):
        self.fname = fname
        self.position = 0
        self.max_size = os.stat(fname).st_size
        self.gen_bytes = {}
        self.state = "OPEN"

    def read(self, length):
        assert self.state == "OPEN"
        out = []
        for i in range(self.position, min(self.position + length,
                                           self.max_size)):
            if i not in self.gen_bytes:
                ret = ExprId("SF_%08x_%d" % (id(self), i), 8)
                self.gen_bytes[i] = ret
            out.append(self.gen_bytes[i])
            self.position += 1

        return out

    def close(self):
        self.state = "CLOSE"


FILE_to_info_symb = {}
FILE_stream = ExprId("FILE_0", 64)
FILE_size = ExprId("FILE_0_size", 64)

def xxx_fopen_symb(dse):
    regs = dse.lifter.arch.regs
    fname_addr = dse.eval_expr(regs.RDI)
    mode = dse.eval_expr(regs.RSI)
    assert fname_addr.is_int()
    assert mode.is_int()
    fname = get_win_str_a(dse.jitter, int(fname_addr))
    ret_addr = ExprInt(dse.jitter.get_stack_arg(0), regs.RIP.size)

    assert len(FILE_to_info_symb) == 0
    ret_value = FILE_stream
    FILE_to_info_symb[ret_value] = SymbolicFile(fname)

    dse.update_state({
        regs.RSP: dse.eval_expr(regs.RSP + ExprInt(8, regs.RSP.size)),
        dse.lifter.IRDst: ret_addr,
        regs.RIP: ret_addr,
        regs.RAX: ret_value,
    })

def xxx_fread_symb(dse):
    regs = dse.lifter.arch.regs
    ptr = dse.eval_expr(regs.RDI)
    size = dse.eval_expr(regs.RSI)
    nmemb = dse.eval_expr(regs.RDX)
    stream = dse.eval_expr(regs.RCX)

    assert size.is_int()
    assert nmemb.is_int()

    # Fill the buffer with symbolic bytes
    update = {}
    sf = FILE_to_info_symb[stream]
    data = sf.read(int(size) * int(nmemb))
    for i, content in enumerate(data):
        addr = dse.symb.expr_simp(ptr + ExprInt(i, ptr.size))
        update[ExprMem(addr, 8)] = content

    ret_addr = ExprInt(dse.jitter.get_stack_arg(0), regs.RIP.size)
    ret_value = FILE_size

    update.update({
        regs.RSP: dse.symb.eval_expr(regs.RSP + ExprInt(8, regs.RSP.size)),
        dse.lifter.IRDst: ret_addr,
        regs.RIP: ret_addr,
        regs.RAX: ret_value,
    })
    dse.update_state(update)

def xxx_fclose_symb(dse):
    regs = dse.lifter.arch.regs
    stream = dse.eval_expr(regs.RDI)
    FILE_to_info_symb[stream].close()

    ret_addr = ExprInt(dse.jitter.get_stack_arg(0), regs.RIP.size)
    dse.update_state({
        regs.RSP: dse.symb.eval_expr(regs.RSP + ExprInt(8, regs.RSP.size)),
        dse.lifter.IRDst: ret_addr,
        regs.RIP: ret_addr,
        regs.RAX: ExprInt(0, regs.RAX.size),
    })

# Symbolic naive version of _libc_start_main

def xxx___libc_start_main_symb(dse):
    # ['RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9']
    # main, argc, argv, ...
    regs = dse.lifter.arch.regs
    top_stack = dse.eval_expr(regs.RSP)
    main_addr = dse.eval_expr(regs.RDI)
    argc = dse.eval_expr(regs.RSI)
    argv = dse.eval_expr(regs.RDX)
    hlt_addr = ExprInt(sb.CALL_FINISH_ADDR, 64)

    dse.update_state({
        ExprMem(top_stack, 64): hlt_addr,
        regs.RDI: argc,
        regs.RSI: argv,
        dse.lifter.IRDst: main_addr,
        dse.lifter.pc: main_addr,
    })

# Stop the execution on puts and get back the corresponding string
class FinishOn(Exception):

    def __init__(self, string):
        self.string = string
        super(FinishOn, self).__init__()

def xxx_puts_symb(dse):
    string = get_win_str_a(dse.jitter, dse.jitter.cpu.RDI)
    raise FinishOn(string)


todo = set([b""]) # Set of file content to test

# Instantiate the DSE engine
machine = Machine("x86_64")
# Convert strategy to the correct value
strategy = {
    "code-cov": DSEPathConstraint.PRODUCE_SOLUTION_CODE_COV,
    "branch-cov": DSEPathConstraint.PRODUCE_SOLUTION_BRANCH_COV,
    "path-cov": DSEPathConstraint.PRODUCE_SOLUTION_PATH_COV,
}[options.strategy]
dse = DSEPathConstraint(machine, loc_db, produce_solution=strategy)

# Attach to the jitter
dse.attach(sb.jitter)

# Update the jitter state: df is read, but never set
# Approaches: specific or generic
# - Specific:
#   df_value = ExprInt(sb.jitter.cpu.df, dse.lifter.arch.regs.df.size)
#   dse.update_state({
#       dse.lifter.arch.regs.df: df_value
#   })
# - Generic:
dse.update_state_from_concrete()

# Add constraint on file size, we don't want to generate too big FILE
z3_file_size = dse.z3_trans.from_expr(FILE_size)
dse.cur_solver.add(0 < z3_file_size)
dse.cur_solver.add(z3_file_size < 0x10)

# Register symbolic stubs for extern functions (xxx_puts_symb, ...)
dse.add_lib_handler(sb.libs, globals())

# Automatic exploration of solution

## Save the current clean state, before any computation of the FILE content
snapshot = dse.take_snapshot()
found = False

while todo:
    # Prepare a solution to try, based on the clean state
    file_content = todo.pop()
    print("CUR: %r" % file_content)
    open(TEMP_FILE.name, "wb").write(file_content)
    dse.restore_snapshot(snapshot, keep_known_solutions=True)
    FILE_to_info.clear()
    FILE_to_info_symb.clear()

    # Play the current file
    try:
        sb.run()
    except FinishOn as finish_info:
        print(finish_info.string)
        if finish_info.string == "OK":
            # Stop if the expected result is found
            found = True
            break

    finfo = FILE_to_info_symb[FILE_stream]
    for sol_ident, model in viewitems(dse.new_solutions):
        # Build the file corresponding to solution in 'model'

        out = []
        fsize = max(model.eval(dse.z3_trans.from_expr(FILE_size)).as_long(),
                    len(finfo.gen_bytes))
        for index in range(fsize):
            try:
                byteid = finfo.gen_bytes[index]
                out.append(int_to_byte(model.eval(dse.z3_trans.from_expr(byteid)).as_long()))
            except (KeyError, AttributeError) as _:
                # Default value if there is no constraint on current byte
                out.append(b"\x00")

        todo.add(b"".join(out))

# Assert that the result has been found
assert found == True
print("FOUND !")

TEMP_FILE.close()

# Replay for real
if not is_win:
    print("Trying to launch the binary without Miasm")
    crackme = subprocess.Popen([options.filename, TEMP_FILE.name],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, stderr = crackme.communicate()
    assert not stderr
    os.unlink(TEMP_FILE.name)
    stdout = stdout.strip()
    print(stdout)
    assert stdout == b"OK"
else:
    os.unlink(TEMP_FILE.name)

