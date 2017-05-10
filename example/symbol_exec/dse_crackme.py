"""Example of DynamicSymbolicExecution engine use

This example should run on the compiled ELF x86 64bits version of
"dse_crackme.c"

"""

#### This part is only related to the run of the sample, without DSE ####
import os
import subprocess
from collections import namedtuple
from pdb import pm

from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.analysis.sandbox import Sandbox_Linux_x86_64
from miasm2.expression.expression import *

# File "management"
my_FILE_ptr = 0x11223344
FInfo = namedtuple("FInfo", ["path", "fdesc"])
FILE_to_info = {}
def xxx_fopen(jitter):
    '''
    #include <stdio.h>

    FILE *fopen(const char *path, const char *mode);
    '''
    global my_FILE_ptr
    ret_addr, args = jitter.func_args_systemv(['path', 'mode'])
    fname = jitter.get_str_ansi(args.path)
    FILE_to_info[my_FILE_ptr] = FInfo(fname, open(fname))
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
options = parser.parse_args()
options.mimic_env = True
sb = Sandbox_Linux_x86_64(options.filename, options, globals())

# Init segment
sb.jitter.ir_arch.do_stk_segm = True
sb.jitter.ir_arch.do_ds_segm = True
sb.jitter.ir_arch.do_str_segm = True
sb.jitter.ir_arch.do_all_segm = True
FS_0_ADDR = 0x7ff70000
sb.jitter.cpu.FS = 0x4
sb.jitter.cpu.set_segm_base(sb.jitter.cpu.FS, FS_0_ADDR)
sb.jitter.vm.add_memory_page(
    FS_0_ADDR + 0x28, PAGE_READ, "\x42\x42\x42\x42\x42\x42\x42\x42",
    "Stack canary FS[0x28]")

# Prepare the execution
sb.jitter.init_run(sb.entry_point)


#### This part handle the DSE ####
from miasm2.analysis.dse import DSEPathConstraint
from miasm2.analysis.machine import Machine


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
        for i in xrange(self.position, min(self.position + length,
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
    regs = dse.ir_arch.arch.regs
    fname_addr = dse.eval_expr(regs.RDI)
    mode = dse.eval_expr(regs.RSI)
    assert fname_addr.is_int()
    assert mode.is_int()
    fname = dse.jitter.get_str_ansi(int(fname_addr))
    ret_addr = ExprInt(dse.jitter.get_stack_arg(0), regs.RIP.size)

    assert len(FILE_to_info_symb) == 0
    ret_value = FILE_stream
    FILE_to_info_symb[ret_value] = SymbolicFile(fname)

    dse.update_state({
        regs.RSP: dse.eval_expr(regs.RSP + ExprInt(8, regs.RSP.size)),
        dse.ir_arch.IRDst: ret_addr,
        regs.RIP: ret_addr,
        regs.RAX: ret_value,
    })

def xxx_fread_symb(dse):
    regs = dse.ir_arch.arch.regs
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
        dse.ir_arch.IRDst: ret_addr,
        regs.RIP: ret_addr,
        regs.RAX: ret_value,
    })
    dse.update_state(update)

def xxx_fclose_symb(dse):
    regs = dse.ir_arch.arch.regs
    stream = dse.eval_expr(regs.RDI)
    FILE_to_info_symb[stream].close()

    ret_addr = ExprInt(dse.jitter.get_stack_arg(0), regs.RIP.size)
    dse.update_state({
        regs.RSP: dse.symb.eval_expr(regs.RSP + ExprInt(8, regs.RSP.size)),
        dse.ir_arch.IRDst: ret_addr,
        regs.RIP: ret_addr,
        regs.RAX: ExprInt(0, regs.RAX.size),
    })

# Symbolic naive version of _libc_start_main

def xxx___libc_start_main_symb(dse):
    # ['RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9']
    # main, argc, argv, ...
    regs = dse.ir_arch.arch.regs
    top_stack = dse.eval_expr(regs.RSP)
    main_addr = dse.eval_expr(regs.RDI)
    argc = dse.eval_expr(regs.RSI)
    argv = dse.eval_expr(regs.RDX)
    hlt_addr = ExprInt(0x1337beef, 64)

    dse.update_state({
        ExprMem(top_stack, 64): hlt_addr,
        regs.RDI: argc,
        regs.RSI: argv,
        dse.ir_arch.IRDst: main_addr,
        dse.ir_arch.pc: main_addr,
    })

# Stop the execution on puts and get back the corresponding string
class FinnishOn(Exception):

    def __init__(self, string):
        self.string = string
        super(FinnishOn, self).__init__()

def xxx_puts_symb(dse):
    string = dse.jitter.get_str_ansi(dse.jitter.cpu.RDI)
    raise FinnishOn(string)


done = set([]) # Set of jump address already handled
todo = set([""]) # Set of file content to test

class DSEGenFile(DSEPathConstraint):
    """DSE with a specific solution creation:
    The solution is the content of the FILE to be read

    The politics of exploration is the branch coverage: create a solution only
    if the target address has never been seen
    """

    def handle_solution(self, model, destination):
        global todo, done
        assert destination.is_int()

        if destination in done:
            # Skip this path, already treated
            return

        finfo = FILE_to_info_symb[FILE_stream]

        # Build corresponding file
        out = ""
        fsize = max(model.eval(self.z3_trans.from_expr(FILE_size)).as_long(),
                    len(finfo.gen_bytes))
        for index in xrange(fsize):
            try:
                byteid = finfo.gen_bytes[index]
                out += chr(model.eval(self.z3_trans.from_expr(byteid)).as_long())
            except (KeyError, AttributeError) as _:
                # Default value if there is no constraint on current byte
                out += "\x00"

        todo.add(out)
        done.add(destination)

# Instanciate the DSE engine
machine = Machine("x86_64")
dse = DSEGenFile(machine)

# Attach to the jitter
dse.attach(sb.jitter)

# Update the jitter state: df is read, but never set
# Approachs: specific or generic
# - Specific:
#   df_value = ExprInt(sb.jitter.cpu.df, dse.ir_arch.arch.regs.df.size)
#   dse.update_state({
#       dse.ir_arch.arch.regs.df: df_value
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
    print "CUR: %r" % file_content
    open("test.txt", "w").write(file_content)
    dse.restore_snapshot(snapshot)
    FILE_to_info.clear()
    FILE_to_info_symb.clear()

    # Play the current file
    try:
        sb.run()
    except FinnishOn as finnish_info:
        print finnish_info.string
        if finnish_info.string == "OK":
            # Stop if the expected result is found
            found = True
            break

# Assert that the result has been found
assert found == True
print "FOUND !"

# Replay for real
print "Trying to launch the binary without Miasm"
crackme = subprocess.Popen([options.filename], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
stdout, stderr = crackme.communicate()
assert not stderr
stdout = stdout.strip()
print stdout
assert stdout == "OK"
