from miasm.expression.expression import *


def dissect_test(expr, expr_type, result):
    if isinstance(expr, expr_type):
        result.add(expr)
        return False
    return True


def dissect_visit(expr, expr_type):
    result = set()
    expr.visit(lambda expr: expr,
               lambda expr: dissect_test(expr, expr_type, result))
    return result


def gen_smt_mem_read(m, arch_size):
    """
    Generates a expression which will
    return a value from memory of the form
    mem_read(M, addr, size),
    where @M is the memory, @addr the
    value's address and @size the size
    of the value to be read.
    The value will be the slice of the
    read value of size m.size.
    :param m: memory expression
    :param mem_name: string, name of memory variable
    :return: ExprSlice of size m.size
    """
    mem = ExprId("M", arch_size)
    addr = zero_padding(m.ptr, arch_size)
    size = ExprInt(m.size, arch_size)
    op = ExprOp("mem_read", mem, addr, size)

    return ExprSlice(op, 0, m.size)


def gen_smt_mem_write(e, arch_size):
    """
    Generates an expression of the form
    M = mem_write(M, addr, val, size),
    where @val is a value of size @size
    which will be written in memory @M at
    address @addr.
    :param e: ExprAssign
    :param mem_name: string, name of memory variable
    :return: ExprAssign
    """
    dst = e.dst
    src = e.src

    mem = ExprId("M", arch_size)
    addr = zero_padding(dst.ptr, arch_size)
    val = zero_padding(src, arch_size)
    size = ExprInt(src.size, arch_size)
    op = ExprOp("mem_write", mem, addr, val, size)
    return ExprAssign(mem, op)


def zero_padding(v, arch_size):
    """
    Paddes a value to the architecture's bit size with zero
    :param v: parameter to be padded
    :return: padded parameter
    """
    # v is smaller than architecture's bit size
    if v.size < arch_size:
        i = ExprInt(0, arch_size)
        slice = ExprSlice(i, 0, i.size - v.size)
        return ExprCompose(v, slice)

    return v


def rewrite_memory_read(e, arch_size):
    """
    Rewrites all memory read expressions
    in an expression to
    mem_read(M, address, size)
    :param e: expression
    :return: rewritten expression
    """
    # parse all memory expressions
    e_new = e
    memory = dissect_visit(e, ExprMem)
    # iterate memory expressions
    for m in memory:
        # create mem_read expression
        mem_read = gen_smt_mem_read(m, arch_size)
        # replace memory expression with mem_read expression
        e_new = e_new.replace_expr({m: mem_read})

    return e_new


def rewrite_memory(e, arch_size):
    """
    Rewrites memory expressions in an ExprAff to

    - mem_read(M, address, size)
    - M = mem_write(M, address, value, size)

    :param e: ExprAssign
    :return: ExprAssign with transformed memory expressions
    """
    dst = e.dst.copy()
    src = e.src.copy()

    # memory expression on LHS: create mem_write expressions
    if isinstance(dst, ExprMem):
        # rewrite all memory read expressions
        src_new = rewrite_memory_read(src, arch_size)

        # generate mem_write expression
        mem_write = ExprAssign(dst, src_new)

        # recreate expression
        e_new = gen_smt_mem_write(mem_write, arch_size)

    # no memory expression on LHS: create mem_read expressions
    else:
        # rewrite all memory read expressions
        src_new = rewrite_memory_read(src, arch_size)

        # recreate expression
        e_new = ExprAssign(dst, src_new)

    return e_new
