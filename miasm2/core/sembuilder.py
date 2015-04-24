"Helper to quickly build instruction's semantic side effects"

import inspect
import ast
import re

import miasm2.expression.expression as m2_expr
from miasm2.ir.ir import irbloc


class MiasmTransformer(ast.NodeTransformer):
    """AST visitor translating DSL to Miasm expression

    memX[Y]       -> ExprMem(Y, X)
    iX(Y)         -> ExprIntX(Y)
    X if Y else Z -> ExprCond(Y, X, Z)
    'X'(Y)        -> ExprOp('X', Y)
    ('X' % Y)(Z)  -> ExprOp('X' % Y, Z)
    """

    # Parsers
    parse_integer = re.compile("^i([0-9]+)$")
    parse_mem = re.compile("^mem([0-9]+)$")

    # Visitors

    def visit_Call(self, node):
        """iX(Y) -> ExprIntX(Y),
        'X'(Y) -> ExprOp('X', Y), ('X' % Y)(Z) -> ExprOp('X' % Y, Z)"""
        if isinstance(node.func, ast.Name):
            # iX(Y) -> ExprIntX(Y)
            fc_name = node.func.id

            # Match the function name
            new_name = fc_name
            integer = self.parse_integer.search(fc_name)

            # Do replacement
            if integer is not None:
                new_name = "ExprInt%s" % integer.groups()[0]

            # Replace in the node
            node.func.id = new_name

        elif (isinstance(node.func, ast.Str) or
              (isinstance(node.func, ast.BinOp) and
               isinstance(node.func.op, ast.Mod) and
               isinstance(node.func.left, ast.Str))):
            # 'op'(args...) -> ExprOp('op', args...)
            # ('op' % (fmt))(args...) -> ExprOp('op' % (fmt), args...)
            op_name = node.func

            # Do replacement
            node.func = ast.Name(id="ExprOp", ctx=ast.Load())
            node.args[0:0] = [op_name]
            node.args = map(self.visit, node.args)

        else:
            # TODO: launch visitor on node
            pass

        return node

    def visit_Subscript(self, node):
        """memX[Y] -> ExprMem(Y, X)"""

        # Detect the syntax
        if not isinstance(node.value, ast.Name):
            return node
        name = node.value.id
        mem = self.parse_mem.search(name)
        if mem is None:
            # TODO: launch visitor on node
            return node

        # Do replacement
        addr = self.visit(node.slice.value)
        call = ast.Call(func=ast.Name(id='ExprMem', ctx=ast.Load()),
                        args=[addr, ast.Num(n=int(mem.groups()[0]))],
                        keywords=[], starargs=None, kwargs=None)
        return call

    def visit_IfExp(self, node):
        """X if Y else Z -> ExprCond(Y, X, Z)"""
        call = ast.Call(func=ast.Name(id='ExprCond', ctx=ast.Load()),
                        args=[self.visit(node.test),
                              self.visit(node.body),
                              self.visit(node.orelse)],
                        keywords=[], starargs=None, kwargs=None)
        return call


class SemBuilder(object):
    """Helper for building instruction's semantic side effects method

    This class provides a decorator @parse to use on them.
    The context in which the function will be parsed must be supplied on
    instanciation
    """

    def __init__(self, ctx):
        """Create a SemBuilder
        @ctx: context dictionnary used during parsing
        """
        # Init
        self.transformer = MiasmTransformer()
        self.ctx = dict(m2_expr.__dict__)
        self.ctx["irbloc"] = irbloc

        # Update context
        self.ctx.update(ctx)


    def parse(self, func):
        """Function decorator, returning a correct method from a pseudo-Python
        one"""

        # Get the function AST
        parsed = ast.parse(inspect.getsource(func))
        fc_ast = parsed.body[0]
        argument_names = [name.id for name in fc_ast.args.args]
        body = []

        # AffBlock of the current instruction
        new_ast = []
        for statement in fc_ast.body:

            if isinstance(statement, ast.Assign):
                src = self.transformer.visit(statement.value)
                dst = self.transformer.visit(statement.targets[0])

                if (isinstance(dst, ast.Name) and
                    dst.id not in argument_names and
                    dst.id not in self.ctx):

                    # Real variable declaration
                    statement.value = src
                    body.append(statement)
                    continue

                dst.ctx = ast.Load()

                res = ast.Call(func=ast.Name(id='ExprAff',
                                             ctx=ast.Load()),
                               args=[dst, src],
                               keywords=[],
                               starargs=None,
                               kwargs=None)

                new_ast.append(res)

            elif (isinstance(statement, ast.Expr) and
                  isinstance(statement.value, ast.Str)):
                # String (docstring, comment, ...) -> keep it
                body.append(statement)
            else:
                # TODO: real var, +=, /=, -=, <<=, >>=, if/else, ...
                raise RuntimeError("Unimplemented %s" % statement)

        # Build the new function
        fc_ast.args.args[0:0] = [ast.Name(id='ir', ctx=ast.Param()),
                                 ast.Name(id='instr', ctx=ast.Param())]
        body.append(ast.Return(value=ast.Tuple(elts=[ast.List(elts=new_ast,
                                                              ctx=ast.Load()),
                                                     ast.List(elts=[],
                                                              ctx=ast.Load())],
                                               ctx=ast.Load())))

        ret = ast.Module([ast.FunctionDef(name=fc_ast.name,
                                          args=fc_ast.args,
                                          body=body,
                                          decorator_list=[])])

        # To display the generated function, use codegen.to_source
        # codegen: https://github.com/andreif/codegen

        # Compile according to the context
        fixed = ast.fix_missing_locations(ret)
        codeobj = compile(fixed, '<string>', 'exec')
        ctx = self.ctx.copy()
        eval(codeobj, ctx)

        # Get the function back
        return ctx[fc_ast.name]
