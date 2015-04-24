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
        self._ctx = dict(m2_expr.__dict__)
        self._ctx["irbloc"] = irbloc
        self._functions = {}

        # Update context
        self._ctx.update(ctx)

    @property
    def functions(self):
        """Return a dictionnary name -> func of parsed functions"""
        return self._functions.copy()

    @staticmethod
    def _create_labels():
        """Return the AST standing for label creations"""
        out = ast.parse("lbl_end = ExprId(ir.get_next_instr(instr))").body
        out += ast.parse("lbl_if = ExprId(ir.gen_label())").body
        return out

    def _parse_body(self, body, argument_names):
        """Recursive function transforming a @body to a block expression
        Return:
         - AST to append to body (real python statements)
         - a list of blocks, ie list of affblock, ie list of ExprAff (AST)"""

        # Init
        ## Real instructions
        real_body = []
        ## Final blocks
        blocks = [[[]]]

        for statement in body:

            if isinstance(statement, ast.Assign):
                src = self.transformer.visit(statement.value)
                dst = self.transformer.visit(statement.targets[0])

                if (isinstance(dst, ast.Name) and
                    dst.id not in argument_names and
                    dst.id not in self._ctx):

                    # Real variable declaration
                    statement.value = src
                    real_body.append(statement)
                    continue

                dst.ctx = ast.Load()

                res = ast.Call(func=ast.Name(id='ExprAff',
                                             ctx=ast.Load()),
                               args=[dst, src],
                               keywords=[],
                               starargs=None,
                               kwargs=None)

                blocks[-1][-1].append(res)

            elif (isinstance(statement, ast.Expr) and
                  isinstance(statement.value, ast.Str)):
                # String (docstring, comment, ...) -> keep it
                real_body.append(statement)

            elif (isinstance(statement, ast.If) and
                  not statement.orelse):
                # Create jumps : ir.IRDst = lbl_if if cond else lbl_end
                cond = statement.test
                real_body += self._create_labels()

                lbl_end = ast.Name(id='lbl_end', ctx=ast.Load())
                lbl_if = ast.Name(id='lbl_if', ctx=ast.Load())
                dst = ast.Call(func=ast.Name(id='ExprCond',
                                             ctx=ast.Load()),
                               args=[cond,
                                     lbl_if,
                                     lbl_end],
                               keywords=[],
                               starargs=None,
                               kwargs=None)

                if (isinstance(cond, ast.UnaryOp) and
                    isinstance(cond.op, ast.Not)):
                    ## if not cond -> switch exprCond
                    dst.args[1:] = dst.args[1:][::-1]
                    dst.args[0] = cond.operand

                IRDst = ast.Attribute(value=ast.Name(id='ir',
                                                     ctx=ast.Load()),
                                      attr='IRDst', ctx=ast.Load())
                blocks[-1][-1].append(ast.Call(func=ast.Name(id='ExprAff',
                                                             ctx=ast.Load()),
                                               args=[IRDst, dst],
                                               keywords=[],
                                               starargs=None,
                                               kwargs=None))

                # Create the new blocks
                sub_blocks, sub_body = self._parse_body(statement.body,
                                                        argument_names)
                if len(sub_blocks) > 1:
                    raise RuntimeError("Imbricated if unimplemented")

                ## Close the last block
                jmp_end = ast.Call(func=ast.Name(id='ExprAff',
                                                 ctx=ast.Load()),
                                   args=[IRDst, lbl_end],
                                   keywords=[],
                                   starargs=None,
                                   kwargs=None)
                sub_blocks[-1][-1].append(jmp_end)
                sub_blocks[-1][-1] = ast.List(elts=sub_blocks[-1][-1],
                                              ctx=ast.Load())
                sub_blocks[-1] = ast.List(elts=sub_blocks[-1],
                                          ctx=ast.Load())

                ## Replace the block with a call to 'irbloc'
                lbl_if_name = ast.Attribute(value=ast.Name(id='lbl_if',
                                                           ctx=ast.Load()),
                                            attr='name', ctx=ast.Load())

                sub_blocks[-1] = ast.Call(func=ast.Name(id='irbloc',
                                                        ctx=ast.Load()),
                                          args=[lbl_if_name,
                                                sub_blocks[-1]],
                                          keywords=[],
                                          starargs=None,
                                          kwargs=None)
                blocks += sub_blocks
                real_body += sub_body

                # Prepare a new block for following statement
                blocks.append([[]])

            else:
                # TODO: real var, +=, /=, -=, <<=, >>=, if/else, ...
                raise RuntimeError("Unimplemented %s" % statement)

        return blocks, real_body

    def parse(self, func):
        """Function decorator, returning a correct method from a pseudo-Python
        one"""

        # Get the function AST
        parsed = ast.parse(inspect.getsource(func))
        fc_ast = parsed.body[0]
        argument_names = [name.id for name in fc_ast.args.args]

        # Translate (blocks[0][0] is the current instr)
        blocks, body = self._parse_body(fc_ast.body, argument_names)

        # Build the new function
        fc_ast.args.args[0:0] = [ast.Name(id='ir', ctx=ast.Param()),
                                 ast.Name(id='instr', ctx=ast.Param())]
        cur_instr = blocks[0][0]
        if len(blocks[-1][0]) == 0:
            ## Last block can be empty
            blocks.pop()
        other_blocks = blocks[1:]
        body.append(ast.Return(value=ast.Tuple(elts=[ast.List(elts=cur_instr,
                                                              ctx=ast.Load()),
                                                     ast.List(elts=other_blocks,
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
        ctx = self._ctx.copy()
        eval(codeobj, ctx)

        # Get the function back
        self._functions[fc_ast.name] = ctx[fc_ast.name]
        return ctx[fc_ast.name]
