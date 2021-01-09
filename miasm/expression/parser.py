import pyparsing
from miasm.expression.expression import ExprInt, ExprId, ExprLoc, ExprSlice, \
    ExprMem, ExprCond, ExprCompose, ExprOp, ExprAssign, LocKey

integer = pyparsing.Word(pyparsing.nums).setParseAction(lambda t:
                                                        int(t[0]))
hex_word = pyparsing.Literal('0x') + pyparsing.Word(pyparsing.hexnums)
hex_int = pyparsing.Combine(hex_word).setParseAction(lambda t:
                                                     int(t[0], 16))

str_int_pos = (hex_int | integer)
str_int_neg = (pyparsing.Suppress('-') + \
                   (hex_int | integer)).setParseAction(lambda t: -t[0])

str_int = str_int_pos | str_int_neg

STR_EXPRINT = pyparsing.Suppress("ExprInt")
STR_EXPRID = pyparsing.Suppress("ExprId")
STR_EXPRLOC = pyparsing.Suppress("ExprLoc")
STR_EXPRSLICE = pyparsing.Suppress("ExprSlice")
STR_EXPRMEM = pyparsing.Suppress("ExprMem")
STR_EXPRCOND = pyparsing.Suppress("ExprCond")
STR_EXPRCOMPOSE = pyparsing.Suppress("ExprCompose")
STR_EXPROP = pyparsing.Suppress("ExprOp")
STR_EXPRASSIGN = pyparsing.Suppress("ExprAssign")

LOCKEY = pyparsing.Suppress("LocKey")

STR_COMMA = pyparsing.Suppress(",")
LPARENTHESIS = pyparsing.Suppress("(")
RPARENTHESIS = pyparsing.Suppress(")")


T_INF = pyparsing.Suppress("<")
T_SUP = pyparsing.Suppress(">")


string_quote = pyparsing.QuotedString(quoteChar="'", escChar='\\', escQuote='\\')
string_dquote = pyparsing.QuotedString(quoteChar='"', escChar='\\', escQuote='\\')


string = string_quote | string_dquote

expr = pyparsing.Forward()

expr_int = STR_EXPRINT + LPARENTHESIS + str_int + STR_COMMA + str_int + RPARENTHESIS
expr_id = STR_EXPRID + LPARENTHESIS + string + STR_COMMA + str_int + RPARENTHESIS
expr_loc = STR_EXPRLOC + LPARENTHESIS + T_INF + LOCKEY + str_int + T_SUP + STR_COMMA + str_int + RPARENTHESIS
expr_slice = STR_EXPRSLICE + LPARENTHESIS + expr + STR_COMMA + str_int + STR_COMMA + str_int + RPARENTHESIS
expr_mem = STR_EXPRMEM + LPARENTHESIS + expr + STR_COMMA + str_int + RPARENTHESIS
expr_cond = STR_EXPRCOND + LPARENTHESIS + expr + STR_COMMA + expr + STR_COMMA + expr + RPARENTHESIS
expr_compose = STR_EXPRCOMPOSE + LPARENTHESIS + pyparsing.delimitedList(expr, delim=',') + RPARENTHESIS
expr_op = STR_EXPROP + LPARENTHESIS + string + STR_COMMA + pyparsing.delimitedList(expr, delim=',') + RPARENTHESIS
expr_aff = STR_EXPRASSIGN + LPARENTHESIS + expr + STR_COMMA + expr + RPARENTHESIS

expr << (expr_int | expr_id | expr_loc | expr_slice | expr_mem | expr_cond | \
         expr_compose | expr_op | expr_aff)

def parse_loc_key(t):
    assert len(t) == 2
    loc_key, size = LocKey(t[0]), t[1]
    return ExprLoc(loc_key, size)

expr_int.setParseAction(lambda t: ExprInt(*t))
expr_id.setParseAction(lambda t: ExprId(*t))
expr_loc.setParseAction(parse_loc_key)
expr_slice.setParseAction(lambda t: ExprSlice(*t))
expr_mem.setParseAction(lambda t: ExprMem(*t))
expr_cond.setParseAction(lambda t: ExprCond(*t))
expr_compose.setParseAction(lambda t: ExprCompose(*t))
expr_op.setParseAction(lambda t: ExprOp(*t))
expr_aff.setParseAction(lambda t: ExprAssign(*t))


def str_to_expr(str_in):
    """Parse the @str_in and return the corresponding Expression
    @str_in: repr string of an Expression"""

    try:
        value = expr.parseString(str_in)
    except:
        raise RuntimeError("Cannot parse expression %s" % str_in)
    assert len(value) == 1
    return value[0]
