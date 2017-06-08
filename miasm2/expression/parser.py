import pyparsing
from miasm2.expression.expression import ExprInt, ExprId, ExprSlice, ExprMem, \
    ExprCond, ExprCompose, ExprOp, ExprAff

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
STR_EXPRSLICE = pyparsing.Suppress("ExprSlice")
STR_EXPRMEM = pyparsing.Suppress("ExprMem")
STR_EXPRCOND = pyparsing.Suppress("ExprCond")
STR_EXPRCOMPOSE = pyparsing.Suppress("ExprCompose")
STR_EXPROP = pyparsing.Suppress("ExprOp")
STR_EXPRAFF = pyparsing.Suppress("ExprAff")

STR_COMMA = pyparsing.Suppress(",")
LPARENTHESIS = pyparsing.Suppress("(")
RPARENTHESIS = pyparsing.Suppress(")")


string_quote = pyparsing.QuotedString(quoteChar="'", escChar='\\', escQuote='\\')
string_dquote = pyparsing.QuotedString(quoteChar='"', escChar='\\', escQuote='\\')


string = string_quote | string_dquote

expr = pyparsing.Forward()

expr_int = pyparsing.Group(STR_EXPRINT + LPARENTHESIS + str_int + STR_COMMA + str_int + RPARENTHESIS)
expr_id = pyparsing.Group(STR_EXPRID + LPARENTHESIS + string + STR_COMMA + str_int + RPARENTHESIS)
expr_slice = pyparsing.Group(STR_EXPRSLICE + LPARENTHESIS + expr + STR_COMMA + str_int + STR_COMMA + str_int + RPARENTHESIS)
expr_mem = pyparsing.Group(STR_EXPRMEM + LPARENTHESIS + expr + STR_COMMA + str_int + RPARENTHESIS)
expr_cond = pyparsing.Group(STR_EXPRCOND + LPARENTHESIS + expr + STR_COMMA + expr + STR_COMMA + expr + RPARENTHESIS)
expr_compose = pyparsing.Group(STR_EXPRCOMPOSE + LPARENTHESIS + pyparsing.delimitedList(expr, delim=',') + RPARENTHESIS)
expr_op = pyparsing.Group(STR_EXPROP + LPARENTHESIS + string + STR_COMMA + pyparsing.delimitedList(expr, delim=',') + RPARENTHESIS)
expr_aff = pyparsing.Group(STR_EXPRAFF + LPARENTHESIS + expr + STR_COMMA + expr + RPARENTHESIS)

expr << (expr_int | expr_id | expr_slice | expr_mem | expr_cond | \
         expr_compose | expr_op | expr_aff)

expr_int.setParseAction(lambda t: ExprInt(*t[0]))
expr_id.setParseAction(lambda t: ExprId(*t[0]))
expr_slice.setParseAction(lambda t: ExprSlice(*t[0]))
expr_mem.setParseAction(lambda t: ExprMem(*t[0]))
expr_cond.setParseAction(lambda t: ExprCond(*t[0]))
expr_compose.setParseAction(lambda t: ExprCompose(*t[0]))
expr_op.setParseAction(lambda t: ExprOp(*t[0]))
expr_aff.setParseAction(lambda t: ExprAff(*t[0]))


def str_to_expr(str_in):
    """Parse the @str_in and return the corresponoding Expression
    @str_in: repr string of an Expression"""

    try:
        value = expr.parseString(str_in)
    except:
        raise RuntimeError("Cannot parse expression %s" % str_in)
    assert len(value) == 1
    return value[0]
