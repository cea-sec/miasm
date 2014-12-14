import miasm2.expression.expression as m2_expr


class Translator(object):
    "Abstract parent class for translators."

    # Registered translators
    available_translators = []
    # Implemented language
    __LANG__ = ""

    @classmethod
    def register(cls, translator):
        """Register a translator
        @translator: Translator sub-class
        """
        cls.available_translators.append(translator)

    @classmethod
    def to_language(cls, target_lang):
        """Return the corresponding translator
        @target_lang: str (case insensitive) wanted language
        Raise a NotImplementedError in case of unmatched language
        """
        target_lang = target_lang.lower()
        for translator in cls.available_translators:
            if translator.__LANG__.lower() == target_lang:
                return translator

        raise NotImplementedError("Unknown target language: %s" % target_lang)

    @classmethod
    def available_languages(cls):
        "Return the list of registered languages"
        return [translator.__LANG__ for translator in cls.available_translators]

    @classmethod
    def from_ExprInt(cls, expr):
        """Translate an ExprInt
        @expr: ExprInt to translate
        """
        raise NotImplementedError("Abstract method")

    @classmethod
    def from_ExprId(cls, expr):
        """Translate an ExprId
        @expr: ExprId to translate
        """
        raise NotImplementedError("Abstract method")

    @classmethod
    def from_ExprCompose(cls, expr):
        """Translate an ExprCompose
        @expr: ExprCompose to translate
        """
        raise NotImplementedError("Abstract method")

    @classmethod
    def from_ExprSlice(cls, expr):
        """Translate an ExprSlice
        @expr: ExprSlice to translate
        """
        raise NotImplementedError("Abstract method")

    @classmethod
    def from_ExprOp(cls, expr):
        """Translate an ExprOp
        @expr: ExprOp to translate
        """
        raise NotImplementedError("Abstract method")

    @classmethod
    def from_ExprMem(cls, expr):
        """Translate an ExprMem
        @expr: ExprMem to translate
        """
        raise NotImplementedError("Abstract method")

    @classmethod
    def from_ExprAff(cls, expr):
        """Translate an ExprAff
        @expr: ExprAff to translate
        """
        raise NotImplementedError("Abstract method")

    @classmethod
    def from_ExprCond(cls, expr):
        """Translate an ExprCond
        @expr: ExprCond to translate
        """
        raise NotImplementedError("Abstract method")

    @classmethod
    def from_expr(cls, expr):
        """Translate an expression according to its type
        @expr: expression to translate
        """
        handlers = {m2_expr.ExprInt: cls.from_ExprInt,
                    m2_expr.ExprId: cls.from_ExprId,
                    m2_expr.ExprCompose: cls.from_ExprCompose,
                    m2_expr.ExprSlice: cls.from_ExprSlice,
                    m2_expr.ExprOp: cls.from_ExprOp,
                    m2_expr.ExprMem: cls.from_ExprMem,
                    m2_expr.ExprAff: cls.from_ExprAff,
                    m2_expr.ExprCond: cls.from_ExprCond
                    }
        for target, handler in handlers.iteritems():
            if isinstance(expr, target):
                return handler(expr)
        raise ValueError("Unhandled type for %s" % expr)

