from future.utils import viewitems

import miasm.expression.expression as m2_expr
from miasm.core.utils import BoundedDict


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
    def to_language(cls, target_lang, *args, **kwargs):
        """Return the corresponding translator instance
        @target_lang: str (case insensitive) wanted language
        Raise a NotImplementedError in case of unmatched language
        """
        target_lang = target_lang.lower()
        for translator in cls.available_translators:
            if translator.__LANG__.lower() == target_lang:
                return translator(*args, **kwargs)

        raise NotImplementedError("Unknown target language: %s" % target_lang)

    @classmethod
    def available_languages(cls):
        "Return the list of registered languages"
        return [translator.__LANG__ for translator in cls.available_translators]

    def __init__(self, cache_size=1000):
        """Instance a translator
        @cache_size: (optional) Expr cache size
        """
        self._cache = BoundedDict(cache_size)

    def from_ExprInt(self, expr):
        """Translate an ExprInt
        @expr: ExprInt to translate
        """
        raise NotImplementedError("Abstract method")

    def from_ExprId(self, expr):
        """Translate an ExprId
        @expr: ExprId to translate
        """
        raise NotImplementedError("Abstract method")

    def from_ExprLoc(self, expr):
        """Translate an ExprLoc
        @expr: ExprLoc to translate
        """
        raise NotImplementedError("Abstract method")

    def from_ExprCompose(self, expr):
        """Translate an ExprCompose
        @expr: ExprCompose to translate
        """
        raise NotImplementedError("Abstract method")

    def from_ExprSlice(self, expr):
        """Translate an ExprSlice
        @expr: ExprSlice to translate
        """
        raise NotImplementedError("Abstract method")

    def from_ExprOp(self, expr):
        """Translate an ExprOp
        @expr: ExprOp to translate
        """
        raise NotImplementedError("Abstract method")

    def from_ExprMem(self, expr):
        """Translate an ExprMem
        @expr: ExprMem to translate
        """
        raise NotImplementedError("Abstract method")

    def from_ExprAssign(self, expr):
        """Translate an ExprAssign
        @expr: ExprAssign to translate
        """
        raise NotImplementedError("Abstract method")

    def from_ExprCond(self, expr):
        """Translate an ExprCond
        @expr: ExprCond to translate
        """
        raise NotImplementedError("Abstract method")

    def from_expr(self, expr):
        """Translate an expression according to its type
        @expr: expression to translate
        """
        # Use cache
        if expr in self._cache:
            return self._cache[expr]

        # Handle Expr type
        handlers = {
            m2_expr.ExprInt: self.from_ExprInt,
            m2_expr.ExprId: self.from_ExprId,
            m2_expr.ExprLoc: self.from_ExprLoc,
            m2_expr.ExprCompose: self.from_ExprCompose,
            m2_expr.ExprSlice: self.from_ExprSlice,
            m2_expr.ExprOp: self.from_ExprOp,
            m2_expr.ExprMem: self.from_ExprMem,
            m2_expr.ExprAssign: self.from_ExprAssign,
            m2_expr.ExprCond: self.from_ExprCond
        }
        for target, handler in viewitems(handlers):
            if isinstance(expr, target):
                ## Compute value and update the internal cache
                ret = handler(expr)
                self._cache[expr] = ret
                return ret
        raise ValueError("Unhandled type for %s" % expr)

