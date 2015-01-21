"""IR Translators"""
from miasm2.ir.translators.translator import Translator
import miasm2.ir.translators.C
import miasm2.ir.translators.python
import miasm2.ir.translators.miasm

__all__ = ["Translator"]
