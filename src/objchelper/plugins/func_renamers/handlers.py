__all__ = ["GLOBAL_HANDLERS", "LOCAL_HANDLERS"]

import functools

from ida_typeinf import tinfo_t

from objchelper.idahelper import tif
from objchelper.plugins.func_renamers.renamer import FuncHandler, FuncHandlerByNameWithStringFinder, Modifications
from objchelper.plugins.func_renamers.visitor import Call


@functools.cache
def _os_symbol_type() -> tinfo_t | None:
    os_symbol = tif.from_struct_name("OSSymbol")
    if os_symbol is not None:
        return tif.pointer_of(os_symbol)
    return None


class OSSymbol_WithCStringNoCopy(FuncHandlerByNameWithStringFinder):
    def __init__(self):
        super().__init__(
            "OSSymbol::withCStringNoCopy",
            tif.from_func_components("OSSymbol*", [tif.FuncParam("const char*", "cString")]),
            search_string="IOMatchedPersonality",
        )
        self._cached_symbol_type: tinfo_t | None = None

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_assignee_by_index(modifications, call, 0, modifier=lambda name: f"sym_{name}")
        self._retype_assignee(modifications, call, _os_symbol_type())


class OSSymbol_WithCString(FuncHandlerByNameWithStringFinder):
    def __init__(self):
        super().__init__(
            "OSSymbol::withCString",
            tif.from_func_components("OSSymbol*", [tif.FuncParam("const char*", "cString")]),
            search_string="ACIPCInterfaceProtocol",
        )
        self._cached_symbol_type: tinfo_t | None = None

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_assignee_by_index(modifications, call, 0, modifier=lambda name: f"sym_{name}")
        self._retype_assignee(modifications, call, _os_symbol_type())


GLOBAL_HANDLERS: list[FuncHandler] = [OSSymbol_WithCStringNoCopy(), OSSymbol_WithCString()]
LOCAL_HANDLERS: list[FuncHandler] = []
