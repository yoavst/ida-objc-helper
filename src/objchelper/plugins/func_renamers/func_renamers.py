import time

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, cfunc_t

from objchelper.idahelper import xrefs
from objchelper.idahelper.microcode import mba
from objchelper.plugins.func_renamers.handlers import GLOBAL_HANDLERS, LOCAL_HANDLERS
from objchelper.plugins.func_renamers.renamer import (
    FuncXref,
    Modifications,
)
from objchelper.plugins.func_renamers.visitor import process_function_calls

ALL_HANDLERS = [*LOCAL_HANDLERS, *GLOBAL_HANDLERS]


def apply_global_rename():
    before = time.time()
    for i, handler in enumerate(GLOBAL_HANDLERS):
        print(f"Applying global rename {i + 1}/{len(GLOBAL_HANDLERS)}: {handler.name}")
        source_xref = handler.get_source_xref()
        if source_xref is None or not isinstance(source_xref, FuncXref):
            print(f"Function {handler.name} has no global source xref, skipping")
            continue
        func_ea = source_xref.ea

        xrefs_in_funcs = xrefs.func_xrefs_to(func_ea)
        if not xrefs_in_funcs:
            print(f"Function {handler.name} not called")
            continue

        print(f"Found {len(xrefs_in_funcs)} functions that call {handler.name}:")
        for j, xref_func_ea in enumerate(xrefs_in_funcs):
            xref_func_ea = 0xFFFFFFF008D63C4C
            with Modifications(xref_func_ea, func_lvars=None) as modifications:
                print(f"  {j + 1}/{len(xrefs_in_funcs)}: {xref_func_ea:#x}")
                process_function_calls(
                    mba.from_func(xref_func_ea), {func_ea: lambda call: handler.on_call(call, modifications)}
                )
    after = time.time()
    print(f"Completed! Took {int(after-before)} seconds")


class LocalRenameHooks(Hexrays_Hooks):
    def maturity(self, cfunc: cfunc_t, new_maturity: int) -> int:
        if new_maturity < ida_hexrays.CMAT_FINAL:
            return 0

        callbacks = {}
        with Modifications(cfunc.entry_ea, func_lvars=cfunc.get_lvars()) as modifications:
            for handler in ALL_HANDLERS:
                source_xref = handler.get_source_xref()
                if source_xref is None:
                    continue
                callbacks[source_xref.ea] = lambda call: handler.on_call(call, modifications)

            process_function_calls(cfunc.mba, callbacks)

        return 0
