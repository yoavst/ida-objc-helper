from ida_funcs import func_t

from objchelper.idahelper import pac, tif
from objchelper.idahelper.ast import cfunc
from objchelper.idahelper.ast.lvars import VariableModification

from .renamer import (
    Modifications,
)
from .visitor import Call, XrefsMatcher, process_function_calls


def apply_pac(func: func_t):
    print(f"Trying to apply pac signature on current function: {func.start_ea:X}")
    xref_matcher = XrefsMatcher.build([], on_unknown_call)  # type: ignore  # noqa: PGH003
    decompiled_func = cfunc.from_func(func)
    if decompiled_func is None:
        return

    with Modifications(decompiled_func.entry_ea, decompiled_func.get_lvars()) as modifications:
        process_function_calls(decompiled_func.mba, xref_matcher, modifications)


def on_unknown_call(call: Call, modifications: Modifications):
    """Called when a call is found"""
    if call.indirect_info is None:
        return

    lvar, _ = call.indirect_info
    prev_mvok = pac.get_previous_movk(call.ea)
    if prev_mvok is None:
        return
    candidates = pac.pac_class_candidates_from_movk(prev_mvok)
    ancestor = tif.get_common_ancestor(candidates)
    if ancestor is not None:
        modifications.modify_local(lvar.name, VariableModification(type=tif.pointer_of(ancestor)))
        print(f"Applying PAC call info on {lvar.name}. Changing its type to {ancestor.dstr()}")
