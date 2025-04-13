__all__ = ['objc_selector_hexrays_hooks_t']

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, carg_t, carglist_t, cexpr_t, cfunc_t, citem_t
from ida_lines import COLOR_ON, COLSTR, SCOLOR_ADDR, SCOLOR_AUTOCMT, SCOLOR_LOCNAME, SCOLOR_SYMBOL

from objchelper.idahelper.ast import cexpr


def is_objc_method(name: str) -> bool:
    """Does the name look like an Obj-C method?"""
    return len(name) > 3 and name[0] in ['-', '+'] and name[1] == '[' and name[-1] == ']'


class objc_selector_hexrays_hooks_t(Hexrays_Hooks):
    def func_printed(self, cfunc: cfunc_t) -> "int":
        selectors_to_remove: dict[int, str] = {}  # obj_id -> selector
        index_to_sel: list[(int, str)] = []  # index, selector

        for i, call_item in enumerate(cfunc.treeitems):
            call_item: citem_t
            # Get the index of the selector AST element
            if call_item.obj_id in selectors_to_remove:
                index_to_sel.append((i, selectors_to_remove.pop(call_item.obj_id)))
            elif call_item.op == ida_hexrays.cot_call:
                call_expr: cexpr_t = call_item.cexpr

                # 1. Check if the function name looks like an Obj-C method
                call_func_name = cexpr.get_call_name(call_expr)
                if call_func_name is None or not is_objc_method(call_func_name):
                    continue

                # 2. Collect selector from arglist
                arglist: carglist_t = call_expr.a
                if len(arglist) < 2:
                    print('[Error]: Obj-C method call with less than 2 arguments:', call_expr.dstr())
                    continue
                sel_arg: carg_t = arglist[1]
                if sel_arg.op != ida_hexrays.cot_str:
                    print('[Error]: Obj-C method call with non-string selector:', call_expr.dstr())
                    continue

                selectors_to_remove[sel_arg.obj_id] = sel_arg.string

        if selectors_to_remove:
            print('[Error]: unmatched Obj-C selectors in the function: ', hex(cfunc.entry_ea))
        elif index_to_sel:
            self.modify_text(cfunc, index_to_sel)
        return 0

    def modify_text(self, cfunc: cfunc_t, index_to_sel: list[(int, str)]):
        token_replacement: list[(str, str)] = []
        # Early return if no tokens to replace
        if not index_to_sel:
            return

        for i, sel in index_to_sel:
            color_obj_id = COLOR_ON + SCOLOR_ADDR + to_hex(i, length=16)
            existing_token = (color_obj_id + color_obj_id +
                              COLSTR('"', SCOLOR_SYMBOL) + COLSTR(sel + '"', SCOLOR_LOCNAME))
            replacement_token = COLSTR("<sel>", SCOLOR_AUTOCMT)
            token_replacement.append((existing_token, replacement_token))

        ps = cfunc.get_pseudocode()
        for line in ps:
            for i in range(len(token_replacement) - 1, -1, -1):
                existing, replacement = token_replacement[i]
                if existing in line.line:
                    line.line = line.line.replace(existing, replacement)
                    del token_replacement[i]


def to_hex(n: int, *, length: int) -> str:
    """Convert an integer to a hex string with leading zeros"""
    return f"{n:0{length}X}"
