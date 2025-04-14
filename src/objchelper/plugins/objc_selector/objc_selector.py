__all__ = ["objc_selector_hexrays_hooks_t"]

import re

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, carg_t, carglist_t, cexpr_t, cfunc_t, citem_t
from ida_kernwin import simpleline_t
from ida_lines import COLOR_OFF, COLOR_ON, COLSTR, SCOLOR_ADDR, SCOLOR_LOCNAME, SCOLOR_SYMBOL, tag_remove
from ida_pro import strvec_t

from objchelper.idahelper.ast import cexpr

SELECTOR_MARKER = "!@#$sel$#@!"
COMMA_COLORED = COLSTR(",", SCOLOR_SYMBOL)
INSIGNIFICANT_LENGTH_FOR_LINE = 5
MAX_LINE_SIZE = 120

SEL_TOKEN_REGEX = re.compile(
    "(?P<prefix>"
    + re.escape(COMMA_COLORED + " ")
    + r")?"
    + re.escape(COLOR_ON + SCOLOR_ADDR)
    + r"(?P<index>[0-9A-Fa-f]{16})"
    + re.escape(COLOR_ON + SCOLOR_ADDR)
    + r"(?P=index)"
    + re.escape(COLSTR('"', SCOLOR_SYMBOL))
    + re.escape(COLOR_ON + SCOLOR_LOCNAME)
    + r"(?P<selector>[A-Za-z0-9_:]+)"
    + '"'
    + re.escape(COLOR_OFF + SCOLOR_LOCNAME)
    + "(?P<postfix>"
    + re.escape(COMMA_COLORED)
    + r" ?)?"
)
"""
a regex for a possible selector in IDA's pseudocode, with support for the prefix ", " or the postfix ","
Its groups are: prefix, index, selector and postfix.
"""


def is_objc_method(name: str) -> bool:
    """Does the name look like an Obj-C method?"""
    return len(name) > 3 and name[0] in ["-", "+"] and name[1] == "[" and name[-1] == "]"


class objc_selector_hexrays_hooks_t(Hexrays_Hooks):
    def func_printed(self, cfunc: cfunc_t) -> int:
        selectors_to_remove: dict[int, str] = {}  # obj_id -> selector
        index_to_sel: dict[int, str] = {}  # index, selector

        for i, call_item in enumerate(cfunc.treeitems):
            call_item: citem_t
            # Get the index of the selector AST element
            if call_item.obj_id in selectors_to_remove:
                index_to_sel[i] = selectors_to_remove.pop(call_item.obj_id)
            elif call_item.op == ida_hexrays.cot_call:
                call_expr: cexpr_t = call_item.cexpr

                # 1. Check if the function name looks like an Obj-C method
                call_func_name = cexpr.get_call_name(call_expr)
                if call_func_name is None or not is_objc_method(call_func_name):
                    continue

                # 2. Collect selector from arglist
                arglist: carglist_t = call_expr.a
                if len(arglist) < 2:
                    print("[Error]: Obj-C method call with less than 2 arguments:", call_expr.dstr())
                    continue
                sel_arg: carg_t = arglist[1]
                if sel_arg.op != ida_hexrays.cot_str:
                    print("[Error]: Obj-C method call with non-string selector:", call_expr.dstr())
                    continue

                selectors_to_remove[sel_arg.obj_id] = sel_arg.string

        if selectors_to_remove:
            print("[Error]: unmatched Obj-C selectors in the function: ", hex(cfunc.entry_ea))
        elif index_to_sel:
            modify_text(cfunc, index_to_sel)
        return 0


def modify_text(cfunc: cfunc_t, index_to_sel: dict[int, str]):
    # Early return if no tokens to replace
    if not index_to_sel:
        return

    ps: strvec_t = cfunc.get_pseudocode()
    lines_marked_for_removal: list[simpleline_t] = []
    for i, line in enumerate(ps):
        line: simpleline_t
        should_merge = False

        # Reverse the results so indices will not change
        for result in reversed(list(re.finditer(SEL_TOKEN_REGEX, line.line))):
            result: re.Match
            index = int(result.group("index"), 16)
            if index in index_to_sel:
                # We found a selector token, remove it from the list
                sel = index_to_sel.pop(index)
                if sel != result.group("selector"):
                    print("[Error]: selector mismatch. Expected:", sel, "Actual:", result.group("selector"))
                    continue

                # If match contains both a prefix and a postfix, remove only the prefix
                left, right = result.span()
                if result.group("prefix") and result.group("postfix"):
                    right = result.start("postfix")

                # Remove the selector, check if we need to merge lines
                before_selector, after_selector = line.line[: result.span()[0]], line.line[right:]
                should_merge = should_merge or should_merge_line(before_selector, after_selector, ps[i - 1].line)
                line.line = before_selector + after_selector

        if should_merge:
            lines_marked_for_removal.append(line)
            ps[i - 1].line += line.line.strip()

    # Remove lines that are marked for removal
    for line_to_remove in reversed(lines_marked_for_removal):
        ps.erase(line_to_remove)


def should_merge_line(before_selector: str, after_selector: str, prev_line: str) -> bool:
    """
    Given a `line` with a selector marker and the previous line, should we merge the two lines.
    """
    before_without_tags = tag_remove(before_selector)

    # We only remove lines that starts with the selector
    if before_without_tags and not before_without_tags.isspace():
        return False

    after_without_tags = tag_remove(after_selector)
    # If the line is short, allow merging
    if len(after_without_tags) < INSIGNIFICANT_LENGTH_FOR_LINE:
        return True

    # Merge if it will not lead to a long line
    prev_line_without_tags = tag_remove(prev_line)
    return len(after_without_tags) + len(prev_line_without_tags) < MAX_LINE_SIZE


def to_hex(n: int, *, length: int) -> str:
    """Convert an integer to a hex string with leading zeros"""
    return f"{n:0{length}X}"
