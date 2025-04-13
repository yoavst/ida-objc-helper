__all__ = ["objc_selector_hexrays_hooks_t"]

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, carg_t, carglist_t, cexpr_t, cfunc_t, citem_t
from ida_kernwin import simpleline_t
from ida_lines import COLOR_ON, COLSTR, SCOLOR_ADDR, SCOLOR_LOCNAME, SCOLOR_SYMBOL, tag_remove
from ida_pro import strvec_t

from objchelper.idahelper.ast import cexpr

SELECTOR_MARKER = "!@#$sel$#@!"
COMMA_COLORED = COLSTR(",", SCOLOR_SYMBOL)
COMMA_COLORED_SPACE = COMMA_COLORED + " "
INSIGNIFICANT_LENGTH_FOR_LINE = 5
MAX_LINE_SIZE = 120


def is_objc_method(name: str) -> bool:
    """Does the name look like an Obj-C method?"""
    return len(name) > 3 and name[0] in ["-", "+"] and name[1] == "[" and name[-1] == "]"


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


def modify_text(cfunc: cfunc_t, index_to_sel: list[(int, str)]):
    # Early return if no tokens to replace
    if not index_to_sel:
        return

    selector_tokens = [sel_to_token(i, sel) for i, sel in index_to_sel]

    ps: strvec_t = cfunc.get_pseudocode()
    lines_marked_for_removal: list[simpleline_t] = []
    for i, line in enumerate(ps):
        line: simpleline_t
        should_merge = False
        for j in range(len(selector_tokens) - 1, -1, -1):
            line_text: str = line.line
            # Check if selector token is in the line, try to expand with commas and spaces
            if (selector_token := maximal_token_in_line(selector_tokens[j], line_text)) is None:
                continue

            # We expect to see each selector once, so we can remove the current token
            del selector_tokens[j]

            # Update line's "should merge with previous" and text
            line_text_with_marker = line_text.replace(selector_token, SELECTOR_MARKER)
            should_merge = should_merge or should_merge_line(line_text_with_marker, ps[i - 1].line)
            line.line = line_text_with_marker.replace(SELECTOR_MARKER, "")

        if should_merge:
            lines_marked_for_removal.append(line)
            ps[i - 1].line += line.line.strip()

    # Remove lines that are marked for removal
    for line_to_remove in reversed(lines_marked_for_removal):
        ps.erase(line_to_remove)


def maximal_token_in_line(selector_token: str, line: str) -> str | None:
    """
    Given a selector token and a line, Check if it is in the line.
    If it is, try to extend it with spaces and unnecessary commas.
    Return the token with the extended spaces and commas.
    If it is not in the line, return None.
    """
    try:
        # Check if the token is in the line
        selector_index = line.index(selector_token)
        # Check if the token is preceded by a comma and a space, so we can remove the comma
        if line.startswith(COMMA_COLORED_SPACE, selector_index - len(COMMA_COLORED_SPACE)):
            selector_token = COMMA_COLORED_SPACE + selector_token
        # If the token is succeeded by a comma, we can remove the comma
        elif line.startswith(COMMA_COLORED, selector_index + len(selector_token)):
            selector_token += COMMA_COLORED
            # If there is an additional space, remove it as well
            if line.startswith(" ", selector_index + len(selector_token) + len(COMMA_COLORED)):
                selector_token += " "
    except ValueError:
        return None
    else:
        return selector_token


def should_merge_line(line: str, prev_line: str) -> bool:
    """
    Given a `line` with a selector marker and the previous line, should we merge the two lines.
    """
    before, after = line.split(SELECTOR_MARKER)
    before_without_tags = tag_remove(before)

    # We only remove lines that starts with the selector
    if before_without_tags and not before_without_tags.isspace():
        return False

    after_without_tags = tag_remove(after)
    # If the line is short, allow merging
    if len(after_without_tags) < INSIGNIFICANT_LENGTH_FOR_LINE:
        return True

    # Merge if it will not lead to a long line
    prev_line_without_tags = tag_remove(prev_line)
    return len(after_without_tags) + len(prev_line_without_tags) < MAX_LINE_SIZE


def sel_to_token(index: int, sel: str) -> str:
    """Return the tokens that represent the selector in IDA's pseudocode"""
    color_obj_id = COLOR_ON + SCOLOR_ADDR + to_hex(index, length=16)
    existing_token = color_obj_id + color_obj_id + COLSTR('"', SCOLOR_SYMBOL) + COLSTR(sel + '"', SCOLOR_LOCNAME)
    return existing_token


def to_hex(n: int, *, length: int) -> str:
    """Convert an integer to a hex string with leading zeros"""
    return f"{n:0{length}X}"
