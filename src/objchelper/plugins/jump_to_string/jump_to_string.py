import ida_funcs
import ida_kernwin
from ida_funcs import func_t

from objchelper.idahelper import memory, strings, widgets, xrefs


def find_matching_string(target_str: str) -> list[tuple[int, str]]:
    matches: list[tuple[int, str]] = []
    for s in strings.strings():
        if target_str in str(s):
            matches.append((s.ea, str(s)))  # type: ignore  # noqa: PGH003
    return matches


def show_xrefs_to_string(ea: int):
    s_xrefs = xrefs.get_xrefs_to(ea)
    if not s_xrefs:
        print("No cross-references found.")
    elif len(s_xrefs) == 1:
        widgets.jump_to(s_xrefs[0])
    else:
        print("Multiple xrefs to the string:")
        for xref in s_xrefs:
            print_xref(xref)


def print_xref(ea: int, match: str | None = None):
    func: func_t | None = ida_funcs.get_func(ea)
    if func is None:
        print(f"{ea:X}")
        return

    func_name = memory.name_from_ea(func.start_ea) or "<unknown>"
    match_str = "" if match is None else f": {match}"

    print(f"{ea:X} at {func_name}+{ea - func.start_ea:X}{match_str}")


def jump_to_string_ask():
    target_str = ida_kernwin.ask_str("", 0, "Enter substring to search in binary strings")
    if not target_str:
        return

    matches = find_matching_string(target_str)

    if not matches:
        print("[Warning] No matching strings found.")
        return

    # If there's only one result, or an exact match, show xrefs
    if len(matches) == 1 or any(s == target_str for _, s in matches):
        for ea, s in matches:
            if s == target_str or len(matches) == 1:
                show_xrefs_to_string(ea)
                return

    # Otherwise, let the user choose
    print("Multiple results for the string:")
    for ea, s in matches:
        print(f"{ea:X}: {s}")
