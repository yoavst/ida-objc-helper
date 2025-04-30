import ida_funcs
import ida_hexrays
from ida_hexrays import cexpr_t
from ida_typeinf import tinfo_t

from objchelper.idahelper import cpp, memory, tif, widgets
from objchelper.idahelper.widgets import EAChoose


def get_vtable_call(verbose: bool = False) -> tuple[tinfo_t, str, int] | None:
    """If the mouse is on a virtual call, return the vtable type, method name and offset."""
    citem = widgets.get_current_citem()
    if citem is None:
        if verbose:
            print("[Error] No citem found. Do you have your cursor on a virtual call?")
        return None
    if not citem.is_expr():
        if verbose:
            print(
                f"[Error] Current citem is not an expression: {citem.dstr()}. Do you have your cursor on the virtual call?"
            )
        return None

    expr: cexpr_t = citem.cexpr
    if expr.op not in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
        if verbose:
            print(
                f"[Error] Current citem is not a member pointer: {citem.dstr()} but a {ida_hexrays.get_ctype_name(citem.cexpr.op)}. Do you have your cursor on the virtual call?"
            )
        return None

    tp: tinfo_t = expr.type
    if not tp.is_funcptr():
        if verbose:
            print(
                f"[Error] Current member is not a function pointer: {citem.dstr()}. Do you have your cursor on a virtual call?"
            )
        return None
    offset = expr.m
    vtable_type = expr.x.type

    # A bit hack but should work. We could implement a better way to get the name in the future...
    call_name = expr.dstr().split(".")[-1].split("->")[-1]
    return vtable_type, call_name, offset


def show_vtable_xrefs():
    vtable_call = get_vtable_call(verbose=True)
    if vtable_call is None:
        return
    vtable_type, call_name, offset = vtable_call

    actual_type = get_actual_class_from_vtable(vtable_type)
    relevant_classes = [actual_type, *tif.get_children_classes(actual_type)]
    # noinspection PyTypeChecker
    matches: dict[int, str] = {}  # addr -> class_name
    for cls in relevant_classes:
        # Get vtable location in memory
        vtable_ea = cpp.vtable_location_from_type(cls)
        if vtable_ea is None:
            continue

        # Read the func at the relevant offset
        vtable_entry = vtable_ea + (2 * 8 + offset)
        vtable_func_ea = memory.qword_from_ea(vtable_entry)
        if ida_funcs.get_func(vtable_func_ea) is None:
            continue

        # Add it to the dict if not already present.
        # get_children_classes returns the classes in order of inheritance
        if vtable_func_ea not in matches:
            # noinspection PyTypeChecker
            matches[vtable_func_ea] = cls.get_type_name()

    method_name = f"{actual_type.get_type_name()}->{call_name}"
    if not matches:
        print(f"[Error] No implementations found for {method_name}")
    if len(matches) == 1:
        # Just jump to the function
        widgets.jump_to(next(iter(matches.keys())))
    elif matches:
        # Show the results in a chooser
        print(f"Implementations for {method_name}:")
        for ea, cls in matches.items():
            print(f"{hex(ea)}: {memory.name_from_ea(ea)} by {cls}")

        xrefs_choose = EAChoose(
            f"Implementations for {method_name}",
            list(matches.items()),
            col_names=("EA", "Implementing class"),
            modal=True,
        )
        xrefs_choose.show()


def get_actual_class_from_vtable(vtable_type: tinfo_t) -> tinfo_t | None:
    # It is usually a pointer to a pointer to a vtable
    if vtable_type.is_ptr():
        vtable_type = vtable_type.get_pointed_object()

    # noinspection PyTypeChecker
    name: str | None = vtable_type.get_type_name()
    if name is None:
        print(f"[Error] Failed to get vtable type name from {vtable_type}")
        return None
    elif not name.endswith("_vtbl"):
        return None

    class_name = name[:-5]
    return tif.from_struct_name(class_name)
