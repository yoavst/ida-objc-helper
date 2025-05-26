__all__ = ["VariableModification", "perform_lvar_modifications"]

from dataclasses import dataclass

from ida_hexrays import (
    cfunc_t,
    lvar_saved_info_t,
    lvar_t,
    lvar_uservec_t,
    lvars_t,
    modify_user_lvars,
    user_lvar_modifier_t,
)
from ida_hexrays import (
    rename_lvar as ida_rename_lvar,
)
from ida_typeinf import tinfo_t

from objchelper.idahelper.ast import cfunc


@dataclass
class VariableModification:
    name: str | None = None
    type: tinfo_t | None = None
    comment: str | None = None
    force_name_change: bool = True


class custom_lvars_modifiers_t(user_lvar_modifier_t):
    def __init__(self, modifications: dict[str, VariableModification]):
        super().__init__()
        self._modifications = modifications

    def modify_lvars(self, lvinf: lvar_uservec_t) -> bool:
        if not self._modifications:
            return False
        has_matched = False
        for lvar in lvinf.lvvec:
            lvar: lvar_saved_info_t
            if (modification := self._modifications.get(lvar.name)) is not None:
                has_matched = True
                custom_lvars_modifiers_t.modify_lvar(lvar, modification)

        return has_matched

    @staticmethod
    def modify_lvar(lvar: lvar_t | lvar_saved_info_t, modification: VariableModification):
        """Modify a single local variable."""
        if modification.name is not None:
            lvar.name = modification.name
            if isinstance(lvar, lvar_t):
                lvar.set_user_name()
        if modification.type is not None:
            lvar.type = modification.type
            if isinstance(lvar, lvar_t):
                lvar.set_user_type()
        if modification.comment is not None:
            lvar.cmt = modification.comment


def perform_lvar_modifications_by_ea(entry_ea: int, modifications: dict[str, VariableModification]) -> bool:
    """Perform the modifications on the local variables of the function."""
    if not modifications:
        return False

    lvars: lvars_t = cfunc.from_ea(entry_ea).get_lvars()
    return perform_lvar_modifications(entry_ea, lvars, modifications)


def perform_lvar_modifications(
    entry_ea: int, lvars: lvars_t, modifications: dict[str, VariableModification], temp_fallback: bool = False
) -> bool:
    """Perform the modifications on the local variables."""
    if not modifications:
        return False

    # According to ida documentation:
    # `lvars.lvvec` contains only variables modified from the defaults.
    # To change other variables, you can, for example, first use rename_lvars, so they get added to this list
    for name, modification in modifications.items():
        if not modification.force_name_change and get_by_name(lvars, name).has_user_name:
            # Already has name, so don't change the name
            # It will be in lvvec, so we can just skip it
            modification.name = None
            continue

        rename_res = ida_rename_lvar(entry_ea, name, name)
        if not rename_res:
            if not temp_fallback:
                print(f"{entry_ea:#x}: Failed to rename local variable {name} to itself, it will not be modified")
            else:
                # IDA API does not support setting local variable's name permanently during decompilation
                # Instead, we will just change it temporarily
                custom_lvars_modifiers_t.modify_lvar(get_by_name(lvars, name), modification)

    return modify_user_lvars(entry_ea, custom_lvars_modifiers_t(modifications))


def rename_lvar(func: cfunc_t | int, old_name: str, new_name: str) -> bool:
    """Rename a local variable in the function."""
    entry_ea = func if isinstance(func, int) else func.entry_ea
    return ida_rename_lvar(entry_ea, old_name, new_name)


def get_by_name(lvars: lvars_t, name: str) -> lvar_t:
    """Get the local variable with the given name, raise exception if it does not exist."""
    for lvar in lvars:
        if lvar.name == name:
            return lvar

    raise ValueError(f"Local variable {name} not found in {lvars}")  # noqa: TRY003


def get_index_by_name(lvars: lvars_t, name: str) -> int:
    """Get the index of the local variable with the given name."""
    for i, lvar in enumerate(lvars):
        if lvar.name == name:
            return i
    return -1


def get_index(lvars: lvars_t, lvar: lvar_t) -> int:
    """Get the index of the local variable with the given name."""
    for i, lvar2 in enumerate(lvars):
        if lvar == lvar2:
            return i
    return -1
