__all__ = ["LvarModification", "perform_lvar_modifications"]

from dataclasses import dataclass

from ida_hexrays import cfunc_t, lvar_saved_info_t, lvar_uservec_t, modify_user_lvars, rename_lvar, user_lvar_modifier_t
from ida_typeinf import tinfo_t


@dataclass
class LvarModification:
    name: str | None = None
    type: tinfo_t | None = None
    comment: str | None = None


class custom_lvars_modifiers_t(user_lvar_modifier_t):
    def __init__(self, modifications: dict[str, LvarModification]):
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
                if modification.name is not None:
                    lvar.name = modification.name
                if modification.type is not None:
                    lvar.type = modification.type
                if modification.comment is not None:
                    lvar.cmt = modification.comment

        return has_matched


def perform_lvar_modifications(func: cfunc_t, modifications: dict[str, LvarModification]) -> bool:
    """Perform the modifications on the local variables of the function."""
    if not modifications:
        return False

    entry_ea = func.entry_ea

    # According to ida documentation:
    # `lvars.lvvec` contains only variables modified from the defaults.
    # To change other variables, you can, for example, first use rename_lvars, so they get added to this list
    for name in modifications:
        if name not in func.get_lvars():
            rename_lvar(entry_ea, name, name)

    return modify_user_lvars(entry_ea, custom_lvars_modifiers_t(modifications))
