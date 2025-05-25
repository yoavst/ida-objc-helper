__all__ = ["local_func_renamer_component", "mass_func_renamer_component"]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t

from objchelper.base.reloadable_plugin import HexraysHookComponent, UIAction, UIActionsComponent
from objchelper.plugins.func_renamers.func_renamers import apply_global_rename, hooks

ACTION_ID = "objchelper:func_renamer"

local_func_renamer_component = HexraysHookComponent.factory("Local rename based on function calls", [hooks])

mass_func_renamer_component = UIActionsComponent.factory(
    "Mass rename based on function calls",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID, "Mass rename globals and fields based on specific function calls", FuncRenameGlobalAction()
            ),
            menu_location=UIAction.base_location(core),
        )
    ],
)


class FuncRenameGlobalAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        apply_global_rename()
        return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
