__all__ = ["ObjcBlockComponent"]

import ida_kernwin
import idaapi
import idc

from objchelper.base.reloadable_plugin import UIAction, UIActionsComponent
from objchelper.idahelper.ast import cfunc
from objchelper.plugins.objc_block.objc_block import try_add_block_arg_byref_to_func
from objchelper.plugins.objc_block.utils import run_objc_plugin_on_func

ACTION_ID = "objchelper:restore_objc_block_args_byref"

ObjcBlockComponent = UIActionsComponent.factory(
    "Objc Blocks",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID, "Restore objc block arguments by ref", ObjcHelperToggleActionHandler(), "Ctrl+5"
            ),
        )
    ],
)


class ObjcHelperToggleActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        # FIXME: get the updated cfunc somehow
        run_objc_plugin_on_func(idc.here())
        try_add_block_arg_byref_to_func(cfunc.from_ea(idc.here()))
        return 0

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS
