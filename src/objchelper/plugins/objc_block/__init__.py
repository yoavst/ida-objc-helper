__all__ = ["objc_block_args_analyzer_component", "objc_block_optimizer_component"]

import ida_kernwin
import idaapi

from objchelper.base.reloadable_plugin import HexraysHookComponent, UIAction, UIActionsComponent
from objchelper.idahelper import widgets
from objchelper.idahelper.ast import cfunc
from objchelper.plugins.objc_block.analyze_byref_args import try_add_block_arg_byref_to_func
from objchelper.plugins.objc_block.optimize_blocks_init import objc_blocks_optimizer_hooks_t
from objchelper.plugins.objc_block.utils import run_objc_plugin_on_func

ACTION_ID = "objchelper:restore_objc_block_args_byref"

objc_block_args_analyzer_component = UIActionsComponent.factory(
    "Objc Blocks - __block arguments",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID,
                "Analyze stack-allocated blocks and their __block args (current function)",
                ObjcHelperToggleActionHandler(),
                "Alt+Shift+s",
            ),
            menu_location="Edit/Other/Objective-C/Analyze stack-allocated blocks (current function)...",
        )
    ],
)

objc_block_optimizer_component = HexraysHookComponent.factory(
    "Objc Blocks - optimizer", [objc_blocks_optimizer_hooks_t]
)


class ObjcHelperToggleActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        if ctx.cur_func is None:
            print("No function selected")
            return 0

        run_objc_plugin_on_func(ctx.cur_ea)
        widgets.refresh_pseudocode_widgets()
        try_add_block_arg_byref_to_func(cfunc.from_ea(ctx.cur_ea))
        return 0

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS
