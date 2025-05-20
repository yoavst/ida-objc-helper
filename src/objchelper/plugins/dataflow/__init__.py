__all__ = ["dataflow_component"]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t

from objchelper.base.reloadable_plugin import UIAction, UIActionsComponent
from objchelper.plugins.dataflow.dataflow import main

ACTION_ID = "objchelper:data_flow_playground"

dataflow_component = UIActionsComponent.factory(
    "Dataflow playground",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID,
                "Dataflow playground",
                DataFlowPlaygroundAction(),
                "F3",
            ),
        )
    ],
)


class DataFlowPlaygroundAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        main()
        return False

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
