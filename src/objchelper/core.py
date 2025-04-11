import ida_hexrays
import ida_kernwin
import idaapi

from .idahelper import widgets
from .plugins.objc_refcnt import optimizer as objc_optimizer
from .plugins.oslog import optimizers as oslog_optimizers

TOGGLE_ACTION_ID = "objchelper:toggle"


class Component:
    def __init__(self, core: "PluginCore"):
        self.core = core

    def load(self):
        pass

    def mount(self):
        pass

    def unmount(self):
        pass

    def unload(self):
        pass


class OptimizerComponent(Component):
    def __init__(self, core: "PluginCore"):
        super().__init__(core)
        self.optimizers = []

    def load(self):
        self.optimizers = [objc_optimizer(), *[opt() for opt in oslog_optimizers]]

    def mount(self):
        for optimizer in self.optimizers:
            optimizer.install()

    def unmount(self):
        for optimizer in self.optimizers:
            optimizer.remove()

    def unload(self):
        self.optimizers = []


class UIActionsComponent(Component):
    def load(self):
        if not idaapi.register_action(
            idaapi.action_desc_t(
                TOGGLE_ACTION_ID,  # Must be the unique item
                "Toggle Obj-C helper optimizations",  # The name the user sees
                ObjcHelperToggleActionHandler(self.core),  # The function to call
            )
        ):
            print("[Error] Failed to register action")
            return

        if not idaapi.attach_action_to_menu(
            "Edit/Other/...",  # The menu location
            TOGGLE_ACTION_ID,  # The unique function ID
            0,
        ):
            print("[Error] Failed to attach to menu")
            return

    def unload(self):
        idaapi.unregister_action(TOGGLE_ACTION_ID)


# Partially copied from lucid https://github.com/gaasedelen/lucid/blob/master/plugins/lucid/core.py#L27C1-L49C20


class PluginCore:
    def __init__(self, defer_load: bool = False):
        self.loaded = False
        self.mounted = False
        self.components = []

        #
        # we can 'defer' the load of the plugin core a little bit. this
        # ensures that all the other plugins (eg, decompilers) can get loaded
        # and initialized when opening an idb/bin
        #

        class UIHooks(ida_kernwin.UI_Hooks):
            def ready_to_run(self):
                pass

        self._startup_hooks = UIHooks()
        self._startup_hooks.ready_to_run = self.load

        if defer_load:
            self._startup_hooks.hook()
            return

        # plugin loading was not deferred (eg, hot reload), load immediately
        self.load()

    def load(self):
        self._startup_hooks.unhook()

        if not ida_hexrays.init_hexrays_plugin():
            return

        print("[ObjcHelper] loading")
        self.components = [OptimizerComponent(self), UIActionsComponent(self)]
        for component in self.components:
            component.load()

        self.mount()
        self.loaded = True

    def mount(self):
        if not self.mounted:
            for component in self.components:
                component.mount()
            self.mounted = True

    def unmount(self):
        if self.mounted:
            for component in self.components:
                component.unmount()

            self.mounted = False

    def unload(self):
        """
        Unload the plugin core.
        """

        # unhook just in-case load() was never actually called...
        self._startup_hooks.unhook()

        # if the core was never fully loaded, there's nothing else to do
        if not self.loaded:
            return

        print("Unloading ObjcHelper")

        # mark the core as 'unloaded' and teardown its components
        self.loaded = False

        self.unmount()
        for component in self.components:
            component.unload()


class ObjcHelperToggleActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, core: PluginCore):
        super().__init__()
        self.core = core

    def activate(self, ctx):
        if self.core.mounted:
            self.core.unmount()
        else:
            self.core.mount()

        widgets.refresh_pseudocode_widgets()

        print("Obj-C optimization are now:", "enabled" if self.core.mounted else "disabled")
        print("Note: You might need to perform decompile again for this change to take effect.")
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS
