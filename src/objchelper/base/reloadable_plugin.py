# This code was inspired by Lucid's plugin core, which is licensed under the MIT License.
# However, this is a complete rewrite that only contains the _startup_hooks part from the original code.
# As such, I find it acceptable to use this code under the same license as the rest of the plugin.
# https://github.com/gaasedelen/lucid/blob/master/plugins/lucid/core.py
import abc
import sys
from collections.abc import Callable
from typing import Protocol

import ida_hexrays
import ida_idaapi
import idaapi
from ida_idaapi import plugin_t
from ida_kernwin import UI_Hooks


class Component:
    """
    A component is a self-contained piece of functionality that can be loaded and unloaded independently.
    It will only be loaded and unloaded when the plugin core is loaded and unloaded.
    However, it can be mounted and unmounted independently of the plugin core.
    """

    def __init__(self, name: str, core: "PluginCore"):
        self.name = name
        self.core = core

    def load(self) -> bool:
        """Load the component and all the relevant resources"""
        return True

    def mount(self) -> bool:
        """Enable the functionality of the component"""
        return True

    def unmount(self):
        """Disable the functionality of the component"""
        pass

    def unload(self):
        """Unload the component and all the relevant resources"""
        pass


ComponentFactory = Callable[["PluginCore"], Component]


class PluginCoreFactory(Protocol):
    def __call__(self, defer_load: bool, should_mount: bool) -> float: ...


class PluginCore:
    def __init__(
        self,
        name: str,
        component_factories: list[ComponentFactory],
        defer_load: bool = False,
        should_mount: bool = True,
    ):
        self.name = name
        self.loaded = False
        self.mounted = False
        self._components = [factory(self) for factory in component_factories]

        # we can 'defer' the load of the plugin core a little bit. this
        # ensures that all the other plugins (eg, decompilers) can get loaded
        # and initialized when opening an idb/bin

        def perform_load():
            self.load()
            if should_mount:
                self.mount()

        class UIHooks(UI_Hooks):
            def ready_to_run(self):
                perform_load()

        self._startup_hooks = UIHooks()

        if defer_load:
            self._startup_hooks.hook()
        else:
            perform_load()

    def load(self):
        self._startup_hooks.unhook()

        if not ida_hexrays.init_hexrays_plugin():
            print(f"[{self.name}] failed to load hexrays plugin, aborting load.")
            return

        print(f"[{self.name}] loading plugin")
        for component in self._components:
            print(f"[{self.name}] loading component {component.name}")
            if not component.load():
                print(f"[{self.name}] failed to load component {component.name}, aborting load.")
                return

        self.loaded = True

    def mount(self):
        if not self.mounted:
            for component in self._components:
                if self.should_mount(component):
                    print(f"[{self.name}] mounting component {component.name}")
                    if not component.mount():
                        print(f"[{self.name}] failed to mount component {component.name}, aborting mount.")
                        return
            self.mounted = True

    def unmount(self):
        if self.mounted:
            for component in self._components:
                print(f"[{self.name}] unmounting component {component.name}")
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

        print(f"[{self.name}] unloading plugin")

        # mark the core as 'unloaded' and teardown its components
        self.loaded = False

        self.unmount()
        for component in self._components:
            print(f"[{self.name}] unloading component {component.name}")
            component.unload()

    def should_mount(self, _component: Component) -> bool:
        """
        Determine if a component should be mounted based on the current state of the plugin core.
        In the future we will implement a more sophisticated system to determine if a component should be mounted.
        """
        return True

    @staticmethod
    def factory(name: str, component_factories: list[ComponentFactory]) -> PluginCoreFactory:
        def plugin_core_factory(defer_load: bool, should_mount: bool) -> PluginCore:
            return PluginCore(name, component_factories, defer_load=defer_load, should_mount=should_mount)

        # The type checker seems to have trouble with the factory method, so we need to suppress it
        # noinspection PyTypeChecker
        return plugin_core_factory


class ReloadablePlugin(abc.ABC, plugin_t):
    def __init__(self, global_name: str, base_package_name: str, plugin_core_factory: PluginCoreFactory):
        super().__init__()
        self._global_name = global_name
        self._plugin_core_factory = plugin_core_factory
        self._base_package_name = base_package_name
        self.core: PluginCore | None = None

    def init(self) -> int:
        self.core = self._plugin_core_factory(defer_load=True, should_mount=True)
        # Provide access from ida python console
        setattr(sys.modules["__main__"], self._global_name, self)
        # Keep plugin alive
        return ida_idaapi.PLUGIN_KEEP

    def term(self) -> None:
        if self.core is not None:
            self.core.unload()

    def reload(self):
        """Hot-reload the plugin core."""
        print(f"[{getattr(self, 'wanted_name', 'plugin')}] Reloading...")

        # Unload the core and all its components
        was_mounted = self.core.mounted if self.core else True
        if self.core is not None:
            self.core.unload()

        # Reload all modules in the base package
        modules_to_reload = [
            module_name for module_name in sys.modules if module_name.startswith(self._base_package_name)
        ]
        for module_name in modules_to_reload:
            idaapi.require(module_name)

        # Load the plugin core
        self.core = self._plugin_core_factory(defer_load=False, should_mount=was_mounted)


# A common type of component is installing optimizers for the decompiler. This is a helper class to make it easier.

optimizer_t = ida_hexrays.optblock_t | ida_hexrays.optinsn_t
optimizer_factory_t = Callable[[], optimizer_t]


class OptimizersComponent(Component):
    def __init__(self, name: str, core: "PluginCore", optimizer_factories: list[optimizer_factory_t]):
        super().__init__(name, core)
        self.optimizer_factories = optimizer_factories
        self.optimizers: list[optimizer_t] | None = None

    def load(self) -> bool:
        self.optimizers = [factory() for factory in self.optimizer_factories]
        return True

    def mount(self) -> bool:
        assert self.optimizers is not None, "Load must be called before mount"

        for optimizer in self.optimizers:
            optimizer.install()
        return True

    def unmount(self):
        assert self.optimizers is not None, "Load must be called before unmount"

        for optimizer in self.optimizers:
            optimizer.remove()

    def unload(self):
        self.optimizers = None

    @staticmethod
    def factory(name: str, optimizer_factories: list[optimizer_factory_t]) -> ComponentFactory:
        """
        Factory method to create an optimizer. This is used to register the optimizer with IDA.
        """
        return lambda core: OptimizersComponent(name, core, optimizer_factories)
