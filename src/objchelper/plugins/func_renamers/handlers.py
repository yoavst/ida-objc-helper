__all__ = ["GLOBAL_HANDLERS", "LOCAL_HANDLERS"]

from objchelper.idahelper import memory, tif
from objchelper.plugins.func_renamers.renamer import (
    FuncHandler,
    FuncHandlerByNameWithStringFinder,
    FuncHandlerVirtualGetter,
    FuncHandlerVirtualSetter,
    Modifications,
)
from objchelper.plugins.func_renamers.visitor import Call, FuncXref, SourceXref


class OSSymbolHandler(FuncHandlerByNameWithStringFinder):
    def __init__(self, name: str, search_string: str):
        super().__init__(
            name,
            tif.from_func_components("OSSymbol*", [tif.FuncParam("const char*", "cString")]),
            search_string,
            is_call=True,
        )

        self._cached_symbol_type = tif.from_c_type("OSSymbol*")

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_assignee_by_index(modifications, call, 0, modifier=lambda name: f"sym_{name}")
        self._retype_assignee(modifications, call, self._cached_symbol_type)


OSSymbol_WithCStringNoCopy = OSSymbolHandler("OSSymbol::withCStringNoCopy", "IOMatchedPersonality")
OSSymbol_WithCString = OSSymbolHandler("OSSymbol::withCString", "ACIPCInterfaceProtocol")


class IORegistry_MakePlane(FuncHandlerByNameWithStringFinder):
    def __init__(self):
        super().__init__(
            "IORegistry::makePlane",
            tif.from_func_components("IORegistryPlane*", [tif.FuncParam("const char*", "name")]),
            "ChildLinks",
            is_call=False,
        )
        self._cached_registry_plane_type = tif.from_c_type("IORegistryPlane*")

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_assignee_by_index(modifications, call, 0, modifier=lambda name: f"plane_{name}")
        self._retype_assignee(modifications, call, self._cached_registry_plane_type)


IOService_SetProperty = [
    FuncHandlerVirtualSetter(
        "IORegistryEntry::setProperty",
        tif.from_c_type("IORegistryEntry"),
        offset,
        name_index=1,
        rename_index=2,
        rename_prefix="val_",
    )
    for offset in range(0xB8, 0xF0, 8)
]
IOService_GetProperty = FuncHandlerVirtualGetter(
    "IORegistryEntry::getProperty", tif.from_c_type("IORegistryEntry"), 0x118, name_index=1, rename_prefix="val_"
)
IOService_CopyProperty = FuncHandlerVirtualGetter(
    "IORegistryEntry::copyProperty", tif.from_c_type("IORegistryEntry"), 0x148, name_index=1, rename_prefix="val_"
)


class MetaClassConstructor(FuncHandlerByNameWithStringFinder):
    def __init__(self):
        super().__init__(
            "__ZN11OSMetaClassC2EPKcPKS_j",
            tif.from_func_components(
                "OSMetaClass*",
                [
                    tif.FuncParam("OSMetaClass*", "this"),
                    tif.FuncParam("const char*", "className"),
                    tif.FuncParam("const OSMetaClass*", "superClass"),
                    tif.FuncParam("unsigned int", "classSize"),
                ],
            ),
            "OSMetaClass: preModLoad() wasn't called for class %s (runtime internal error).",
            is_call=False,
        )

        self._cached_metaclass_type = tif.from_c_type("OSMetaClass*")

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_parameter_by_index(
            modifications,
            call,
            name_index=1,
            rename_index=0,
            modifier=lambda name: f"__ZN{len(name)}{name}10gMetaclassE",
        )
        self._retype_parameter_by_index(modifications, call, 0, self._cached_metaclass_type)


class peParseBootArgn(FuncHandler):
    def __init__(self):
        super().__init__("PE_parse_boot_argn")

    def get_source_xref(self) -> SourceXref | None:
        existing = memory.ea_from_name("PE_parse_boot_argn")
        if existing is not None:
            return FuncXref(existing)

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_parameter_by_index(
            modifications, call, 0, 1, modifier=lambda name: f"boot_{name.replace('-', '_')}"
        )

        if isinstance(call.params[2], int):
            new_type = tif.from_size(call.params[2])
            if new_type is not None:
                self._retype_parameter_by_index(modifications, call, 1, tif.pointer_of(new_type))


GLOBAL_HANDLERS: list[FuncHandler] = [
    OSSymbol_WithCStringNoCopy,
    OSSymbol_WithCString,
    IORegistry_MakePlane(),
    MetaClassConstructor(),
]
LOCAL_HANDLERS: list[FuncHandler] = [
    *IOService_SetProperty,
    IOService_GetProperty,
    IOService_CopyProperty,
    peParseBootArgn(),
]
