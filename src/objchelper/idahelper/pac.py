__all__ = ["is_pac_plugin_installed", "pac_candidates_for_call", "pac_xrefs_to_func"]

import sys
from collections import namedtuple
from functools import cache
from importlib.util import find_spec
from typing import Protocol

import idautils


def is_pac_plugin_installed() -> bool:
    return find_spec("pacexplorer") is not None


def ensure_pac_plugin_installed():
    if not is_pac_plugin_installed():
        raise AssertionError(  # noqa: TRY003
            "PacExplorer plugin is not installed, please install from https://github.com/yoavst/PacXplorer/tree/patch-1"
        )


# region pacxplorer plugin protocols
VtableXrefTuple = namedtuple("VtableXrefTuple", ["xref_to", "vtable_addr", "vtable_entry_addr", "offset", "pac"])
MovkCodeTuple = namedtuple("MovkCodeTuple", ["pac_tuple", "movk_addr", "trace"])


class VtableAnalyzerProtocol(Protocol):
    def codes_from_func_addr(self, ea: int) -> list: ...

    def func_from_pac_tuple(self, pac_tuple: MovkCodeTuple) -> list[VtableXrefTuple]: ...


class MovkAnalyzerProtocol(Protocol):
    def pac_tuple_from_ea(self, ea: int) -> MovkCodeTuple: ...

    def movks_from_pac_codes(self, pac_codes) -> list[tuple]: ...


class PacxplorerPluginProtocol(Protocol):
    vtable_analyzer: VtableAnalyzerProtocol
    movk_analyzer: MovkAnalyzerProtocol
    analysis_done: bool

    def analyze(self, only_cached=False) -> None: ...


# endregion


@cache
def get_pac_plugin() -> PacxplorerPluginProtocol:
    # Cache it somewhere else, to avoid analyzing every time we reload our plugin
    main_module = sys.modules["__main__"]
    if hasattr(main_module, "pacexplorer_plugin"):
        return getattr(main_module, "pacexplorer_plugin")  # noqa: B009

    ensure_pac_plugin_installed()
    # noinspection PyUnresolvedReferences
    import pacexplorer

    plugin: PacxplorerPluginProtocol = pacexplorer.PacxplorerPlugin()
    plugin.analyze(False)
    if not plugin.analysis_done:
        raise AssertionError("PacExplorer plugin analysis not done, please run the analysis first")  # noqa: TRY003
    setattr(main_module, "pacexplorer_plugin", plugin)  # noqa: B010
    return plugin


def pac_xrefs_to_func(func_ea: int) -> list[int]:
    """Given the EA of a function, return possible xrefs to the function using PAC matching"""
    pac_plugin = get_pac_plugin()
    pac_codes = pac_plugin.vtable_analyzer.codes_from_func_addr(func_ea)
    if pac_codes is None:
        return []
    movks = pac_plugin.movk_analyzer.movks_from_pac_codes(pac_codes)
    return [addr for addr, code in movks]


def pac_candidates_from_movk(movk_ea: int) -> list[int]:
    """Given the EA of a movk, return possible functions that could be called using this movk"""
    pac_plugin = get_pac_plugin()
    candidates = pac_plugin.vtable_analyzer.func_from_pac_tuple(pac_plugin.movk_analyzer.pac_tuple_from_ea(movk_ea))
    return [candidate.xref_to for candidate in candidates]


MAX_PREVIOUS_OPCODES_FOR_MOVK_SCAN = 10


def get_previous_movk(call_ea: int) -> int | None:
    """Given a call, search previous instructions to find a movk call"""
    insn = idautils.DecodeInstruction(call_ea)
    if not insn:
        return None

    if insn.get_canon_mnem() != "BLR":
        return None

    # Get the register for PAC code
    movk_reg = insn[1].reg
    # BLR with just one register is unauthenticated, so there will be no PAC xref
    if movk_reg == 0:
        return None

    for _ in range(MAX_PREVIOUS_OPCODES_FOR_MOVK_SCAN):
        insn, _ = idautils.DecodePrecedingInstruction(insn.ea)
        # No more instructions in this execution flow
        if insn is None:
            break
        if insn.get_canon_mnem() == "MOVK" and insn[0].reg == movk_reg:
            return insn.ea
    return None


def pac_candidates_for_call(call_ea: int) -> list[int]:
    """Given the EA of a call, return possible functions that could be called from this authenticated call"""
    movk_ea = get_previous_movk(call_ea)
    if movk_ea is None:
        return []
    return pac_candidates_from_movk(movk_ea)
