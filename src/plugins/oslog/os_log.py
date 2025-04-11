__all__ = ["LogCallInfo", "LogCallParams", "get_call_info_for_name", "log_type_to_str"]

import re
from dataclasses import dataclass

from base.utils import match


@dataclass
class LogCallInfo:
    size_index: int
    buf_index: int
    format_index: int
    type_index: int


@dataclass
class LogCallParams:
    log_type: int
    size: int
    stack_base_offset: int
    format_str_ea: int
    call_ea: int


OS_LOG_NAMES: list[str | re.Pattern] = [
    "__os_log_impl",
    "__os_log_error_impl",
    "__os_log_debug_impl",
    "__os_log_info_impl",
]
OS_LOG_IMPL_CALL_INFO = LogCallInfo(type_index=2, format_index=3, buf_index=4, size_index=5)

LOG_TYPES: dict[int, str] = {0: "default", 1: "info", 2: "debug", 16: "error", 17: "fault"}


def log_type_to_str(log_type: int) -> str:
    return LOG_TYPES.get(log_type, f"log{log_type}")


def get_call_info_for_name(name: str) -> LogCallInfo | None:
    if match(OS_LOG_NAMES, name):
        return OS_LOG_IMPL_CALL_INFO
