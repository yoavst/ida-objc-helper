import idaapi

from objchelper.idahelper import segments


def is_kernelcache() -> bool:
    """Check if the current file is a kernel cache"""
    file_type = idaapi.get_file_type_name()
    return "kernelcache" in file_type and "ARM64" in file_type


def is_objc() -> bool:
    """Check if the current file is an Objective-C binary"""
    return any(seg.name.startswith("__objc") or "__objc" in seg.name for seg in segments.get_segments())
