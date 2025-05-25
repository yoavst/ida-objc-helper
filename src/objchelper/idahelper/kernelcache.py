import idaapi


def is_kernelcache():
    """Check if the current file is a kernel cache"""
    file_type = idaapi.get_file_type_name()
    return "kernelcache" in file_type and "ARM64" in file_type
