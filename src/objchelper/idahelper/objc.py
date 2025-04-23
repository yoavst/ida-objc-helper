def is_objc_method(name: str) -> bool:
    """Does the name look like an Obj-C method?"""
    return len(name) > 3 and name[0] in ["-", "+"] and name[1] == "[" and name[-1] == "]"


def is_objc_static_method(name: str) -> bool:
    """Given obj-C method name, check if it is a static method."""
    return name[0] == "+"
