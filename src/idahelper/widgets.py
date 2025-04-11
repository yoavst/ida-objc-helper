import idaapi


def refresh_pseudocode_widgets() -> None:
    """Refresh all pseudocode widgets in IDA Pro, forcing redecompiling."""
    for name in "ABCDEFGHIJKLMNOPQRSTUVWXY":
        widget = idaapi.find_widget(f"Pseudocode-{name}")
        if widget is None:
            continue
        vdui: idaapi.vdui_t = idaapi.get_widget_vdui(widget)
        if vdui is None:
            continue
        vdui.refresh_view(True)
