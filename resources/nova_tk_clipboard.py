"""Clipboard keys and a right-click menu for every text field, whatever the keyboard layout.

Tk on Windows binds <<Paste>>/<<Copy>>/<<Cut>> to <Control-Key-v/c/x>. With a Russian layout the
keysym is Cyrillic_em/es/che, so Ctrl+V in an Entry (simpledialog.askstring included) does
nothing, and Tk entries have no context menu at all. `install(root)` adds both at class level,
so every Entry, ttk.Entry, Spinbox and Text in the interpreter gets them, dialogs too.

The keycode is the Windows virtual key and does not depend on the layout. A Latin layout still
goes through Tk's own, more specific <Control-Key-v> binding; the handler below only answers
when that one did not match.
"""

import tkinter as tk

# Windows virtual-key codes -> virtual event.
_KEY_EVENTS = {86: "<<Paste>>", 67: "<<Copy>>", 88: "<<Cut>>", 65: "<<SelectAll>>"}
_LATIN = frozenset("vcxa")
_CLASSES = ("Entry", "TEntry", "Spinbox", "TSpinbox", "TCombobox", "Text")

_MENU_ITEMS = (
    ("Вырезать", "<<Cut>>"),
    ("Копировать", "<<Copy>>"),
    ("Вставить", "<<Paste>>"),
    None,
    ("Выделить всё", "<<SelectAll>>"),
)


def _is_readonly(widget):
    try:
        return str(widget.cget("state")) in ("disabled", "readonly")
    except tk.TclError:
        return False


def _on_control_key(event):
    if str(getattr(event, "keysym", "")).lower() in _LATIN:
        return None  # Tk's own binding handles it
    virtual = _KEY_EVENTS.get(getattr(event, "keycode", None))
    if not virtual:
        return None
    widget = event.widget
    if virtual == "<<SelectAll>>" and widget.winfo_class() != "Text":
        # Entry has no <<SelectAll>> on every Tk build; select directly.
        try:
            widget.select_range(0, "end")
            widget.icursor("end")
        except (tk.TclError, AttributeError):
            pass
        return "break"
    try:
        widget.event_generate(virtual)
    except tk.TclError:
        pass
    return "break"


def _on_context_menu(event):
    widget = event.widget
    try:
        widget.focus_set()
    except tk.TclError:
        pass
    readonly = _is_readonly(widget)
    menu = tk.Menu(widget, tearoff=0)
    for item in _MENU_ITEMS:
        if item is None:
            menu.add_separator()
            continue
        label, virtual = item
        state = "disabled" if readonly and virtual in ("<<Cut>>", "<<Paste>>") else "normal"
        if virtual == "<<SelectAll>>" and widget.winfo_class() != "Text":
            command = lambda w=widget: _select_all_entry(w)
        else:
            command = lambda w=widget, v=virtual: _generate(w, v)
        menu.add_command(label=label, command=command, state=state)
    try:
        menu.tk_popup(event.x_root, event.y_root)
    finally:
        menu.grab_release()
    return "break"


def _generate(widget, virtual):
    try:
        widget.event_generate(virtual)
    except tk.TclError:
        pass


def _select_all_entry(widget):
    try:
        widget.select_range(0, "end")
        widget.icursor("end")
    except (tk.TclError, AttributeError):
        pass


def install(root):
    """Bind once per Tk interpreter. Widgets with their own <Button-3> keep it (instance tag wins
    only if it returns "break"; the log view does)."""
    for cls in _CLASSES:
        root.bind_class(cls, "<Control-KeyPress>", _on_control_key, add="+")
        root.bind_class(cls, "<Button-3>", _on_context_menu, add="+")
