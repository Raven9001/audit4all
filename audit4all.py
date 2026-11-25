"""
audit4all.py - AUDIT4ALL desktop interface (Tkinter, no extra UI libraries).

Run:  python audit4all.py      (as Administrator for full results + live capture)

Look: dark slate panels, orange accent, LCD-style readouts and a segmented meter bar,
in the spirit of a music-production workstation. Dark only, on purpose.
"""
import ctypes
import json
import logging
import os
import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

import backend
from backend import (
    build_json_report,  # noqa: F401  (kept for parity with the web app)
    build_plain_report,
    clear_api_key,
    collect_network_facts,
    generate_executive_summary,
    get_api_key,
    is_admin,
    needs_attention,
    normal_app_names,
)

logger = logging.getLogger(__name__)

try:
    import startup_audit
    STARTUP_OK = True
except ImportError as exc:
    startup_audit = None
    STARTUP_OK = False
    logger.exception("Failed to import startup_audit: %s", exc)

try:
    from pcap_analyzer import capture_live, explain_capture, list_interfaces
    PCAP_OK = bool(backend.PCAP_ANALYZER_OK)
except ImportError as exc:
    PCAP_OK = False
    logger.exception("Failed to import pcap_analyzer: %s", exc)

if os.name == "nt":
    try:  # crisp text on high-DPI Windows screens
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception as exc:
        logger.exception("Failed to set DPI awareness: %s", exc)

# --------------------------------------------------------------------------- theme
APP_NAME = "AUDIT4ALL"

C = dict(
    bg="#232a2e",        # work area
    side="#1b2125",      # side rail (darkest panel)
    top="#2f383e",       # toolbar
    card="#2b343a",      # panels
    head="#36424a",      # raised controls, table headers
    inset="#161b1e",     # LCD wells, fields, meter trough
    border="#101417",    # hard dark outline
    edge="#44525b",      # light bevel edge
    text="#d6dee3",
    muted="#8e9ca6",
    dim="#5f6e78",
    accent="#ff9d1c",    # the orange
    accent_hi="#ffb54d",
    accent_lo="#b86e00",
    on_accent="#17191b",
    sel="#3d3428",
    hover="#3a464e",
    odd="#2f383e",
    green="#8dd44a", green_bg="#273520", green_br="#4d6e2e",
    amber="#ffd23f", amber_bg="#3b3418", amber_br="#7d6a21",
    red="#ff5f4f", red_bg="#3d2220", red_br="#8a3a32",
)

LEVEL = {
    "High": ("ACT NOW", C["red"], C["red_bg"]),
    "Medium": ("WORTH A LOOK", C["amber"], C["amber_bg"]),
}
KINDS = {  # banner kind -> (colour, background, border, glyph)
    "idle": (C["muted"], C["card"], C["border"], "i"),
    "ok": (C["green"], C["green_bg"], C["green_br"], "\u2713"),
    "warn": (C["amber"], C["amber_bg"], C["amber_br"], "!"),
    "bad": (C["red"], C["red_bg"], C["red_br"], "\u2715"),
}

F_UI = ("Segoe UI", 10)
F_BOLD = ("Segoe UI Semibold", 10)
F_H1 = ("Segoe UI Semibold", 20)
F_H2 = ("Segoe UI Semibold", 11)
F_CAP = ("Segoe UI Semibold", 8)
F_SMALL = ("Segoe UI", 9)
F_MONO = ("Consolas", 10)
F_LCD = ("Consolas", 11, "bold")
F_LCD_BIG = ("Consolas", 24, "bold")

INTRO_TEXT = (
    "This app checks if anything on your computer is exposed to the internet — "
    "the way a stranger would see it. It takes about 10 seconds. Nothing leaves "
    "your computer unless you ask for an AI summary. Click below to start."
)


def clear(widget):
    for w in widget.winfo_children():
        w.destroy()


def dark_titlebar(window):
    """Dark Windows title bar (Windows 10/11 only; silently skipped elsewhere)."""
    if os.name != "nt":
        return
    try:
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        one = ctypes.c_int(1)
        for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (new / older builds)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(one), ctypes.sizeof(one)) == 0:
                break

        def colorref(hex_color):
            r, g, b = (int(hex_color[i:i + 2], 16) for i in (1, 3, 5))
            return ctypes.c_int(r | (g << 8) | (b << 16))

        # Windows 11 only: caption colour + caption text colour (ignored on older builds)
        for attr, col in ((35, C["top"]), (36, C["text"])):
            val = colorref(col)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(val), ctypes.sizeof(val))
        ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0004 | 0x0020)
    except Exception as exc:
        logger.debug("Titlebar theme sync skipped: %s", exc)


# --------------------------------------------------------------------------- widgets
class WrapLabel(tk.Label):
    """Label that re-wraps its text to the width it is given."""

    def __init__(self, master, **kw):
        kw.setdefault("justify", "left")
        kw.setdefault("anchor", "w")
        super().__init__(master, **kw)
        self.bind("<Configure>", lambda e: self.configure(wraplength=max(e.width - 4, 120)))


class FlatButton(tk.Label):
    def __init__(self, master, text, command, primary=True, padx=18, pady=8):
        self._cmd, self._on = command, True
        self._fill = C["accent"] if primary else C["head"]
        self._hot = C["accent_hi"] if primary else C["hover"]
        self._ink = C["on_accent"] if primary else C["text"]
        self._edge = C["accent_lo"] if primary else C["edge"]
        super().__init__(master, text=text, bg=self._fill, fg=self._ink, font=F_BOLD, padx=padx, pady=pady,
                         cursor="hand2", highlightthickness=1, highlightbackground=self._edge,
                         highlightcolor=self._edge)
        self.bind("<Enter>", lambda e: self._on and self.configure(bg=self._hot))
        self.bind("<Leave>", lambda e: self.configure(bg=self._fill if self._on else C["inset"]))
        self.bind("<Button-1>", lambda e: self._cmd() if self._on else None)

    def set_enabled(self, on):
        self._on = on
        if on:
            self.configure(bg=self._fill, fg=self._ink, highlightbackground=self._edge, cursor="hand2")
        else:
            self.configure(bg=C["inset"], fg=C["dim"], highlightbackground=C["border"], cursor="arrow")


class Led(tk.Frame):
    """Small status light with a caption, for the toolbar."""

    def __init__(self, master, text="", color=None, command=None, bg=None):
        bg = bg or C["top"]
        super().__init__(master, bg=bg)
        self.cv = tk.Canvas(self, width=13, height=13, bg=bg, highlightthickness=0)
        self.cv.pack(side="left", padx=(0, 6))
        self.cv.create_oval(0, 0, 12, 12, fill=C["inset"], outline=C["border"])
        self.dot = self.cv.create_oval(3, 3, 9, 9, fill=color or C["dim"], outline="")
        self.lbl = tk.Label(self, text=text, font=F_CAP, bg=bg, fg=C["muted"])
        self.lbl.pack(side="left")
        if command:
            for w in (self, self.cv, self.lbl):
                w.configure(cursor="hand2")
                w.bind("<Button-1>", lambda e: command())

    def set(self, color, text=None):
        self.cv.itemconfigure(self.dot, fill=color)
        if text is not None:
            self.lbl.configure(text=text)


class Lcd(tk.Frame):
    """Inset display, like a transport readout."""

    def __init__(self, master, width=36):
        super().__init__(master, bg=C["border"])
        well = tk.Frame(self, bg=C["inset"])
        well.pack(padx=1, pady=1)
        self.var = tk.StringVar()
        self.lbl = tk.Label(well, textvariable=self.var, font=F_LCD, bg=C["inset"], fg=C["accent"],
                            width=width, anchor="w", padx=10, pady=4)
        self.lbl.pack()

    def set(self, text, color=None):
        self.var.set(text.upper())
        self.lbl.configure(fg=color or C["accent"])


class NavItem(tk.Frame):
    """Sidebar entry: numbered like channels in a rack."""

    def __init__(self, master, number, text, command):
        super().__init__(master, bg=C["side"], cursor="hand2")
        self._selected = False
        self.bar = tk.Frame(self, width=3, bg=C["side"])
        self.bar.pack(side="left", fill="y")
        self.num = tk.Label(self, text=f"{number:02d}", font=F_MONO, bg=C["side"], fg=C["dim"], padx=12, pady=11)
        self.num.pack(side="left")
        self.lbl = tk.Label(self, text=text.upper(), font=F_BOLD, bg=C["side"], fg=C["muted"], anchor="w")
        self.lbl.pack(side="left", fill="x", expand=True)
        for w in (self, self.num, self.lbl):
            w.bind("<Button-1>", lambda e: command())
            w.bind("<Enter>", lambda e: self._paint(True))
            w.bind("<Leave>", lambda e: self._paint(False))

    def _paint(self, hover=False):
        bg = C["sel"] if self._selected else (C["hover"] if hover else C["side"])
        for w in (self, self.num, self.lbl):
            w.configure(bg=bg)
        self.num.configure(fg=C["accent"] if self._selected else C["dim"])
        self.lbl.configure(fg=C["accent_hi"] if self._selected else (C["text"] if hover else C["muted"]))
        self.bar.configure(bg=C["accent"] if self._selected else bg)

    def set_selected(self, on):
        self._selected = on
        self._paint()


class Card(tk.Frame):
    def __init__(self, master, stripe=None):
        super().__init__(master, bg=C["border"])
        self.body = tk.Frame(self, bg=C["card"])
        if stripe:
            tk.Frame(self, bg=stripe, width=4).pack(side="left", fill="y", padx=(1, 0), pady=1)
            self.body.pack(side="left", fill="both", expand=True, padx=(0, 1), pady=1)
        else:
            self.body.pack(fill="both", expand=True, padx=1, pady=1)


class MetricCard(Card):
    """LCD-style readout."""

    def __init__(self, master, label, value, color=None):
        super().__init__(master)
        tk.Label(self.body, text=label.upper(), font=F_CAP, bg=C["card"], fg=C["muted"]).pack(
            anchor="w", padx=16, pady=(12, 5))
        well = tk.Frame(self.body, bg=C["inset"], highlightthickness=1, highlightbackground=C["border"])
        well.pack(fill="x", padx=14, pady=(0, 14))
        tk.Label(well, text=str(value), font=F_LCD_BIG, bg=C["inset"], fg=color or C["text"],
                 anchor="w", padx=12, pady=3).pack(fill="x")


def metrics_row(parent, items):
    row = tk.Frame(parent, bg=C["bg"])
    for i, (label, value, color) in enumerate(items):
        row.columnconfigure(i, weight=1, uniform="m")
        MetricCard(row, label, value, color).grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 12, 0))
    return row


class Banner(tk.Frame):
    """Big verdict: calm status in a few words plus a clear next step."""

    def __init__(self, master):
        super().__init__(master, bg=C["card"], highlightthickness=1, highlightbackground=C["border"])
        self.dot = tk.Canvas(self, width=44, height=44, bg=C["card"], highlightthickness=0)
        self.dot.pack(side="left", padx=(18, 14), pady=16)
        self.ring = self.dot.create_oval(1, 1, 43, 43, fill=C["inset"], outline=C["border"])
        self.oval = self.dot.create_oval(6, 6, 38, 38, fill=C["muted"], outline="")
        self.glyph = self.dot.create_text(22, 22, text="i", font=("Segoe UI Semibold", 15), fill=C["on_accent"])
        self.txt = tk.Frame(self, bg=C["card"])
        self.txt.pack(side="left", fill="x", expand=True, pady=12, padx=(0, 18))
        self.title = tk.Label(self.txt, font=("Segoe UI Semibold", 15), anchor="w", bg=C["card"], fg=C["text"])
        self.title.pack(fill="x")
        self.sub = WrapLabel(self.txt, font=F_UI, bg=C["card"], fg=C["text"])
        self.sub.pack(fill="x", pady=(2, 0))

    def show(self, kind, title, sub):
        fg, bg, border, glyph = KINDS[kind]
        for w in (self, self.dot, self.txt, self.title, self.sub):
            w.configure(bg=bg)
        self.configure(highlightbackground=border)
        self.dot.itemconfigure(self.oval, fill=fg)
        self.dot.itemconfigure(self.glyph, text=glyph, fill=C["on_accent"])
        self.title.configure(text=title, fg=C["text"] if kind == "idle" else fg)
        self.sub.configure(text=sub, fg=C["muted"] if kind == "idle" else C["text"])


class Collapsible(tk.Frame):
    def __init__(self, master, title):
        super().__init__(master, bg=C["bg"])
        self._title, self._open = title, False
        self.header = tk.Label(self, text="\u25b8  " + title.upper(), bg=C["bg"], fg=C["muted"], font=F_CAP,
                               cursor="hand2", anchor="w")
        self.header.pack(fill="x", pady=(6, 4))
        self.header.bind("<Button-1>", lambda e: self.toggle())
        self.body = tk.Frame(self, bg=C["bg"])

    def toggle(self):
        self._open = not self._open
        self.header.configure(text=("\u25be  " if self._open else "\u25b8  ") + self._title.upper(),
                              fg=C["accent"] if self._open else C["muted"])
        if self._open:
            self.body.pack(fill="x", padx=(18, 0))
        else:
            self.body.pack_forget()


class ScrollFrame(tk.Frame):
    _live = []   # every ScrollFrame that currently exists

    def __init__(self, master):
        super().__init__(master, bg=C["bg"])
        self.canvas = tk.Canvas(self, bg=C["bg"], highlightthickness=0, yscrollincrement=20)
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview, style="Vertical.TScrollbar")
        self.canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=C["bg"])
        win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(win, width=e.width))
        ScrollFrame._live.append(self)

    def destroy(self):
        if self in ScrollFrame._live:
            ScrollFrame._live.remove(self)
        super().destroy()

    @staticmethod
    def dispatch(app, e):
        """Bound once on the app: scroll whichever ScrollFrame is under the pointer."""
        try:
            w = app.winfo_containing(e.x_root, e.y_root)
        except (KeyError, tk.TclError):
            return
        if isinstance(w, (ttk.Treeview, tk.Text)):
            return
        while w is not None:
            for sf in ScrollFrame._live:
                if w is sf:
                    sf.canvas.yview_scroll(-3 if e.delta > 0 else 3, "units")
                    return
            w = getattr(w, "master", None)


class MeterBar(tk.Canvas):
    """Segmented meter. start()/stop() animate a sweep; set(0-100) shows a level."""

    SEG, GAP = 12, 3

    def __init__(self, master, height=10):
        super().__init__(master, height=height, bg=C["inset"], highlightthickness=1,
                         highlightbackground=C["border"])
        self._value, self._pos, self._running, self._job = 0.0, 0, False, None
        self.bind("<Configure>", lambda e: self._draw())

    def set(self, pct):
        self._value = max(0.0, min(100.0, float(pct)))
        self._draw()

    def start(self):
        if not self._running:
            self._running = True
            self._tick()

    def stop(self):
        self._running = False
        if self._job:
            try:
                self.after_cancel(self._job)
            except (tk.TclError, ValueError):
                pass
            self._job = None
        self._value = 0.0
        self._draw()

    def _tick(self):
        if not self._running:
            return
        self._pos += 1
        self._draw()
        self._job = self.after(55, self._tick)

    def _draw(self):
        self.delete("all")
        w = self.winfo_width()
        h = int(float(self.cget("height")))
        n = max(1, (w - 4) // (self.SEG + self.GAP))
        tail = 7
        for i in range(n):
            x = 3 + i * (self.SEG + self.GAP)
            if self._running:
                d = (i - self._pos) % (n + tail)
                lit = d < tail
                col = C["accent_hi"] if d == tail - 1 else C["accent"] if lit else C["card"]
                if lit and d < tail - 3:
                    col = C["accent_lo"]
            else:
                lit = (i + 1) / n * 100 <= self._value + 0.001
                col = C["accent"] if lit else C["card"]
            self.create_rectangle(x, 2, x + self.SEG, h - 1, fill=col, outline="")


class SlimSlider(tk.Canvas):
    """Thin orange-filled slider that snaps to a step."""

    def __init__(self, master, lo, hi, value, step, command=None, width=210, bg=None):
        super().__init__(master, width=width, height=28, bg=bg or C["card"], highlightthickness=0, cursor="hand2")
        self.lo, self.hi, self.step, self.value, self._cmd = lo, hi, step, value, command
        self.bind("<Button-1>", self._move)
        self.bind("<B1-Motion>", self._move)
        self.bind("<Configure>", lambda e: self._draw())
        self._draw()

    def get(self):
        return self.value

    def _move(self, e):
        w = max(1, (self.winfo_width() or int(float(self.cget("width")))) - 24)
        frac = min(1.0, max(0.0, (e.x - 12) / w))
        v = int(round((self.lo + frac * (self.hi - self.lo)) / self.step) * self.step)
        v = max(self.lo, min(self.hi, v))
        if v != self.value:
            self.value = v
            self._draw()
            if self._cmd:
                self._cmd(v)

    def _draw(self):
        self.delete("all")
        w = self.winfo_width() or int(float(self.cget("width")))
        x0, x1, y = 12, w - 12, 14
        hx = x0 + (self.value - self.lo) / (self.hi - self.lo) * (x1 - x0)
        self.create_rectangle(x0, y - 3, x1, y + 3, fill=C["inset"], outline=C["border"])
        self.create_rectangle(x0, y - 2, hx, y + 2, fill=C["accent"], outline="")
        self.create_rectangle(hx - 6, y - 10, hx + 6, y + 10, fill=C["head"], outline=C["edge"])
        self.create_line(hx, y - 6, hx, y + 6, fill=C["accent"], width=2)


def page_header(parent, title, subtitle):
    f = tk.Frame(parent, bg=C["bg"])
    f.pack(fill="x", padx=28, pady=(24, 0))
    tk.Label(f, text=title, font=F_H1, fg=C["text"], bg=C["bg"], anchor="w").pack(fill="x")
    tk.Label(f, text=subtitle, font=F_UI, fg=C["muted"], bg=C["bg"], anchor="w").pack(fill="x", pady=(2, 8))
    tk.Frame(f, bg=C["accent"], width=44, height=3).pack(anchor="w")


def heading(parent, text):
    row = tk.Frame(parent, bg=C["bg"])
    row.pack(fill="x", pady=(22, 8))
    tk.Frame(row, bg=C["accent"], width=3, height=14).pack(side="left", padx=(0, 8))
    tk.Label(row, text=text.upper(), font=F_CAP, fg=C["text"], bg=C["bg"], anchor="w").pack(side="left")


def brief_card(parent, title, text, source):
    c = Card(parent)
    c.pack(fill="x", pady=(12, 0))
    tk.Label(c.body, text=title.upper(), font=F_CAP, fg=C["accent"], bg=C["card"]).pack(
        anchor="w", padx=16, pady=(12, 4))
    WrapLabel(c.body, text=text, font=("Segoe UI", 11), fg=C["text"], bg=C["card"]).pack(fill="x", padx=16)
    tk.Label(c.body, text=f"Written by: {source}", font=F_SMALL, fg=C["dim"], bg=C["card"]).pack(
        anchor="w", padx=16, pady=(8, 12))


def alert_card(parent, level, title, what, why, fix, tech="", evidence=()):
    badge, fg, bg = LEVEL.get(level, LEVEL["Medium"])
    c = Card(parent, stripe=fg)
    b = c.body
    top = tk.Frame(b, bg=C["card"])
    top.pack(fill="x", padx=16, pady=(14, 8))
    tk.Label(top, text=title, bg=C["card"], fg=C["text"], font=F_H2).pack(side="left")
    tk.Label(top, text=badge, bg=bg, fg=fg, font=F_CAP, padx=9, pady=2).pack(side="left", padx=12)
    for label, text in ((" What's happening", what), (" Why it matters", why), (" What to do", fix)):
        row = tk.Frame(b, bg=C["card"])
        row.pack(fill="x", padx=16, pady=3)
        tk.Label(row, text=label.strip().upper(), width=17, anchor="nw", fg=C["muted"], bg=C["card"],
                 font=F_CAP).pack(side="left", anchor="n", pady=(2, 0))
        WrapLabel(row, text=text, bg=C["card"], fg=C["text"], font=F_UI).pack(side="left", fill="x", expand=True)
    if evidence:
        tk.Label(b, text="\n".join(evidence), bg=C["inset"], fg=C["text"], font=F_MONO, anchor="w",
                 justify="left", padx=10, pady=8).pack(fill="x", padx=16, pady=(8, 0))
    if tech:
        tk.Label(b, text=tech, bg=C["card"], fg=C["muted"], font=("Consolas", 9), anchor="w").pack(
            fill="x", padx=16, pady=(8, 0))
    tk.Frame(b, bg=C["card"], height=14).pack()
    return c


def make_tree(parent, cols, widths, height=6):
    frame = tk.Frame(parent, bg=C["border"])
    tree = ttk.Treeview(frame, columns=cols, show="headings", height=height, selectmode="browse")
    for col, w in zip(cols, widths):
        tree.heading(col, text=col.upper(), anchor="w")
        tree.column(col, width=w, anchor="w", stretch=True)
    tree.tag_configure("odd", background=C["odd"])
    tree.pack(fill="both", expand=True, padx=1, pady=1)
    return frame, tree


def show_friendly_error(parent, plain_message, technical_details):
    b = Banner(parent)
    b.pack(fill="x", pady=(4, 12), padx=(0, 12))
    b.show("bad", "Something went wrong", plain_message)
    if technical_details:
        sec = Collapsible(parent, "Technical details")
        sec.pack(fill="x", pady=(4, 12), padx=(0, 12))
        txt = tk.Text(sec.body, height=4, bg=C["inset"], fg=C["muted"], relief="flat", font=F_MONO,
                      padx=10, pady=8, wrap="word", highlightthickness=1, highlightbackground=C["border"])
        txt.insert("1.0", technical_details)
        txt.configure(state="disabled")
        txt.pack(fill="x")


# --------------------------------------------------------------------------- app
class Audit4AllApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1180x800")
        self.minsize(980, 660)
        self.configure(bg=C["bg"])

        self.q = queue.Queue()
        self.audit = None
        self.audit_time = ""
        self.traffic = None
        self.iface_map = {}
        self._auditing = False
        self._capturing = False
        self._current = None
        self._startup_busy = False
        self._downloading = False
        self._seconds = 60
        self.startup = None

        self._style()
        self._layout()
        dark_titlebar(self)
        self.bind_all("<MouseWheel>", lambda e: ScrollFrame.dispatch(self, e))

        if PCAP_OK:
            threading.Thread(target=self._load_ifaces, daemon=True).start()
        self.after(100, self._poll)

    # ---- ttk styling
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        s.configure("Treeview", background=C["card"], fieldbackground=C["card"], foreground=C["text"],
                    rowheight=28, borderwidth=0, font=F_UI)
        s.configure("Treeview.Heading", background=C["head"], foreground=C["muted"], font=F_CAP,
                    relief="flat", padding=(8, 7))
        s.map("Treeview", background=[("selected", C["sel"])], foreground=[("selected", C["accent_hi"])])
        s.map("Treeview.Heading", background=[("active", C["head"])])
        s.configure("TCombobox", fieldbackground=C["inset"], background=C["head"], foreground=C["text"],
                    arrowcolor=C["accent"], bordercolor=C["border"], lightcolor=C["border"],
                    darkcolor=C["border"], selectbackground=C["inset"], selectforeground=C["text"], padding=6)
        s.map("TCombobox", fieldbackground=[("readonly", C["inset"])], foreground=[("readonly", C["text"])],
              selectbackground=[("readonly", C["inset"])], selectforeground=[("readonly", C["text"])])
        self.option_add("*TCombobox*Listbox.background", C["inset"])
        self.option_add("*TCombobox*Listbox.foreground", C["text"])
        self.option_add("*TCombobox*Listbox.selectBackground", C["sel"])
        self.option_add("*TCombobox*Listbox.selectForeground", C["accent_hi"])
        s.layout("Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [
            ("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
        s.configure("Vertical.TScrollbar", background=C["edge"], troughcolor=C["bg"], bordercolor=C["bg"],
                    lightcolor=C["edge"], darkcolor=C["edge"], gripcount=0, width=10, relief="flat")
        s.map("Vertical.TScrollbar", background=[("active", C["muted"])])
        for name, bg in (("Card.TCheckbutton", C["card"]), ("Dlg.TCheckbutton", C["bg"])):
            s.configure(name, background=bg, foreground=C["muted"], font=F_SMALL, focuscolor=bg,
                        indicatorbackground=C["inset"], indicatorforeground=C["on_accent"],
                        upperbordercolor=C["border"], lowerbordercolor=C["border"])
            s.map(name, background=[("active", bg)], foreground=[("active", C["text"])],
                  indicatorbackground=[("selected", C["accent"]), ("active", C["head"])])

    # ---- layout: toolbar + sidebar + pages
    def _layout(self):
        self.shell = tk.Frame(self, bg=C["bg"])
        self.shell.pack(fill="both", expand=True)

        # ---- toolbar
        top = tk.Frame(self.shell, bg=C["top"], height=56)
        top.pack(fill="x")
        top.pack_propagate(False)
        brand = tk.Frame(top, bg=C["top"])
        brand.pack(side="left", padx=(20, 22))
        tk.Label(brand, text=APP_NAME, font=("Segoe UI Black", 15), fg=C["accent"], bg=C["top"]).pack(anchor="w")
        self.lcd = Lcd(top, width=38)
        self.lcd.pack(side="left", pady=11)
        right = tk.Frame(top, bg=C["top"])
        right.pack(side="right", padx=20)
        admin = is_admin()
        self.admin_led = Led(right, "ADMIN" if admin else "STANDARD", C["green"] if admin else C["amber"])
        self.admin_led.pack(side="left", padx=(0, 18))
        self.ai_led = Led(right, "", C["dim"], command=self.open_settings)
        self.ai_led.pack(side="left")
        tk.Frame(self.shell, bg=C["border"], height=1).pack(fill="x")

        body = tk.Frame(self.shell, bg=C["bg"])
        body.pack(fill="both", expand=True)

        # ---- side rail
        side = tk.Frame(body, bg=C["side"], width=220)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(body, bg=C["border"], width=1).pack(side="left", fill="y")
        self.main = tk.Frame(body, bg=C["bg"])
        self.main.pack(side="left", fill="both", expand=True)

        bottom = tk.Frame(side, bg=C["side"])   # packed first so it can never be squeezed out
        bottom.pack(side="bottom", fill="x", padx=16, pady=(0, 16))
        tk.Frame(bottom, bg=C["border"], height=1).pack(fill="x", pady=(0, 12))
        FlatButton(bottom, "AI settings", self.open_settings, primary=False, pady=6).pack(fill="x")
        WrapLabel(bottom, font=F_SMALL, fg=C["dim"], bg=C["side"],
                  text="Checks stay on your computer. Only a short summary of results is sent if you turn on AI."
                  ).pack(fill="x", pady=(12, 0))

        tk.Label(side, text="CHECKS", font=F_CAP, fg=C["dim"], bg=C["side"], anchor="w").pack(
            fill="x", padx=18, pady=(20, 8))
        self.nav = {}
        for i, (key, label) in enumerate((("audit", "Home check"), ("startup", "Startup programs"),
                                          ("traffic", "Network activity"), ("tech", "Technical details")), 1):
            item = NavItem(side, i, label, lambda k=key: self.show_page(k))
            item.pack(fill="x", pady=1)
            self.nav[key] = item
        self._refresh_ai_badge()

        if not admin:
            tk.Label(
                self.main,
                text="We couldn't check everything. For a full check, right-click the app and choose 'Run as administrator.'",
                font=F_SMALL, fg=C["amber"], bg=C["amber_bg"], pady=8, padx=28, anchor="w",
            ).pack(fill="x")

        self.tab_audit = tk.Frame(self.main, bg=C["bg"])
        self.tab_startup = tk.Frame(self.main, bg=C["bg"])
        self.tab_traffic = tk.Frame(self.main, bg=C["bg"])
        self.tab_tech = tk.Frame(self.main, bg=C["bg"])
        self.pages = {"audit": self.tab_audit, "startup": self.tab_startup,
                      "traffic": self.tab_traffic, "tech": self.tab_tech}
        self._build_audit_tab()
        self._build_startup_tab()
        self._build_traffic_tab()
        self._build_tech_tab()
        self.show_page("audit")
        self._lcd_idle()

    def show_page(self, key):
        if self._current:
            self.pages[self._current].pack_forget()
            self.nav[self._current].set_selected(False)
        self.pages[key].pack(fill="both", expand=True)
        self.nav[key].set_selected(True)
        self._current = key

    def _refresh_ai_badge(self):
        ok = bool(get_api_key())
        self.ai_led.set(C["green"] if ok else C["dim"], "AI ON" if ok else "AI OFF")

    # ---- toolbar readout
    def _lcd(self, text, color=None):
        self.lcd.set(text, color)

    def _lcd_idle(self):
        if self._busy():
            return
        self._lcd("Ready")

    def _busy(self):
        return self._auditing or self._capturing or self._startup_busy or self._downloading

    # ================================================================ endpoint audit
    def _build_audit_tab(self):
        page = self.tab_audit
        page_header(page, "Am I being hacked or spied on?", "A calm, plain-English check of your computer.")
        bar = tk.Frame(page, bg=C["bg"])
        bar.pack(fill="x", padx=28, pady=(14, 8))
        self.audit_btn = FlatButton(bar, "RUN AUDIT", self.run_audit, padx=22)
        self.audit_btn.pack(side="left")
        self.audit_export = FlatButton(bar, "Save a plain report (readable)", self.export_audit, primary=False)
        self.audit_export.pack(side="left", padx=10)
        self.audit_export.set_enabled(False)
        self.audit_status = tk.Label(bar, text="", font=F_UI, fg=C["muted"], bg=C["bg"])
        self.audit_status.pack(side="left", padx=12)

        self.audit_progress = MeterBar(page)
        self.audit_scroll = ScrollFrame(page)
        self.audit_scroll.pack(fill="both", expand=True, padx=(28, 16), pady=(4, 12))
        self._render_audit_idle()

    def _render_audit_idle(self):
        body = self.audit_scroll.inner
        clear(body)
        wrap = tk.Frame(body, bg=C["bg"])
        wrap.pack(fill="x", padx=(0, 12))
        c = Card(wrap)
        c.pack(fill="x", pady=(4, 12))
        WrapLabel(c.body, text=INTRO_TEXT, font=("Segoe UI", 11), fg=C["text"], bg=C["card"]).pack(
            fill="x", padx=18, pady=(16, 12))
        FlatButton(c.body, "RUN AUDIT", self.run_audit, padx=22).pack(anchor="w", padx=18, pady=(0, 18))

    def run_audit(self):
        if self._auditing:
            return
        self._auditing = True
        self.audit_btn.set_enabled(False)
        self.audit_status.configure(text="Checking your computer...", fg=C["muted"])
        self._lcd("Scanning this computer")
        self.audit_progress.pack(fill="x", padx=28, pady=(0, 4), before=self.audit_scroll)
        self.audit_progress.start()
        threading.Thread(target=self._audit_worker, daemon=True).start()

    def _audit_worker(self):
        try:
            facts = collect_network_facts()
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.q.put(("audit_stage", "Writing the plain-English answer..."))
            summary, source = generate_executive_summary(facts)
            self.q.put(("audit_ok", facts, summary, source, stamp))
        except Exception as exc:
            logger.exception("Audit worker failed: %s", exc)
            self.q.put(("audit_err", f"{type(exc).__name__}: {exc}"))

    def _on_audit_stage(self, text):
        self.audit_status.configure(text=text)
        self._lcd("Writing the answer")

    def _audit_finish(self):
        self._auditing = False
        self.audit_progress.stop()
        self.audit_progress.pack_forget()
        self.audit_btn.set_enabled(True)

    def _on_audit_err(self, tech_text):
        self._audit_finish()
        self.audit_status.configure(text="Check could not finish", fg=C["red"])
        self._lcd("Check failed", C["red"])
        body = self.audit_scroll.inner
        clear(body)
        wrap = tk.Frame(body, bg=C["bg"])
        wrap.pack(fill="x", padx=(0, 12))
        show_friendly_error(
            wrap,
            "We couldn't complete this check right now. Try running the app again, or right-click and choose 'Run as administrator.'",
            tech_text,
        )

    def _on_audit_ok(self, facts, summary, source, stamp):
        self._audit_finish()
        self.audit = {"summary": summary, "summary_source": source, "findings": facts}
        self.audit_time = stamp
        self.audit_export.set_enabled(True)
        self.audit_status.configure(text=f"Last check: {stamp}", fg=C["muted"])
        actionable = needs_attention(facts)
        if actionable:
            self._lcd(f"{len(actionable)} to look at", C["amber"])
        else:
            self._lcd("All clear" if not backend.PARTIAL_RESULTS else "Incomplete check",
                      C["green"] if not backend.PARTIAL_RESULTS else C["amber"])
        self._render_audit()
        self._fill_tech()

    def _render_audit(self):
        body = self.audit_scroll.inner
        clear(body)
        wrap = tk.Frame(body, bg=C["bg"])
        wrap.pack(fill="x", padx=(0, 12))
        findings = self.audit["findings"]
        actionable = needs_attention(findings)
        normal = normal_app_names(findings, actionable)

        banner = Banner(wrap)
        banner.pack(fill="x", pady=(4, 12))
        if not actionable and backend.PARTIAL_RESULTS:
            banner.show("warn", "Check was incomplete.",
                        "We couldn't check everything. Run as administrator for a full answer.")
            n_color = C["amber"]
        elif not actionable:
            banner.show("ok", "Your computer looks normal. Nothing to do.",
                        "You are likely fine. You can close this app.")
            n_color = C["green"]
        elif actionable[0]["alert_level"] == "High":
            banner.show("bad", "Something needs your attention. Here's how to fix it.",
                        "Follow the steps below to protect your computer.")
            n_color = C["red"]
        else:
            banner.show("warn", "One thing to look at. It's probably fine. Here's how to check.",
                        "Take a quick look below — most items turn out to be normal.")
            n_color = C["amber"]

        metrics_row(wrap, [
            ("Checked", len(findings), None),
            ("To look at", len(actionable), n_color),
            ("Normal", len(findings) - len(actionable), C["green"]),
        ]).pack(fill="x")

        brief_card(wrap, "Answer", self.audit["summary"], self.audit["summary_source"])

        if actionable:
            heading(wrap, "What to look at")
            for f in actionable:
                alert_card(
                    wrap, f["alert_level"], f["plain_title"],
                    f["description"], f["business_impact"], f["fix"],
                    tech=f"program: {f['process']}",
                ).pack(fill="x", pady=(0, 10))

        if normal:
            sec = Collapsible(wrap, f"Checked and normal ({len(normal)})")
            sec.pack(fill="x", pady=(12, 0))
            for n in normal:
                tk.Label(sec.body, text="\u2713   " + n, font=F_UI, fg=C["text"], bg=C["bg"],
                         anchor="w").pack(fill="x", pady=2)
        tk.Label(wrap, text=f"Checked {self.audit_time}", font=F_SMALL, fg=C["dim"],
                 bg=C["bg"]).pack(anchor="w", pady=(16, 10))

    def export_audit(self):
        if not self.audit:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Plain text report", "*.txt")],
            initialfile=f"audit4all_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(build_plain_report(self.audit, self.audit_time))
            self.audit_status.configure(text=f"Saved {os.path.basename(path)}", fg=C["green"])

    # ================================================================ startup programs
    def _build_startup_tab(self):
        page = self.tab_startup
        page_header(page, "Startup programs",
                    "Checks which programs start automatically when you turn on your computer.")
        bar = tk.Frame(page, bg=C["bg"])
        bar.pack(fill="x", padx=28, pady=(14, 8))
        self.startup_btn = FlatButton(bar, "RUN CHECK", self.run_startup, padx=22)
        self.startup_btn.pack(side="left")
        self.startup_export = FlatButton(bar, "Save a plain report (readable)", self.export_startup, primary=False)
        self.startup_export.pack(side="left", padx=10)
        self.startup_export.set_enabled(False)
        self.startup_status = tk.Label(bar, text="", font=F_UI, fg=C["muted"], bg=C["bg"])
        self.startup_status.pack(side="left", padx=12)

        self.startup_progress = MeterBar(page)
        self.startup_scroll = ScrollFrame(page)
        self.startup_scroll.pack(fill="both", expand=True, padx=(28, 16), pady=(4, 12))
        self._render_startup_idle()

    def _render_startup_idle(self):
        body = self.startup_scroll.inner
        clear(body)
        wrap = tk.Frame(body, bg=C["bg"])
        wrap.pack(fill="x", padx=(0, 12))
        b = Banner(wrap)
        b.pack(fill="x", pady=(4, 12))
        if not STARTUP_OK:
            self.startup_btn.set_enabled(False)
            b.show("warn", "Startup check is unavailable.",
                   "The startup check helper wasn't found next to this app, so this button is turned off.")
            return
        if startup_audit.find_tool():
            b.show("idle", "Ready when you are.",
                   "Choose 'Run check' to see what starts automatically on your computer.")
            return
        b.show("idle", "One-time setup needed.",
               "This check uses a free tool from Microsoft to inspect programs that start on their own.")
        c = Card(wrap)
        c.pack(fill="x")
        WrapLabel(c.body, font=F_UI, fg=C["text"], bg=C["card"],
                  text="We can download it from Microsoft into a 'tools' folder next to this app and check "
                       "that it is genuinely signed by Microsoft before using it."
                  ).pack(fill="x", padx=16, pady=(14, 10))
        self.tool_btn = FlatButton(c.body, "DOWNLOAD FROM MICROSOFT", self.download_autoruns)
        self.tool_btn.pack(anchor="w", padx=16, pady=(0, 16))

    def download_autoruns(self):
        if self._downloading or not STARTUP_OK:
            return
        self._downloading = True
        self.tool_btn.set_enabled(False)
        self.startup_status.configure(text="Downloading from Microsoft...", fg=C["muted"])
        self._lcd("Downloading tool")
        threading.Thread(target=self._download_worker, daemon=True).start()

    def _download_worker(self):
        try:
            startup_audit.download_tool()
            self.q.put(("tool_ok",))
        except Exception as exc:
            logger.exception("Autoruns download failed: %s", exc)
            self.q.put(("tool_err", f"{type(exc).__name__}: {exc}"))

    def _on_tool_ok(self):
        self._downloading = False
        self.startup_status.configure(text="Setup complete.", fg=C["green"])
        self._lcd("Setup complete", C["green"])
        self._render_startup_idle()

    def _on_tool_err(self, tech_text):
        self._downloading = False
        self.startup_status.configure(text="Download didn't work", fg=C["red"])
        self._lcd("Download failed", C["red"])
        self._render_startup_idle()
        show_friendly_error(
            self.startup_scroll.inner,
            "We couldn't download the startup tool right now. Check your internet connection and try again.",
            tech_text,
        )

    def run_startup(self):
        if self._startup_busy or not STARTUP_OK:
            return
        if not startup_audit.find_tool():
            self._render_startup_idle()
            return
        self._startup_busy = True
        self.startup_btn.set_enabled(False)
        self.startup_status.configure(text="Checking startup programs (about a minute)...", fg=C["muted"])
        self._lcd("Scanning startup items")
        self.startup_progress.pack(fill="x", padx=28, pady=(0, 4), before=self.startup_scroll)
        self.startup_progress.start()
        threading.Thread(target=self._startup_worker, daemon=True).start()

    def _startup_worker(self):
        try:
            result = startup_audit.audit_startup()
            self.q.put(("startup_stage", "Writing the plain-English answer..."))
            summary, source = startup_audit.explain_startup(result)
            self.q.put(("startup_ok", result, summary, source, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        except Exception as exc:
            logger.exception("Startup check failed: %s", exc)
            self.q.put(("startup_err", f"{type(exc).__name__}: {exc}"))

    def _on_startup_stage(self, text):
        self.startup_status.configure(text=text)
        self._lcd("Writing the answer")

    def _startup_finish(self):
        self._startup_busy = False
        self.startup_progress.stop()
        self.startup_progress.pack_forget()
        self.startup_btn.set_enabled(True)

    def _on_startup_err(self, tech_text):
        self._startup_finish()
        self.startup_status.configure(text="Check could not finish", fg=C["red"])
        self._lcd("Check failed", C["red"])
        body = self.startup_scroll.inner
        clear(body)
        wrap = tk.Frame(body, bg=C["bg"])
        wrap.pack(fill="x", padx=(0, 12))
        show_friendly_error(
            wrap,
            "We couldn't finish checking your startup programs. Try again, or run as administrator for a full check.",
            tech_text,
        )

    def _on_startup_ok(self, result, summary, source, stamp):
        self._startup_finish()
        self.startup = {"result": result, "summary": summary, "source": source, "time": stamp}
        self.startup_export.set_enabled(True)
        self.startup_status.configure(text=f"Last check: {stamp}", fg=C["muted"])
        n = len(result["findings"])
        self._lcd(f"{n} to look at" if n else "All clear", C["amber"] if n else C["green"])
        self._render_startup()

    def _render_startup(self):
        t = self.startup
        result, findings = t["result"], t["result"]["findings"]
        body = self.startup_scroll.inner
        clear(body)
        wrap = tk.Frame(body, bg=C["bg"])
        wrap.pack(fill="x", padx=(0, 12))

        banner = Banner(wrap)
        banner.pack(fill="x", pady=(4, 12))
        if not findings:
            banner.show("ok", "Your computer looks normal. Nothing to do.",
                        "None of the programs starting automatically look suspicious.")
            n_color = C["green"]
        elif findings[0]["risk"] == "High":
            banner.show("bad", "Something needs your attention. Here's how to fix it.",
                        "A startup program looks unusual and is worth checking.")
            n_color = C["red"]
        else:
            banner.show("warn", "One thing to look at. It's probably fine. Here's how to check.",
                        "Review the startup programs listed below.")
            n_color = C["amber"]

        metrics_row(wrap, [
            ("Checked", result["stats"]["entries"], None),
            ("To look at", len(findings), n_color),
            ("Normal", len(result["normal"]), C["green"]),
        ]).pack(fill="x")

        brief_card(wrap, "Answer", t["summary"], t["source"])

        if findings:
            heading(wrap, "What to look at")
            for f in findings:
                alert_card(wrap, f["risk"], f["title"], f["what"], f["why"], f["fix"],
                           evidence=f["evidence"]).pack(fill="x", pady=(0, 10))

        if result["normal"]:
            sec = Collapsible(wrap, f"Checked and normal ({len(result['normal'])})")
            sec.pack(fill="x", pady=(12, 0))
            for line in result["normal"]:
                tk.Label(sec.body, text="\u2713   " + line, font=F_UI, fg=C["text"], bg=C["bg"],
                         anchor="w").pack(fill="x", pady=2)

        note = "Standard Windows entries are left out."
        if not is_admin():
            note += " We couldn't check everything — run as administrator for full results."
        tk.Label(wrap, text=note, font=F_SMALL, fg=C["dim"], bg=C["bg"]).pack(anchor="w", pady=(16, 10))

    def export_startup(self):
        if not self.startup:
            return
        t = self.startup
        findings = t["result"].get("findings", [])
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Plain text report", "*.txt")],
            initialfile=f"audit4all_startup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if path:
            lines = [
                "=== AUDIT4ALL REPORT ===",
                f"Date: {t['time'][:16]}",
            ]
            if not findings:
                lines.extend([
                    "Result: YOUR COMPUTER LOOKS NORMAL",
                    "",
                    f"What we checked: {t['result'].get('stats', {}).get('entries', 0)} startup programs.",
                    "What we found: nothing suspicious.",
                ])
            else:
                top = findings[0]
                lines.extend([
                    "Result: ONE THING NEEDS YOUR ATTENTION",
                    f"What: {top.get('title', 'Startup program')}",
                    f"Why it matters: {top.get('why', 'A program starts automatically on your computer.')}",
                    f"What to do: {top.get('fix', 'Disable or remove it if you do not recognize it.')}",
                    "",
                    "Nothing else on your computer looks suspicious.",
                ])
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            self.startup_status.configure(text=f"Saved {os.path.basename(path)}", fg=C["green"])

    # ================================================================ live traffic
    def _build_traffic_tab(self):
        page = self.tab_traffic
        page_header(page, "Network activity",
                    "Watches what your computer sends and receives for a short time to spot anything unusual.")
        ctl = Card(page)
        ctl.pack(fill="x", padx=28, pady=(16, 8))
        row = tk.Frame(ctl.body, bg=C["card"])
        row.pack(fill="x", padx=16, pady=(14, 4))
        row.columnconfigure(0, weight=1)

        tk.Label(row, text="CONNECTION TYPE", font=F_CAP, fg=C["muted"], bg=C["card"]).grid(
            row=0, column=0, sticky="w")
        self.iface_var = tk.StringVar(value="Default connection")
        self.iface_box = ttk.Combobox(row, textvariable=self.iface_var, state="readonly",
                                      values=["Default connection"])
        self.iface_box.grid(row=1, column=0, sticky="we", padx=(0, 20), pady=(4, 0))

        tk.Label(row, text="HOW LONG TO WATCH", font=F_CAP, fg=C["muted"], bg=C["card"]).grid(
            row=0, column=1, sticky="w")
        dur = tk.Frame(row, bg=C["card"])
        dur.grid(row=1, column=1, pady=(4, 0))
        self.dur = 60
        self.dur_slider = SlimSlider(dur, 10, 300, 60, 10, command=self._on_dur, width=200)
        self.dur_slider.pack(side="left")
        self.dur_lbl = tk.Label(dur, text="60 s", width=6, font=F_LCD, fg=C["accent"], bg=C["card"])
        self.dur_lbl.pack(side="left")

        self.cap_btn = FlatButton(row, "START CHECK", self.start_capture, padx=22)
        self.cap_btn.grid(row=1, column=2, padx=(20, 0), pady=(4, 0))

        self.ptr_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctl.body,
                        text="Look up unknown internet addresses (sends those addresses to your internet provider's lookup)",
                        variable=self.ptr_var, style="Card.TCheckbutton").pack(anchor="w", padx=16, pady=(8, 0))
        self.cap_status = tk.Label(ctl.body, font=F_UI, fg=C["muted"], bg=C["card"], anchor="w",
                                   text="Use your computer normally while it checks. Longer checks can spot repeating background activity.")
        self.cap_status.pack(fill="x", padx=16, pady=(8, 6))
        self.cap_progress = MeterBar(ctl.body)
        self.cap_progress.pack(fill="x", padx=16, pady=(0, 14))

        self.traffic_scroll = ScrollFrame(page)
        self.traffic_scroll.pack(fill="both", expand=True, padx=(28, 16), pady=(4, 12))
        self._render_traffic_idle()

        if not PCAP_OK:
            self.cap_btn.set_enabled(False)
            self.cap_status.configure(
                text="To watch live network traffic, install Npcap from npcap.com (tick 'WinPcap API-compatible mode') and run as administrator.",
                fg=C["amber"],
            )

    def _on_dur(self, v):
        self.dur = int(v)
        self.dur_lbl.configure(text=f"{self.dur} s")

    def _render_traffic_idle(self):
        body = self.traffic_scroll.inner
        clear(body)
        b = Banner(body)
        b.pack(fill="x", pady=(4, 0), padx=(0, 12))
        b.show("idle", "Ready to check activity.",
               "Choose 'Start check' and use your computer normally. On Windows, live traffic watching needs Npcap from npcap.com and running as administrator.")

    def _load_ifaces(self):
        try:
            self.q.put(("ifaces", list_interfaces()))
        except Exception as exc:
            logger.exception("Failed to list network adapters: %s", exc)
            self.q.put(("ifaces", {}))

    def _on_ifaces(self, mapping):
        self.iface_map = mapping
        self.iface_box.configure(values=["Default connection"] + list(mapping))

    def start_capture(self):
        if self._capturing or not PCAP_OK:
            return
        self._capturing = True
        seconds = int(self.dur)
        iface = self.iface_map.get(self.iface_var.get())
        ptr = self.ptr_var.get()
        self._seconds = seconds
        self.cap_btn.set_enabled(False)
        self.cap_progress.set(0)
        self._lcd("Watching traffic")
        self._cap_start, self._cap_total = time.time(), seconds
        self._tick_capture()
        threading.Thread(target=self._capture_worker, args=(seconds, iface, ptr), daemon=True).start()

    def _tick_capture(self):
        if not self._capturing:
            return
        elapsed = time.time() - self._cap_start
        if elapsed < self._cap_total:
            left = int(self._cap_total - elapsed)
            self.cap_progress.set(elapsed / self._cap_total * 100)
            self.cap_status.configure(text=f"Checking... {left} s left. Use your computer normally.", fg=C["text"])
            self._lcd(f"Watching traffic  {left:>3} s", C["accent"])
        self.after(250, self._tick_capture)

    def _capture_worker(self, seconds, iface, ptr=False):
        try:
            result = capture_live(seconds, iface, ptr_lookup=ptr)
            self.q.put(("cap_stage", "Writing the plain-English answer..."))
            summary, source = explain_capture(result)
            self.q.put(("cap_ok", result, summary, source, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        except Exception as exc:
            logger.exception("Live capture failed: %s", exc)
            self.q.put(("cap_err", f"{type(exc).__name__}: {exc}"))

    def _on_cap_stage(self, text):
        self._cap_total = 0  # stop the countdown text
        self.cap_progress.set(100)
        self.cap_status.configure(text=text, fg=C["text"])
        self._lcd("Writing the answer")

    def _cap_finish(self):
        self._capturing = False
        self.cap_btn.set_enabled(True)
        self.cap_progress.set(0)

    def _on_cap_err(self, tech_text):
        self._cap_finish()
        self.cap_status.configure(text="Check could not finish", fg=C["red"])
        self._lcd("Check failed", C["red"])
        body = self.traffic_scroll.inner
        clear(body)
        wrap = tk.Frame(body, bg=C["bg"])
        wrap.pack(fill="x", padx=(0, 12))
        show_friendly_error(
            wrap,
            "To watch live network traffic, install Npcap from npcap.com (tick 'WinPcap API-compatible mode') and run as administrator.",
            tech_text,
        )

    def _on_cap_ok(self, result, summary, source, stamp):
        self._cap_finish()
        self.traffic = {"result": result, "summary": summary, "source": source, "time": stamp,
                        "adapter": self.iface_var.get(), "seconds": self._seconds}
        self.cap_status.configure(text=f"Last check: {stamp}", fg=C["muted"])
        n = len(result["findings"])
        if result["stats"]["packets"] == 0:
            self._lcd("No traffic caught", C["amber"])
        else:
            self._lcd(f"{n} to look at" if n else "All clear", C["amber"] if n else C["green"])
        self._render_traffic()

    def _render_traffic(self):
        t = self.traffic
        result, stats, findings = t["result"], t["result"]["stats"], t["result"]["findings"]
        body = self.traffic_scroll.inner
        clear(body)
        wrap = tk.Frame(body, bg=C["bg"])
        wrap.pack(fill="x", padx=(0, 12))

        banner = Banner(wrap)
        banner.pack(fill="x", pady=(4, 12))
        levels = {f["risk"] for f in findings}
        if stats["packets"] == 0:
            banner.show("warn", "No activity caught yet.",
                        "Try another connection option, install Npcap from npcap.com, and run as administrator.")
            f_color = C["amber"]
        elif "High" in levels:
            banner.show("bad", "Something needs your attention. Here's how to fix it.",
                        "Unusual activity was spotted during this check.")
            f_color = C["red"]
        elif "Medium" in levels:
            banner.show("warn", "One thing to look at. It's probably fine. Here's how to check.",
                        "Something minor stood out and is worth a quick look.")
            f_color = C["amber"]
        else:
            banner.show("ok", "Your computer looks normal. Nothing to do.",
                        "Nothing suspicious stood out during this check.")
            f_color = C["green"]

        metrics_row(wrap, [
            ("Activity items", f"{stats['packets']:,}", None),
            ("Seconds", stats["duration_s"], None),
            ("To look at", len(findings), f_color),
        ]).pack(fill="x")
        if stats["truncated"]:
            tk.Label(wrap, text="This check hit its size limit and stopped early.", font=F_UI,
                     fg=C["amber"], bg=C["bg"]).pack(anchor="w", pady=(8, 0))

        brief_card(wrap, "Answer", t["summary"], t["source"])

        if findings:
            heading(wrap, "What to look at")
            for f in findings:
                alert_card(wrap, f["risk"], f["title"], f["what"], f["why"], f["fix"],
                           evidence=f["evidence"]).pack(fill="x", pady=(0, 10))

        sec = Collapsible(wrap, "Technical details (conversations, DNS, protocols)")
        sec.pack(fill="x", pady=(12, 0))
        proto = "   ".join(f"{k}: {v:,}" for k, v in stats["protocols"].items())
        tk.Label(sec.body, text=f"Protocol mix  \u2022  {proto}", font=("Consolas", 9), fg=C["muted"], bg=C["bg"],
                 anchor="w").pack(fill="x", pady=(2, 8))
        fr, tree = make_tree(sec.body, ("From", "To", "Name", "Owner", "MB"), (150, 150, 270, 110, 60), height=7)
        fr.pack(fill="x", pady=(0, 10))
        for i, r in enumerate(result["top_talkers"]):
            src = r["src"] + ("  (this PC)" if r.get("src_is_me") else "")
            dst = r["dst"] + ("  (this PC)" if r.get("dst_is_me") else "")
            tree.insert("", "end", tags=("odd",) if i % 2 else (),
                        values=(src, dst, r.get("name") or "\u2014", r.get("owner") or "\u2014", r["megabytes"]))
        fr2, tree2 = make_tree(sec.body, ("Most-requested name (DNS)", "Count"), (480, 80), height=6)
        fr2.pack(fill="x", pady=(0, 6))
        for i, r in enumerate(result["top_dns"]):
            tree2.insert("", "end", tags=("odd",) if i % 2 else (), values=(r["name"], r["count"]))

        FlatButton(wrap, "Save a plain report (readable)", self.export_traffic, primary=False, padx=16, pady=6).pack(
            anchor="w", pady=(12, 16))

    def export_traffic(self):
        if not self.traffic:
            return
        t = self.traffic
        findings = t["result"].get("findings", [])
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Plain text report", "*.txt")],
            initialfile=f"audit4all_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if path:
            lines = [
                "=== AUDIT4ALL REPORT ===",
                f"Date: {t['time'][:16]}",
            ]
            if not findings:
                lines.extend([
                    "Result: YOUR COMPUTER LOOKS NORMAL",
                    "",
                    f"What we checked: {t['result'].get('stats', {}).get('packets', 0):,} network activity items.",
                    "What we found: nothing suspicious.",
                ])
            else:
                top = findings[0]
                lines.extend([
                    "Result: ONE THING NEEDS YOUR ATTENTION",
                    f"What: {top.get('title', 'Unusual network activity')}",
                    f"Why it matters: {top.get('why', 'Unusual activity appeared during the check.')}",
                    f"What to do: {top.get('fix', 'Check your network connection and close unfamiliar apps.')}",
                    "",
                    "Nothing else on your computer looks suspicious.",
                ])
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
            self.cap_status.configure(text=f"Saved {os.path.basename(path)}", fg=C["green"])

    # ================================================================ technical tab
    def _build_tech_tab(self):
        page = self.tab_tech
        page_header(page, "Technical details", "Raw connection and process details for IT support.")
        cols = ("Alert", "Risk", "Port", "Service", "Process", "PID", "Exposure")
        fr, self.tech_tree = make_tree(page, cols, (110, 80, 70, 170, 210, 70, 110), height=14)
        fr.pack(fill="both", expand=True, padx=28, pady=(16, 10))
        self.tech_tree.tag_configure("High", foreground=C["red"])
        self.tech_tree.tag_configure("Medium", foreground=C["amber"])
        self.tech_detail = tk.Text(page, height=10, bg=C["inset"], fg=C["text"], relief="flat", font=F_MONO,
                                   padx=14, pady=10, wrap="word", state="disabled", highlightthickness=1,
                                   highlightbackground=C["border"], insertbackground=C["text"])
        self.tech_detail.pack(fill="x", padx=28, pady=(0, 24))
        self.tech_tree.bind("<<TreeviewSelect>>", self._on_tech_select)
        self._tech_items = {}

    def _fill_tech(self):
        self.tech_tree.delete(*self.tech_tree.get_children())
        self._tech_items = {}
        levels = {(a["port"], a["pid"]): a["alert_level"] for a in needs_attention(self.audit["findings"])}
        for i, f in enumerate(self.audit["findings"]):
            tags = []
            if f["risk"] in ("High", "Medium"):
                tags.append(f["risk"])
            if i % 2:
                tags.append("odd")
            iid = self.tech_tree.insert("", "end", tags=tuple(tags), values=(
                levels.get((f["port"], f["pid"]), "-"), f["risk"], f["port"], f["service"],
                f["process"], f["pid"], f["exposure"]))
            self._tech_items[iid] = f

    def _on_tech_select(self, _e):
        sel = self.tech_tree.selection()
        if not sel:
            return
        self.tech_detail.configure(state="normal")
        self.tech_detail.delete("1.0", "end")
        self.tech_detail.insert("1.0", json.dumps(self._tech_items[sel[0]], indent=2, default=str))
        self.tech_detail.configure(state="disabled")

    # ================================================================ settings
    def open_settings(self):
        win = tk.Toplevel(self)
        win.title("AI settings")
        win.configure(bg=C["bg"])
        win.transient(self)
        win.resizable(False, False)
        pad = tk.Frame(win, bg=C["bg"])
        pad.pack(padx=26, pady=22)
        tk.Label(pad, text="AI summary key (optional)", font=F_H2, fg=C["text"], bg=C["bg"]).pack(anchor="w")
        tk.Label(pad, text="AI summaries are off by default. The app still works — you'll get calm, hand-written summaries instead.",
                 font=F_UI, fg=C["muted"], bg=C["bg"], wraplength=440, justify="left").pack(anchor="w", pady=(2, 12))
        var = tk.StringVar()
        entry = tk.Entry(pad, textvariable=var, show="\u2022", width=52, font=F_MONO, bg=C["inset"], fg=C["text"],
                         insertbackground=C["accent"], relief="flat", highlightthickness=1,
                         highlightbackground=C["border"], highlightcolor=C["accent"])
        entry.pack(fill="x", ipady=7)
        entry.focus_set()
        show = tk.BooleanVar()
        ttk.Checkbutton(pad, text="Show key", variable=show, style="Dlg.TCheckbutton",
                        command=lambda: entry.configure(show="" if show.get() else "\u2022")).pack(anchor="w", pady=(8, 0))
        keep = tk.BooleanVar()
        ttk.Checkbutton(pad, text="Save for future visits (stored in .streamlit/secrets.toml)", variable=keep,
                        style="Dlg.TCheckbutton").pack(anchor="w", pady=(2, 0))

        def save():
            key = var.get().strip()
            if not key or any(ch in key for ch in "\"'\\\r\n "):
                messagebox.showerror("AI settings", "Paste the key only: no spaces, quotes or backslashes.", parent=win)
                return
            os.environ["GROQ_API_KEY"] = key
            if keep.get():
                folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".streamlit")
                os.makedirs(folder, exist_ok=True)
                with open(os.path.join(folder, "secrets.toml"), "w", encoding="utf-8") as fh:
                    fh.write(f'GROQ_API_KEY = "{key}"\n')
            self._refresh_ai_badge()
            win.destroy()

        def clear_key():
            clear_api_key()
            self._refresh_ai_badge()
            win.destroy()

        btns = tk.Frame(pad, bg=C["bg"])
        btns.pack(fill="x", pady=(18, 0))
        if get_api_key():
            FlatButton(btns, "Clear key", clear_key, primary=False, padx=14, pady=7).pack(side="left")
        FlatButton(btns, "SAVE", save, padx=22, pady=7).pack(side="right")
        FlatButton(btns, "Cancel", win.destroy, primary=False, padx=18, pady=7).pack(side="right", padx=10)
        win.bind("<Return>", lambda e: save())
        win.bind("<Escape>", lambda e: win.destroy())
        win.update_idletasks()
        x = self.winfo_rootx() + (self.winfo_width() - win.winfo_width()) // 2
        y = self.winfo_rooty() + 120
        win.geometry(f"+{x}+{y}")
        dark_titlebar(win)
        try:
            win.grab_set()
        except tk.TclError:
            pass

    # ================================================================ queue pump
    def _poll(self):
        try:
            while True:
                kind, *args = self.q.get_nowait()
                try:
                    getattr(self, "_on_" + kind)(*args)
                except Exception as exc:
                    logger.exception("Queue handler error (%s): %s", kind, exc)
        except queue.Empty:
            pass
        self.after(100, self._poll)


if __name__ == "__main__":
    if os.name != "nt" and not os.environ.get("AUDIT4ALL_ANY_OS"):
        raise SystemExit("AUDIT4ALL is Windows-only.")
    Audit4AllApp().mainloop()
