"""
WoW 1.12.1 (build 5875) - Live Position Capture Tool
Reads player X, Y, Z, Orientation directly from WoW process memory.
Click "Capture" to add current position to the list.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ctypes
import ctypes.wintypes as wt
import struct
import threading
import time
import math
import os
import re

PROCESS_VM_READ            = 0x0010
PROCESS_QUERY_INFORMATION  = 0x0400
PROCESS_TERMINATE          = 0x0001
TH32CS_SNAPPROCESS         = 0x00000002

WOW_EXE          = r"D:\World of Warcraft Classic 1.12.1\WoW.exe"
WOW_PROCESS_NAME = "wow.exe"   # lowercase — change if your exe has a different name

kernel32 = ctypes.windll.kernel32

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb",              wt.DWORD),
                ("lpReserved",      wt.LPWSTR),
                ("lpDesktop",       wt.LPWSTR),
                ("lpTitle",         wt.LPWSTR),
                ("dwX",             wt.DWORD),
                ("dwY",             wt.DWORD),
                ("dwXSize",         wt.DWORD),
                ("dwYSize",         wt.DWORD),
                ("dwXCountChars",   wt.DWORD),
                ("dwYCountChars",   wt.DWORD),
                ("dwFillAttribute", wt.DWORD),
                ("dwFlags",         wt.DWORD),
                ("wShowWindow",     wt.WORD),
                ("cbReserved2",     wt.WORD),
                ("lpReserved2",     ctypes.c_char_p),
                ("hStdInput",       wt.HANDLE),
                ("hStdOutput",      wt.HANDLE),
                ("hStdError",       wt.HANDLE)]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess",    wt.HANDLE),
                ("hThread",     wt.HANDLE),
                ("dwProcessId", wt.DWORD),
                ("dwThreadId",  wt.DWORD)]

def launch_wow_debug(exe_path=None):
    """
    Kill any existing WoW, relaunch normally (no DEBUG_PROCESS).
    CreateProcess returns pi.hProcess — a kernel-granted handle created before
    any AV ObRegisterCallbacks fire, so Avast can't block it.
    WoW never sees a debugger, so no anti-debug checks trigger.
    Returns (hProcess, pid) or (None, None) on failure.
    """
    target_exe = exe_path or WOW_EXE
    target_dir = os.path.dirname(target_exe)
    proc_name  = os.path.basename(target_exe)

    existing = find_wow_pid(proc_name)
    if existing:
        h = kernel32.OpenProcess(PROCESS_TERMINATE, False, existing)
        if h:
            kernel32.TerminateProcess(h, 0)
            kernel32.CloseHandle(h)
        time.sleep(0.8)

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()

    # Launch with NO debug flags — WoW runs completely normally.
    # pi.hProcess is still a valid full-access handle for ReadProcessMemory.
    ok = kernel32.CreateProcessW(
        target_exe, None, None, None, False,
        0, None, target_dir,
        ctypes.byref(si), ctypes.byref(pi))

    if not ok:
        return None, None

    # Close the thread handle — we only need the process handle.
    kernel32.CloseHandle(pi.hThread)

    return pi.hProcess, pi.dwProcessId


# ── Win32 process enumeration ─────────────────────────────────────────────────
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize',              wt.DWORD),
        ('cntUsage',            wt.DWORD),
        ('th32ProcessID',       wt.DWORD),
        ('th32DefaultHeapID',   ctypes.POINTER(ctypes.c_ulong)),
        ('th32ModuleID',        wt.DWORD),
        ('cntThreads',          wt.DWORD),
        ('th32ParentProcessID', wt.DWORD),
        ('pcPriClassBase',      ctypes.c_long),
        ('dwFlags',             wt.DWORD),
        ('szExeFile',           ctypes.c_char * 260),
    ]

def find_wow_pid(process_name=None):
    name = (process_name or WOW_PROCESS_NAME).lower().encode()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wt.HANDLE(-1).value:
        return None
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    try:
        if kernel32.Process32First(snapshot, ctypes.byref(entry)):
            while True:
                if entry.szExeFile.lower() == name:
                    return entry.th32ProcessID
                if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)
    return None

MARIADB_EXE   = r"D:\MariaDB\bin\mysql.exe"
CHAR_NAME     = "Dingle"

# ── Memory scanning ───────────────────────────────────────────────────────────
MEM_COMMIT    = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD    = 0x100

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [("BaseAddress",       ctypes.c_void_p),
                ("AllocationBase",    ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD),
                ("RegionSize",        ctypes.c_size_t),
                ("State",             wt.DWORD),
                ("Protect",           wt.DWORD),
                ("Type",              wt.DWORD)]

def scan_for_xyzo(handle, tx, ty, tz, to_, tol=0.05, progress_cb=None):
    """
    Scan all readable committed memory pages for four consecutive floats
    matching (x, y, z, orientation) within tolerance.
    Returns list of addresses where the X float sits.
    """
    results = []
    mbi     = MEMORY_BASIC_INFORMATION()
    addr    = 0x10000
    CHUNK   = 0x80000   # 512 KB per read
    total_scanned = 0

    while addr < 0x7FFF0000:
        sz = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not sz:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize  or 0
        if size == 0:
            addr += 0x1000
            continue

        skip = (mbi.State   != MEM_COMMIT or
                mbi.Protect &  PAGE_NOACCESS or
                mbi.Protect &  PAGE_GUARD)

        if not skip:
            for off in range(0, size, CHUNK):
                csz  = min(CHUNK, size - off)
                buf  = ctypes.create_string_buffer(csz)
                nrd  = ctypes.c_size_t(0)
                caddr = base + off
                ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(caddr),
                                                buf, csz, ctypes.byref(nrd))
                if not ok:
                    continue
                data = buf.raw[:nrd.value]
                for i in range(0, len(data) - 15, 4):
                    try:
                        fx, fy, fz, fo = struct.unpack_from('<ffff', data, i)
                        if (abs(fx - tx) < tol and abs(fy - ty) < tol and
                                abs(fz - tz) < tol and abs(fo - to_) < tol):
                            results.append(caddr + i)
                    except Exception:
                        pass
            total_scanned += size
            if progress_cb:
                progress_cb(total_scanned)

        addr = base + size if (base + size) > addr else addr + 0x1000

    return results

def query_db_position():
    """
    Query MariaDB for the last logout position of CHAR_NAME.
    Returns (x, y, z, o) as floats, or None on failure.
    """
    import subprocess
    sql = (f"SELECT position_x, position_y, position_z, orientation "
           f"FROM characters WHERE name='{CHAR_NAME}' "
           f"ORDER BY logout_time DESC LIMIT 1;")
    try:
        r = subprocess.run(
            [MARIADB_EXE, "-u", "mangos", "-pmangos", "classiccharacters", "-e", sql],
            capture_output=True, text=True, timeout=10)
        lines = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
        if len(lines) >= 2:
            vals = lines[1].split()
            return tuple(float(v) for v in vals)
    except Exception:
        pass
    return None

# ── Memory reading helpers ────────────────────────────────────────────────────
def read_bytes(handle, addr, n):
    buf  = ctypes.create_string_buffer(n)
    read = ctypes.c_size_t(0)
    ok   = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(addr),
                                      buf, n, ctypes.byref(read))
    return buf.raw if ok else None

def read_f32(handle, addr):
    d = read_bytes(handle, addr, 4)
    return struct.unpack('<f', d)[0] if d else None

def get_player_pos(handle, pos_addr):
    """Read player (x, y, z, facing) directly from the scanned address."""
    if not pos_addr:
        return None
    x = read_f32(handle, pos_addr)
    y = read_f32(handle, pos_addr + 4)
    z = read_f32(handle, pos_addr + 8)
    o = read_f32(handle, pos_addr + 12)
    if None not in (x, y, z, o):
        return x, y, z, o
    return None

# Expected point count per shape (None = variable)
SHAPE_POINTS = {
    "single point": 1,
    "rectangle":    2,
    "rhombus":      4,
    "triangle":     3,
    "pentagon":     5,
    "pillar":       4,
    "other":        None,
}

# ── Wizard step definitions ───────────────────────────────────────────────────
WIZARD_STEPS = [
    ("Exe Path",
     "Enter the full path to your WoW executable in the 'Exe path' field below.\n"
     "The Process name field will fill automatically."),
    ("Launch WoW",
     "Click '🚀 Launch WoW'. The game starts through the tool so it can access memory."),
    ("Move & Orient",
     "Log in, walk to a new position and turn to face a new direction.\n"
     "⚠️  Orientation MUST be non-zero: spin away from the default (north-facing) direction.\n"
     "This is essential — 0.0 is too common in memory to scan for reliably."),
    ("Log Out",
     "Log out of the game. This saves your position AND orientation to the CMaNGOS database.\n"
     "The scan will fail if orientation is near zero — if unsure, go back and re-orient first."),
    ("Scan Memory",
     "Log back in WITHOUT moving or turning, then click '🔍 Scan Memory'.\n"
     "Live coordinates will appear once the address is found.\n"
     "If the scan is blocked, it means orientation was near zero — go back to step 3."),
]

# ── Wrapping button frame ─────────────────────────────────────────────────────
class FlowFrame(tk.Frame):
    """Lays out children left-to-right, wrapping to the next row on resize."""
    def __init__(self, master, gap=4, **kw):
        kw.setdefault("bg", "#1e1e2e")
        super().__init__(master, **kw)
        self._gap = gap
        self.bind("<Configure>", self._reflow)

    def _reflow(self, _=None):
        self.update_idletasks()
        w = self.winfo_width()
        if w <= 1:
            self.after(20, self._reflow)
            return
        g = self._gap
        x, y, rh = g, g, 0
        for c in self.winfo_children():
            cw = c.winfo_reqwidth()
            ch = c.winfo_reqheight()
            if x + cw + g > w and x > g:
                x, y = g, y + rh + g
                rh = 0
            c.place(x=x, y=y)
            x += cw + g
            rh = max(rh, ch)
        self.configure(height=y + rh + g)

# ── GUI ───────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("WoW Position Capture  |  1.12.1")
        self.resizable(True, True)
        self.configure(bg="#1e1e2e")

        self.handle          = None
        self.pos_addr        = None
        self.pos_candidates  = []   # all addresses from last scan
        self.running         = True
        self.groups          = []   # [{"shape": str, "tree_id": str, "points": [(lbl,x,y,z,o),...]}]
        self.shape       = tk.StringVar(value="rectangle")
        self.last_pos    = None
        self.wizard_step = 0          # 0-based index into WIZARD_STEPS
        self.wizard_done = set()      # indices of manually-confirmed steps

        self._build_ui()
        self.attributes("-topmost", True)
        self._set_status = self._make_set_status()
        self.geometry("700x640+10+10")
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._connect()
        threading.Thread(target=self._poll_loop, daemon=True).start()

    # ── UI construction ───────────────────────────────────────────────────────
    def _build_ui(self):
        PAD   = 8
        BG    = "#1e1e2e"
        FG    = "#cdd6f4"
        ENTRY = "#313244"
        ACC   = "#89b4fa"
        BTN   = "#45475a"
        GRN   = "#a6e3a1"

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame",        background=BG)
        style.configure("TLabel",        background=BG, foreground=FG,
                        font=("Consolas", 10))
        style.configure("Header.TLabel", background=BG, foreground=ACC,
                        font=("Consolas", 11, "bold"))
        style.configure("Pos.TLabel",    background=BG, foreground=GRN,
                        font=("Consolas", 13, "bold"))
        style.configure("TButton",       background=BTN, foreground=FG,
                        font=("Consolas", 10), relief="flat", padding=4)
        style.map("TButton", background=[("active", ACC)],
                  foreground=[("active", "#1e1e2e")])
        style.configure("Treeview",      background=ENTRY, foreground=FG,
                        fieldbackground=ENTRY, rowheight=22,
                        font=("Consolas", 9))
        style.configure("Treeview.Heading", background=BTN, foreground=ACC,
                        font=("Consolas", 9, "bold"))
        style.configure("TLabelframe",        background=BG)
        style.configure("TLabelframe.Label",  background=BG, foreground=ACC,
                        font=("Consolas", 9, "bold"))

        # ── top: live coords ──────────────────────────────────────────────────
        top = ttk.Frame(self, padding=PAD)
        top.pack(fill="x")
        ttk.Label(top, text="LIVE POSITION", style="Header.TLabel").pack(anchor="w")
        self.pos_label = ttk.Label(top, text="X: ---   Y: ---   Z: ---   O: ---",
                                   style="Pos.TLabel")
        self.pos_label.pack(anchor="w", pady=(2, 2))
        self.status_label = tk.Entry(top, font=("Consolas", 9),
                                     bg=BG, fg="#f38ba8",
                                     insertbackground="#f38ba8",
                                     relief="flat", readonlybackground=BG)
        self.status_label.pack(anchor="w", fill="x")
        self.status_label.insert(0, "⏳ Connecting to WoW...")
        self.status_label.config(state="readonly")

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=PAD, pady=(4, 0))

        # ── wizard ────────────────────────────────────────────────────────────
        wiz = ttk.LabelFrame(self, text="Setup Steps", padding=(PAD, 4))
        wiz.pack(fill="x", padx=PAD, pady=4)

        # step indicator buttons (navigate on click)
        step_bar = tk.Frame(wiz, bg=BG)
        step_bar.pack(fill="x")
        self._wiz_btns = []
        for i, (title, _) in enumerate(WIZARD_STEPS):
            btn = tk.Button(step_bar, text=f"  {i+1}. {title}  ",
                            font=("Consolas", 9), relief="flat", bd=0,
                            cursor="hand2",
                            command=lambda idx=i: self._wizard_goto(idx))
            btn.pack(side="left", padx=2, pady=2)
            self._wiz_btns.append(btn)

        # description
        self._wiz_desc = tk.Label(wiz, text="", bg=BG, fg=FG,
                                  font=("Consolas", 9), justify="left",
                                  anchor="w", wraplength=600)
        self._wiz_desc.pack(fill="x", pady=(4, 4))

        # nav buttons
        nav = tk.Frame(wiz, bg=BG)
        nav.pack(fill="x")
        self._wiz_back_btn = tk.Button(nav, text="← Back",
                                       font=("Consolas", 9), relief="flat",
                                       bg=BTN, fg=FG, bd=0, padx=8, pady=3,
                                       command=self._wizard_back)
        self._wiz_back_btn.pack(side="left", padx=(0, 6))
        self._wiz_next_btn = tk.Button(nav, text="✓ Done, Next →",
                                       font=("Consolas", 9, "bold"),
                                       relief="flat", bg=ACC, fg="#1e1e2e",
                                       bd=0, padx=8, pady=3,
                                       command=self._wizard_next)
        self._wiz_next_btn.pack(side="left")

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=PAD, pady=(0, 4))

        # ── shape selector (wrapping) ─────────────────────────────────────────
        shape_flow = FlowFrame(self, gap=4, bg=BG)
        shape_flow.pack(fill="x", padx=PAD, pady=(4, 0))
        tk.Label(shape_flow, text="Zone shape:", bg=BG, fg=FG,
                 font=("Consolas", 10)).pack()
        shapes = ["single point", "rectangle", "rhombus", "triangle", "pentagon", "pillar", "other"]
        for s in shapes:
            tk.Radiobutton(shape_flow, text=s, variable=self.shape, value=s,
                           indicatoron=False, font=("Consolas", 10),
                           bg=BTN, fg=FG, selectcolor=ACC,
                           activebackground=ACC, activeforeground="#1e1e2e",
                           relief="flat", bd=0, padx=6, pady=3).pack()

        # ── label entry + capture buttons (wrapping flow) ─────────────────────
        lbl_row = tk.Frame(self, bg=BG)
        lbl_row.pack(fill="x", padx=PAD, pady=(4, 0))
        tk.Label(lbl_row, text="Label:", bg=BG, fg=FG,
                 font=("Consolas", 10)).pack(side="left")
        self.lbl_entry = tk.Entry(lbl_row, width=16, bg=ENTRY, fg=FG,
                                  insertbackground=FG, font=("Consolas", 10),
                                  relief="flat")
        self.lbl_entry.insert(0, "point 1")
        self.lbl_entry.pack(side="left", padx=(4, 8))

        flow = FlowFrame(self, gap=4, bg=BG)
        flow.pack(fill="x", padx=PAD, pady=(2, 2))
        self.bind("<Configure>", lambda e: flow._reflow())

        def _btn(text, cmd):
            return tk.Button(flow, text=text, command=cmd,
                             font=("Consolas", 10), relief="flat",
                             bg=BTN, fg=FG, activebackground=ACC,
                             activeforeground="#1e1e2e", padx=6, pady=3, bd=0)

        self.cap_btn    = _btn("📍 Capture",         self._capture);    self.cap_btn.pack()
        _btn("🗑 Clear all",        self._clear).pack()
        _btn("💾 Append to file",   self._save).pack()
        self.launch_btn = _btn("🚀 Launch WoW",      self._launch_wow); self.launch_btn.pack()
        self.scan_btn   = _btn("🔍 Scan Memory",     self._scan);       self.scan_btn.pack()

        # ── exe / process / output file (grid, each entry fills full width) ────
        cfg = tk.Frame(self, bg=BG)
        cfg.pack(fill="x", padx=PAD, pady=(2, 4))
        cfg.columnconfigure(1, weight=1)

        tk.Label(cfg, text="Exe path:", bg=BG, fg=FG,
                 font=("Consolas", 9)).grid(row=0, column=0, sticky="w", pady=1)
        self.exe_entry = tk.Entry(cfg, bg=ENTRY, fg=FG,
                                  insertbackground=FG,
                                  font=("Consolas", 9), relief="flat")
        self.exe_entry.insert(0, WOW_EXE)
        self.exe_entry.grid(row=0, column=1, sticky="ew", padx=(4, 4), pady=1)
        self.exe_entry.bind("<FocusOut>", lambda e: self._sync_proc_from_exe())
        self.exe_entry.bind("<Return>",   lambda e: self._sync_proc_from_exe())
        self.exe_browse_btn = tk.Button(cfg, text="📂", font=("Consolas", 9), relief="flat",
                                        bg=BTN, fg=FG, activebackground=ACC,
                                        activeforeground="#1e1e2e",
                                        bd=0, padx=4, pady=2,
                                        command=self._browse_exe)
        self.exe_browse_btn.grid(row=0, column=2, pady=1)

        tk.Label(cfg, text="Process:", bg=BG, fg=FG,
                 font=("Consolas", 9)).grid(row=1, column=0, sticky="w", pady=1)
        self.proc_entry = tk.Entry(cfg, bg=ENTRY, fg=FG,
                                   insertbackground=FG,
                                   font=("Consolas", 9), relief="flat")
        self.proc_entry.insert(0, WOW_PROCESS_NAME)
        self.proc_entry.grid(row=1, column=1, sticky="ew", padx=(4, 0), pady=1)

        tk.Label(cfg, text="Output file:", bg=BG, fg=FG,
                 font=("Consolas", 9)).grid(row=2, column=0, sticky="w", pady=1)
        self.file_entry = tk.Entry(cfg, bg=ENTRY, fg=FG,
                                   insertbackground=FG,
                                   font=("Consolas", 9), relief="flat")
        _default_out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "safe zones in dungeons.md")
        self.file_entry.insert(0, _default_out)
        self.file_entry.grid(row=2, column=1, sticky="ew", padx=(4, 4), pady=1)
        tk.Button(cfg, text="📂", font=("Consolas", 9), relief="flat",
                  bg=BTN, fg=FG, activebackground=ACC, activeforeground="#1e1e2e",
                  bd=0, padx=4, pady=2,
                  command=self._browse_output).grid(row=2, column=2, pady=1)

        self.bind("<Return>", lambda e: self._capture())

        # ── capture list ──────────────────────────────────────────────────────
        cols = ("x", "y", "z", "facing", "dist")
        self.tree = ttk.Treeview(self, columns=cols, show="tree headings", height=10)
        self.tree.heading("#0",       text="Label");      self.tree.column("#0", width=120, anchor="w", stretch=True)
        widths = {"x": 80, "y": 80, "z": 65, "facing": 70, "dist": 75}
        heads  = {"x": "X", "y": "Y", "z": "Z", "facing": "Facing (O)", "dist": "Dist prev"}
        for c in cols:
            self.tree.heading(c, text=heads[c])
            self.tree.column(c, width=widths[c], anchor="center")
        # Row styles
        self.tree.tag_configure("group",
                                background="#313244", foreground=ACC,
                                font=("Consolas", 9, "bold"))
        self.tree.tag_configure("point",
                                background=ENTRY, foreground=FG,
                                font=("Consolas", 9))
        sb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(fill="both", expand=True, padx=PAD, pady=(0, 2))

        self.tree.bind("<Button-3>",        self._right_click)
        self.tree.bind("<Double-1>",        self._edit_row_event)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # ── .go command display ───────────────────────────────────────────────
        go_row = tk.Frame(self, bg=BG)
        go_row.pack(fill="x", padx=PAD, pady=(0, PAD))
        tk.Label(go_row, text=".go:", bg=BG, fg=FG,
                 font=("Consolas", 9)).pack(side="left")
        self.go_entry = tk.Entry(go_row, bg=ENTRY, fg=GRN,
                                 insertbackground=GRN, font=("Consolas", 10),
                                 relief="flat", readonlybackground=ENTRY,
                                 state="readonly")
        self.go_entry.pack(side="left", padx=(4, 0), fill="x", expand=True)

        # initialise wizard display
        self._wizard_update()

    def _make_set_status(self):
        """Return a callable that sets the status entry text + colour."""
        def _set(text, fg="#f38ba8"):
            self.status_label.config(state="normal", fg=fg)
            self.status_label.delete(0, "end")
            self.status_label.insert(0, text)
            self.status_label.config(state="readonly")
        return _set

    # ── wizard helpers ────────────────────────────────────────────────────────
    def _browse_exe(self):
        """Open a file-picker dialog and populate the exe path field."""
        current = self.exe_entry.get().strip()
        init_dir = os.path.dirname(current) if current and os.path.exists(
            os.path.dirname(current)) else "C:\\"
        path = filedialog.askopenfilename(
            title="Select WoW executable",
            initialdir=init_dir,
            filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if path:
            self.exe_entry.delete(0, "end")
            self.exe_entry.insert(0, path)
            self._sync_proc_from_exe()

    def _browse_output(self):
        """Open a save-file dialog and populate the output file field."""
        current = self.file_entry.get().strip()
        init_dir  = os.path.dirname(current) if current else os.path.dirname(
            os.path.abspath(__file__))
        init_file = os.path.basename(current) if current else "safe zones in dungeons.md"
        path = filedialog.asksaveasfilename(
            title="Choose output file",
            initialdir=init_dir,
            initialfile=init_file,
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("Text", "*.txt"), ("All files", "*.*")])
        if path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)

    def _sync_proc_from_exe(self):
        """Auto-fill the Process name field from the exe path basename."""
        exe = self.exe_entry.get().strip()
        if exe:
            name = os.path.basename(exe).lower()
            self.proc_entry.delete(0, "end")
            self.proc_entry.insert(0, name)
            # auto-advance wizard: "Exe Path" (step 0) → "Launch WoW" (step 1)
            if self.wizard_step == 0:
                self.wizard_done.add(0)
                self.wizard_step = 1
                self._wizard_update()

    def _wizard_update(self):
        BG   = "#1e1e2e"
        ACC  = "#89b4fa"
        GRN  = "#a6e3a1"
        BTN  = "#45475a"
        FG   = "#cdd6f4"
        HILIGHT = "#f9e2af"   # amber — "click this button"

        for i, btn in enumerate(self._wiz_btns):
            if i == self.wizard_step:
                btn.config(bg=ACC, fg="#1e1e2e")
            elif i in self.wizard_done:
                btn.config(bg=GRN, fg="#1e1e2e")
            else:
                btn.config(bg=BTN, fg=FG)

        _, desc = WIZARD_STEPS[self.wizard_step]
        self._wiz_desc.config(text=f"Step {self.wizard_step + 1}: {desc}")
        self._wiz_back_btn.config(
            state="normal" if self.wizard_step > 0 else "disabled")
        if self.wizard_step >= len(WIZARD_STEPS) - 1:
            self._wiz_next_btn.config(text="✓ All done!", state="disabled")
        else:
            self._wiz_next_btn.config(text="✓ Done, Next →", state="normal")

        # Highlight action buttons / fields relevant to the current step
        # (guard against being called before widgets are built)
        if not hasattr(self, "launch_btn"):
            return
        step = self.wizard_step

        # Exe path field + browse button — step 0
        exe_hl = step == 0
        self.exe_entry.config(
            bg=HILIGHT    if exe_hl else "#313244",
            fg="#1e1e2e"  if exe_hl else FG,
            insertbackground="#1e1e2e" if exe_hl else FG)
        self.exe_browse_btn.config(
            bg=HILIGHT if exe_hl else BTN,
            fg="#1e1e2e" if exe_hl else FG)

        # Launch WoW button — step 1
        self.launch_btn.config(
            bg=HILIGHT if step == 1 else BTN,
            fg="#1e1e2e" if step == 1 else FG)

        # Scan Memory button — step 4
        self.scan_btn.config(
            bg=HILIGHT if step == 4 else BTN,
            fg="#1e1e2e" if step == 4 else FG)

    def _wizard_next(self):
        self.wizard_done.add(self.wizard_step)
        if self.wizard_step < len(WIZARD_STEPS) - 1:
            self.wizard_step += 1
        self._wizard_update()

    def _wizard_back(self):
        if self.wizard_step > 0:
            self.wizard_step -= 1
        self._wizard_update()

    def _wizard_goto(self, idx):
        self.wizard_step = idx
        self._wizard_update()

    # ── treeview helpers ──────────────────────────────────────────────────────
    def _find_point(self, item):
        """Return (group_idx, point_idx) for a point item, or (None, None)."""
        parent = self.tree.parent(item)
        for gi, g in enumerate(self.groups):
            if g["tree_id"] == parent:
                children = list(self.tree.get_children(parent))
                return gi, children.index(item)
        return None, None

    def _set_go_command(self, text):
        self.go_entry.config(state="normal")
        self.go_entry.delete(0, "end")
        self.go_entry.insert(0, text)
        self.go_entry.config(state="readonly")

    def _on_tree_select(self, _event=None):
        sel = self.tree.selection()
        if not sel or "point" not in self.tree.item(sel[0], "tags"):
            self._set_go_command("")
            return
        gi, pi = self._find_point(sel[0])
        if gi is None:
            return
        _, x, y, z, _ = self.groups[gi]["points"][pi]
        self._set_go_command(f".go {x:.2f} {y:.2f} {z:.2f}")

    # ── row edit dialog (double-click / right-click → Edit) ───────────────────
    def _edit_row_event(self, event):
        item = self.tree.identify_row(event.y)
        if item and "point" in self.tree.item(item, "tags"):
            self._edit_row(item)

    def _edit_row(self, item):
        gi, pi = self._find_point(item)
        if gi is None:
            return
        lbl, cx, cy, cz, co = self.groups[gi]["points"][pi]

        BG    = "#1e1e2e"
        FG    = "#cdd6f4"
        ENTRY = "#313244"

        dlg = tk.Toplevel(self)
        dlg.title("Edit point")
        dlg.resizable(False, False)
        dlg.attributes("-topmost", True)
        dlg.configure(bg=BG)

        fields = [("Label",   str(lbl)),
                  ("X",       f"{cx:.4f}"),
                  ("Y",       f"{cy:.4f}"),
                  ("Z",       f"{cz:.4f}"),
                  ("O (rad)", f"{co:.6f}")]

        entries = []
        for row_i, (name, val) in enumerate(fields):
            ttk.Label(dlg, text=f"{name}:").grid(
                row=row_i, column=0, padx=8, pady=4, sticky="w")
            e = tk.Entry(dlg, width=26, bg=ENTRY, fg=FG,
                         insertbackground=FG,
                         font=("Consolas", 10), relief="flat")
            e.insert(0, val)
            e.grid(row=row_i, column=1, padx=(0, 8), pady=4)
            entries.append(e)
        entries[0].focus_set()
        entries[0].select_range(0, "end")

        def _apply(*_):
            try:
                new_lbl = entries[0].get().strip() or lbl
                new_x   = float(entries[1].get())
                new_y   = float(entries[2].get())
                new_z   = float(entries[3].get())
                new_o   = float(entries[4].get())
            except ValueError:
                messagebox.showerror("Invalid",
                                     "X, Y, Z, O must be numbers.", parent=dlg)
                return
            self.groups[gi]["points"][pi] = (new_lbl, new_x, new_y, new_z, new_o)
            dist_str = "—"
            if pi > 0:
                _, px, py_, pz, _ = self.groups[gi]["points"][pi - 1]
                d = math.sqrt((new_x-px)**2 + (new_y-py_)**2 + (new_z-pz)**2)
                dist_str = f"{d:.2f}"
            self.tree.item(item, text=new_lbl,
                           values=(f"{new_x:.2f}", f"{new_y:.2f}",
                                   f"{new_z:.2f}", f"{math.degrees(new_o):.1f}°",
                                   dist_str))
            dlg.destroy()

        for e in entries:
            e.bind("<Return>", _apply)
        ttk.Button(dlg, text="OK", command=_apply).grid(
            row=len(fields), column=0, columnspan=2, pady=(0, 8))

    # ── connection (startup only — primary path is Launch WoW button) ──────────
    def _connect(self):
        """Try to attach to an already-running WoW process on startup."""
        proc_name = getattr(self, 'proc_entry', None)
        proc_name = proc_name.get().strip() if proc_name else WOW_PROCESS_NAME
        pid = find_wow_pid(proc_name)
        if pid is None:
            self._set_status("⏳ WoW not running — use 🚀 Launch WoW to start it")
            return
        handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            self._set_status(
                f"⚠️  Found PID {pid} but OpenProcess failed (err {kernel32.GetLastError()}) "
                f"— use 🚀 Launch WoW instead")
            return
        self.handle = handle
        self._set_status(f"✅ Attached to {proc_name}  (PID {pid})", fg="#a6e3a1")

    # ── polling loop ──────────────────────────────────────────────────────────
    def _read_best_pos(self):
        """
        Read the player position. If multiple scan candidates exist, compare
        them on every poll and lock onto the first address that diverges from
        the rest — that's the live player struct.
        """
        if not self.handle:
            return None

        candidates = self.pos_candidates
        if len(candidates) <= 1:
            return get_player_pos(self.handle, self.pos_addr)

        readings = [(addr, get_player_pos(self.handle, addr)) for addr in candidates]
        valid    = [(addr, pos) for addr, pos in readings if pos]
        if not valid:
            return None

        # If any address has a different X from the rest, it's the live one
        xs      = [pos[0] for _, pos in valid]
        mean_x  = sum(xs) / len(xs)
        outlier = next(((a, p) for a, p in valid if abs(p[0] - mean_x) > 0.05), None)
        if outlier:
            addr, pos = outlier
            self.pos_addr       = addr
            self.pos_candidates = [addr]
            self.after(0, self._set_status,
                       f"✅ Live address locked: 0x{addr:08X}", "#a6e3a1")
            return pos

        return valid[0][1]   # all identical — return first

    def _poll_loop(self):
        warn_counter = 0
        while self.running:
            if self.handle:
                pos = self._read_best_pos()
                if pos:
                    x, y, z, o = pos
                    self.last_pos = pos
                    self.after(0, self._update_display, x, y, z, o)
                else:
                    warn_counter += 1
                    if warn_counter % 8 == 1:
                        if self.pos_addr:
                            self.after(0, self._set_status,
                                       f"⚠️  pos_addr=0x{self.pos_addr:08X} unreadable — rescan needed?")
                        else:
                            self.after(0, self._set_status,
                                       "⏳ Log in and use 🔍 Scan Memory to find position address")
            time.sleep(0.25)

    def _update_display(self, x, y, z, o):
        deg = math.degrees(o) % 360
        self.pos_label.config(
            text=f"X: {x:>10.2f}   Y: {y:>10.2f}   Z: {z:>8.2f}   O: {deg:>6.1f}°")
        # Warn if orientation is suspiciously stuck at zero
        if abs(o) < 0.001 and self.pos_addr:
            self._set_status(
                "⚠️  O: is 0.0 — orientation address may be wrong. "
                "Go back to Step 3, re-orient, log out, rescan.")

    # ── capture ───────────────────────────────────────────────────────────────
    def _capture(self):
        if not self.last_pos:
            messagebox.showwarning("No data", "No position data yet.")
            return
        x, y, z, o = self.last_pos
        total_pts = sum(len(g["points"]) for g in self.groups)
        label = self.lbl_entry.get().strip() or f"point {total_pts + 1}"
        shape = self.shape.get()

        # Start a new group when shape changes or no group exists yet
        if not self.groups or self.groups[-1]["shape"] != shape:
            gid = self.tree.insert("", "end",
                                   text=f"▾  {shape.title()}",
                                   values=("", "", "", "", ""),
                                   tags=("group",), open=True)
            self.groups.append({"shape": shape, "tree_id": gid, "points": []})

        g = self.groups[-1]

        # Distance from previous point within this group
        dist_str = "—"
        if g["points"]:
            _, px, py, pz, _ = g["points"][-1]
            d = math.sqrt((x-px)**2 + (y-py)**2 + (z-pz)**2)
            dist_str = f"{d:.2f}"

        g["points"].append((label, x, y, z, o))
        self.tree.insert(g["tree_id"], "end",
                         text=label,
                         values=(f"{x:.2f}", f"{y:.2f}", f"{z:.2f}",
                                 f"{math.degrees(o):.1f}°", dist_str),
                         tags=("point",))

        # Auto-increment label if it ends with a number
        m = re.match(r'^(.*?)(\d+)$', label)
        if m:
            self.lbl_entry.delete(0, "end")
            self.lbl_entry.insert(0, m.group(1) + str(int(m.group(2)) + 1))

    def _clear(self):
        if messagebox.askyesno("Clear", "Clear all captured points?"):
            self.groups.clear()
            for item in self.tree.get_children():
                self.tree.delete(item)
            self._set_go_command("")

    # ── right-click context menu ──────────────────────────────────────────────
    def _right_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        tags = self.tree.item(item, "tags")
        menu = tk.Menu(self, tearoff=0)

        if "group" in tags:
            shape_menu = tk.Menu(menu, tearoff=0)
            for s in SHAPE_POINTS:
                shape_menu.add_command(
                    label=s,
                    command=lambda sh=s, it=item: self._change_group_shape(it, sh))
            menu.add_cascade(label="Change shape to ▶", menu=shape_menu)
            menu.add_separator()
            menu.add_command(label="🗑  Delete zone",
                             command=lambda: self._delete_group(item))
        elif "point" in tags:
            menu.add_command(label="✏️  Edit point",
                             command=lambda: self._edit_row(item))
            menu.add_command(label="🗑  Delete point",
                             command=lambda: self._delete_row(item))

        menu.tk_popup(event.x_root, event.y_root)

    def _delete_row(self, item):
        gi, pi = self._find_point(item)
        if gi is None:
            return
        self.groups[gi]["points"].pop(pi)
        self.tree.delete(item)
        # If group is now empty, remove it
        if not self.groups[gi]["points"]:
            self.tree.delete(self.groups[gi]["tree_id"])
            self.groups.pop(gi)
        self._set_go_command("")

    def _delete_group(self, item):
        for gi, g in enumerate(self.groups):
            if g["tree_id"] == item:
                n = len(g["points"])
                if messagebox.askyesno(
                        "Delete zone",
                        f"Delete this {g['shape']} zone ({n} point(s))?"):
                    self.tree.delete(item)
                    self.groups.pop(gi)
                    self._set_go_command("")
                return

    def _change_group_shape(self, item, new_shape):
        for gi, g in enumerate(self.groups):
            if g["tree_id"] != item:
                continue
            old_shape = g["shape"]
            if new_shape == old_shape:
                return
            n_have = len(g["points"])
            n_need = SHAPE_POINTS.get(new_shape)

            if n_need is not None and n_have > n_need:
                ans = messagebox.askyesnocancel(
                    "Too many points",
                    f"'{new_shape}' needs {n_need} point(s) but you have {n_have}.\n\n"
                    f"Yes  — keep first {n_need}, delete the rest\n"
                    f"No   — delete this zone and start again\n"
                    f"Cancel — keep current shape")
                if ans is None:
                    return
                if ans:
                    # Keep first n_need, delete the rest from tree + data
                    for child in list(self.tree.get_children(item))[n_need:]:
                        self.tree.delete(child)
                    g["points"] = g["points"][:n_need]
                else:
                    self.tree.delete(item)
                    self.groups.pop(gi)
                    self._set_go_command("")
                    return

            g["shape"] = new_shape
            self.tree.item(item, text=f"▾  {new_shape.title()}")
            return

    # ── save / append ─────────────────────────────────────────────────────────
    def _save(self):
        if not any(g["points"] for g in self.groups):
            messagebox.showinfo("Nothing to save", "No points captured yet.")
            return

        path  = self.file_entry.get().strip()
        lines = []
        for g in self.groups:
            if not g["points"]:
                continue
            lines.append(f"\n### Captured Zone ({g['shape']})\n")
            lines.append("| Point | X | Y | Z |\n")
            lines.append("|-------|---------|---------|-------|\n")
            for label, x, y, z, o in g["points"]:
                lines.append(f"| {label} | {x:.2f} | {y:.2f} | {z:.2f} |\n")

        try:
            mode = "a" if os.path.exists(path) else "w"
            with open(path, mode, encoding="utf-8") as f:
                f.writelines(lines)
            action = "Appended to" if mode == "a" else "Created"
            messagebox.showinfo("Saved", f"{action}:\n{path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    # ── memory scan to find player position address ───────────────────────────
    def _scan(self):
        if not self.handle:
            self._set_status("❌ No WoW handle — launch or attach first")
            return
        self._set_status("⏳ Querying DB for last logout position…", fg="#f9e2af")
        self.update()

        dbpos = query_db_position()
        if not dbpos:
            self._set_status("❌ DB query failed — check MariaDB path / char name")
            return

        tx, ty, tz, to_ = dbpos

        # Orientation near zero → 0.0 is too common in memory; scan would be unreliable
        if abs(to_) < 0.15:   # ~8.6 degrees
            self._set_status(
                f"⛔ Orientation in DB is {math.degrees(to_):.1f}° (near zero) — "
                "go back to Step 3: log in, turn to a non-default direction, log out again")
            # Snap wizard back to step 3 (Move & Orient) so the user knows what to do
            self.wizard_step = 2
            self._wizard_update()
            return

        self._set_status(
            f"⏳ Scanning memory for X={tx:.2f} Y={ty:.2f} Z={tz:.2f} O={to_:.4f} …",
            fg="#f9e2af")
        self.update()

        handle = self.handle

        def _do_scan():
            def prog(scanned):
                mb = scanned // (1024*1024)
                self.after(0, self._set_status,
                           f"⏳ Scanning… {mb} MB checked", "#f9e2af")

            hits = scan_for_xyzo(handle, tx, ty, tz, to_, tol=0.05, progress_cb=prog)

            if not hits:
                self.after(0, self._set_status,
                           "❌ No match found — are you in-game and did you NOT move after logging in?")
                return
            if len(hits) > 5:
                self.after(0, self._set_status,
                           f"⚠️  {len(hits)} matches — try tighter tolerance or move slightly and rescan")
                return

            self.pos_candidates = hits
            self.pos_addr       = hits[0]
            note = " — move to lock live addr" if len(hits) > 1 else ""
            self.after(0, self._set_status,
                       f"✅ Found {len(hits)} candidate(s) at 0x{hits[0]:08X}{note}",
                       "#a6e3a1")
            # auto-advance wizard: "Scan Memory" (step 4) → all done
            def _adv_scan():
                if self.wizard_step == 4:
                    self.wizard_done.add(4)
                    self._wizard_update()
            self.after(0, _adv_scan)

        threading.Thread(target=_do_scan, daemon=True).start()

    # ── launch WoW via CreateProcess + DEBUG_PROCESS ──────────────────────────
    def _launch_wow(self):
        self._set_status("⏳ Launching WoW…", fg="#f9e2af")
        self.update()
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

        exe_path = self.exe_entry.get().strip()

        # Run in a background thread so the UI doesn't freeze during the pump loop
        def _do_launch():
            h, pid = launch_wow_debug(exe_path)
            if not h:
                err = kernel32.GetLastError()
                self.after(0, self._set_status,
                           f"❌ CreateProcess failed (err {err}). Is WoW.exe at {exe_path}?")
                return
            self.handle = h
            self.after(0, self._set_status,
                       f"✅ WoW launched (PID {pid}) — log in to see coords",
                       "#a6e3a1")
            # auto-advance wizard: "Launch WoW" (step 1) → "Move & Orient" (step 2)
            def _adv_launch():
                if self.wizard_step == 1:
                    self.wizard_done.add(1)
                    self.wizard_step = 2
                    self._wizard_update()
            self.after(0, _adv_launch)

        threading.Thread(target=_do_launch, daemon=True).start()

    def destroy(self):
        total_pts = sum(len(g["points"]) for g in self.groups)
        if total_pts:
            choice = messagebox.askyesnocancel(
                "Save before exit",
                f"You have {total_pts} captured point(s) across {len(self.groups)} zone(s).\n"
                "Save to output file before closing?")
            if choice is None:       # Cancel — don't close
                return
            if choice:               # Yes — save then close
                self._save()
        self.running = False
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None
        super().destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      