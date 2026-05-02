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

# ── Wizard step definitions ───────────────────────────────────────────────────
WIZARD_STEPS = [
    ("Exe Path",
     "Enter the full path to your WoW executable in the 'Exe path' field below.\n"
     "The Process name field will fill automatically."),
    ("Launch WoW",
     "Click '🚀 Launch WoW'. The game starts through the tool so it can access memory."),
    ("Move & Orient",
     "Log in, walk to a new position and turn to face a new direction.\n"
     "This gives the scanner a known coordinate to search for."),
    ("Log Out",
     "Log out of the game. This saves your current position and orientation\n"
     "to the CMaNGOS database so the scanner can find it."),
    ("Scan Memory",
     "Log back in without moving, then click '🔍 Scan Memory'.\n"
     "Live coordinates will appear once the address is found."),
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

        self.handle      = None
        self.pos_addr    = None
        self.running     = True
        self.captures    = []
        self.shape       = tk.StringVar(value="rectangle")
        self.last_pos    = None
        self.wizard_step = 0          # 0-based index into WIZARD_STEPS
        self.wizard_done = set()      # indices of manually-confirmed steps

        self._build_ui()
        self.attributes("-topmost", True)
        self._set_status = self._make_set_status()
        self.geometry("700x640+10+10")
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
        shapes = ["rectangle", "rhombus", "triangle", "pentagon", "pillar", "other"]
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

        self.cap_btn = _btn("📍 Capture",      self._capture);    self.cap_btn.pack()
        _btn("🗑 Clear all",   self._clear).pack()
        _btn("💾 Append to file", self._save).pack()
        _btn("🚀 Launch WoW", self._launch_wow).pack()
        _btn("🔍 Scan Memory", self._scan).pack()

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
        tk.Button(cfg, text="📂", font=("Consolas", 9), relief="flat",
                  bg=BTN, fg=FG, activebackground=ACC, activeforeground="#1e1e2e",
                  bd=0, padx=4, pady=2,
                  command=self._browse_exe).grid(row=0, column=2, pady=1)

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
        self.file_entry.grid(row=2, column=1, sticky="ew", padx=(4, 0), pady=1)

        self.bind("<Return>", lambda e: self._capture())

        # ── capture list ──────────────────────────────────────────────────────
        cols = ("label", "x", "y", "z", "facing", "dist")
        self.tree = ttk.Treeview(self, columns=cols, show="headings", height=10)
        widths = {"label": 110, "x": 90, "y": 90, "z": 70, "facing": 70, "dist": 80}
        heads  = {"label": "Label", "x": "X", "y": "Y", "z": "Z",
                  "facing": "Facing (O)", "dist": "Dist prev"}
        for c in cols:
            self.tree.heading(c, text=heads[c])
            self.tree.column(c, width=widths[c], anchor="center")
        sb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(fill="both", expand=True, padx=PAD, pady=(0, PAD))

        self.tree.bind("<Button-3>", self._right_click)
        self.tree.bind("<Double-1>", self._edit_row_event)

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
        BG  = "#1e1e2e"
        ACC = "#89b4fa"
        GRN = "#a6e3a1"
        BTN = "#45475a"
        FG  = "#cdd6f4"
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

    # ── row edit dialog (double-click / right-click → Edit) ───────────────────
    def _edit_row_event(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self._edit_row(item)

    def _edit_row(self, item):
        idx = self.tree.index(item)
        lbl, cx, cy, cz, co = self.captures[idx]

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
            self.captures[idx] = (new_lbl, new_x, new_y, new_z, new_o)
            dist_str = "—"
            if idx > 0:
                px, py, pz = self.captures[idx - 1][1:4]
                d = math.sqrt((new_x - px)**2 + (new_y - py)**2 + (new_z - pz)**2)
                dist_str = f"{d:.2f}"
            self.tree.item(item, values=(new_lbl,
                                         f"{new_x:.2f}", f"{new_y:.2f}",
                                         f"{new_z:.2f}",
                                         f"{math.degrees(new_o):.1f}°",
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
    def _poll_loop(self):
        warn_counter = 0
        while self.running:
            if self.handle:
                pos = get_player_pos(self.handle, self.pos_addr)
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

    # ── capture ───────────────────────────────────────────────────────────────
    def _capture(self):
        if not self.last_pos:
            messagebox.showwarning("No data", "No position data yet.")
            return
        x, y, z, o = self.last_pos
        label = self.lbl_entry.get().strip() or f"point {len(self.captures)+1}"

        # distance from previous capture
        dist_str = "—"
        if self.captures:
            px, py, pz = self.captures[-1][1:4]
            d = math.sqrt((x-px)**2 + (y-py)**2 + (z-pz)**2)
            dist_str = f"{d:.2f}"

        self.captures.append((label, x, y, z, o))
        self.tree.insert("", "end",
                         values=(label, f"{x:.2f}", f"{y:.2f}",
                                 f"{z:.2f}", f"{math.degrees(o):.1f}°",
                                 dist_str))

        # auto-increment label if it ends with a number
        import re
        m = re.match(r'^(.*?)(\d+)$', label)
        if m:
            self.lbl_entry.delete(0, "end")
            self.lbl_entry.insert(0, m.group(1) + str(int(m.group(2)) + 1))

    def _clear(self):
        if messagebox.askyesno("Clear", "Clear all captured points?"):
            self.captures.clear()
            for item in self.tree.get_children():
                self.tree.delete(item)

    def _right_click(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="✏️  Edit point",
                             command=lambda: self._edit_row(item))
            menu.add_command(label="🗑  Delete row",
                             command=lambda: self._delete_row(item))
            menu.tk_popup(event.x_root, event.y_root)

    def _delete_row(self, item):
        idx = self.tree.index(item)
        self.captures.pop(idx)
        self.tree.delete(item)

    # ── save / append ─────────────────────────────────────────────────────────
    def _save(self):
        if not self.captures:
            messagebox.showinfo("Nothing to save", "No points captured yet.")
            return

        path  = self.file_entry.get().strip()
        shape = self.shape.get()

        # Build the block to append
        lines = [f"\n### Captured Zone ({shape})\n",
                 f"| Point | X | Y | Z |\n",
                 f"|-------|---------|---------|-------|\n"]
        for label, x, y, z, o in self.captures:
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

            # Use first hit; if multiple exist, prefer one where nearby bytes look plausible
            addr = hits[0]
            self.pos_addr = addr
            self.after(0, self._set_status,
                       f"✅ Found at 0x{addr:08X} ({len(hits)} hit(s)) — coords live",
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
        self.running = False
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None
        super().destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()
