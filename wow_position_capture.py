"""
WoW 1.12.1 (build 5875) - Live Position Capture Tool
Reads player X, Y, Z, Orientation directly from WoW process memory.
Click "Capture" to add current position to the list.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import ctypes
import ctypes.wintypes as wt
import struct
import threading
import time
import math
import os

# ── WoW 1.12.1 build 5875 memory offsets ─────────────────────────────────────
OBJECT_MANAGER_PTR  = 0x00B41414   # pointer-to-pointer to object manager
CUR_MGR_OFFSET      = 0x1C
FIRST_OBJ_OFFSET    = 0xAC
LOCAL_GUID_OFFSET   = 0xC0
NEXT_OBJ_OFFSET     = 0x3C
OBJ_TYPE_OFFSET     = 0x14
OBJ_GUID_OFFSET     = 0x30

# From player object base
POS_X_OFFSET        = 0x9B8
POS_Y_OFFSET        = 0x9BC
POS_Z_OFFSET        = 0x9C0
FACING_OFFSET       = 0x9C4

PROCESS_VM_READ            = 0x0010
PROCESS_QUERY_INFORMATION  = 0x0400
PROCESS_ALL_ACCESS         = 0x1F0FFF
PROCESS_TERMINATE          = 0x0001
TH32CS_SNAPPROCESS         = 0x00000002
DEBUG_PROCESS              = 0x00000001
EXCEPTION_DEBUG_EVENT      = 1
EXIT_PROCESS_DEBUG_EVENT   = 5
DBG_EXCEPTION_NOT_HANDLED  = 0x80010001

WOW_EXE          = r"D:\World of Warcraft Classic 1.12.1\WoW.exe"
WOW_DIR          = r"D:\World of Warcraft Classic 1.12.1"
WOW_PROCESS_NAME = "wow.exe"   # lowercase — change if your exe has a different name

kernel32  = ctypes.windll.kernel32
ntdll     = ctypes.windll.ntdll


DBG_CONTINUE               = 0x00010002
CREATE_PROCESS_DEBUG_EVENT = 3

class _CREATE_PROCESS_INFO(ctypes.Structure):
    _fields_ = [("hFile",                 wt.HANDLE),
                ("hProcess",              wt.HANDLE),
                ("hThread",               wt.HANDLE),
                ("lpBaseOfImage",         ctypes.c_void_p),
                ("dwDebugInfoFileOffset", wt.DWORD),
                ("nDebugInfoSize",        wt.DWORD),
                ("lpThreadLocalBase",     ctypes.c_void_p),
                ("lpStartAddress",        ctypes.c_void_p),
                ("lpImageName",           ctypes.c_void_p),
                ("fUnicode",              wt.WORD)]

class _DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [("CreateProcessInfo", _CREATE_PROCESS_INFO),
                ("_pad",              ctypes.c_byte * 160)]

class _DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", wt.DWORD),
                ("dwProcessId",      wt.DWORD),
                ("dwThreadId",       wt.DWORD),
                ("u",                _DEBUG_EVENT_UNION)]

def open_process_via_debug(pid):
    """
    Attach as debugger. The CREATE_PROCESS_DEBUG_EVENT hands us hProcess
    directly from the kernel — never calls OpenProcess, so AV can't block it.
    Detach immediately after grabbing the handle; WoW resumes, handle stays valid.
    """
    if not kernel32.DebugActiveProcess(pid):
        return None
    ev = _DEBUG_EVENT()
    handle = None
    for _ in range(100):
        if not kernel32.WaitForDebugEvent(ctypes.byref(ev), 200):
            continue
        if ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
            handle = ev.u.CreateProcessInfo.hProcess  # kernel-granted handle
        kernel32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
        if handle:
            break
    kernel32.DebugActiveProcessStop(pid)
    return handle

# NtOpenProcess structures (fallback)
class _OBJECT_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Length",                   ctypes.c_ulong),
                ("RootDirectory",            ctypes.c_void_p),
                ("ObjectName",               ctypes.c_void_p),
                ("Attributes",               ctypes.c_ulong),
                ("SecurityDescriptor",       ctypes.c_void_p),
                ("SecurityQualityOfService", ctypes.c_void_p)]

class _CLIENT_ID(ctypes.Structure):
    _fields_ = [("UniqueProcess", ctypes.c_void_p),
                ("UniqueThread",  ctypes.c_void_p)]

def nt_open_process(pid, access):
    h  = ctypes.c_void_p(0)
    oa = _OBJECT_ATTRIBUTES()
    oa.Length = ctypes.sizeof(_OBJECT_ATTRIBUTES)
    cid = _CLIENT_ID()
    cid.UniqueProcess = ctypes.c_void_p(pid)
    cid.UniqueThread  = ctypes.c_void_p(0)
    status = ntdll.NtOpenProcess(ctypes.byref(h), access,
                                 ctypes.byref(oa), ctypes.byref(cid))
    return h.value if status == 0 else None

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

def list_all_pids():
    """Return list of (pid, exe_name) for all running processes."""
    procs = []
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == wt.HANDLE(-1).value:
        return procs
    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    try:
        if kernel32.Process32First(snapshot, ctypes.byref(entry)):
            while True:
                procs.append((entry.th32ProcessID, entry.szExeFile.decode(errors='replace')))
                if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                    break
    finally:
        kernel32.CloseHandle(snapshot)
    return procs

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

def read_u32(handle, addr):
    d = read_bytes(handle, addr, 4)
    return struct.unpack('<I', d)[0] if d else None

def read_u64(handle, addr):
    d = read_bytes(handle, addr, 8)
    return struct.unpack('<Q', d)[0] if d else None

def read_f32(handle, addr):
    d = read_bytes(handle, addr, 4)
    return struct.unpack('<f', d)[0] if d else None

def get_player_pos(handle, pos_addr=None):
    """
    Read player (x,y,z,facing).
    If pos_addr is given (found via memory scan), read directly from that address.
    Otherwise fall back to the object manager walk.
    """
    if pos_addr:
        x = read_f32(handle, pos_addr)
        y = read_f32(handle, pos_addr + 4)
        z = read_f32(handle, pos_addr + 8)
        o = read_f32(handle, pos_addr + 12)
        if None not in (x, y, z, o):
            return x, y, z, o
        return None

    # Object manager walk (fallback)
    om_ptr = read_u32(handle, OBJECT_MANAGER_PTR)
    if not om_ptr:
        return None
    cur_mgr = read_u32(handle, om_ptr + CUR_MGR_OFFSET)
    if not cur_mgr:
        return None
    local_guid = read_u64(handle, cur_mgr + LOCAL_GUID_OFFSET)
    if not local_guid:
        return None
    obj = read_u32(handle, cur_mgr + FIRST_OBJ_OFFSET)
    for _ in range(2000):
        if not obj or obj % 4 != 0:
            break
        guid = read_u64(handle, obj + OBJ_GUID_OFFSET)
        if guid == local_guid:
            x = read_f32(handle, obj + POS_X_OFFSET)
            y = read_f32(handle, obj + POS_Y_OFFSET)
            z = read_f32(handle, obj + POS_Z_OFFSET)
            o = read_f32(handle, obj + FACING_OFFSET)
            if None not in (x, y, z, o):
                return x, y, z, o
            return None
        nxt = read_u32(handle, obj + NEXT_OBJ_OFFSET)
        if nxt == obj:
            break
        obj = nxt
    return None

def _hex_row(handle, base, offset, n=16):
    d = read_bytes(handle, base + offset, n)
    if not d:
        return f"  +0x{offset:03X}: <unreadable>"
    hex_part = ' '.join(f'{b:02X}' for b in d)
    dwords = ' '.join(f'[{struct.unpack_from("<I",d,i)[0]:08X}]' for i in range(0,n,4))
    return f"  +0x{offset:03X}: {hex_part}   {dwords}"

def diagnose_handle(handle):
    """Return a short string; also writes wow_obj_dump.txt with full details."""
    if not handle:
        return "no handle"
    buf   = ctypes.create_string_buffer(4)
    nread = ctypes.c_size_t(0)
    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(OBJECT_MANAGER_PTR),
                                    buf, 4, ctypes.byref(nread))
    if not ok:
        err = kernel32.GetLastError()
        return f"ReadProcessMemory FAILED at 0x{OBJECT_MANAGER_PTR:08X} (err {err})"
    om_ptr = struct.unpack('<I', buf.raw)[0]
    if not om_ptr:
        return "object manager ptr = 0 — login/char-select screen, keep waiting"

    try:
        log_path = os.path.expanduser("~\\Desktop\\wow_obj_dump.txt")
        with open(log_path, "w") as f:
            f.write(f"=== WoW Object Manager Diagnostic ===\n")
            f.write(f"OBJECT_MANAGER_PTR : 0x{OBJECT_MANAGER_PTR:08X}\n")
            f.write(f"om_ptr (value)     : 0x{om_ptr:08X}\n\n")

            # Try four possible CUR_MGR_OFFSET values
            f.write("--- om_ptr + various offsets (finding cur_mgr) ---\n")
            for off in [0x14, 0x18, 0x1C, 0x20, 0x24]:
                v = read_u32(handle, om_ptr + off)
                marker = " ← current CUR_MGR_OFFSET" if off == CUR_MGR_OFFSET else ""
                f.write(f"  om_ptr+0x{off:02X} = 0x{(v or 0):08X}{marker}\n")
            f.write("\n")

            # For each candidate cur_mgr, show FIRST_OBJ and LOCAL_GUID candidates
            f.write("--- Scanning candidate cur_mgr values ---\n")
            for cmoff in [0x18, 0x1C]:
                cm = read_u32(handle, om_ptr + cmoff)
                if not cm:
                    continue
                f.write(f"\n  cur_mgr (om_ptr+0x{cmoff:02X}) = 0x{cm:08X}\n")
                for foff in range(0x98, 0xC4, 4):
                    v = read_u32(handle, cm + foff)
                    f.write(f"    +0x{foff:02X} = 0x{(v or 0):08X}\n")

            # Current values
            cur_mgr    = read_u32(handle, om_ptr + CUR_MGR_OFFSET)
            local_guid = read_u64(handle, cur_mgr + LOCAL_GUID_OFFSET) if cur_mgr else 0
            first_obj  = read_u32(handle, cur_mgr + FIRST_OBJ_OFFSET)  if cur_mgr else 0

            f.write(f"\n=== Current offsets (CUR_MGR=0x{CUR_MGR_OFFSET:02X} FIRST_OBJ=0x{FIRST_OBJ_OFFSET:02X} LOCAL_GUID=0x{LOCAL_GUID_OFFSET:02X}) ===\n")
            f.write(f"cur_mgr    : 0x{(cur_mgr or 0):08X}\n")
            f.write(f"local_guid : 0x{(local_guid or 0):016X}\n")
            f.write(f"first_obj  : 0x{(first_obj or 0):08X}\n\n")

            # Raw hex dump of first 256 bytes of first_obj (sentinel/header node)
            if first_obj:
                f.write(f"--- Raw hex dump: first_obj 0x{first_obj:08X} (first 256 bytes) ---\n")
                for row in range(0, 256, 16):
                    f.write(_hex_row(handle, first_obj, row) + "\n")

                # Also dump the object pointed to by next@+0x3C (first real object?)
                nxt = read_u32(handle, first_obj + 0x3C)
                if nxt and nxt != first_obj and nxt % 4 == 0 and nxt > 0x10000:
                    f.write(f"\n--- Raw hex dump: first_obj->next (0x{nxt:08X}) first 256 bytes ---\n")
                    for row in range(0, 256, 16):
                        f.write(_hex_row(handle, nxt, row) + "\n")

    except Exception as e:
        pass

    cur_mgr = read_u32(handle, om_ptr + CUR_MGR_OFFSET) if om_ptr else 0
    local_guid = read_u64(handle, cur_mgr + LOCAL_GUID_OFFSET) if cur_mgr else 0
    return (f"om_ptr=0x{om_ptr:08X} cur_mgr=0x{(cur_mgr or 0):08X} "
            f"guid=0x{(local_guid or 0):016X} — full dump → wow_obj_dump.txt on Desktop")

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
        self.exe_entry.grid(row=0, column=1, sticky="ew", padx=(4, 0), pady=1)
        self.exe_entry.bind("<FocusOut>", lambda e: self._sync_proc_from_exe())
        self.exe_entry.bind("<Return>",   lambda e: self._sync_proc_from_exe())

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

    # ── connection ────────────────────────────────────────────────────────────
    def _reconnect(self):
        """Re-run _connect using whatever is in the process name field."""
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None
        self._connect()

    def _connect(self):
        # Use process name from UI field if available, else fall back to constant
        proc_name = getattr(self, 'proc_entry', None)
        proc_name = proc_name.get().strip() if proc_name else WOW_PROCESS_NAME
        pid = find_wow_pid(proc_name)
        if pid is None:
            # Dump all running processes to the log so we can see the real name
            try:
                procs = list_all_pids()
                log_path = os.path.expanduser("~\\Desktop\\wow_attach_log.txt")
                with open(log_path, "w") as f:
                    f.write(f"Looking for: {proc_name}\n")
                    f.write("Running processes:\n")
                    for p_pid, p_name in sorted(procs, key=lambda x: x[1].lower()):
                        f.write(f"  {p_pid:>6}  {p_name}\n")
            except Exception:
                pass
            self._set_status(f"❌ '{proc_name}' not found — check wow_attach_log.txt on Desktop for actual process name")
            return

        log = []  # diagnostic log
        access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION

        handle = kernel32.OpenProcess(access, False, pid)
            log.append(f"OpenProcess(VM_READ): {'ok' if handle else 'err'+str(kernel32.GetLastError())}")

        if not handle:
            handle = nt_open_process(pid, access)
            log.append(f"NtOpenProcess(VM_READ): {'ok' if handle else 'fail'}")

        if not handle:
            handle = open_process_via_debug(pid)
            log.append(f"DebugAttach: {'ok' if handle else 'fail, DebugActiveProcess err='+str(kernel32.GetLastError())}")

        if not handle:
            handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
            log.append(f"OpenProcess(ALL): {'ok' if handle else 'err'+str(kernel32.GetLastError())}")

        if not handle:
            handle = nt_open_process(pid, PROCESS_ALL_ACCESS)
            log.append(f"NtOpenProcess(ALL): {'ok' if handle else 'fail'}")

        # Write diagnostic log to desktop
        try:
            with open(os.path.expanduser("~\\Desktop\\wow_attach_log.txt"), "w") as f:
                f.write(f"PID: {pid}\n" + "\n".join(log))
        except Exception:
            pass

        if not handle:
            self._set_status(f"❌ PID {pid} — all methods failed. See wow_attach_log.txt on Desktop.")
            return
        self.handle = handle
        self._set_status(f"✅ Attached to WoW.exe  (PID {pid})", fg="#a6e3a1")

    # ── polling loop ──────────────────────────────────────────────────────────
    def _poll_loop(self):
        diag_counter = 0
        while self.running:
            if self.handle:
                pos = get_player_pos(self.handle, self.pos_addr)
                if pos:
                    x, y, z, o = pos
                    self.last_pos = pos
                    self.after(0, self._update_display, x, y, z, o)
                else:
                    diag_counter += 1
                    if diag_counter % 8 == 1:
                        if self.pos_addr:
                            self.after(0, self._set_status,
                                       f"⚠️  pos_addr=0x{self.pos_addr:08X} unreadable — rescan needed?")
                        else:
                            msg = diagnose_handle(self.handle)
                            self.after(0, self._set_status, f"⚠️  {msg}")
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
