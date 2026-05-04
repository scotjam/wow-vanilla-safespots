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

# Log file for diagnostics — written to the same folder as this script
_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_debug.log")
# Clear log on each launch
try:
    open(_LOG_PATH, "w").close()
except Exception:
    pass
def _log(msg):
    """Append a line to scan_debug.log and also print to console."""
    print(msg)
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except Exception:
        pass

PROCESS_VM_READ            = 0x0010
PROCESS_QUERY_INFORMATION  = 0x0400
PROCESS_TERMINATE          = 0x0001
TH32CS_SNAPPROCESS         = 0x00000002
TH32CS_SNAPMODULE          = 0x00000008
TH32CS_SNAPMODULE32        = 0x00000010

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

    ok = kernel32.CreateProcessW(
        target_exe, None, None, None, False,
        0, None, target_dir,
        ctypes.byref(si), ctypes.byref(pi))

    if not ok:
        return None, None

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


# ── Module base address detection ────────────────────────────────────────────
class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize',        wt.DWORD),
        ('th32ModuleID',  wt.DWORD),
        ('th32ProcessID', wt.DWORD),
        ('GlblcntUsage',  wt.DWORD),
        ('ProccntUsage',  wt.DWORD),
        ('modBaseAddr',   ctypes.c_void_p),
        ('modBaseSize',   wt.DWORD),
        ('hModule',       wt.HANDLE),
        ('szModule',      ctypes.c_wchar * 256),
        ('szExePath',     ctypes.c_wchar * 260),
    ]

def get_all_modules(pid):
    """Return list of (name, base, size) for all loaded modules in a process."""
    modules = []
    snap = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap and snap != wt.HANDLE(-1).value:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        try:
            fn_first = getattr(kernel32, 'Module32FirstW', None) or kernel32.Module32First
            fn_next = getattr(kernel32, 'Module32NextW', None) or kernel32.Module32Next
            if fn_first(snap, ctypes.byref(me)):
                while True:
                    modules.append((me.szModule, me.modBaseAddr, me.modBaseSize))
                    me2 = MODULEENTRY32W()
                    me2.dwSize = ctypes.sizeof(MODULEENTRY32W)
                    if not fn_next(snap, ctypes.byref(me2)):
                        break
                    me = me2
        finally:
            kernel32.CloseHandle(snap)
    return modules

def addr_in_any_module(addr, modules):
    """Check if addr falls within any loaded module. Returns module name or None."""
    for name, base, size in modules:
        if base <= addr < base + size:
            return name
    return None

def get_module_base(pid, handle=None):
    """Return the base address of the main exe module for a given PID."""
    # Strategy 1: module snapshot
    snap = kernel32.CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap and snap != wt.HANDLE(-1).value:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        try:
            fn = getattr(kernel32, 'Module32FirstW', None) or kernel32.Module32First
            if fn(snap, ctypes.byref(me)):
                kernel32.CloseHandle(snap)
                return me.modBaseAddr
        finally:
            kernel32.CloseHandle(snap)
    # Strategy 2: PE-header probe at common bases
    if handle:
        for base in [0x00400000, 0x00010000, 0x00100000, 0x00500000]:
            sig = read_bytes(handle, base, 2)
            if sig == b'MZ':
                return base
    return None


MARIADB_EXE   = r"D:\MariaDB\bin\mysql.exe"
CHAR_NAME     = "Dingle"

# ── Static pointer chain for WoW 1.12.1 build 5875 ──────────────────────────
STANDARD_IMAGE_BASE       = 0x00400000

# Standard WoW.exe offsets
STATIC_CLIENT_CONNECTION  = 0x00C79CE0
STATIC_LOCAL_PLAYER_GUID  = 0x00C79D18
RVA_CLIENT_CONNECTION     = STATIC_CLIENT_CONNECTION - STANDARD_IMAGE_BASE
RVA_LOCAL_PLAYER_GUID     = STATIC_LOCAL_PLAYER_GUID - STANDARD_IMAGE_BASE
OBJ_MGR_OFFSET            = 0x2ED0
FIRST_OBJECT_OFFSET       = 0xAC
NEXT_OBJECT_OFFSET        = 0x3C
OBJECT_TYPE_OFFSET         = 0x14
OBJECT_GUID_OFFSET         = 0x30
MOVEMENT_STRUCT_OFFSET     = 0x118
MOVEMENT_POS_X_OFFSET      = 0x10
MOVEMENT_POS_Y_OFFSET      = 0x14
MOVEMENT_POS_Z_OFFSET      = 0x18
MOVEMENT_FACING_OFFSET     = 0x1C
OBJECT_TYPE_PLAYER         = 4

# wow_tweaked.exe offsets — not yet discovered (previous values were false positives)
# The reverse scanner will find these automatically when heap-pointer validation passes.
# Once found, hardcode them here for instant detection on future sessions.
TWEAKED_CLIENT_CONNECTION  = None   # will be filled by reverse scanner
TWEAKED_OBJ_MGR_OFFSET    = None
TWEAKED_FIRST_OBJ_OFFSET  = None
TWEAKED_OFFSETS            = None

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
    results = []
    mbi     = MEMORY_BASIC_INFORMATION()
    addr    = 0x10000
    CHUNK   = 0x80000
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
        skip = (mbi.State != MEM_COMMIT or
                mbi.Protect & PAGE_NOACCESS or
                mbi.Protect & PAGE_GUARD)
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

def read_u32(handle, addr):
    d = read_bytes(handle, addr, 4)
    return struct.unpack('<I', d)[0] if d else None

def read_u64(handle, addr):
    d = read_bytes(handle, addr, 8)
    return struct.unpack('<Q', d)[0] if d else None

def get_player_pos(handle, pos_addr):
    if not pos_addr:
        return None
    x = read_f32(handle, pos_addr)
    y = read_f32(handle, pos_addr + 4)
    z = read_f32(handle, pos_addr + 8)
    o = read_f32(handle, pos_addr + 12)
    if None not in (x, y, z, o):
        return x, y, z, o
    return None

def _is_valid_coord(x, y, z):
    return (abs(x) < 65000 and abs(y) < 65000 and abs(z) < 15000
            and not (x == 0.0 and y == 0.0 and z == 0.0))

def scan_for_movement_struct(handle, pid=None):
    """Fast pattern-based scan for the WoW movement struct in memory.
    Pattern: X,Y,Z,O at consecutive floats, 16 zero bytes before X,
    and the same X,Y,Z duplicated at X+0x34.  This fingerprint is
    extremely specific and doesn't depend on object layout or pointer chains.
    Returns (pos_addr,) or None where pos_addr points to X."""
    CHUNK = 0x10000
    mbi   = MEMORY_BASIC_INFORMATION()
    addr  = 0x01000000
    candidates = []

    # Skip modules
    modules = get_all_modules(pid) if pid else []
    _log(f"[PatternScan] Loaded {len(modules)} modules to skip")

    while addr < 0x7FFF0000:
        ret = ctypes.windll.kernel32.VirtualQueryEx(
            handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if ret == 0:
            addr += 0x10000
            continue
        base = mbi.BaseAddress or addr
        size = mbi.RegionSize or 0x1000
        skip = (mbi.State != MEM_COMMIT or
                mbi.Protect & PAGE_NOACCESS or
                mbi.Protect & PAGE_GUARD)
        if not skip and modules and addr_in_any_module(base, modules):
            skip = True
        if not skip and size > 0:
            for off in range(0, size, CHUNK):
                csz = min(CHUNK, size - off)
                buf = ctypes.create_string_buffer(csz)
                nrd = ctypes.c_size_t(0)
                caddr = base + off
                ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(caddr),
                                                buf, csz, ctypes.byref(nrd))
                if not ok:
                    continue
                data = buf.raw[:nrd.value]
                # Need at least 0x10 (zeros) + 0x10 (XYZO) + 0x24 + 0x0C (dup XYZ)
                # = 0x50 bytes, and X starts at offset 0x10 in our window
                for i in range(0x10, len(data) - 0x50, 4):
                    # Quick check: X at [i] must be a meaningful WoW coordinate
                    x = struct.unpack_from('<f', data, i)[0]
                    if not (10.0 < abs(x) < 64000):
                        continue
                    y = struct.unpack_from('<f', data, i + 4)[0]
                    if not (10.0 < abs(y) < 64000):
                        continue
                    z = struct.unpack_from('<f', data, i + 8)[0]
                    if not (abs(z) < 15000):  # z can be small/zero
                        continue
                    if math.isnan(z):
                        continue
                    # Check orientation at +0x0C: must be 0 to 2*pi
                    o = struct.unpack_from('<f', data, i + 0x0C)[0]
                    if not (0.0 <= o <= 6.3):
                        continue
                    # Check 16 zero bytes before X (movement struct header)
                    zeros = struct.unpack_from('<IIII', data, i - 0x10)
                    if zeros != (0, 0, 0, 0):
                        continue
                    # Check duplicate X,Y,Z at +0x34 from X
                    if i + 0x34 + 12 > len(data):
                        continue
                    x2 = struct.unpack_from('<f', data, i + 0x34)[0]
                    y2 = struct.unpack_from('<f', data, i + 0x38)[0]
                    z2 = struct.unpack_from('<f', data, i + 0x3C)[0]
                    if abs(x2 - x) > 0.5 or abs(y2 - y) > 0.5 or abs(z2 - z) > 0.5:
                        continue
                    # ALL checks passed — this is a movement struct
                    pos_addr = caddr + i
                    candidates.append((pos_addr, x, y, z, o))
                    _log(f"[PatternScan] MATCH at 0x{pos_addr:08X}: "
                          f"X={x:.2f} Y={y:.2f} Z={z:.2f} O={o:.4f}")
        addr = base + size if (base + size) > addr else addr + 0x1000

    _log(f"[PatternScan] Total matches: {len(candidates)}")
    if not candidates:
        return None
    # Return ALL candidate addresses — the poll loop's outlier detection
    # will lock onto the player when they move (NPCs stay still)
    addrs = [c[0] for c in candidates]
    return addrs


# ── Window handle + rotation-based player identification ─────────────────────

# Windows constants for PostMessage / keypress
WM_KEYDOWN = 0x0100
WM_KEYUP   = 0x0101
VK_LEFT    = 0x25   # left arrow — turns character left in WoW
VK_RIGHT   = 0x27   # right arrow — turns character right

user32 = ctypes.windll.user32

# Callback type for EnumWindows
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

def find_wow_hwnd(pid):
    """Find the main WoW window handle for a given process ID."""
    result = []
    def _cb(hwnd, _lparam):
        tid_pid = wt.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(tid_pid))
        if tid_pid.value == pid and user32.IsWindowVisible(hwnd):
            # Check it's a real top-level window with a title
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                result.append(hwnd)
        return True  # continue enumeration
    user32.EnumWindows(WNDENUMPROC(_cb), 0)
    return result[0] if result else None


def _read_orientation(handle, addr):
    """Read orientation float at addr + 0x0C (O is 4 floats after X)."""
    return read_f32(handle, addr + 0x0C)


def identify_player_by_rotation(handle, pid, candidates):
    """Identify the player among multiple movement struct candidates by sending
    brief rotation keypresses to the WoW window.

    1. Read orientation of all candidates
    2. Send left-arrow keydown, wait, keyup  (rotates player left)
    3. Read orientations again — find which changed
    4. Send right-arrow keydown, wait, keyup  (rotates player back)
    5. Read orientations — confirm the same address changed again
    6. Return the confirmed player address, or None if ambiguous.
    """
    hwnd = find_wow_hwnd(pid)
    if not hwnd:
        _log("[RotationID] Could not find WoW window handle")
        return None

    _log(f"[RotationID] Found WoW HWND: {hwnd}, testing {len(candidates)} candidates")

    # Step 1: baseline orientations
    baseline = {}
    for addr in candidates:
        o = _read_orientation(handle, addr)
        if o is not None:
            baseline[addr] = o
    _log(f"[RotationID] Baseline orientations: {len(baseline)} readable")
    if not baseline:
        return None

    # Step 2: send left-arrow press (rotate left)
    user32.PostMessageW(hwnd, WM_KEYDOWN, VK_LEFT, 0)
    time.sleep(0.25)
    user32.PostMessageW(hwnd, WM_KEYUP, VK_LEFT, 0)
    time.sleep(0.10)

    # Step 3: read orientations, find who changed
    changed_left = set()
    for addr, orig_o in baseline.items():
        new_o = _read_orientation(handle, addr)
        if new_o is not None and abs(new_o - orig_o) > 0.01:
            changed_left.add(addr)
            _log(f"[RotationID] Left turn: 0x{addr:08X} changed O {orig_o:.4f} -> {new_o:.4f}")

    if not changed_left:
        _log("[RotationID] No candidate changed orientation on left turn")
        return None

    # Step 4: read new baseline before right turn
    mid = {}
    for addr in changed_left:
        o = _read_orientation(handle, addr)
        if o is not None:
            mid[addr] = o

    # Step 5: send right-arrow press (rotate back)
    user32.PostMessageW(hwnd, WM_KEYDOWN, VK_RIGHT, 0)
    time.sleep(0.25)
    user32.PostMessageW(hwnd, WM_KEYUP, VK_RIGHT, 0)
    time.sleep(0.10)

    # Step 6: confirm — same addresses changed again
    changed_right = set()
    for addr in changed_left:
        new_o = _read_orientation(handle, addr)
        prev_o = mid.get(addr)
        if prev_o is not None and new_o is not None and abs(new_o - prev_o) > 0.01:
            changed_right.add(addr)
            _log(f"[RotationID] Right turn: 0x{addr:08X} changed O {prev_o:.4f} -> {new_o:.4f}")

    confirmed = changed_left & changed_right
    _log(f"[RotationID] Confirmed by both turns: {len(confirmed)} address(es)")

    if len(confirmed) == 1:
        addr = confirmed.pop()
        _log(f"[RotationID] Player identified: 0x{addr:08X}")
        return addr
    elif len(confirmed) > 1:
        # Multiple changed both times — pick the one with the largest orientation delta
        best = None
        best_delta = 0
        for addr in confirmed:
            orig = baseline.get(addr, 0)
            now = _read_orientation(handle, addr) or 0
            delta = abs(now - orig)
            if delta > best_delta:
                best_delta = delta
                best = addr
        _log(f"[RotationID] Multiple confirmed — picking largest delta: 0x{best:08X}")
        return best
    else:
        _log("[RotationID] No candidate confirmed by both turns")
        return None


def scan_for_player_via_db(handle, pid=None):
    """Use known position from the DB to find coordinates in memory, then dump
    the surrounding structure so we can identify a stable pattern for future scans.
    Returns (pos_addr, n_hits) or None."""
    _log("[DBScan] Querying database for known position...")
    dbpos = query_db_position()
    if not dbpos:
        _log("[DBScan] DB query failed!")
        return None
    tx, ty, tz, to_ = dbpos
    _log(f"[DBScan] DB says: X={tx:.4f} Y={ty:.4f} Z={tz:.4f} O={to_:.4f}")

    # Scan memory for those exact float values
    _log("[DBScan] Scanning memory for matching XYZO floats...")
    hits = scan_for_xyzo(handle, tx, ty, tz, to_, tol=0.05)
    _log(f"[DBScan] Found {len(hits)} exact matches")

    if not hits:
        # Try XYZ only (orientation may have changed)
        _log("[DBScan] Trying XYZ-only match (ignoring orientation)...")
        hits_xyz = []
        mbi = MEMORY_BASIC_INFORMATION()
        addr = 0x10000
        CHUNK = 0x80000
        while addr < 0x7FFF0000:
            sz = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                         ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not sz:
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            if size == 0:
                addr += 0x1000; continue
            skip = (mbi.State != MEM_COMMIT or
                    mbi.Protect & PAGE_NOACCESS or
                    mbi.Protect & PAGE_GUARD)
            if not skip:
                for off in range(0, size, CHUNK):
                    csz = min(CHUNK, size - off)
                    buf = ctypes.create_string_buffer(csz)
                    nrd = ctypes.c_size_t(0)
                    caddr = base + off
                    ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(caddr),
                                                    buf, csz, ctypes.byref(nrd))
                    if not ok:
                        continue
                    data = buf.raw[:nrd.value]
                    for i in range(0, len(data) - 12, 4):
                        fx, fy, fz = struct.unpack_from('<fff', data, i)
                        if (abs(fx - tx) < 0.05 and abs(fy - ty) < 0.05
                                and abs(fz - tz) < 0.05):
                            hits_xyz.append(caddr + i)
            addr = base + size if (base + size) > addr else addr + 0x1000
        _log(f"[DBScan] Found {len(hits_xyz)} XYZ-only matches")
        hits = hits_xyz

    if not hits:
        return None

    # For each hit, dump a wide area around it to discover the surrounding structure
    modules = get_all_modules(pid) if pid else []
    for hit_idx, pos_addr in enumerate(hits):
        in_mod = addr_in_any_module(pos_addr, modules) if modules else None
        _log(f"\n{'='*70}")
        _log(f"[DBScan] Hit #{hit_idx}: pos_addr=0x{pos_addr:08X}"
              f"{' (in ' + in_mod + ')' if in_mod else ' (HEAP)'}")
        _log(f"{'='*70}")

        # Dump 0x200 bytes before and 0x80 bytes after the X coordinate
        # This captures the object header and nearby fields
        dump_start = pos_addr - 0x200
        dump_end   = pos_addr + 0x80
        raw = read_bytes(handle, dump_start, dump_end - dump_start)
        if not raw:
            _log("  (could not read memory)")
            continue

        _log(f"  Dumping 0x{dump_start:08X} to 0x{dump_end:08X}:")
        for off in range(0, len(raw), 4):
            addr_here = dump_start + off
            ival = struct.unpack_from('<I', raw, off)[0]
            fval = struct.unpack_from('<f', raw, off)[0]

            # Relative to pos_addr (X)
            rel = addr_here - pos_addr

            # Annotations
            markers = []
            if rel == 0:  markers.append("X")
            elif rel == 4:  markers.append("Y")
            elif rel == 8:  markers.append("Z")
            elif rel == 12: markers.append("O?")

            # Check if value looks like a pointer to something
            if 0x00400000 < ival < 0x7FFF0000:
                mod = addr_in_any_module(ival, modules) if modules else None
                if mod:
                    markers.append(f"ptr->{mod}")
                elif ival > 0x01000000:
                    markers.append("ptr->heap?")

            # Check if value is a small integer (type field, flags, etc)
            if 0 < ival < 100:
                markers.append(f"int={ival}")

            # Check if float is in orientation range
            if rel != 0 and rel != 4 and rel != 8 and 0.01 < fval < 6.29:
                markers.append(f"orientation?")

            # Check for GUID-like values (64-bit)
            if off + 8 <= len(raw):
                qval = struct.unpack_from('<Q', raw, off)[0]
                if 0 < qval < 0xFFFFFFFF and ival != qval:
                    pass  # not interesting

            marker_str = f"  <- {', '.join(markers)}" if markers else ""
            _log(f"  0x{addr_here:08X} [X{rel:+05d}] 0x{ival:08X}  f={fval:>14.4f}{marker_str}")

        # Also try to read any strings near the object (field names, class names)
        _log(f"\n  Checking for readable strings near hit:")
        for scan_off in range(-0x400, 0x100, 4):
            saddr = pos_addr + scan_off
            sraw = read_bytes(handle, saddr, 64)
            if sraw:
                # Check if it looks like an ASCII string
                try:
                    text = sraw.split(b'\x00')[0].decode('ascii')
                    if len(text) >= 4 and text.isprintable():
                        _log(f"  0x{saddr:08X} [X{scan_off:+05d}]: \"{text}\"")
                except (UnicodeDecodeError, ValueError):
                    pass

    # Return the first hit (or filter to heap-only if multiple)
    heap_hits = [h for h in hits if not (modules and addr_in_any_module(h, modules))]
    if heap_hits:
        _log(f"\n[DBScan] Using heap hit: 0x{heap_hits[0]:08X}")
        return (heap_hits[0], len(hits))
    _log(f"\n[DBScan] Using first hit: 0x{hits[0]:08X}")
    return (hits[0], len(hits))


def get_player_pos_pointer_chain(handle, module_base=None,
                                  discovered_cc=None, discovered_guid=None,
                                  discovered_offsets=None):
    """Follow the static pointer chain to read player (X,Y,Z,O).
    Tries discovered addresses/offsets first, then standard/rebased addresses."""
    # Build list of (cc_addr, guid_addr, offsets_dict) to try
    attempts = []
    if discovered_cc is not None:
        attempts.append((discovered_cc, discovered_guid, discovered_offsets))
    # Try hardcoded tweaked exe addresses if they've been discovered
    if TWEAKED_CLIENT_CONNECTION is not None:
        attempts.append((TWEAKED_CLIENT_CONNECTION, None, TWEAKED_OFFSETS))
    if module_base is not None and module_base != STANDARD_IMAGE_BASE:
        attempts.append((module_base + RVA_CLIENT_CONNECTION,
                         module_base + RVA_LOCAL_PLAYER_GUID, None))
    # Standard WoW.exe addresses
    attempts.append((STATIC_CLIENT_CONNECTION, STATIC_LOCAL_PLAYER_GUID, None))
    for addr_cc, addr_guid, offsets in attempts:
        result = _try_pointer_chain(handle, addr_cc, addr_guid, offsets)
        if result:
            return result
    return None

def _try_pointer_chain(handle, addr_cc, addr_guid, offsets=None):
    """Single attempt at following a pointer chain from given static addresses.
    offsets is an optional dict with keys: om_offset, first_obj_offset,
    next_offset, type_offset, movement_offset, x_offset."""
    om_off   = offsets.get('om_offset', OBJ_MGR_OFFSET)       if offsets else OBJ_MGR_OFFSET
    fo_off   = offsets.get('first_obj_offset', FIRST_OBJECT_OFFSET) if offsets else FIRST_OBJECT_OFFSET
    nxt_off  = offsets.get('next_offset', NEXT_OBJECT_OFFSET)  if offsets else NEXT_OBJECT_OFFSET
    typ_off  = offsets.get('type_offset', OBJECT_TYPE_OFFSET)  if offsets else OBJECT_TYPE_OFFSET
    mov_off  = offsets.get('movement_offset', MOVEMENT_STRUCT_OFFSET) if offsets else MOVEMENT_STRUCT_OFFSET
    x_off    = offsets.get('x_offset', MOVEMENT_POS_X_OFFSET)  if offsets else MOVEMENT_POS_X_OFFSET

    client_conn = read_u32(handle, addr_cc)
    if not client_conn or client_conn < 0x10000:
        return None
    obj_mgr = read_u32(handle, client_conn + om_off)
    if not obj_mgr or obj_mgr < 0x10000:
        return None
    local_guid = None
    if addr_guid:
        local_guid = read_u64(handle, addr_guid)
    obj = read_u32(handle, obj_mgr + fo_off)
    if not obj or obj < 0x10000:
        return None
    visited = 0
    while obj and obj >= 0x10000 and visited < 10000:
        visited += 1
        obj_type = read_u32(handle, obj + typ_off)
        if obj_type == OBJECT_TYPE_PLAYER:
            # If we have a GUID, match it; otherwise take the first player
            if local_guid:
                guid = read_u64(handle, obj + OBJECT_GUID_OFFSET)
                if guid != local_guid:
                    next_obj = read_u32(handle, obj + nxt_off)
                    if not next_obj or next_obj == obj:
                        break
                    obj = next_obj
                    continue
            for base in [read_u32(handle, obj + mov_off),
                         obj + mov_off]:
                if not base or base < 0x10000:
                    continue
                x = read_f32(handle, base + x_off)
                y = read_f32(handle, base + x_off + 4)
                z = read_f32(handle, base + x_off + 8)
                o = read_f32(handle, base + x_off + 12)
                if None not in (x, y, z, o) and _is_valid_coord(x, y, z):
                    return x, y, z, o
            return None
        next_obj = read_u32(handle, obj + nxt_off)
        if not next_obj or next_obj == obj:
            break
        obj = next_obj
    return None

def diagnose_pointer_chain(handle, module_base=None):
    """Walk the pointer chain and return diagnostic lines."""
    lines = []
    if module_base is not None:
        lines.append(f"Module base: 0x{module_base:08X}  (std=0x{STANDARD_IMAGE_BASE:08X})")
    else:
        lines.append("Module base: NOT DETECTED (using standard addresses)")
    if module_base is not None and module_base != STANDARD_IMAGE_BASE:
        addr_cc   = module_base + RVA_CLIENT_CONNECTION
        addr_guid = module_base + RVA_LOCAL_PLAYER_GUID
    else:
        addr_cc   = STATIC_CLIENT_CONNECTION
        addr_guid = STATIC_LOCAL_PLAYER_GUID
    lines.append(f"ClientConnection addr: 0x{addr_cc:08X}")
    lines.append(f"LocalPlayerGUID addr:  0x{addr_guid:08X}")
    # Step 1
    cc = read_u32(handle, addr_cc)
    if not cc:
        lines.append("  [1] ClientConnection: READ FAILED <- chain breaks here")
        return lines
    lines.append(f"  [1] ClientConnection ptr = 0x{cc:08X}" +
                 ("  !! invalid" if cc < 0x10000 else "  ok"))
    if cc < 0x10000:
        return lines
    # Step 2
    om = read_u32(handle, cc + OBJ_MGR_OFFSET)
    if not om:
        lines.append(f"  [2] ObjMgr at CC+0x{OBJ_MGR_OFFSET:X}: READ FAILED")
        return lines
    lines.append(f"  [2] ObjectManager ptr = 0x{om:08X}" +
                 ("  !! invalid" if om < 0x10000 else "  ok"))
    if om < 0x10000:
        return lines
    # Step 3
    guid = read_u64(handle, addr_guid)
    if not guid:
        lines.append("  [3] Local GUID: 0 or READ FAILED (not logged in?)")
        return lines
    lines.append(f"  [3] Local GUID = 0x{guid:016X}  ok")
    # Step 4
    first = read_u32(handle, om + FIRST_OBJECT_OFFSET)
    if not first or first < 0x10000:
        lines.append(f"  [4] FirstObject: {'FAIL' if not first else f'0x{first:08X} invalid'}")
        return lines
    lines.append(f"  [4] First object = 0x{first:08X}  ok")
    # Step 5 - walk
    obj = first
    visited = 0
    types = {}
    while obj and obj >= 0x10000 and visited < 500:
        visited += 1
        ot = read_u32(handle, obj + OBJECT_TYPE_OFFSET)
        t = ot if ot is not None else -1
        types[t] = types.get(t, 0) + 1
        if ot == OBJECT_TYPE_PLAYER:
            g = read_u64(handle, obj + OBJECT_GUID_OFFSET)
            if g == guid:
                lines.append(f"  [5] Player found @ 0x{obj:08X} after {visited} objs  ok")
                raw = read_u32(handle, obj + MOVEMENT_STRUCT_OFFSET)
                lines.append(f"  [6] obj+0x118 raw = 0x{raw:08X}" if raw else "  [6] obj+0x118 READ FAIL")
                emb = obj + MOVEMENT_STRUCT_OFFSET
                for label, b in [("embedded", emb), ("pointer", raw)]:
                    if not b or b < 0x10000:
                        continue
                    ex = read_f32(handle, b + 0x10)
                    ey = read_f32(handle, b + 0x14)
                    ez = read_f32(handle, b + 0x18)
                    eo = read_f32(handle, b + 0x1C)
                    valid = None not in (ex, ey, ez) and _is_valid_coord(ex, ey, ez)
                    lines.append(f"      {label}: X={ex} Y={ey} Z={ez} O={eo}  "
                                 f"{'ok' if valid else '!! bad'}")
                lines.append("      -- nearby offsets --")
                for p in range(0xD8, 0x210, 0x10):
                    rv = read_u32(handle, obj + p)
                    fv = read_f32(handle, obj + p)
                    if rv is not None:
                        lines.append(f"        +0x{p:03X}: 0x{rv:08X}  ({fv:.4f})")
                return lines
        nxt = read_u32(handle, obj + NEXT_OBJECT_OFFSET)
        if not nxt or nxt == obj:
            break
        obj = nxt
    lines.append(f"  [5] Walked {visited} objs, no player matched. Types: {types}")
    return lines

def _diagnose_tweaked_chain(handle):
    """Detailed diagnostic of the tweaked pointer chain."""
    lines = ["=== TWEAKED CHAIN DIAGNOSTIC ==="]
    addr_cc = TWEAKED_CLIENT_CONNECTION
    if addr_cc is None:
        lines.append("CC static addr: NOT YET DISCOVERED")
        lines.append("  (reverse scanner with heap validation will find it)")
        return "\n".join(lines)
    lines.append(f"CC static addr: 0x{addr_cc:08X}")
    cc = read_u32(handle, addr_cc)
    if cc is None:
        lines.append("  [1] READ FAILED (address not mapped?)")
        return "\n".join(lines)
    lines.append(f"  [1] CC ptr = 0x{cc:08X}" + ("  !! zero/invalid" if not cc or cc < 0x10000 else "  ok"))
    if not cc or cc < 0x10000:
        return "\n".join(lines)
    om_off = TWEAKED_OBJ_MGR_OFFSET
    om = read_u32(handle, cc + om_off)
    lines.append(f"  [2] ObjMgr at CC+0x{om_off:X} = " +
                 (f"0x{om:08X}  ok" if om and om >= 0x10000 else f"FAIL ({om})"))
    if not om or om < 0x10000:
        return "\n".join(lines)
    fo_off = TWEAKED_FIRST_OBJ_OFFSET
    first = read_u32(handle, om + fo_off)
    lines.append(f"  [3] FirstObj at ObjMgr+0x{fo_off:X} = " +
                 (f"0x{first:08X}  ok" if first and first >= 0x10000 else f"FAIL ({first})"))
    if not first or first < 0x10000:
        return "\n".join(lines)
    # Walk objects
    obj = first; visited = 0; types = {}
    while obj and obj >= 0x10000 and visited < 200:
        visited += 1
        ot = read_u32(handle, obj + OBJECT_TYPE_OFFSET)
        t = ot if ot is not None else -1
        types[t] = types.get(t, 0) + 1
        if ot == OBJECT_TYPE_PLAYER:
            lines.append(f"  [4] Player @ 0x{obj:08X} after {visited} objs")
            mv = read_u32(handle, obj + MOVEMENT_STRUCT_OFFSET)
            lines.append(f"  [5] Movement ptr (obj+0x118) = 0x{mv:08X}" if mv else "  [5] Movement: FAIL")
            if mv and mv >= 0x10000:
                x = read_f32(handle, mv + MOVEMENT_POS_X_OFFSET)
                y = read_f32(handle, mv + MOVEMENT_POS_Y_OFFSET)
                z = read_f32(handle, mv + MOVEMENT_POS_Z_OFFSET)
                lines.append(f"  [6] Pos: X={x} Y={y} Z={z}")
                if x is not None and y is not None and z is not None:
                    lines.append(f"      valid={_is_valid_coord(x, y, z)}")
            return "\n".join(lines)
        nxt = read_u32(handle, obj + NEXT_OBJECT_OFFSET)
        if not nxt or nxt == obj:
            break
        obj = nxt
    lines.append(f"  [4] Walked {visited} objs, no player. Types: {types}")
    return "\n".join(lines)

def probe_around_pos(handle, pos_addr):
    """Dump memory around a known position address to find the object base."""
    lines = [f"Position X at: 0x{pos_addr:08X}", ""]
    # Dump 0x300 bytes before pos_addr looking for struct markers
    lines.append("-- Memory before X (looking for object base) --")
    for off in range(-0x200, 0x40, 4):
        addr = pos_addr + off
        raw = read_u32(handle, addr)
        fv  = read_f32(handle, addr)
        if raw is None:
            continue
        marker = ""
        if off == 0:
            marker = " <-- X float"
        elif off == 4:
            marker = " <-- Y float"
        elif off == 8:
            marker = " <-- Z float"
        elif off == 12:
            marker = " <-- O float"
        lines.append(f"  0x{addr:08X} (X{off:+05d}): 0x{raw:08X}  float={fv:12.4f}{marker}")
    return lines

def _reverse_scan_for_value(handle, target_u32, progress_cb=None):
    """Scan all committed memory for any DWORD containing target_u32.
    Returns list of (address_where_found,)."""
    results = []
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0x10000
    CHUNK = 0x80000
    total = 0
    target_bytes = struct.pack('<I', target_u32)
    while addr < 0x7FFF0000:
        sz = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not sz:
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize or 0
        if size == 0:
            addr += 0x1000; continue
        skip = (mbi.State != MEM_COMMIT or
                mbi.Protect & PAGE_NOACCESS or
                mbi.Protect & PAGE_GUARD)
        if not skip:
            for off in range(0, size, CHUNK):
                csz = min(CHUNK, size - off)
                buf = ctypes.create_string_buffer(csz)
                nrd = ctypes.c_size_t(0)
                caddr = base + off
                ok = kernel32.ReadProcessMemory(handle, ctypes.c_void_p(caddr),
                                                 buf, csz, ctypes.byref(nrd))
                if not ok:
                    continue
                data = buf.raw[:nrd.value]
                # Fast search using bytes.find
                pos = 0
                while True:
                    idx = data.find(target_bytes, pos)
                    if idx == -1:
                        break
                    if idx % 4 == 0:  # aligned
                        results.append(caddr + idx)
                    pos = idx + 1
            total += size
            if progress_cb:
                progress_cb(total)
        addr = base + size if (base + size) > addr else addr + 0x1000
    return results

def scan_for_client_connection(handle, known_pos_addr, module_base=None,
                               progress_cb=None, pid=None):
    """
    Bottom-up pointer chain discovery.
    Starts from the known position address and traces pointers backwards:
      movement_struct ← object ← object_list ← obj_mgr ← client_connection ← static_addr
    Returns a diagnostic dict with discovered offsets and addresses, or None.
    """
    base = module_base or STANDARD_IMAGE_BASE
    static_lo = base
    # Read PE SizeOfImage to get actual module end (more accurate than fixed range)
    pe_off_raw = read_u32(handle, base + 0x3C)  # e_lfanew
    if pe_off_raw and pe_off_raw < 0x1000:
        size_of_image = read_u32(handle, base + pe_off_raw + 0x50)  # OptionalHeader.SizeOfImage
        static_hi = base + (size_of_image if size_of_image else 0x00A00000)
    else:
        static_hi = base + 0x00A00000  # conservative fallback ~6MB

    # Enumerate ALL loaded modules so we can check for statics in DLLs too
    all_modules = []
    if pid:
        all_modules = get_all_modules(pid)

    known_x = read_f32(handle, known_pos_addr)
    known_y = read_f32(handle, known_pos_addr + 4)
    if known_x is None or known_y is None:
        return None

    # Step 1: Find the movement struct base.
    # Try common X offsets within movement struct: 0x10 (standard), 0x00, 0x08, 0x0C
    move_base_candidates = []
    for x_off in [0x10, 0x00, 0x08, 0x0C, 0x18, 0x20]:
        candidate = known_pos_addr - x_off
        move_base_candidates.append((candidate, x_off))

    # Step 2: For each movement base candidate, scan for pointers to it
    diag_lines = ["=== REVERSE POINTER CHAIN SCAN ==="]
    diag_lines.append(f"Main module: 0x{static_lo:08X}-0x{static_hi:08X}")
    if all_modules:
        diag_lines.append(f"Loaded modules: {len(all_modules)}")
        for mname, mbase, msize in all_modules[:15]:
            diag_lines.append(f"  {mname}: 0x{mbase:08X}-0x{mbase+msize:08X}")
        if len(all_modules) > 15:
            diag_lines.append(f"  ... and {len(all_modules)-15} more")
    diag_lines.append("")
    found_chain = None

    for move_base, x_offset in move_base_candidates:
        if progress_cb:
            progress_cb(0, 0, f"Scanning for ptrs to movement struct (X@+0x{x_offset:X})...")
        ptrs_to_move = _reverse_scan_for_value(handle, move_base & 0xFFFFFFFF)
        if not ptrs_to_move:
            continue
        diag_lines.append(f"Movement base 0x{move_base:08X} (X@+0x{x_offset:X}): "
                         f"{len(ptrs_to_move)} pointer(s) found")

        for ptr_addr in ptrs_to_move:
            # ptr_addr = object_base + some_offset
            # The offset is unknown, so try to find the object base by scanning
            # backwards from ptr_addr for a vtable-like pointer (address in module range)
            # Try known offsets first: 0x118 (standard), then brute-force 0x00-0x400
            for obj_offset in [0x118, 0x110, 0x120, 0x128, 0x100, 0xE8, 0xD8, 0xF0, 0xF8,
                               0x108, 0x130, 0x138, 0x140, 0x148, 0x150]:
                obj_base = ptr_addr - obj_offset
                if obj_base < 0x10000:
                    continue
                # Check if this looks like a valid WoW object:
                # - offset 0x00 or 0x04 should be a vtable pointer (in module range)
                # - some offset should have type (small int 1-7)
                vtable = read_u32(handle, obj_base)
                if vtable is None:
                    continue
                # Check for object type at common offsets: 0x14, 0x10, 0x18, 0x0C, 0x08
                for type_off in [0x14, 0x10, 0x18, 0x0C, 0x08, 0x20]:
                    otype = read_u32(handle, obj_base + type_off)
                    if otype == OBJECT_TYPE_PLAYER:
                        diag_lines.append(f"  → Player object candidate at 0x{obj_base:08X} "
                                         f"(type@+0x{type_off:X}=4, movement@+0x{obj_offset:X})")
                        # Try to find "next object" pointer by scanning nearby offsets
                        # and looking for another object with a vtable
                        chain_info = _trace_chain_up(handle, obj_base, obj_offset, type_off,
                                                      x_offset, move_base, static_lo, static_hi,
                                                      diag_lines, progress_cb,
                                                      all_modules=all_modules)
                        if chain_info:
                            chain_info['move_base'] = move_base
                            chain_info['x_offset'] = x_offset
                            chain_info['obj_base'] = obj_base
                            chain_info['obj_offset'] = obj_offset
                            chain_info['type_offset'] = type_off
                            chain_info['diag'] = diag_lines
                            return chain_info
    diag_lines.append("No valid chain found.")
    return {'diag': diag_lines}  # return diag even on failure

def _trace_chain_up(handle, obj_base, movement_offset, type_offset,
                     x_offset, move_base, static_lo, static_hi,
                     diag_lines, progress_cb, all_modules=None):
    """From a player object, trace upwards to find ObjectManager and ClientConnection."""
    # Step 3: Find what points to this object (or to the head of the object list)
    # We need to find the ObjectManager. Scan for pointers to obj_base.
    if progress_cb:
        progress_cb(0, 0, "Scanning for ptrs to player object...")
    ptrs_to_obj = _reverse_scan_for_value(handle, obj_base & 0xFFFFFFFF)
    diag_lines.append(f"  Pointers to player obj: {len(ptrs_to_obj)}")

    # Also try to find a "next" pointer on the object to identify the linked list structure
    # Look for a nearby offset that contains a pointer to another object of same structure
    next_offset = None
    for noff in [0x3C, 0x38, 0x40, 0x34, 0x44, 0x48, 0x30, 0x2C]:
        nxt = read_u32(handle, obj_base + noff)
        if nxt and nxt >= 0x10000 and nxt != obj_base:
            # Check if the target also has a similar structure (vtable + type)
            nxt_type = read_u32(handle, nxt + type_offset)
            if nxt_type is not None and 1 <= nxt_type <= 7:
                next_offset = noff
                diag_lines.append(f"  Next-object offset: +0x{noff:X} → 0x{nxt:08X} (type={nxt_type})")
                break

    # Walk backwards through the list to find the first object
    first_obj = obj_base
    if next_offset is not None:
        # Walk the list to find all objects, then scan for what points to them
        all_objs = set()
        o = obj_base
        visited = 0
        while o and o >= 0x10000 and visited < 1000:
            all_objs.add(o)
            visited += 1
            n = read_u32(handle, o + next_offset)
            if not n or n in all_objs:
                break
            o = n
        diag_lines.append(f"  Object list has {len(all_objs)} objects")

        # The first object in the list is pointed to by ObjMgr + some_offset
        # Scan for pointers to each object; ones from outside the list are from ObjMgr
        if progress_cb:
            progress_cb(0, 0, "Scanning for ObjectManager...")
        for candidate_first in all_objs:
            # Heap validation: real objects live on the heap, well above the module
            if candidate_first < static_hi:
                continue  # silently skip to reduce log noise
            # Validate this looks like a real object (has valid type 1-7)
            ctype = read_u32(handle, candidate_first + type_offset)
            if ctype is None or not (1 <= ctype <= 7):
                continue  # not a valid WoW object — skip
            ptrs = _reverse_scan_for_value(handle, candidate_first & 0xFFFFFFFF)
            for pa in ptrs:
                # Skip if the pointer is from within an object in the list
                is_from_list = False
                for lo in all_objs:
                    if lo <= pa < lo + 0x400:
                        is_from_list = True
                        break
                if is_from_list:
                    continue
                # pa = ObjMgr + first_object_offset
                first_obj_off = pa  # absolute address
                # Try common first-object offsets to derive ObjMgr base
                for fo in [0xAC, 0xA8, 0xB0, 0xA0, 0xB4, 0xB8, 0xC0, 0x98, 0x90]:
                    om_base = pa - fo
                    if om_base < 0x10000:
                        continue
                    # Heap validation: ObjMgr must be a heap pointer above the module
                    if om_base < static_hi:
                        continue  # silently skip to reduce log noise
                    diag_lines.append(f"  ObjMgr candidate: 0x{om_base:08X} "
                                     f"(first_obj@+0x{fo:X} → 0x{candidate_first:08X})")
                    # Step 4: find what points to om_base (should be CC + some_offset)
                    ptrs_to_om = _reverse_scan_for_value(handle, om_base & 0xFFFFFFFF)
                    diag_lines.append(f"    Pointers to ObjMgr 0x{om_base:08X}: {len(ptrs_to_om)}")
                    # Show first few pointer sources for debugging
                    for om_pa in ptrs_to_om[:3]:
                        mod_src = addr_in_any_module(om_pa, all_modules) if all_modules else None
                        diag_lines.append(f"      om_pa=0x{om_pa:08X}"
                                         f" ({mod_src or 'heap'})")
                    for om_pa in ptrs_to_om:
                        # om_pa = CC_value + obj_mgr_offset
                        for omo in [0x2ED0, 0x2EC0, 0x2EE0, 0x2E00, 0x2F00,
                                    0x2D00, 0x3000, 0x2C00, 0x2800, 0x3800]:
                            cc_value = om_pa - omo
                            if cc_value < 0x10000:
                                continue
                            # Heap validation: CC ptr must be a heap pointer above the module
                            if cc_value < static_hi:
                                continue
                            # Step 5: find a static address containing cc_value
                            ptrs_to_cc = _reverse_scan_for_value(handle, cc_value & 0xFFFFFFFF)
                            for cc_pa in ptrs_to_cc:
                                # Check if cc_pa is in the main exe module
                                in_main = static_lo <= cc_pa < static_hi
                                # Also check all loaded modules (DLLs)
                                mod_name = None
                                if not in_main and all_modules:
                                    mod_name = addr_in_any_module(cc_pa, all_modules)
                                if in_main or mod_name:
                                    src = mod_name or "main exe"
                                    diag_lines.append(
                                        f"  === FOUND STATIC CC ===\n"
                                        f"  Static addr:     0x{cc_pa:08X} (in {src})\n"
                                        f"  CC ptr:          0x{cc_value:08X}\n"
                                        f"  ObjMgr offset:   +0x{omo:X}\n"
                                        f"  ObjMgr ptr:      0x{om_base:08X}\n"
                                        f"  FirstObj offset:  +0x{fo:X}\n"
                                        f"  Next offset:      +0x{next_offset:X}\n"
                                        f"  Type offset:      +0x{type_offset:X}\n"
                                        f"  Movement offset:  +0x{movement_offset:X}\n"
                                        f"  X offset in move: +0x{x_offset:X}")
                                    return {
                                        'cc_static': cc_pa,
                                        'cc_ptr': cc_value,
                                        'om_offset': omo,
                                        'om_ptr': om_base,
                                        'first_obj_offset': fo,
                                        'next_offset': next_offset,
                                        'movement_offset': movement_offset,
                                        'type_offset': type_offset,
                                        'x_offset': x_offset,
                                    }
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

# ── Vanilla 1.12.1 map IDs ───────────────────────────────────────────────────
DUNGEON_MAPS = [
    ("-- Open World --",        None),
    ("Eastern Kingdoms",        "0"),
    ("Kalimdor",                "1"),
    ("-- Dungeons --",          None),
    ("Ragefire Chasm",          "389"),
    ("Wailing Caverns",         "43"),
    ("The Deadmines",           "36"),
    ("Shadowfang Keep",         "33"),
    ("Blackfathom Deeps",       "48"),
    ("The Stockade",            "34"),
    ("Gnomeregan",              "90"),
    ("Razorfen Kraul",          "47"),
    ("Scarlet Monastery",       "189"),
    ("Razorfen Downs",          "129"),
    ("Uldaman",                 "70"),
    ("Zul'Farrak",              "209"),
    ("Maraudon",                "349"),
    ("Temple of Atal'Hakkar",   "109"),
    ("Blackrock Depths",        "230"),
    ("Lower Blackrock Spire",   "229"),
    ("Upper Blackrock Spire",   "229"),
    ("Dire Maul East",          "429"),
    ("Dire Maul West",          "430"),
    ("Dire Maul North",         "432"),
    ("Stratholme",              "329"),
    ("Scholomance",             "289"),
    ("-- Raids --",             None),
    ("Molten Core",             "409"),
    ("Onyxia's Lair",           "249"),
    ("Blackwing Lair",          "469"),
    ("Zul'Gurub",               "309"),
    ("Ruins of Ahn'Qiraj",      "509"),
    ("Temple of Ahn'Qiraj",     "531"),
    ("Naxxramas",               "533"),
]
_COMBO_VALUES = [
    name if mid is None else f"{name}  [{mid}]"
    for name, mid in DUNGEON_MAPS
]

WIZARD_STEPS = [
    ("Exe Path",
     "Enter the full path to your WoW executable in the 'Exe path' field below.\n"
     "The Process name field will fill automatically."),
    ("Launch WoW",
     "Click 'Launch WoW'. The game starts through the tool so it can read memory."),
    ("Log In",
     "Log into the game. The tool will automatically find your player —\n"
     "it briefly rotates your camera to identify the right address."),
    ("Ready",
     "Live coordinates are active! Use 'Capture' to record positions.\n"
     "If detection failed, try walking a few steps or click 'DB Scan (fallback)'."),
]

# ── Wrapping button frame ─────────────────────────────────────────────────────
class FlowFrame(tk.Frame):
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
        self.wow_pid         = None
        self.module_base     = None
        self.pos_addr        = None
        self.pos_candidates  = []
        self._use_chain      = False
        self._discovered_cc  = None   # discovered ClientConnection static addr
        self._discovered_guid = None  # discovered LocalPlayerGUID static addr
        self._discovered_offsets = None  # dict of discovered struct offsets
        self.running         = True
        self.groups          = []
        self.map_id      = tk.StringVar(value="")
        self.shape       = tk.StringVar(value="single point")
        self.last_pos    = None
        self.wizard_step = 0
        self.wizard_done = set()
        self._last_click = 0.0

        self._build_ui()
        self.attributes("-topmost", True)
        self._set_status = self._make_set_status()
        self.geometry("700x760+10+10")
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._connect()
        threading.Thread(target=self._poll_loop, daemon=True).start()

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
        style.configure("TLabel",        background=BG, foreground=FG, font=("Consolas", 10))
        style.configure("Header.TLabel", background=BG, foreground=ACC, font=("Consolas", 11, "bold"))
        style.configure("Pos.TLabel",    background=BG, foreground=GRN, font=("Consolas", 13, "bold"))
        style.configure("TButton",       background=BTN, foreground=FG, font=("Consolas", 10), relief="flat", padding=4)
        style.map("TButton", background=[("active", ACC)], foreground=[("active", "#1e1e2e")])
        style.configure("Treeview", background=ENTRY, foreground=FG, fieldbackground=ENTRY, rowheight=22, font=("Consolas", 9))
        style.configure("Treeview.Heading", background=BTN, foreground=ACC, font=("Consolas", 9, "bold"))
        style.configure("TLabelframe",       background=BG)
        style.configure("TLabelframe.Label", background=BG, foreground=ACC, font=("Consolas", 9, "bold"))

        # live coords
        top = ttk.Frame(self, padding=PAD)
        top.pack(fill="x")
        ttk.Label(top, text="LIVE POSITION", style="Header.TLabel").pack(anchor="w")
        self.pos_label = ttk.Label(top, text="X: ---   Y: ---   Z: ---   O: ---", style="Pos.TLabel")
        self.pos_label.pack(anchor="w", pady=(2, 2))
        self.status_label = tk.Entry(top, font=("Consolas", 9), bg=BG, fg="#f38ba8",
                                     insertbackground="#f38ba8", relief="flat", readonlybackground=BG)
        self.status_label.pack(anchor="w", fill="x")
        self.status_label.insert(0, "Connecting...")
        self.status_label.config(state="readonly")
        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=PAD, pady=(4, 0))

        # wizard
        wiz = ttk.LabelFrame(self, text="Setup Steps", padding=(PAD, 4))
        wiz.pack(fill="x", padx=PAD, pady=4)
        step_bar = tk.Frame(wiz, bg=BG)
        step_bar.pack(fill="x")
        self._wiz_btns = []
        for i, (title, _) in enumerate(WIZARD_STEPS):
            btn = tk.Button(step_bar, text=f"  {i+1}. {title}  ", font=("Consolas", 9),
                            relief="flat", bd=0, cursor="hand2",
                            command=lambda idx=i: self._wizard_goto(idx))
            btn.pack(side="left", padx=2, pady=2)
            self._wiz_btns.append(btn)
        self._wiz_desc = tk.Label(wiz, text="", bg=BG, fg=FG, font=("Consolas", 9),
                                  justify="left", anchor="w", wraplength=600)
        self._wiz_desc.pack(fill="x", pady=(4, 4))
        nav = tk.Frame(wiz, bg=BG)
        nav.pack(fill="x")
        self._wiz_back_btn = tk.Button(nav, text="<- Back", font=("Consolas", 9), relief="flat",
                                       bg=BTN, fg=FG, bd=0, padx=8, pady=3, command=self._wizard_back)
        self._wiz_back_btn.pack(side="left", padx=(0, 6))
        self._wiz_next_btn = tk.Button(nav, text="Done, Next ->", font=("Consolas", 9, "bold"),
                                       relief="flat", bg=ACC, fg="#1e1e2e", bd=0, padx=8, pady=3,
                                       command=self._wizard_next)
        self._wiz_next_btn.pack(side="left")
        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=PAD, pady=(0, 4))

        # shape selector
        shape_flow = FlowFrame(self, gap=4, bg=BG)
        shape_flow.pack(fill="x", padx=PAD, pady=(4, 0))
        tk.Label(shape_flow, text="Zone shape:", bg=BG, fg=FG, font=("Consolas", 10)).pack()
        for s in ["single point", "rectangle", "rhombus", "triangle", "pentagon", "pillar", "other"]:
            tk.Radiobutton(shape_flow, text=s, variable=self.shape, value=s, indicatoron=False,
                           font=("Consolas", 10), bg=BTN, fg=FG, selectcolor=ACC,
                           activebackground=ACC, activeforeground="#1e1e2e",
                           relief="flat", bd=0, padx=6, pady=3).pack()

        # label + map ID
        lbl_row = tk.Frame(self, bg=BG)
        lbl_row.pack(fill="x", padx=PAD, pady=(4, 0))
        tk.Label(lbl_row, text="Label:", bg=BG, fg=FG, font=("Consolas", 10)).pack(side="left")
        self.lbl_entry = tk.Entry(lbl_row, width=16, bg=ENTRY, fg=FG, insertbackground=FG,
                                  font=("Consolas", 10), relief="flat")
        self.lbl_entry.insert(0, "point 1")
        self.lbl_entry.pack(side="left", padx=(4, 8))
        tk.Label(lbl_row, text="Map ID:", bg=BG, fg=FG, font=("Consolas", 10)).pack(side="left")
        self.mapid_entry = tk.Entry(lbl_row, width=6, bg=ENTRY, fg=FG, insertbackground=FG,
                                    font=("Consolas", 10), relief="flat", textvariable=self.map_id)
        self.mapid_entry.pack(side="left", padx=(4, 8))

        # dungeon selector
        dsel_row = tk.Frame(self, bg=BG)
        dsel_row.pack(fill="x", padx=PAD, pady=(2, 0))
        tk.Label(dsel_row, text="Dungeon / zone:", bg=BG, fg=FG, font=("Consolas", 10)).pack(side="left")
        self._dungeon_var = tk.StringVar()
        self.dungeon_combo = ttk.Combobox(dsel_row, textvariable=self._dungeon_var,
                                          values=_COMBO_VALUES, state="readonly",
                                          font=("Consolas", 10), width=36)
        self.dungeon_combo.pack(side="left", padx=(6, 0))
        self.dungeon_combo.bind("<<ComboboxSelected>>", self._on_dungeon_select)

        # buttons
        flow = FlowFrame(self, gap=4, bg=BG)
        flow.pack(fill="x", padx=PAD, pady=(2, 2))
        self.bind("<Configure>", lambda e: flow._reflow())
        def _btn(text, cmd):
            return tk.Button(flow, text=text, command=cmd, font=("Consolas", 10), relief="flat",
                             bg=BTN, fg=FG, activebackground=ACC, activeforeground="#1e1e2e",
                             padx=6, pady=3, bd=0)
        self.cap_btn    = _btn("Capture",       self._guard(self._capture));    self.cap_btn.pack()
        _btn("Clear all",       self._guard(self._clear)).pack()
        _btn("Append to file",  self._guard(self._save)).pack()
        self.launch_btn = _btn("Launch WoW",    self._guard(self._launch_wow)); self.launch_btn.pack()
        self.scan_btn   = _btn("DB Scan (fallback)", self._guard(self._scan)); self.scan_btn.pack()

        # exe / process / output
        cfg = tk.Frame(self, bg=BG)
        cfg.pack(fill="x", padx=PAD, pady=(2, 4))
        cfg.columnconfigure(1, weight=1)
        tk.Label(cfg, text="Exe path:", bg=BG, fg=FG, font=("Consolas", 9)).grid(row=0, column=0, sticky="w", pady=1)
        self.exe_entry = tk.Entry(cfg, bg=ENTRY, fg=FG, insertbackground=FG, font=("Consolas", 9), relief="flat")
        self.exe_entry.insert(0, WOW_EXE)
        self.exe_entry.grid(row=0, column=1, sticky="ew", padx=(4, 4), pady=1)
        self.exe_entry.bind("<FocusOut>", lambda e: self._sync_proc_from_exe())
        self.exe_entry.bind("<Return>",   lambda e: self._sync_proc_from_exe())
        self.exe_browse_btn = tk.Button(cfg, text="...", font=("Consolas", 9), relief="flat",
                                        bg=BTN, fg=FG, activebackground=ACC, activeforeground="#1e1e2e",
                                        bd=0, padx=4, pady=2, command=self._browse_exe)
        self.exe_browse_btn.grid(row=0, column=2, pady=1)
        tk.Label(cfg, text="Process:", bg=BG, fg=FG, font=("Consolas", 9)).grid(row=1, column=0, sticky="w", pady=1)
        self.proc_entry = tk.Entry(cfg, bg=ENTRY, fg=FG, insertbackground=FG, font=("Consolas", 9), relief="flat")
        self.proc_entry.insert(0, WOW_PROCESS_NAME)
        self.proc_entry.grid(row=1, column=1, sticky="ew", padx=(4, 0), pady=1)
        tk.Label(cfg, text="Output file:", bg=BG, fg=FG, font=("Consolas", 9)).grid(row=2, column=0, sticky="w", pady=1)
        self.file_entry = tk.Entry(cfg, bg=ENTRY, fg=FG, insertbackground=FG, font=("Consolas", 9), relief="flat")
        _default_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "safe zones in dungeons.md")
        self.file_entry.insert(0, _default_out)
        self.file_entry.grid(row=2, column=1, sticky="ew", padx=(4, 4), pady=1)
        tk.Button(cfg, text="...", font=("Consolas", 9), relief="flat", bg=BTN, fg=FG,
                  activebackground=ACC, activeforeground="#1e1e2e", bd=0, padx=4, pady=2,
                  command=self._browse_output).grid(row=2, column=2, pady=1)
        self.bind("<Return>", lambda e: self._guard(self._capture)())

        # capture list
        cols = ("x", "y", "z", "facing", "dist")
        self.tree = ttk.Treeview(self, columns=cols, show="tree headings", height=10)
        self.tree.heading("#0", text="Label"); self.tree.column("#0", width=120, anchor="w", stretch=True)
        for c, w, h in [("x",80,"X"),("y",80,"Y"),("z",65,"Z"),("facing",70,"Facing"),("dist",75,"Dist prev")]:
            self.tree.heading(c, text=h); self.tree.column(c, width=w, anchor="center")
        self.tree.tag_configure("group", background="#313244", foreground=ACC, font=("Consolas", 9, "bold"))
        self.tree.tag_configure("point", background=ENTRY, foreground=FG, font=("Consolas", 9))
        sb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(fill="both", expand=True, padx=PAD, pady=(0, 2))
        self.tree.bind("<Button-3>", self._right_click)
        self.tree.bind("<Double-1>", self._edit_row_event)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # .go command
        go_frame = tk.LabelFrame(self, text="teleport command:", bg=BG, fg=ACC,
                                 font=("Consolas", 9, "bold"), relief="groove", bd=1)
        go_frame.pack(fill="x", padx=PAD, pady=(0, PAD))
        self.go_entry = tk.Entry(go_frame, bg=ENTRY, fg=GRN, insertbackground=GRN,
                                 font=("Consolas", 11, "bold"), relief="flat",
                                 readonlybackground=ENTRY, state="readonly")
        self.go_entry.pack(fill="x", expand=True, padx=4, pady=(4, 0))
        self.go_warn_label = tk.Label(go_frame, text="", bg=BG, fg="#f9e2af",
                                      font=("Consolas", 8), anchor="w")
        self.go_warn_label.pack(fill="x", padx=6, pady=(0, 4))
        self._wizard_update()

    def _make_set_status(self):
        def _set(text, fg="#f38ba8"):
            self.status_label.config(state="normal", fg=fg)
            self.status_label.delete(0, "end")
            self.status_label.insert(0, text)
            self.status_label.config(state="readonly")
        return _set

    def _show_diagnostic(self, text):
        BG, FG, ENTRY = "#1e1e2e", "#cdd6f4", "#313244"
        dlg = tk.Toplevel(self)
        dlg.title("Pointer Chain Diagnostic")
        dlg.geometry("750x450")
        dlg.configure(bg=BG)
        dlg.attributes("-topmost", True)
        txt = tk.Text(dlg, bg=ENTRY, fg=FG, font=("Consolas", 9), wrap="none", relief="flat", padx=6, pady=6)
        txt.insert("1.0", text)
        txt.config(state="disabled")
        sby = ttk.Scrollbar(dlg, orient="vertical", command=txt.yview)
        sbx = ttk.Scrollbar(dlg, orient="horizontal", command=txt.xview)
        txt.configure(yscrollcommand=sby.set, xscrollcommand=sbx.set)
        sby.pack(side="right", fill="y"); sbx.pack(side="bottom", fill="x")
        txt.pack(fill="both", expand=True)
        def _copy():
            self.clipboard_clear(); self.clipboard_append(text)
        tk.Button(dlg, text="Copy to clipboard", command=_copy, font=("Consolas", 9),
                  bg="#45475a", fg=FG, relief="flat", bd=0, padx=8, pady=4).pack(pady=(4, 6))

    def _guard(self, fn):
        def _wrapped(*args, **kwargs):
            now = time.monotonic()
            if now - self._last_click < 0.3:
                return
            self._last_click = now
            fn(*args, **kwargs)
        return _wrapped

    # ── wizard helpers ────────────────────────────────────────────────────────
    def _browse_exe(self):
        current = self.exe_entry.get().strip()
        init_dir = os.path.dirname(current) if current and os.path.exists(os.path.dirname(current)) else "C:\\"
        path = filedialog.askopenfilename(title="Select WoW executable", initialdir=init_dir,
                                          filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if path:
            self.exe_entry.delete(0, "end"); self.exe_entry.insert(0, path)
            self._sync_proc_from_exe()

    def _browse_output(self):
        current = self.file_entry.get().strip()
        init_dir  = os.path.dirname(current) if current else os.path.dirname(os.path.abspath(__file__))
        init_file = os.path.basename(current) if current else "safe zones in dungeons.md"
        path = filedialog.asksaveasfilename(title="Choose output file", initialdir=init_dir,
                                            initialfile=init_file, defaultextension=".md",
                                            filetypes=[("Markdown","*.md"),("Text","*.txt"),("All","*.*")])
        if path:
            self.file_entry.delete(0, "end"); self.file_entry.insert(0, path)

    def _sync_proc_from_exe(self):
        exe = self.exe_entry.get().strip()
        if exe:
            self.proc_entry.delete(0, "end"); self.proc_entry.insert(0, os.path.basename(exe).lower())
            if self.wizard_step == 0:
                self.wizard_done.add(0); self.wizard_step = 1; self._wizard_update()

    def _wizard_update(self):
        BG, ACC, GRN, BTN, FG = "#1e1e2e", "#89b4fa", "#a6e3a1", "#45475a", "#cdd6f4"
        HILIGHT = "#f9e2af"
        for i, btn in enumerate(self._wiz_btns):
            if i == self.wizard_step:        btn.config(bg=ACC, fg="#1e1e2e")
            elif i in self.wizard_done:      btn.config(bg=GRN, fg="#1e1e2e")
            else:                            btn.config(bg=BTN, fg=FG)
        _, desc = WIZARD_STEPS[self.wizard_step]
        self._wiz_desc.config(text=f"Step {self.wizard_step + 1}: {desc}")
        self._wiz_back_btn.config(state="normal" if self.wizard_step > 0 else "disabled")
        if self.wizard_step >= len(WIZARD_STEPS) - 1:
            self._wiz_next_btn.config(text="All done!", state="disabled")
        else:
            self._wiz_next_btn.config(text="Done, Next ->", state="normal")
        if not hasattr(self, "launch_btn"): return
        step = self.wizard_step
        FG_ = "#cdd6f4"
        self.exe_entry.config(bg=HILIGHT if step==0 else "#313244", fg="#1e1e2e" if step==0 else FG_,
                              insertbackground="#1e1e2e" if step==0 else FG_)
        self.exe_browse_btn.config(bg=HILIGHT if step==0 else BTN, fg="#1e1e2e" if step==0 else FG_)
        self.launch_btn.config(bg=HILIGHT if step==1 else BTN, fg="#1e1e2e" if step==1 else FG_)
        self.cap_btn.config(bg=HILIGHT if step==3 else BTN, fg="#1e1e2e" if step==3 else FG_)

    def _wizard_next(self):
        self.wizard_done.add(self.wizard_step)
        if self.wizard_step < len(WIZARD_STEPS) - 1: self.wizard_step += 1
        self._wizard_update()

    def _wizard_back(self):
        if self.wizard_step > 0: self.wizard_step -= 1
        self._wizard_update()

    def _wizard_goto(self, idx):
        self.wizard_step = idx; self._wizard_update()

    def _reset_to_step2(self):
        """Reset detection state — back to 'Log In' step."""
        self.pos_addr = None; self.pos_candidates = []
        self._use_chain = False; self.module_base = None; self.wow_pid = None
        self._discovered_cc = None; self._discovered_guid = None; self._discovered_offsets = None
        self.wizard_step = 2
        for s in [2, 3]: self.wizard_done.discard(s)
        self._wizard_update()

    def _on_dungeon_select(self, _event=None):
        val = self._dungeon_var.get()
        m = re.search(r'\[(\d+)\]', val)
        if m: self.map_id.set(m.group(1))
        self.dungeon_combo.selection_clear()

    # ── treeview helpers ──────────────────────────────────────────────────────
    def _find_point(self, item):
        parent = self.tree.parent(item)
        for gi, g in enumerate(self.groups):
            if g["tree_id"] == parent:
                return gi, list(self.tree.get_children(parent)).index(item)
        return None, None

    def _set_go_command(self, text, warn_msg=""):
        self.go_entry.config(state="normal")
        self.go_entry.delete(0, "end"); self.go_entry.insert(0, text)
        self.go_entry.config(state="readonly")
        self.go_warn_label.config(text=warn_msg)

    def _on_tree_select(self, _event=None):
        sel = self.tree.selection()
        if not sel or "point" not in self.tree.item(sel[0], "tags"):
            self._set_go_command(""); return
        gi, pi = self._find_point(sel[0])
        if gi is None: return
        _, x, y, z, _, map_id = self.groups[gi]["points"][pi]
        cmd = f".go {x:.2f} {y:.2f} {z:.2f}"
        if map_id:
            self._set_go_command(f"{cmd} {map_id}")
        else:
            self._set_go_command(cmd, "no map ID set - command only works from within the dungeon")

    def _edit_row_event(self, event):
        item = self.tree.identify_row(event.y)
        if item and "point" in self.tree.item(item, "tags"): self._edit_row(item)

    def _edit_row(self, item):
        gi, pi = self._find_point(item)
        if gi is None: return
        lbl, cx, cy, cz, co, cmid = self.groups[gi]["points"][pi]
        BG, FG, ENTRY = "#1e1e2e", "#cdd6f4", "#313244"
        dlg = tk.Toplevel(self); dlg.title("Edit point"); dlg.resizable(False, False)
        dlg.attributes("-topmost", True); dlg.configure(bg=BG)
        fields = [("Label",str(lbl)),("X",f"{cx:.4f}"),("Y",f"{cy:.4f}"),
                  ("Z",f"{cz:.4f}"),("O (rad)",f"{co:.6f}"),("Map ID",str(cmid))]
        entries = []
        for ri, (name, val) in enumerate(fields):
            ttk.Label(dlg, text=f"{name}:").grid(row=ri, column=0, padx=8, pady=4, sticky="w")
            e = tk.Entry(dlg, width=26, bg=ENTRY, fg=FG, insertbackground=FG, font=("Consolas", 10), relief="flat")
            e.insert(0, val); e.grid(row=ri, column=1, padx=(0,8), pady=4); entries.append(e)
        entries[0].focus_set(); entries[0].select_range(0, "end")
        def _apply(*_):
            try:
                nl=entries[0].get().strip() or lbl; nx=float(entries[1].get()); ny=float(entries[2].get())
                nz=float(entries[3].get()); no=float(entries[4].get()); nm=entries[5].get().strip()
            except ValueError:
                messagebox.showerror("Invalid","X,Y,Z,O must be numbers.",parent=dlg); return
            self.groups[gi]["points"][pi] = (nl,nx,ny,nz,no,nm)
            ds = "---"
            if pi > 0:
                _,px,py_,pz,_,_ = self.groups[gi]["points"][pi-1]
                ds = f"{math.sqrt((nx-px)**2+(ny-py_)**2+(nz-pz)**2):.2f}"
            self.tree.item(item, text=nl, values=(f"{nx:.2f}",f"{ny:.2f}",f"{nz:.2f}",f"{math.degrees(no):.1f}deg",ds))
            dlg.destroy()
        for e in entries: e.bind("<Return>", _apply)
        ttk.Button(dlg, text="OK", command=_apply).grid(row=len(fields), column=0, columnspan=2, pady=(0,8))

    # ── connection ────────────────────────────────────────────────────────────
    def _detect_module_base(self, pid):
        base = get_module_base(pid, handle=self.handle)
        self.module_base = base
        if base is not None and base != STANDARD_IMAGE_BASE:
            delta = base - STANDARD_IMAGE_BASE
            if hasattr(self, '_set_status') and callable(self._set_status):
                self.after(0, self._set_status,
                           f"Module rebased: base=0x{base:08X} (delta=0x{abs(delta):X})", "#f9e2af")

    def _connect(self):
        proc_name = getattr(self, 'proc_entry', None)
        proc_name = proc_name.get().strip() if proc_name else WOW_PROCESS_NAME
        pid = find_wow_pid(proc_name)
        if pid is None:
            self._set_status("WoW not running - use Launch WoW to start it"); return
        handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            self._set_status(f"Found PID {pid} but OpenProcess failed - use Launch WoW instead"); return
        self.handle = handle; self.wow_pid = pid
        self._detect_module_base(pid)
        self._set_status(f"Attached to {proc_name}  (PID {pid})", fg="#a6e3a1")

    # ── polling loop ──────────────────────────────────────────────────────────
    def _read_best_pos(self):
        if not self.handle: return None
        if self._use_chain:
            pos = get_player_pos_pointer_chain(self.handle, self.module_base,
                                                self._discovered_cc, self._discovered_guid,
                                                self._discovered_offsets)
            if pos: return pos
        candidates = self.pos_candidates
        if len(candidates) <= 1:
            return get_player_pos(self.handle, self.pos_addr)
        readings = [(a, get_player_pos(self.handle, a)) for a in candidates]
        valid = [(a, p) for a, p in readings if p]
        if not valid: return None
        xs = [p[0] for _, p in valid]
        mean_x = sum(xs) / len(xs)
        outlier = next(((a, p) for a, p in valid if abs(p[0] - mean_x) > 0.05), None)
        if outlier:
            addr, pos = outlier
            self.pos_addr = addr; self.pos_candidates = [addr]
            self.after(0, self._set_status, f"Player locked @ 0x{addr:08X}", "#a6e3a1")
            def _adv_locked():
                for s in range(len(WIZARD_STEPS)):
                    self.wizard_done.add(s)
                self.wizard_step = len(WIZARD_STEPS) - 1
                self._wizard_update()
            self.after(0, _adv_locked)
            return pos
        return valid[0][1]

    def _poll_loop(self):
        warn_counter = 0
        chain_probe_counter = 0
        while self.running:
            if self.handle:
                # auto-probe: pointer chain then pattern scan
                if not self._use_chain and not self.pos_addr:
                    chain_probe_counter += 1
                    # Try pointer chain every ~1s (every 4th tick)
                    if chain_probe_counter % 4 == 1:
                        try:
                            if self.module_base is None and self.wow_pid:
                                self._detect_module_base(self.wow_pid)
                            pos = get_player_pos_pointer_chain(self.handle, self.module_base,
                                                    self._discovered_cc, self._discovered_guid,
                                                    self._discovered_offsets)
                        except Exception:
                            pos = None
                        if pos:
                            self._use_chain = True
                            self.after(0, self._set_status, "Pointer chain active", "#a6e3a1")
                            def _adv():
                                for s in range(len(WIZARD_STEPS)):
                                    self.wizard_done.add(s)
                                self.wizard_step = len(WIZARD_STEPS) - 1
                                self._wizard_update()
                            self.after(0, _adv)
                    # Pattern scan every ~5s (every 20th tick),
                    # starting after tick 12 (~3s grace for chain to try first).
                    # Keeps retrying until candidates found — handles slow logins.
                    if (not self._use_chain
                            and chain_probe_counter >= 12
                            and chain_probe_counter % 20 == 12):
                        self.after(0, self._set_status,
                                   "Scanning for movement structs...", "#f9e2af")
                        try:
                            result = scan_for_movement_struct(self.handle, pid=self.wow_pid)
                            if result:
                                addrs = result
                                n = len(addrs)
                                self.pos_candidates = addrs
                                self.pos_addr = addrs[0]
                                if n == 1:
                                    vx = read_f32(self.handle, addrs[0])
                                    vy = read_f32(self.handle, addrs[0] + 4)
                                    vz = read_f32(self.handle, addrs[0] + 8)
                                    self.after(0, self._set_status,
                                        f"Player found @ 0x{addrs[0]:08X} ({vx:.1f}, {vy:.1f}, {vz:.1f})",
                                        "#a6e3a1")
                                    def _adv_single():
                                        for s in range(len(WIZARD_STEPS)):
                                            self.wizard_done.add(s)
                                        self.wizard_step = len(WIZARD_STEPS) - 1
                                        self._wizard_update()
                                    self.after(0, _adv_single)
                                else:
                                    self.after(0, self._set_status,
                                        f"Found {n} structs — identifying player by rotation...",
                                        "#f9e2af")
                                    # Use rotation-based identification
                                    player_addr = identify_player_by_rotation(
                                        self.handle, self.wow_pid, addrs)
                                    if player_addr:
                                        self.pos_addr = player_addr
                                        self.pos_candidates = [player_addr]
                                        vx = read_f32(self.handle, player_addr)
                                        vy = read_f32(self.handle, player_addr + 4)
                                        vz = read_f32(self.handle, player_addr + 8)
                                        self.after(0, self._set_status,
                                            f"Player locked @ 0x{player_addr:08X} ({vx:.1f}, {vy:.1f}, {vz:.1f})",
                                            "#a6e3a1")
                                        def _adv_rotation():
                                            for s in range(len(WIZARD_STEPS)):
                                                self.wizard_done.add(s)
                                            self.wizard_step = len(WIZARD_STEPS) - 1
                                            self._wizard_update()
                                        self.after(0, _adv_rotation)
                                    else:
                                        # Rotation ID failed — fall back to move-to-lock
                                        self.after(0, self._set_status,
                                            f"Found {n} structs — walk a few steps to identify player",
                                            "#f9e2af")
                            else:
                                self.after(0, self._set_status,
                                    "No movement struct found — waiting for login...",
                                    "#f9e2af")
                        except Exception as e:
                            self.after(0, self._set_status,
                                f"Pattern scan error: {e}", "#f38ba8")
                pos = self._read_best_pos()
                if pos:
                    x, y, z, o = pos; self.last_pos = pos; warn_counter = 0
                    self.after(0, self._update_display, x, y, z, o)
                else:
                    warn_counter += 1
                    if warn_counter % 8 == 1:
                        if self._use_chain:
                            self.after(0, self._set_status, "Pointer chain lost - waiting for login...", "#f9e2af")
                        elif self.pos_addr:
                            self.after(0, self._set_status, "WoW exited? Rescan needed after restart.")
                            self.after(0, self._reset_to_step2)
                        else:
                            self.after(0, self._set_status,
                                       f"Waiting for login... (probe #{chain_probe_counter})", "#f9e2af")
            time.sleep(0.25)

    def _update_display(self, x, y, z, o):
        deg = math.degrees(o) % 360
        self.pos_label.config(text=f"X: {x:>10.2f}   Y: {y:>10.2f}   Z: {z:>8.2f}   O: {deg:>6.1f} deg")
        if abs(o) < 0.001 and self.pos_addr and not self._use_chain:
            _dump_count = getattr(self, '_movstruct_dump_count', 0)
            _dump_time = getattr(self, '_movstruct_dump_time', 0)
            # Dump up to 10 times, at least 5 seconds apart
            if _dump_count < 10 and (time.time() - _dump_time) > 5:
                self._movstruct_dump_count = _dump_count + 1
                self._movstruct_dump_time = time.time()
                self._set_status("O is 0.0 — dumping movement struct to scan_debug.log")
                move_ptr = self.pos_addr - MOVEMENT_POS_X_OFFSET
                raw = read_bytes(self.handle, move_ptr, 0x60)
                if raw and len(raw) >= 0x60:
                    _log(f"\n[MovStruct] base=0x{move_ptr:08X}  pos_addr=0x{self.pos_addr:08X}")
                    _log(f"[MovStruct] X={x:.2f} Y={y:.2f} Z={z:.2f}")
                    _log(f"[MovStruct] Looking for orientation (0.01 - 6.28 radians):")
                    for off in range(0, 0x60, 4):
                        val = struct.unpack_from('<f', raw, off)[0]
                        ival = struct.unpack_from('<I', raw, off)[0]
                        marker = ""
                        if off == 0x10: marker = " <-- X"
                        elif off == 0x14: marker = " <-- Y"
                        elif off == 0x18: marker = " <-- Z"
                        elif off == 0x1C: marker = " <-- O (expected)"
                        elif 0.01 < val < 6.29 and val != x and val != y and val != z:
                            marker = " <-- POSSIBLE ORIENTATION?"
                        _log(f"  +0x{off:02X}: float={val:>12.4f}  hex=0x{ival:08X}{marker}")

    # ── capture ───────────────────────────────────────────────────────────────
    def _capture(self):
        if not self.last_pos:
            messagebox.showwarning("No data", "No position data yet."); return
        x, y, z, o = self.last_pos
        total_pts = sum(len(g["points"]) for g in self.groups)
        label  = self.lbl_entry.get().strip() or f"point {total_pts + 1}"
        shape  = self.shape.get()
        map_id = self.map_id.get().strip()
        if not map_id:
            if not messagebox.askyesno("No Map ID", "Map ID is empty. Capture anyway?"): return
        if not self.groups or self.groups[-1]["shape"] != shape:
            gid = self.tree.insert("", "end", text=f"  {shape.title()}", values=("","","","",""),
                                   tags=("group",), open=True)
            self.groups.append({"shape": shape, "tree_id": gid, "points": []})
        g = self.groups[-1]
        dist_str = "---"
        if g["points"]:
            _, px, py, pz, _, _ = g["points"][-1]
            dist_str = f"{math.sqrt((x-px)**2+(y-py)**2+(z-pz)**2):.2f}"
        g["points"].append((label, x, y, z, o, map_id))
        self.tree.insert(g["tree_id"], "end", text=label,
                         values=(f"{x:.2f}", f"{y:.2f}", f"{z:.2f}", f"{math.degrees(o):.1f} deg", dist_str),
                         tags=("point",))
        m = re.match(r'^(.*?)(\d+)$', label)
        if m:
            self.lbl_entry.delete(0, "end")
            self.lbl_entry.insert(0, m.group(1) + str(int(m.group(2)) + 1))

    def _clear(self):
        if messagebox.askyesno("Clear", "Clear all captured points?"):
            self.groups.clear()
            for item in self.tree.get_children(): self.tree.delete(item)
            self._set_go_command("")

    # ── right-click menu ──────────────────────────────────────────────────────
    def _right_click(self, event):
        item = self.tree.identify_row(event.y)
        if not item: return
        tags = self.tree.item(item, "tags")
        menu = tk.Menu(self, tearoff=0)
        if "group" in tags:
            sm = tk.Menu(menu, tearoff=0)
            for s in SHAPE_POINTS:
                sm.add_command(label=s, command=lambda sh=s, it=item: self._change_group_shape(it, sh))
            menu.add_cascade(label="Change shape to", menu=sm)
            menu.add_separator()
            menu.add_command(label="Delete zone", command=lambda: self._delete_group(item))
        elif "point" in tags:
            menu.add_command(label="Edit point", command=lambda: self._edit_row(item))
            menu.add_command(label="Delete point", command=lambda: self._delete_row(item))
        menu.tk_popup(event.x_root, event.y_root)

    def _delete_row(self, item):
        gi, pi = self._find_point(item)
        if gi is None: return
        self.groups[gi]["points"].pop(pi); self.tree.delete(item)
        if not self.groups[gi]["points"]:
            self.tree.delete(self.groups[gi]["tree_id"]); self.groups.pop(gi)
        self._set_go_command("")

    def _delete_group(self, item):
        for gi, g in enumerate(self.groups):
            if g["tree_id"] == item:
                if messagebox.askyesno("Delete", f"Delete this {g['shape']} zone ({len(g['points'])} pt(s))?"):
                    self.tree.delete(item); self.groups.pop(gi); self._set_go_command("")
                return

    def _change_group_shape(self, item, new_shape):
        for gi, g in enumerate(self.groups):
            if g["tree_id"] != item: continue
            if new_shape == g["shape"]: return
            n_have, n_need = len(g["points"]), SHAPE_POINTS.get(new_shape)
            if n_need is not None and n_have > n_need:
                ans = messagebox.askyesnocancel("Too many points",
                    f"'{new_shape}' needs {n_need} pt(s) but you have {n_have}.\nYes=trim, No=delete zone")
                if ans is None: return
                if ans:
                    for ch in list(self.tree.get_children(item))[n_need:]: self.tree.delete(ch)
                    g["points"] = g["points"][:n_need]
                else:
                    self.tree.delete(item); self.groups.pop(gi); self._set_go_command(""); return
            g["shape"] = new_shape
            self.tree.item(item, text=f"  {new_shape.title()}")
            return

    # ── save ──────────────────────────────────────────────────────────────────
    def _save(self):
        if not any(g["points"] for g in self.groups):
            messagebox.showinfo("Nothing to save", "No points captured yet."); return
        path = self.file_entry.get().strip()
        lines = []
        for g in self.groups:
            if not g["points"]: continue
            lines.append(f"\n### Captured Zone ({g['shape']})\n")
            lines.append("| Point | X | Y | Z | Teleport command |\n")
            lines.append("|-------|---------|---------|-------|------------------|\n")
            for label, x, y, z, o, mid in g["points"]:
                cmd = f".go {x:.2f} {y:.2f} {z:.2f}"
                if mid: cmd += f" {mid}"
                lines.append(f"| {label} | {x:.2f} | {y:.2f} | {z:.2f} | `{cmd}` |\n")
        try:
            mode = "a" if os.path.exists(path) else "w"
            with open(path, mode, encoding="utf-8") as f: f.writelines(lines)
            messagebox.showinfo("Saved", f"{'Appended to' if mode=='a' else 'Created'}:\n{path}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    # ── memory scan ───────────────────────────────────────────────────────────
    def _scan(self):
        """Fallback: DB-based scan. Use when auto-detection (pattern scan + move) fails."""
        if not self.handle:
            self._set_status("No WoW handle — launch WoW first"); return
        # Try pointer chain first
        self._set_status("Trying pointer chain...", fg="#f9e2af"); self.update()
        pos = get_player_pos_pointer_chain(self.handle, self.module_base,
                                                self._discovered_cc, self._discovered_guid,
                                                self._discovered_offsets)
        if pos:
            self._use_chain = True
            x, y, z, o = pos
            self._set_status(f"Pointer chain active — X={x:.2f} Y={y:.2f} Z={z:.2f}", fg="#a6e3a1")
            for s in range(len(WIZARD_STEPS)): self.wizard_done.add(s)
            self.wizard_step = len(WIZARD_STEPS) - 1; self._wizard_update()
            return
        # Show diagnostic
        diag = diagnose_pointer_chain(self.handle, self.module_base)
        self._show_diagnostic("\n".join(diag))
        # DB scan fallback
        self._set_status("Pointer chain failed — trying DB scan...", fg="#f9e2af"); self.update()
        dbpos = query_db_position()
        if not dbpos:
            self._set_status("DB query failed — check MariaDB path / character name"); return
        tx, ty, tz, to_ = dbpos
        if abs(to_) < 0.15:
            self._set_status(f"Orientation in DB is {math.degrees(to_):.1f} deg (near zero) — re-orient and log out first")
            return
        self._set_status(f"DB scan: X={tx:.2f} Y={ty:.2f} Z={tz:.2f} O={to_:.4f}...", fg="#f9e2af")
        self.update()
        handle = self.handle
        def _do_scan():
            def prog(scanned):
                self.after(0, self._set_status, f"DB scan... {scanned//(1024*1024)} MB checked", "#f9e2af")
            hits = scan_for_xyzo(handle, tx, ty, tz, to_, tol=0.05, progress_cb=prog)
            if not hits:
                self.after(0, self._set_status, "No match — are you in-game? Did you move after logging in?"); return
            if len(hits) > 5:
                self.after(0, self._set_status, f"{len(hits)} matches — try tighter tolerance"); return
            self.pos_candidates = hits; self.pos_addr = hits[0]
            note = " — walk to lock" if len(hits) > 1 else ""
            self.after(0, self._set_status, f"DB scan: {len(hits)} candidate(s) at 0x{hits[0]:08X}{note}", "#a6e3a1")
            def _adv():
                for s in range(len(WIZARD_STEPS)): self.wizard_done.add(s)
                self.wizard_step = len(WIZARD_STEPS) - 1; self._wizard_update()
            self.after(0, _adv)
        threading.Thread(target=_do_scan, daemon=True).start()

    # ── launch WoW ────────────────────────────────────────────────────────────
    def _launch_wow(self):
        self._set_status("Launching WoW...", fg="#f9e2af"); self.update()
        if self.handle: kernel32.CloseHandle(self.handle); self.handle = None
        exe_path = self.exe_entry.get().strip()
        def _do_launch():
            h, pid = launch_wow_debug(exe_path)
            if not h:
                self.after(0, self._set_status, f"CreateProcess failed. Is WoW.exe at {exe_path}?"); return
            self.handle = h; self.wow_pid = pid
            time.sleep(0.5)
            self._detect_module_base(pid)
            self.after(0, self._set_status, f"WoW launched (PID {pid}) — log in, auto-detection will start", "#a6e3a1")
            def _adv():
                if self.wizard_step == 1:
                    self.wizard_done.add(1); self.wizard_step = 2; self._wizard_update()
            self.after(0, _adv)
        threading.Thread(target=_do_launch, daemon=True).start()

    def destroy(self):
        total_pts = sum(len(g["points"]) for g in self.groups)
        if total_pts:
            choice = messagebox.askyesnocancel("Save before exit",
                f"You have {total_pts} captured point(s). Save before closing?")
            if choice is None: return
            if choice: self._save()
        self.running = False
        if self.handle: kernel32.CloseHandle(self.handle); self.handle = None
        super().destroy()


if __name__ == "__main__":
    app = App()
    app.mainloop()
