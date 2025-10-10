# kiosk_launcher.py
# Python Kiosk Launcher for Win32 exe (Windows Pro)
# Dependencies: pywin32, psutil, keyboard
# Run as Administrator for best results
from LogLibrary import Load_Config, Loguru_Logging
import win32process
import subprocess
import threading
import keyboard
import win32con
import win32gui
import win32api
import psutil
import ctypes
import time
import os
import sys

# ---------------- App Config ----------------
Program_Name = "Kiosk_Launcher"
Program_Version = "1.3"

default_config = {
    "EXE_Path":"",
    "Restart_Delay":2,
    "Watch_Interval":1.0,
    "log_Level": "DEBUG",
    "Log_Console": 1,
    "log_Backup": 90,
    "Log_Size": "100 MB"
}

config = Load_Config(default_config, Program_Name)
logger = Loguru_Logging(config, Program_Name, Program_Version)

"""
===============================================================================
Kiosk Launcher v1.3 — Logging & Flow Overview
===============================================================================
วัตถุประสงค์:
- รันโปรแกรมเป้าหมาย (EXE) แบบคีออสค์, ทำให้เต็มจอ/บนสุด, ป้องกันคีย์ลัดออกนอกระบบ
- เฝ้ากระบวนการ หากล้มเหลวให้สตาร์ตใหม่อัตโนมัติ
- รองรับปุ่มฉุกเฉินเพื่อปิดคีออสค์และปิดโปรแกรมเป้าหมายทั้งหมดอย่างปลอดภัย
- อนุญาตให้ป็อปอัป/ไดอะล็อกของโปรแกรมใช้งานได้ตามปกติ
- รองรับ Numpad โดยบังคับเปิด NumLock และ whitelist ปุ่ม Numpad

การทำงานของระบบ Log (อาศัย LogLibrary.Loguru_Logging):
- คอนฟิกผ่านไฟล์ (โหลดด้วย Load_Config) โดยคีย์สำคัญใน default_config:
  - log_Level: ระดับล็อก (เช่น DEBUG/INFO/WARNING/ERROR)
  - Log_Console: แสดงบนคอนโซล (1=เปิด, 0=ปิด)
  - log_Backup: จำนวนวันเก็บรักษา (retention)
  - Log_Size: ขนาดไฟล์สูงสุดก่อนหมุนเวียน (rotation) เช่น "100 MB"
- ตัว logger ที่สร้างจาก Loguru_Logging จะเซ็ต sink สำหรับไฟล์/คอนโซลให้เองตาม config
- ข้อความล็อกที่สำคัญ:
  - INFO: เหตุการณ์ปกติของวงจรชีวิต เช่น เริ่ม/หยุด, เริ่มโปรเซส, รีสตาร์ต, fullscreen สำเร็จ
  - DEBUG: ระดับละเอียด ใช้ติดตามสถานะ foreground, การ hook คีย์, บังคับ NumLock, รายละเอียด refocus
  - WARNING: เหตุการณ์ที่อาจกระทบการทำงาน เช่น ไม่ได้รันเป็น Administrator, บังคับ kill กระบวนการ
  - ERROR: ความผิดพลาดเช่น เปิด EXE ไม่ได้, หา window ไม่เจอภายในเวลาที่กำหนด, set window style ล้มเหลว

ตำแหน่งสำคัญที่มีการล็อก:
- start_target(): บันทึกการเริ่มโปรเซส (pid), กรณียกระดับสิทธิ (runas) และความล้มเหลว
- make_window_fullscreen(): รายงานผลการตั้งค่าสไตล์/ขนาด/ลำดับหน้าต่าง
- block_hotkeys_when_target_active(): รายงานการลง hook และกุญแจที่บล็อก
- monitor_loop(): รายงานเมื่อสลับโฟกัส, เมื่อโปรเซสล้ม/รีสตาร์ต, และสถานะค้นหา hwnd
- terminate_target(): รายงานขั้นตอนปิดโปรแกรม (WM_CLOSE -> terminate tree -> kill)
- emergency_stop_listener(): รายงานการกดปุ่มฉุกเฉินและการคืนสภาพหน้าต่าง

ทิศทางการไล่ปัญหา (ดูที่ระดับ DEBUG ก่อน):
1) ตรวจว่าเริ่มโปรเซสและ pid ถูกต้อง ("Started pid=...")
2) ตรวจการหา hwnd และการทำ fullscreen ("Window set to fullscreen ...")
3) ดู hook คีย์/whitelist ("Key hooks registered ...")
4) กรณี popup ไม่ขึ้น ให้ดู fg_pid เทียบ _target_pid ในบล็อก refocus
5) กรณีปิดไม่สนิท ให้ดูลอกรอบ terminate_target()

"""

# ---------- CONFIG ----------
EXE_PATH = config.get('EXE_Path', '').strip()
if not EXE_PATH or not os.path.isfile(EXE_PATH):
    logger.error(f"EXE_Path not set or invalid in config: '{EXE_PATH}'")
    sys.exit(1)
RESTART_DELAY = float(config.get('Restart_Delay', 2))   # seconds to wait before restarting target
WATCH_INTERVAL = float(config.get('Watch_Interval', 1.0))  # how often to check process/window (seconds)
EMERGENCY_HOTKEY = "ctrl+alt+q"  # hotkey to stop kiosk launcher
# ----------------------------

# Globals
_target_proc = None
_target_pid = None
_target_hwnd = None
_running = True
_altf4_handler = None

# --- Process termination helper ---
def terminate_target(grace_seconds: float = 3.0):
    """Gracefully close target app then force kill if needed.
    - Try WM_CLOSE on the main window (if any)
    - Then psutil.terminate() (and children)
    - Finally kill if still alive
    """
    global _target_proc, _target_pid, _target_hwnd
    try:
        # Step 1: Ask window to close
        if _target_hwnd and win32gui.IsWindow(_target_hwnd):
            try:
                logger.info("[kiosk] Sending WM_CLOSE to target window")
                win32gui.PostMessage(_target_hwnd, win32con.WM_CLOSE, 0, 0)
            except Exception as e:
                logger.debug(f"[kiosk] WM_CLOSE failed: {e}")
        # Wait a bit for graceful shutdown
        end = time.time() + max(0.5, grace_seconds)
        while time.time() < end:
            try:
                if _target_pid is None:
                    break
                p = psutil.Process(_target_pid)
                if not p.is_running() or p.status() == psutil.STATUS_ZOMBIE:
                    break
            except psutil.Error:
                break
            time.sleep(0.2)
        # Step 2: terminate process tree
        if _target_pid is not None:
            try:
                p = psutil.Process(_target_pid)
                if p.is_running():
                    logger.info("[kiosk] Terminating target process tree")
                    # children first
                    for c in p.children(recursive=True):
                        try:
                            c.terminate()
                        except psutil.Error:
                            pass
                    p.terminate()
                    gone, alive = psutil.wait_procs([p], timeout=2.5)
                    # Step 3: kill if still alive
                    if alive:
                        logger.warning("[kiosk] Forcing kill of target process")
                        for a in alive:
                            try:
                                a.kill()
                            except psutil.Error:
                                pass
            except psutil.Error:
                pass
    finally:
        _target_proc = None
        _target_pid = None
        _target_hwnd = None

# --- Numpad/NumLock helpers ---
NUMPAD_NAMES = {
    'num 0','num 1','num 2','num 3','num 4','num 5','num 6','num 7','num 8','num 9',
    'decimal','divide','multiply','subtract','add','enter'
}
VK_NUMLOCK = 0x90

def ensure_numlock_on():
    """Force Num Lock on (toggle if currently off)."""
    try:
        if (win32api.GetKeyState(VK_NUMLOCK) & 1) == 0:
            win32api.keybd_event(VK_NUMLOCK, 0, 0, 0)
            win32api.keybd_event(VK_NUMLOCK, 0, win32con.KEYEVENTF_KEYUP, 0)
            logger.debug("[kiosk] NumLock forced ON")
    except Exception as e:
        logger.debug(f"[kiosk] ensure_numlock_on failed: {e}")

# ---------- Helper: admin check ----------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# ---------- Start target (with elevation fallback) ----------
def _start_target_elevated_shell():
    """Open EXE with UAC prompt (runas)."""
    workdir = os.path.dirname(EXE_PATH) or None
    hinst = win32api.ShellExecute(
        0, "runas", EXE_PATH, None, workdir, win32con.SW_SHOWNORMAL
    )
    if int(hinst) <= 32:
        raise RuntimeError(f"ShellExecute failed: {hinst}")

    # detect pid within a short window
    exe_norm = os.path.normcase(os.path.abspath(EXE_PATH))
    deadline = time.time() + 10
    pid = None
    while time.time() < deadline and pid is None:
        for p in psutil.process_iter(['pid', 'exe']):
            try:
                p_exe = p.info.get('exe')
                if p_exe and os.path.normcase(p_exe) == exe_norm:
                    pid = p.info['pid']
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        if pid is None:
            time.sleep(0.2)
    return pid

def start_target():
    """Start target EXE. If not admin, fallback to ShellExecute('runas')."""
    global _target_proc, _target_pid
    logger.info(f"[kiosk] Starting target exe: {EXE_PATH}")

    try:
        if is_admin():
            # launcher already elevated -> normal Popen is fine
            p = subprocess.Popen([EXE_PATH], cwd=os.path.dirname(EXE_PATH) or None)
            _target_proc = p
            _target_pid = p.pid
            logger.info(f"[kiosk] Started pid={_target_pid}")
            return p
        else:
            # not admin -> try runas (UAC prompt will appear)
            pid = _start_target_elevated_shell()
            if not pid:
                logger.error("[kiosk] Could not detect target PID after elevation.")
                return None
            _target_pid = pid

            class PseudoProc:
                def poll(self):
                    try:
                        pr = psutil.Process(_target_pid)
                        return None if pr.is_running() and pr.status() != psutil.STATUS_ZOMBIE else 0
                    except psutil.Error:
                        return 0
                def terminate(self):
                    try:
                        psutil.Process(_target_pid).terminate()
                    except psutil.Error:
                        pass

            _target_proc = PseudoProc()
            logger.info(f"[kiosk] Started (elevated) pid={_target_pid}")
            return _target_proc
    except Exception as e:
        logger.error(f"[kiosk] Failed to start target: {e}")
        return None

# ---------- Window discovery ----------
def find_hwnd_by_pid(pid, timeout=8.0):
    """Find first top-level window that belongs to pid."""
    end = time.time() + timeout
    hwnd_found = None

    def callback(hwnd, extra):
        nonlocal hwnd_found
        if hwnd_found:
            return True
        if not win32gui.IsWindowVisible(hwnd):
            return True
        try:
            _, procid = win32process.GetWindowThreadProcessId(hwnd)
            if procid == pid:
                hwnd_found = hwnd
                return False
        except Exception:
            pass
        return True

    while time.time() < end and hwnd_found is None:
        try:
            win32gui.EnumWindows(callback, None)
        except Exception:
            pass
        if hwnd_found:
            break
        time.sleep(0.2)
    return hwnd_found

# ---------- Fullscreen + TopMost ----------
def make_window_fullscreen(hwnd):
    """Borderless fullscreen + TOPMOST on primary monitor."""
    if not hwnd or not win32gui.IsWindow(hwnd):
        return False
    try:
        style = win32gui.GetWindowLong(hwnd, win32con.GWL_STYLE)
        new_style = style & ~(win32con.WS_CAPTION | win32con.WS_SYSMENU | win32con.WS_THICKFRAME |
                              win32con.WS_MINIMIZEBOX | win32con.WS_MAXIMIZEBOX)
        win32gui.SetWindowLong(hwnd, win32con.GWL_STYLE, new_style)
    except Exception as e:
        logger.error(f"[kiosk] SetWindowLong failed: {e}")

    try:
        screen_w = win32api.GetSystemMetrics(win32con.SM_CXSCREEN)
        screen_h = win32api.GetSystemMetrics(win32con.SM_CYSCREEN)
        # TOPMOST to resist Win+D / focus steal
        win32gui.SetWindowPos(
            hwnd,
            win32con.HWND_TOPMOST,
            0, 0, screen_w, screen_h,
            win32con.SWP_FRAMECHANGED | win32con.SWP_SHOWWINDOW
        )
        try:
            win32gui.SetForegroundWindow(hwnd)
        except Exception:
            pass

        # Ensure NumLock ON whenever we claim focus/fullscreen
        ensure_numlock_on()

        logger.info(f"[kiosk] Window set to fullscreen (topmost): hwnd={hwnd}")
        return True
    except Exception as e:
        logger.error(f"[kiosk] SetWindowPos failed: {e}")
        return False

def restore_window_style(hwnd):
    try:
        style = win32gui.GetWindowLong(hwnd, win32con.GWL_STYLE)
        new_style = style | win32con.WS_CAPTION | win32con.WS_SYSMENU
        win32gui.SetWindowLong(hwnd, win32con.GWL_STYLE, new_style)
        win32gui.SetWindowPos(hwnd, win32con.HWND_TOP, 50, 50, 800, 600,
                              win32con.SWP_FRAMECHANGED | win32con.SWP_SHOWWINDOW)
    except Exception as e:
        logger.debug(f"[kiosk] restore_window_style failed: {e}")

# ---------- Key blocking ----------
# Helpers for foreground/PID

def _get_pid_of_hwnd(hwnd):
    try:
        if not hwnd:
            return None
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        return pid
    except Exception:
        return None


def block_hotkeys_when_target_active():
    """Block Alt+F4, Ctrl+W, Windows keys, Ctrl+Esc; best-effort Alt+Tab when target focused."""
    logger.debug("[kiosk] Hotkey blocker started.")

    # Block specific Windows keys (avoid generic 'windows')
    for k in ('left windows', 'right windows', 'apps'):
        try:
            keyboard.block_key(k)
            logger.debug(f"[kiosk] Hard-blocked key: {k}")
        except Exception as e:
            logger.warning(f"[kiosk] Cannot hard-block {k}: {e}")

    # low-level listener with conditional suppression when any target-owned window is foreground
    def low_level_listener(e):
        try:
            name = (e.name or '').lower()
            if e.event_type != 'down':
                return True

            # --- Whitelist Numpad: always allow ---
            if name in NUMPAD_NAMES:
                return True

            active_ok = False
            try:
                fg = win32gui.GetForegroundWindow()
                active_ok = (_get_pid_of_hwnd(fg) == _target_pid)
            except Exception:
                active_ok = False

            # Alt+F4
            if name == 'f4' and keyboard.is_pressed('alt') and active_ok:
                logger.debug("[kiosk] Suppressing Alt+F4")
                return False

            # Ctrl+W / Cmd+W
            if name == 'w' and (keyboard.is_pressed('ctrl') or keyboard.is_pressed('command')) and active_ok:
                logger.debug("[kiosk] Suppressing Ctrl+W")
                return False

            # Ctrl+Esc (Start menu)
            if name == 'esc' and keyboard.is_pressed('ctrl'):
                logger.debug("[kiosk] Suppressing Ctrl+Esc")
                return False

            # Best-effort: Alt+Tab (not guaranteed)
            if name == 'tab' and keyboard.is_pressed('alt') and active_ok:
                logger.debug("[kiosk] Attempting to suppress Alt+Tab")
                return False

            # Win+ combos — rely on left/right windows pressed
            if name in ('d','e','x','r','tab') and (
                keyboard.is_pressed('left windows') or keyboard.is_pressed('right windows')
            ):
                logger.debug("[kiosk] Suppressing Win+ combo")
                return False

            # Ctrl+Alt+Del is SAS -> cannot be reliably blocked (log only)
            if name == 'delete' and keyboard.is_pressed('ctrl') and keyboard.is_pressed('alt'):
                logger.debug("[kiosk] CAD detected (cannot block in user-mode)")
                return True

        except Exception:
            pass
        return True

    keyboard.hook(low_level_listener)
    logger.debug("[kiosk] Key hooks registered (Alt+F4/Ctrl+W/Win/Ctrl+Esc; with Numpad whitelist).")

# ---------- Emergency exit ----------
def emergency_stop_listener():
    """Emergency hotkey to quit kiosk launcher and restore styles and close target."""
    def on_emergency():
        global _running
        logger.warning("[kiosk] Emergency hotkey pressed. Stopping kiosk launcher...")
        _running = False
        try:
            if _target_hwnd:
                try:
                    restore_window_style(_target_hwnd)
                except Exception:
                    pass
            # Close target immediately (graceful then force)
            terminate_target(grace_seconds=3.0)
        finally:
            keyboard.unhook_all()
    keyboard.add_hotkey(EMERGENCY_HOTKEY, on_emergency)
    logger.info(f"[kiosk] Emergency hotkey registered: {EMERGENCY_HOTKEY}")

# ---------- Monitor loop ----------
def monitor_loop():
    global _target_proc, _target_pid, _target_hwnd, _running, _altf4_handler

    block_hotkeys_when_target_active()
    emergency_stop_listener()

    while _running:
        if _target_proc is None or (_target_proc and _target_proc.poll() is not None):
            p = start_target()
            if p is None:
                logger.error("[kiosk] Could not start target. Retrying in 5 seconds.")
                time.sleep(5)
                continue

            # wait then find main window
            time.sleep(0.7)
            hwnd = find_hwnd_by_pid(_target_pid, timeout=8.0)
            _target_hwnd = hwnd
            if hwnd:
                make_window_fullscreen(hwnd)
            else:
                logger.warning(f"[kiosk] could not find window for pid={_target_pid}")
        else:
            # keep window on top & focused
            if _target_hwnd and win32gui.IsWindow(_target_hwnd):
                try:
                    fg = win32gui.GetForegroundWindow()
                    fg_pid = _get_pid_of_hwnd(fg)

                    if fg_pid == _target_pid:
                        # A popup/dialog from the same target app is in front -> allow it.
                        if fg and fg != _target_hwnd and win32gui.IsWindow(fg):
                            # Make sure the dialog stays above the main window.
                            try:
                                win32gui.SetWindowPos(_target_hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0,
                                                      win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_NOACTIVATE)
                            except Exception:
                                pass
                            try:
                                win32gui.SetWindowPos(fg, win32con.HWND_TOPMOST, 0, 0, 0, 0,
                                                      win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW)
                            except Exception:
                                pass
                            ensure_numlock_on()
                        # Do nothing else; let the app handle its own popups.
                    else:
                        # Foreground belongs to another process -> pull our app back.
                        try:
                            # Reassert main as topmost and refocus
                            win32gui.SetWindowPos(
                                _target_hwnd, win32con.HWND_TOPMOST,
                                0, 0, 0, 0,
                                win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW
                            )
                        except Exception:
                            pass
                        try:
                            win32gui.SetForegroundWindow(_target_hwnd)
                            ensure_numlock_on()
                        except Exception:
                            pass
                        logger.debug("[kiosk] Re-topmost & refocused target")
                except Exception as e:
                    logger.debug(f"[kiosk] Foreground check failed: {e}")
                except Exception as e:
                    logger.debug(f"[kiosk] Foreground check failed: {e}")
            else:
                # try to locate window again
                try:
                    hwnd = find_hwnd_by_pid(_target_pid, timeout=1.0)
                    _target_hwnd = hwnd
                    if hwnd:
                        make_window_fullscreen(hwnd)
                    else:
                        logger.debug(f"[kiosk] still could not find hwnd for pid={_target_pid}")
                except Exception as e:
                    logger.debug(f"[kiosk] find_hwnd_by_pid error: {e}")

        # liveness
        if _target_proc:
            if _target_proc.poll() is not None:
                logger.info(f"[kiosk] Target process exited. Restarting in {RESTART_DELAY} s")
                _target_proc = None
                _target_pid = None
                _target_hwnd = None
                time.sleep(RESTART_DELAY)
            else:
                time.sleep(WATCH_INTERVAL)
        else:
            time.sleep(WATCH_INTERVAL)

    # cleanup
    logger.info("[kiosk] Exiting monitor loop. Cleaning up.")
    try:
        keyboard.unhook_all()
    except Exception:
        pass
    # Ensure target is closed when kiosk stops
    try:
        terminate_target(grace_seconds=2.0)
    except Exception:
        pass
    if _target_proc and _target_proc.poll() is None:
        try:
            _target_proc.terminate()
        except Exception:
            pass

def ensure_admin_and_warn():
    if not is_admin():
        logger.warning("[kiosk] Warning: Not running as Administrator. Some features may not work (key hooks/topmost).")

if __name__ == "__main__":
    logger.info("[kiosk] Launcher starting...")
    ensure_admin_and_warn()
    ensure_numlock_on()  # turn on NumLock at startup
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    try:
        while _running:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("[kiosk] KeyboardInterrupt received, exiting.")
        _running = False
        # Immediately close target on Ctrl+C exit path
        try:
            terminate_target(grace_seconds=2.0)
        except Exception:
            pass
    logger.info("[kiosk] Done.")
