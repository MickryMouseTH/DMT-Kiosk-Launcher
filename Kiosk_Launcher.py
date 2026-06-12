# kiosk_launcher.py
# Python Kiosk Launcher for Win32 exe (Windows Pro)
# Dependencies: pywin32, psutil, keyboard, tkinter
# Run as Administrator for best results
#
# Exit password (no encryption key needed):
#   Type your password in PLAIN TEXT in the config field "EXIT_Password".
#   On the next launch it is auto-converted to a salted PBKDF2 hash and the
#   plaintext is overwritten in the file.

import subprocess
import time
import os
import sys
import threading
import hashlib
import hmac
import base64
import psutil
import keyboard
import tkinter as tk
import win32con
import win32gui
import win32process
import win32api
import ctypes
from LogLibrary import Load_Config, Loguru_Logging, Save_Config

# ---------- Password hashing (one-way, no key stored in source) ----------
PBKDF2_ALGO = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 200_000

def hash_password(plain, iterations=PBKDF2_ITERATIONS, salt=None):
    """Return a self-describing salted hash: 'pbkdf2_sha256$iters$salt_b64$hash_b64'."""
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, iterations)
    return "{}${}${}${}".format(
        PBKDF2_ALGO,
        iterations,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )

def verify_password(plain, stored):
    """Constant-time check of a plaintext attempt against a stored hash string."""
    try:
        algo, iter_s, salt_b64, hash_b64 = stored.split("$")
        if algo != PBKDF2_ALGO:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode("utf-8"), salt, int(iter_s))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

# ---------------- App Config ----------------
Program_Name = "Kiosk_Launcher"
Program_Version = "2.0"

default_config = {
    "EXE_Path": "",
    "Restart_Delay": 2,
    # Type your password here in PLAIN TEXT. On the next run the launcher
    # auto-converts it to a salted one-way hash and rewrites this field.
    "EXIT_Password": "",
    "Watch_Interval": 1.0,
    "log_Level": "DEBUG",
    "Log_Console": 1,
    "log_Backup": 90,
    "Log_Size": "100 MB",
}

# Assuming Load_Config and Loguru_Logging can resolve script_dir internally or use CWD if frozen
config = Load_Config(default_config, Program_Name)
logger = Loguru_Logging(config, Program_Name, Program_Version)


# ---------- Resolve EXIT password (plaintext -> hash auto-migration) ----------
def _is_hashed(value):
    return isinstance(value, str) and value.startswith(PBKDF2_ALGO + "$")

def resolve_exit_password_hash(cfg):
    """Read EXIT_Password from config. If the operator typed a plaintext
    password, hash it (salted) and persist it back so the plaintext is never
    stored at rest. Returns the stored hash string (or '' if unset)."""
    stored = (cfg.get("EXIT_Password", "") or "").strip()
    if not stored:
        logger.critical("[kiosk] EXIT_Password is empty. Set it in the config "
                        "(plain text is fine — it will be hashed automatically). "
                        "Emergency exit is DISABLED until then.")
        return ""
    if _is_hashed(stored):
        return stored  # already migrated
    # Plaintext provided -> convert to salted hash and write back to config.
    hashed = hash_password(stored)
    cfg["EXIT_Password"] = hashed
    try:
        Save_Config(cfg, Program_Name)
        logger.warning("[kiosk] Plaintext EXIT_Password detected -> converted to "
                       "a salted hash and saved back to config.")
    except Exception as e:
        logger.error(f"[kiosk] Could not persist hashed EXIT_Password: {e}. "
                     f"Using the hash in-memory for this session only.")
    return hashed

# ---------- CONFIG ----------
EMERGENCY_HOTKEY = "ctrl+alt+q"
EXIT_PASSWORD_HASH = resolve_exit_password_hash(config)

EXE_PATH = config.get('EXE_Path', '').strip()
if not EXE_PATH or not os.path.isfile(EXE_PATH):
    logger.error(f"EXE_Path not set or invalid in config: '{EXE_PATH}'")
    sys.exit(1)
RESTART_DELAY = float(config.get('Restart_Delay', 2))
WATCH_INTERVAL = float(config.get('Watch_Interval', 1.0))
# ----------------------------

# Globals
_target_proc = None
_target_pid = None
_target_hwnd = None
_running = True
_monitor_paused = False
_original_target_topmost = False

# Synchronization for shared state accessed by monitor thread + main thread (M3)
_state_lock = threading.RLock()
# Emergency-exit coordination: keyboard thread signals, MAIN thread runs Tk (M4)
_emergency_request = threading.Event()
_dialog_open = False  # re-entrancy guard for the password dialog (H2)

# --- Process termination helper ---
def terminate_target(grace_seconds: float = 3.0):
    """Gracefully close target app then force kill if needed."""
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
        with _state_lock:
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

# ---------- Helper: admin check & auto-elevation ----------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def ensure_admin_and_elevate():
    """Checks if the script is running as admin and attempts to elevate if not."""
    if is_admin():
        return True
    
    # Not admin, attempt to elevate itself
    try:
        # Get the path to the current script/executable
        script = os.path.abspath(sys.argv[0])
        # Quote args so paths/values containing spaces survive relaunch (L4)
        params = subprocess.list2cmdline(sys.argv[1:])
        
        # 'runas' verb triggers UAC prompt
        hinst = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", script, params, None, win32con.SW_SHOWNORMAL
        )
        
        if hinst <= 32:
            logger.error(f"[kiosk] ShellExecuteW failed to elevate (Code: {hinst}). Cannot continue without Admin rights.")
            return False
        
        # Exit the current non-elevated instance
        logger.warning("[kiosk] Relaunching as Administrator. Exiting non-elevated instance.")
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"[kiosk] Failed to execute self for elevation: {e}")
        return False

# ---------- Start target (with elevation fallback) ----------
def _start_target_elevated_shell():
    # This remains as the logic for running the *target* app elevated if needed
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
            with _state_lock:
                _target_proc = p
                _target_pid = p.pid
            logger.info(f"[kiosk] Started pid={_target_pid}")
            return p
        else:
            # This 'else' path is theoretically unreachable now but kept as a safeguard.
            pid = _start_target_elevated_shell()
            if not pid:
                logger.error("[kiosk] Could not detect target PID after elevation.")
                return None

            class PseudoProc:
                def poll(self):
                    # Return None while running, exit-code (0) once gone (M1).
                    try:
                        pr = psutil.Process(_target_pid)
                        if pr.is_running() and pr.status() != psutil.STATUS_ZOMBIE:
                            return None
                        return 0
                    except psutil.Error:
                        return 0
                def terminate(self):
                    try:
                        psutil.Process(_target_pid).terminate()
                    except psutil.Error:
                        pass

            with _state_lock:
                _target_pid = pid  # M2: was never assigned before
                _target_proc = PseudoProc()
            logger.info(f"[kiosk] Started (elevated) pid={_target_pid}")
            return _target_proc
    except Exception as e:
        logger.error(f"[kiosk] Failed to start target: {e}")
        return None

# ---------- Window discovery and manipulation (unchanged) ----------
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

def make_window_fullscreen(hwnd):
    """Borderless fullscreen + TOPMOST on primary monitor."""
    if not hwnd or not win32gui.IsWindow(hwnd):
        return False
    try:
        style = win32gui.GetWindowLong(hwnd, win32con.GWL_STYLE)
        new_style = style & ~(win32con.WS_CAPTION | win32con.WS_SYSMENU | win32con.WS_THICKFRAME | win32con.WS_MINIMIZEBOX | win32con.WS_MAXIMIZEBOX)
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
        win32gui.SetWindowPos(hwnd, win32con.HWND_TOP, 50, 50, 800, 600,win32con.SWP_FRAMECHANGED | win32con.SWP_SHOWWINDOW)
    except Exception as e:
        logger.debug(f"[kiosk] restore_window_style failed: {e}")

# ---------- Key blocking (Fixed Input) ----------
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
        global _monitor_paused # <<<--- Access global state
        
        # *** FIX: If paused (password screen is active), allow all keyboard input ***
        if _monitor_paused:
            return True
        # **************************************************************************

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

    # suppress=True is REQUIRED: only "blocking" hooks can filter events.
    # With the default (suppress=False) the callback's return value is ignored
    # and none of the combos above would actually be blocked (V1).
    keyboard.hook(low_level_listener, suppress=True)
    logger.debug("[kiosk] Key hooks registered (Alt+F4/Ctrl+W/Win/Ctrl+Esc; with Numpad whitelist).")

# ---------- Emergency exit (Fixed Input & Submit Logic) ----------
# ----------------------------------------------------
# Custom Fullscreen Dialog Function (runs on the MAIN thread — M4)
# ----------------------------------------------------
def show_fullscreen_password_dialog():
    # 1. Setup Tkinter Root
    root = tk.Tk()
    root.withdraw()

    # 2. Fullscreen top-level dialog
    dialog = tk.Toplevel(root)
    dialog.title("Kiosk Exit")
    dialog.attributes("-fullscreen", True)
    dialog.attributes("-topmost", True)
    dialog.overrideredirect(True)

    def disable_close():
        logger.debug("[kiosk] Alt+F4 or window close attempted, blocked.")
        dialog.attributes("-topmost", True)
        # intentionally not calling focus_force repeatedly

    dialog.protocol("WM_DELETE_WINDOW", disable_close)

    # Dialog state
    input_attempt = None

    # Center frame
    center_frame = tk.Frame(dialog, bg="#333333")
    center_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

    tk.Label(
        center_frame,
        text="ENTER KIOSK EXIT PASSWORD",
        font=("Arial", 20, "bold"),
        fg="white",
        bg="#333333",
        pady=10,
    ).pack()

    error_label = tk.Label(center_frame, text="", font=("Arial", 12), fg="red", bg="#333333", pady=5)
    error_label.pack()

    # If no password is configured, warn the operator on-screen (H3)
    if not EXIT_PASSWORD_HASH:
        error_label.config(text="EXIT password not set. Configure EXIT_Password first.")

    password_var = tk.StringVar()
    password_entry = tk.Entry(center_frame, show="*", width=30, font=("Arial", 16), textvariable=password_var)
    password_entry.pack(pady=10)
    password_entry.focus_set()

    submit_button = tk.Button(
        center_frame,
        text="Submit",
        command=None,
        font=("Arial", 14),
        width=10,
        bg="#5cb85c",
        fg="white",
        state=tk.DISABLED,
    )
    submit_button.pack(pady=10)

    def check_input_and_set_button(*_):
        submit_button.config(state=tk.NORMAL if password_var.get() else tk.DISABLED)

    password_var.trace_add("write", check_input_and_set_button)

    def close_dialog():
        # Cancel the pending refocus job, then destroy the ROOT so mainloop()
        # actually returns. Destroying only the Toplevel leaves the withdrawn
        # root alive and mainloop() would hang forever (H1).
        if hasattr(dialog, "_refocus_job"):
            try:
                root.after_cancel(dialog._refocus_job)
            except Exception:
                pass
        root.destroy()

    def submit_password():
        nonlocal input_attempt
        current_password = password_var.get()
        # Verify against the stored salted hash (constant-time). A blank/unset
        # config hash can never match.
        if EXIT_PASSWORD_HASH and verify_password(current_password, EXIT_PASSWORD_HASH):
            input_attempt = current_password
            close_dialog()
        else:
            error_label.config(text="Invalid Password. Please try again.")
            password_entry.delete(0, tk.END)
            password_entry.focus_set()
            submit_button.config(state=tk.DISABLED)
            logger.warning("[kiosk] Failed exit attempt: Invalid password entered in dialog.")

    submit_button.config(command=submit_password)
    password_entry.bind("<Return>", lambda _e: submit_password())

    def cancel_dialog(_e=None):
        # Allow staff to dismiss an accidentally opened dialog and return to
        # kiosk mode without knowing the password (V2). Returning None means
        # "no exit" — the kiosk keeps running.
        nonlocal input_attempt
        input_attempt = None
        logger.info("[kiosk] Password dialog cancelled; returning to kiosk mode.")
        close_dialog()

    tk.Button(
        center_frame,
        text="Cancel",
        command=cancel_dialog,
        font=("Arial", 14),
        width=10,
        bg="#d9534f",
        fg="white",
    ).pack(pady=5)
    dialog.bind("<Escape>", cancel_dialog)

    def continuous_lift():
        if dialog.winfo_exists():
            dialog.lift()
            dialog.attributes("-topmost", True)
            dialog._refocus_job = root.after(100, continuous_lift)

    dialog._refocus_job = root.after(100, continuous_lift)
    root.mainloop()
    return input_attempt


def handle_emergency():
    """Run the password dialog and act on the result. MUST run on the main thread."""
    global _running, _monitor_paused, _target_hwnd, _original_target_topmost, _dialog_open

    if _dialog_open:
        return  # re-entrancy guard (H2)
    _dialog_open = True

    _monitor_paused = True  # pause monitor + let keyboard hook pass input through
    logger.debug("[kiosk] Monitor loop paused for password dialog.")

    accepted = False
    try:
        # 1. Remember and temporarily drop the target window's TOPMOST state
        if _target_hwnd and win32gui.IsWindow(_target_hwnd):
            try:
                ex_style = win32gui.GetWindowLong(_target_hwnd, win32con.GWL_EXSTYLE)
                _original_target_topmost = bool(ex_style & win32con.WS_EX_TOPMOST)
                win32gui.SetWindowPos(_target_hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_NOACTIVATE)
                logger.debug("[kiosk] Target window set to NOTOPMOST temporarily.")
            except Exception as e:
                logger.debug(f"[kiosk] Failed to set window to NOTOPMOST: {e}")

        # 2. Show the fullscreen password dialog (blocks until closed)
        password_attempt = show_fullscreen_password_dialog()

        # 3. Decide the verdict while the monitor is STILL paused, and stop the
        #    monitor before unpausing — otherwise it could wake up, see the
        #    target gone and restart it mid-shutdown (V3).
        accepted = bool(password_attempt) and verify_password(password_attempt, EXIT_PASSWORD_HASH)
        if accepted:
            _running = False
        else:
            # Staying in kiosk mode -> restore the target window's TOPMOST state
            if _target_hwnd and win32gui.IsWindow(_target_hwnd) and _original_target_topmost:
                try:
                    win32gui.SetWindowPos(_target_hwnd, win32con.HWND_TOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_NOACTIVATE)
                    logger.debug("[kiosk] Target window re-asserted TOPMOST.")
                except Exception as e:
                    logger.debug(f"[kiosk] Failed to re-assert TOPMOST: {e}")
    finally:
        _monitor_paused = False
        _dialog_open = False
        logger.debug("[kiosk] Monitor loop resumed.")

    # 4. Act on the verdict
    if accepted:
        logger.warning("[kiosk] Emergency hotkey pressed & password accepted. Stopping kiosk launcher...")
        try:
            if _target_hwnd:
                restore_window_style(_target_hwnd)
            terminate_target(grace_seconds=3.0)
        except Exception as e:
            logger.debug(f"[kiosk] cleanup during emergency exit failed: {e}")
    else:
        logger.debug("[kiosk] Emergency exit cancelled or dialog closed without a valid password.")


def emergency_stop_listener():
    """Register the emergency hotkey. The handler only SIGNALS the main thread,
    which actually runs the Tk dialog (Tk must live on the main thread — M4).
    Registered exactly once; never re-added (H2)."""
    def on_emergency():
        _emergency_request.set()

    keyboard.add_hotkey(EMERGENCY_HOTKEY, on_emergency)
    logger.info(f"[kiosk] Emergency hotkey registered: {EMERGENCY_HOTKEY}")


# ---------- Monitor loop (unchanged) ----------
def monitor_loop():
    global _target_proc, _target_pid, _target_hwnd, _running, _monitor_paused

    block_hotkeys_when_target_active()
    emergency_stop_listener()

    while _running:
        if _monitor_paused: # ถ้า monitor ถูกสั่งหยุดชั่วคราว
            time.sleep(0.1)
            continue

        if _target_proc is None or (_target_proc and _target_proc.poll() is not None):
            p = start_target()
            if p is None:
                logger.error("[kiosk] Could not start target. Retrying in 1 seconds.")
                time.sleep(1)
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
                                win32gui.SetWindowPos(_target_hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0,win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_NOACTIVATE)
                            except Exception:
                                pass
                            try:
                                win32gui.SetWindowPos(fg, win32con.HWND_TOPMOST, 0, 0, 0, 0,win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW)
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
                with _state_lock:
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

# ----------------- Main Execution Block -----------------
if __name__ == "__main__":
    logger.info("[kiosk] Launcher starting...")
    
    # NEW: Check and force elevation here
    if not ensure_admin_and_elevate():
        logger.error("[kiosk] Failed to obtain Administrator privileges. Kiosk security features will fail. Exiting.")
        # If elevation failed or user declined, exit the program completely
        sys.exit(1)
    
    # If the code reaches this point, it is running as Administrator
    logger.info("[kiosk] Running with Administrator privileges.")
    
    ensure_numlock_on() # turn on NumLock at startup
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    try:
        # Main thread owns Tk: when the keyboard thread signals an emergency,
        # run the password dialog HERE (Tk is not thread-safe — M4).
        while _running:
            if _emergency_request.wait(timeout=1.0):
                _emergency_request.clear()
                if _running:
                    handle_emergency()
                    # Drop hotkey presses queued while the dialog was open so
                    # it doesn't immediately re-open after closing (V4).
                    _emergency_request.clear()
    except KeyboardInterrupt:
        logger.info("[kiosk] KeyboardInterrupt received, exiting.")
        _running = False
        # Immediately close target on Ctrl+C exit path
        try:
            terminate_target(grace_seconds=2.0)
        except Exception:
            pass
    logger.info("[kiosk] Done.")