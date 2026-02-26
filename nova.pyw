# -----------------------------------------------------------------------------
# Copyright (c) 2026 Brent
#
# This file is part of the Nova project.
#
# All rights reserved. No part of this code may be reproduced, distributed,
# or transmitted in any form or by any means, including photocopying, recording,
# or other electronic or mechanical methods, without the prior written
# permission of the copyright holder.
# -----------------------------------------------------------------------------
import sys
import os
import ctypes
import shutil
import subprocess
import collections
from datetime import datetime

# === CAPTURE ORIGINAL PATHS (Fix for Restart) ===
try:
    _STARTUP_CWD = os.getcwd()
    if getattr(sys, 'frozen', False):
        _ORIGINAL_EXE = sys.argv[0]
        if not os.path.isabs(_ORIGINAL_EXE):
            _ORIGINAL_EXE = os.path.join(_STARTUP_CWD, _ORIGINAL_EXE)
    else:
        _ORIGINAL_EXE = sys.executable
except:
    _ORIGINAL_EXE = sys.argv[0]

# === VERSION & CONFIG ===
CURRENT_VERSION = "1.14.1"
WINWS_FILENAME = "winws.exe"
UPDATE_URL = "https://confeden.github.io/nova_updates/version.json"

print(f"!!! DEBUG: NOVA SCRIPT LOADING FROM: {os.path.abspath(__file__)} !!!")
print(f"!!! DEBUG: VERSION: {CURRENT_VERSION} !!!")

# === PORTABLE PATH SAFEGUARD ===
def apply_path_safeguard():
    try:
        # 1. Determine launch directory
        if getattr(sys, 'frozen', False):
            exe_dir = os.path.dirname(os.path.abspath(sys.executable))
        else:
            exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        
        # 2. Fix CWD if started from System32 (admin bug)
        cwd = os.getcwd().lower()
        system32 = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'system32').lower()
        if cwd == system32:
            os.chdir(exe_dir)

        # 3. Create local temp directory for full portability
        local_temp = os.path.join(exe_dir, "temp")
        if not os.path.exists(local_temp):
            os.makedirs(local_temp, exist_ok=True)
        
        # 4. OVERRIDE System Temp variables for this process and its children
        # This forces Nuitka, Python tempfile, and subprocesses to use OUR folder
        os.environ['TEMP'] = local_temp
        os.environ['TMP'] = local_temp
        os.environ['NUITKA_PACKAGE_HOME'] = os.path.join(local_temp, "nuitka_runtime")
        
    except Exception as e:
        print(f"Path Safeguard Error: {e}")

apply_path_safeguard()

# === AUTO-INSTALL REQUIREMENTS ===
def install_requirements_visually():
    if getattr(sys, 'frozen', False): return
    
    # Check for required packages
    required = {
        "requests": "requests", 
        "urllib3": "urllib3", 
        "Pillow": "PIL",
        "pystray": "pystray"
    }
    
    missing = []
    for package, module in required.items():
        try: __import__(module)
        except ImportError: missing.append(package)
    
    if not missing: return

    # Try to use Tkinter for GUI feedback
    try:
        import tkinter as tk
        has_tk = True
    except ImportError:
        has_tk = False
        
    root = None
    if has_tk:
        try:
            root = tk.Tk()
            root.overrideredirect(True)
            root.configure(bg="#2b2b2b")
            w, h = 400, 100
            sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
            root.geometry(f"{w}x{h}+{int((sw-w)/2)}+{int((sh-h)/2)}")
            lbl = tk.Label(root, text="Настройка окружения...\nУстановка зависимостей, подождите.", 
                           fg="white", bg="#2b2b2b", font=("Arial", 10))
            lbl.pack(expand=True)
            root.update()
        except:
            if root: root.destroy()
            root = None

    try:
        # Use python.exe instead of pythonw.exe for pip if possible (more reliable)
        pip_python = sys.executable.lower().replace("pythonw.exe", "python.exe")
        if not os.path.exists(pip_python): pip_python = sys.executable

        for lib in missing:
            # Install package
            cmd = [pip_python, "-m", "pip", "install", lib, "--quiet", "--disable-pip-version-check"]
            # Use CREATE_NO_WINDOW (0x08000000)
            try:
                subprocess.check_call(cmd, creationflags=0x08000000)
                # Verify import
                __import__(required[lib])
            except:
                # If non-critical (Pillow/pystray), just continue
                if lib in ["Pillow", "pystray"]: continue
                raise # Re-raise if critical (requests)
            
    except Exception as e:
        if has_tk:
            # Try to show error
            try: ctypes.windll.user32.MessageBoxW(0, f"Ошибка установки библиотек: {e}\nПопробуйте установить их вручную: pip install requests urllib3 Pillow pystray", "Nova Error", 0x10)
            except: pass
        # Fallback: only exit if critical deps (requests) are still missing
        try:
            import requests
        except ImportError:
            sys.exit(1)
    finally:
        if root: 
            try: root.destroy()
            except: pass

install_requirements_visually()

# IMPORTS
try:
    import winreg # Added for Autostart feature
    import pystray # Added for Tray feature
    from PIL import Image # Added for Tray feature
    TRAY_SUPPORT = True
except ImportError as e:
    TRAY_SUPPORT = False
    # Optional: Warn user but continue
    # ctypes.windll.user32.MessageBoxW(0, f"Функция трея отключена. Ошибка: {e}", "Nova Warning", 0x30)

# TRACE UTILS
def safe_trace(msg):
    try: print(msg)
    except: pass

safe_trace("=== NOVA SCRIPT STARTED ===")

def restart_nova():
    """Перезапускает Nova надежно (без зависания на долгой остановке)."""
    def do_restart():
        try:
            if getattr(restart_nova, "_in_progress", False):
                return
            restart_nova._in_progress = True

            # 0. Сохраняем геометрию окна ДО остановки (on_closing не вызывается при restart)
            try:
                _root = globals().get('root')
                _log_window = globals().get('log_window')
                _save_ws = globals().get('save_window_state')
                if _root and _save_ws:
                    _state = {}
                    try: _state['main_geometry'] = _root.geometry()
                    except: pass
                    try:
                        import tkinter as _tk
                        if _log_window and _tk.Toplevel.winfo_exists(_log_window):
                            _state['log_size'] = _log_window.geometry()
                    except: pass
                    if _state:
                        _save_ws(**_state)
            except: pass

            # 1. Остановка логики
            save_visited_domains_func = globals().get('save_visited_domains')
            if save_visited_domains_func:
                try: save_visited_domains_func()
                except: pass

            log_func = globals().get('log_print', print)
            log_func("[Restart] Остановка сервисов...")
            
            stop_func = globals().get('stop_nova_service')
            if stop_func:
                # Best-effort stop with timeout: never block full restart forever.
                stop_done = threading.Event()
                stop_error = {"err": None}

                def _stop_worker():
                    try:
                        # Full cleanup in worker to avoid relaunch races with stale processes.
                        stop_func(silent=False, wait_for_cleanup=True)
                    except Exception as e:
                        stop_error["err"] = e
                    finally:
                        stop_done.set()

                threading.Thread(target=_stop_worker, daemon=True).start()
                if not stop_done.wait(timeout=6.0):
                    log_func("[Restart] Таймаут остановки (>6с). Продолжаем перезапуск принудительно.")
                elif stop_error["err"] is not None:
                    log_func(f"[Restart] Ошибка остановки: {stop_error['err']}")
            
            # 2. Освобождение мьютекса
            try:
                kernel32 = ctypes.windll.kernel32
                app_mut = globals().get('app_mutex')
                if app_mut:
                    kernel32.CloseHandle(app_mut)
                    globals()['app_mutex'] = None
                    log_func("[Restart] Mutex освобожден")
            except: pass
            
            time.sleep(0.3)
            
            # 3. Перезапуск процесса
            log_func("[Restart] Запуск новой копии...")
            
            try:
                base_dir = get_base_dir()
            except:
                base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

            restart_args = ["--show-log", "--restart", "--force-instance"]
            
            # Formulate the definitive launch command
            if getattr(sys, 'frozen', False) or sys.argv[0].lower().endswith(".exe"):
                # Frozen EXE mode
                exe_path = os.path.abspath(sys.executable)
                cmd = [exe_path] + restart_args
            else:
                # Script mode (.py / .pyw)
                exe_path = os.path.abspath(sys.executable)
                script_path = os.path.abspath(sys.argv[0])
                cmd = [exe_path, script_path] + restart_args

            if IS_DEBUG_MODE: log_func(f"[Restart] Command: {cmd}")

            try:
                # Nuclear detachment on Windows
                # We do NOT use stdout/stderr pipes here to avoid blocking
                # We do NOT use CREATE_NO_WINDOW for the GUI app
                subprocess.Popen(
                    cmd,
                    cwd=base_dir,
                    creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
                    close_fds=True,
                    start_new_session=True
                )
                launched = True
            except Exception as e:
                log_func(f"[Restart] Popen failed: {e}")
                # Last ditch fallback: OS shell 'start'
                try:
                    cmd_line = subprocess.list2cmdline(cmd)
                    os.system(f'start "" {cmd_line}')
                    launched = True
                except: pass

            if not launched:
                raise RuntimeError("Не удалось запустить новую копию")
            
            time.sleep(1.0) # Give Windows a second to register the new process group
            os._exit(0)
        except Exception as e:
            try:
                log_func = globals().get('log_print', print)
                log_func(f"[Restart] Ошибка перезапуска: {e}")
            except:
                print(f"Restart failed: {e}")
        finally:
            try:
                restart_nova._in_progress = False
            except:
                pass

    import threading, time
    threading.Thread(target=do_restart, daemon=True).start()

# === FIX: Force Hide Console (Safeguard) ===
# Проверяем, запущено ли как скомпилированный EXE
is_compiled = getattr(sys, 'frozen', False) or (sys.argv[0].lower().endswith(".exe"))
# Check debug flag early to allow console visibility on demand
is_debug_launch = "--debug" in sys.argv or "-debug" in sys.argv

if is_compiled and not is_debug_launch:
    try:
        # Nuclear option: Find window and HIDE it immediately
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd != 0:
            ctypes.windll.user32.ShowWindow(hwnd, 0) # 0 = SW_HIDE
            
        # Then detach
        ctypes.windll.kernel32.FreeConsole()
    except: pass
    
    # Перенаправляем stdout/stderr в devnull, чтобы не создавать ошибок записи
    try:
        sys.stdout = open(os.devnull, 'w')
        sys.stderr = open(os.devnull, 'w')
    except (OSError, AttributeError):
        # Если перенаправление не удалось (например, в некоторых средах sys.stdout 
        # может быть недоступен), игнорируем ошибку, чтобы не прерывать запуск.
        pass

# === FIX: Исправление загрузки DLL для Nuitka/Python 3.13+ ===
if getattr(sys, 'frozen', False):
    base_path = os.path.dirname(os.path.abspath(__file__))
    # Добавляем корень и папку DLLs в PATH, чтобы _tkinter.pyd нашел tcl86t.dll
    os.environ['PATH'] = base_path + ";" + os.path.join(base_path, "DLLs") + ";" + os.environ.get('PATH', '')

    # FIX: Принудительная загрузка DLL Tcl/Tk перед импортом
    # Это решает проблему "ImportError: DLL load failed" в Nuitka OneFile
    try:
        # Порядок важен: зависимости (zlib, ffi, ssl) -> tcl -> tk
        priority_order = ["vcruntime", "zlib", "libffi", "libcrypto", "libssl", "tcl", "tk"]
        
        libs_to_load = []
        for folder in [base_path, os.path.join(base_path, "DLLs")]:
            if os.path.exists(folder):
                for file in os.listdir(folder):
                    if file.endswith(".dll"):
                        libs_to_load.append(os.path.join(folder, file))
        
        # Сортируем: сначала приоритетные в нужном порядке, потом остальные
        libs_to_load.sort(key=lambda p: next((i for i, k in enumerate(priority_order) if k in os.path.basename(p).lower()), 999))
        
        for lib in libs_to_load:
            try: ctypes.CDLL(lib)
            except: pass
    except: pass

import traceback
try:
    import tkinter as tk
    import tkinter.ttk as ttk
    from tkinter import messagebox
except ImportError as e:
    ctypes.windll.user32.MessageBoxW(0, f"Critical Error: Failed to load Tkinter.\n\n{e}", "Nova Boot Error", 0x10)
    sys.exit(1)

# === CHECK ADMIN PRIVILEGES ===
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

if not is_admin():
    # FIX: Check for infinite loop (relaunch flag)
    if "--admin-relaunch" in sys.argv:
        ctypes.windll.user32.MessageBoxW(0, "Не удалось получить права администратора автоматически.\n\nПожалуйста, нажмите правой кнопкой мыши на файл и выберите 'Запуск от имени администратора'.", "Nova - Ошибка прав", 0x10)
        sys.exit(1)

    try:
        # Re-run the script with Admin rights
        # Prepare args: Quote them to handle spaces, and add restart flag
        new_args = [arg for arg in sys.argv[1:] if arg != "--admin-relaunch"]
        new_args.append("--admin-relaunch")
        
        # Proper quoting for arguments using standard subprocess library
        args_str = subprocess.list2cmdline(new_args)
        
        # FIX: Explicitly pass Current Working Directory (CWD) to elevated process
        # This prevents issues where the new process starts in System32 (default for Admin shell)
        cwd = os.getcwd()
        
        result = 0
        if getattr(sys, 'frozen', False):
            # Running as compiled EXE
            result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args_str, cwd, 1)
        else:
            # Running as script
            # sys.executable is python.exe, sys.argv[0] is script path
            # FIX: Use absolute path for script to handle CWD changes during elevation
            script_abs = os.path.abspath(sys.argv[0])
            script_path_quoted = subprocess.list2cmdline([script_abs])
            result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'{script_path_quoted} {args_str}', cwd, 1)
            
        # ShellExecuteW returns > 32 on success. If <= 32, it failed.
        if result <= 32:
            # Common errors: 5 (Access Denied), 1223 (Cancelled by user)
            msg = f"Для модификации трафика необходимы повышенные права.\nКод ошибки: {result}"
            if result == 5: msg += " (Доступ запрещён)"
            elif result == 1223: msg += " (Отменено пользователем)"
            
            ctypes.windll.user32.MessageBoxW(0, msg + "\n\nПожалуйста, запустите программу от имени Администратора вручную.", "Ошибка запуска Nova", 0x10)
            sys.exit(1)
        
        # If success, the new process is starting. We can exit.
        sys.exit(0)
            
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(0, f"Не удалось инициировать запрос прав администратора: {e}\n\nПожалуйста, запустите программу от имени Администратора вручную.", "Ошибка запуска Nova", 0x10)
        sys.exit(1)

# Обертка для отлова ошибок при запуске
try:
    import subprocess
    import threading
    import time
    import re
    import queue
    import urllib.request
    import json
    import http.client
    import urllib.error
    import ssl
    import socket
    import concurrent.futures
    import math
    from tkinter import scrolledtext
    import random
    import requests  # FIX: Ensure requests is included in Nuitka build
    import hashlib
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from collections import deque
    from tkinter import font as tkfont
    import winreg
    import glob

    # === HELPER: Path Resolution ===
    def get_base_dir():
        """Returns the absolute path to the application directory."""
        if getattr(sys, 'frozen', False):
            return os.path.dirname(os.path.abspath(sys.executable))
        return os.path.dirname(os.path.abspath(sys.argv[0]))

    def mask_ip(ip_str):
        """
        Masks the first two octets of an IP address (e.g., 192.168.1.1 -> ***.***.1.1).
        Returns "***" on error or invalid format.
        """
        try:
            if not ip_str or not isinstance(ip_str, str):
                return "***"
            value = ip_str.strip().strip("[]")

            # IPv4
            parts = value.split('.')
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return f"***.***.{parts[2]}.{parts[3]}"

            # IPv6 (mask first 2 hextets; keep tail for diagnostics)
            if ":" in value:
                left, sep, right = value.partition("::")
                left_parts = left.split(":") if left else []
                if len(left_parts) >= 2:
                    tail_left = ":".join(left_parts[2:]) if len(left_parts) > 2 else ""
                    masked_left = "***.***" + (f":{tail_left}" if tail_left else "")
                    return f"{masked_left}{sep}{right}" if sep else masked_left
                if len(left_parts) == 1:
                    return f"***.***:{left_parts[0]}"
            return "***"
        except:
            return "***"

    # === WINDOW STATE MANAGEMENT (Global Helper) ===
    def load_window_state():
        try:
            path = os.path.join(get_base_dir(), "temp", "window_state.json")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except: pass
        return {}

    def save_window_state(**kwargs):
        try:
            path = os.path.join(get_base_dir(), "temp", "window_state.json")
            target_dir = os.path.dirname(path)
            if not os.path.exists(target_dir): os.makedirs(target_dir, exist_ok=True)
            
            data = {}
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except: pass
            
            data.update(kwargs)
            
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
                
        except Exception:
            pass

    def mask_ips_in_text(text):
        """Masks IPv4/IPv6 addresses in text while preserving useful tail diagnostics."""
        if not text or not isinstance(text, str):
            return text
        try:
            # IPv4
            out = re.sub(r'\b\d{1,3}\.\d{1,3}\.(\d{1,3}\.\d{1,3})\b', r'***.***.\1', text)

            # Bracketed IPv6 with optional port, e.g. [2606:4700:103::2]:500
            def _mask_bracketed_ipv6(m):
                ip6 = m.group(1)
                port = m.group(2) or ""
                return f"[{mask_ip(ip6)}]{port}"
            out = re.sub(r'\[([0-9A-Fa-f:]+)\](:\d+)?', _mask_bracketed_ipv6, out)

            # Bare IPv6 token (without brackets)
            def _mask_bare_ipv6(m):
                candidate = m.group(0)
                try:
                    import ipaddress
                    ipaddress.ip_address(candidate)
                    if ":" in candidate:
                        return mask_ip(candidate)
                except:
                    pass
                return candidate
            out = re.sub(r'(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:]{1,}(?![0-9A-Fa-f:])', _mask_bare_ipv6, out)
            return out
        except:
            return text

    def is_local_http_proxy_responsive(port, timeout=0.9):
        """
        Low-impact local proxy probe.
        It validates that proxy listener parses HTTP locally without forcing upstream tunnel dials.
        """
        try:
            import socket
            with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as s:
                s.settimeout(timeout)
                req = (
                    "OPTIONS * HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii", errors="ignore")
                s.sendall(req)
                data = s.recv(128) or b""
                if data.startswith(b"HTTP/"):
                    return True
        except:
            pass
        try:
            import socket
            with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as s:
                s.settimeout(timeout)
                s.sendall(b"PING\r\n\r\n")
                data = s.recv(32) or b""
                return bool(data)
        except:
            return False

    # === CLEANUP OLD EXE (SELF-DELETION HANDLER) ===
    # This replaces the vulnerable shell-based self-deletion.
    # The new process receives the path of the old executable and deletes it after a delay.
    if "--cleanup-old-exe" in sys.argv:
        try:
            _idx = sys.argv.index("--cleanup-old-exe")
            _old_exe = sys.argv[_idx + 1]
            def _deferred_delete(path):
                global OLD_VERSION_CLEANED
                time.sleep(3)
                for _ in range(5):
                    try:
                        if os.path.exists(path): 
                            os.remove(path)
                            OLD_VERSION_CLEANED = True
                        break
                    except: time.sleep(1)
            threading.Thread(target=_deferred_delete, args=(_old_exe,), daemon=True).start()
            del sys.argv[_idx:_idx+2]
        except: pass

    # Global defer
    dns_manager = None

    # Debug Flag: Check args OR existence of "debug" file
    # Centralized argument parsing for consistency
    def _has_debug_cli_flag():
        return ("--debug" in sys.argv or "-debug" in sys.argv)

    def _check_debug_mode():
        return (_has_debug_cli_flag() or
                os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug")) or 
                os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug.txt")))
    
    IS_DEBUG_MODE = _check_debug_mode()
    IS_DEBUG_CLI = _has_debug_cli_flag()
    
    # FIX: Force Evolution Mode (Skip standard checks)
    IS_EVO_MODE = "--evo" in sys.argv

    # Global argument parser dictionary (populated in main())
    ARGS_PARSED = {}

    # === RESTORE SYSTEM: Default Strategies ===
    # FIX: Removed hardcoded dictionary to prevent pollution.
    # Strategies are now loaded ONLY from external JSON or embedded resource in EXE.
    DEFAULT_STRATEGIES = {}

    # === LOAD EMBEDDED STRATEGIES (Build Snapshot) ===
    # Если запущен EXE, проверяем наличие "замороженного" конфига
    if getattr(sys, 'frozen', False):
        try:
            # PyInstaller unpacks data to sys._MEIPASS
            base_temp_path = sys._MEIPASS
            embedded_strat_path = os.path.join(base_temp_path, "default_strategies.json")
            if os.path.exists(embedded_strat_path):
                try: 
                    with open(embedded_strat_path, "r", encoding="utf-8") as f:
                        snapset = json.load(f)
                        if isinstance(snapset, dict):
                            DEFAULT_STRATEGIES.update(snapset)
                except: pass
        except: pass

    def restore_missing_strategies():
        """Восстанавливает отсутствующие стратегии и управляет версиями файлов (Smart Merge)."""
        logs = []
        try:
            base_dir = get_base_dir()
            strat_dir = os.path.join(base_dir, "strat")
            if not os.path.exists(strat_dir): os.makedirs(strat_dir)
            
            # === 1. General List Version Management ===
            try:
                gen_path = os.path.join(base_dir, "list", "general.txt")
                is_frozen_exe = getattr(sys, 'frozen', False)
                
                # Check existing file
                target_lines = []
                has_version = False
                current_ver_in_file = None
                
                if os.path.exists(gen_path):
                    try:
                        with open(gen_path, "r", encoding="utf-8") as f:
                            target_lines = f.readlines()
                        if target_lines and target_lines[0].strip().startswith("# version:"):
                            has_version = True
                            try: current_ver_in_file = target_lines[0].strip().split(":", 1)[1].strip()
                            except: pass
                    except: pass
                
                g_action = ""
                
                # --- SCRIPT MODE (.pyw) ---
                if not is_frozen_exe:
                    if not os.path.exists(gen_path):
                        pass # Do nothing
                    elif not target_lines:
                         # FIX: Read failed or file empty? Don't overwrite blindly
                         logs.append("[Init] general.txt read failed or empty. Skipping header update to prevent data loss.")
                    elif not has_version:
                        # Append header
                        target_lines.insert(0, f"# version: {CURRENT_VERSION}\n")
                        try:
                            with open(gen_path, "w", encoding="utf-8") as f:
                                f.writelines(target_lines)
                            g_action = "Header Added (Script)"
                        except Exception as e:
                            logs.append(f"[Init] Failed to write general.txt: {e}")
                    elif current_ver_in_file != CURRENT_VERSION:
                        # Update header
                        target_lines[0] = f"# version: {CURRENT_VERSION}\n"
                        try:
                            with open(gen_path, "w", encoding="utf-8") as f:
                                f.writelines(target_lines)
                            g_action = "Header Updated (Script)"
                        except Exception as e:
                            logs.append(f"[Init] Failed to write general.txt: {e}")
                
                # --- FROZEN EXE MODE ---
                else:
                    internal_gen = get_internal_path(os.path.join("list", "general.txt"))
                    
                    if not os.path.exists(gen_path):
                        # Missing -> Restore
                         if os.path.exists(internal_gen):
                             shutil.copy2(internal_gen, gen_path)
                             g_action = "Restored from Bundle (Missing)"
                    
                    elif not has_version:
                         # No Version -> Replace
                         if os.path.exists(internal_gen):
                             shutil.copy2(internal_gen, gen_path)
                             g_action = "Restored from Bundle (No Version)"
                    
                    elif current_ver_in_file != CURRENT_VERSION:
                         # Version Mismatch -> Force Replace from Bundle (User Request)
                         if os.path.exists(internal_gen):
                             shutil.copy2(internal_gen, gen_path)
                             g_action = f"Restored from Bundle (Version Mismatch {current_ver_in_file}->{CURRENT_VERSION})"

                
                if g_action:
                    logs.append(f"[Init] general.txt: {g_action}")

            except Exception as e:
                logs.append(f"[Init] Ошибка проверки версии general.txt: {e}")

            
            # === 1.5 Discord List Independent Version Check ===
            # Ensure discord.txt has a version header or replace it (EXE) / update it (Script)
            try:
                discord_path = os.path.join(base_dir, "list", "discord.txt")
                is_frozen_exe = getattr(sys, 'frozen', False)
                
                # Читаем текущий файл
                target_lines = []
                has_version = False
                current_ver_in_file = None
                
                if os.path.exists(discord_path):
                    with open(discord_path, "r", encoding="utf-8") as f:
                        target_lines = f.readlines()
                    if target_lines and target_lines[0].strip().startswith("# version:"):
                        has_version = True
                        try: current_ver_in_file = target_lines[0].strip().split(":", 1)[1].strip()
                        except: pass
                
                d_action = ""
                
                # --- SCRIPT MODE (.pyw) ---
                if not is_frozen_exe:
                    if not os.path.exists(discord_path):
                        pass # Do nothing in script mode
                    elif not has_version:
                        # Append header to beginning
                        target_lines.insert(0, f"# version: {CURRENT_VERSION}\n")
                        with open(discord_path, "w", encoding="utf-8") as f:
                            f.writelines(target_lines)
                        d_action = "Header Added (Script)"
                    elif current_ver_in_file != CURRENT_VERSION:
                        # Update header only
                        target_lines[0] = f"# version: {CURRENT_VERSION}\n"
                        with open(discord_path, "w", encoding="utf-8") as f:
                            f.writelines(target_lines)
                        d_action = "Header Updated (Script)"

                # --- FROZEN EXE MODE ---
                else:
                    internal_discord = get_internal_path(os.path.join("list", "discord.txt"))
                    
                    if not os.path.exists(discord_path):
                         # Missing -> Copy from bundle
                         if os.path.exists(internal_discord):
                             shutil.copy2(internal_discord, discord_path)
                             d_action = "Restored from Bundle (Missing)"
                    
                    elif not has_version:
                         # No Version in User File -> Force Replace (Assume corrupted/unknown)
                         if os.path.exists(internal_discord):
                             shutil.copy2(internal_discord, discord_path)
                             d_action = "Restored from Bundle (No Version)"
                    
                    elif current_ver_in_file != CURRENT_VERSION:
                         # Version Mismatch -> Force Replace from Bundle
                         if os.path.exists(internal_discord):
                             shutil.copy2(internal_discord, discord_path)
                             d_action = f"Restored from Bundle (Version Mismatch {current_ver_in_file}->{CURRENT_VERSION})"

                if d_action:
                    logs.append(f"[Init] discord.txt: {d_action}")

            except Exception as e:
                logs.append(f"[Init] Ошибка проверки версии discord.txt: {e}")

            # === 1.5.5 EU List Version Management (Smart Merge) ===
            try:
                eu_path = os.path.join(base_dir, "list", "eu.txt")
                is_frozen_exe = getattr(sys, 'frozen', False)
                
                # Check existing file
                target_lines = []
                has_version = False
                current_ver_in_file = None
                
                if os.path.exists(eu_path):
                    try:
                        with open(eu_path, "r", encoding="utf-8") as f:
                            target_lines = f.readlines()
                        if target_lines and target_lines[0].strip().startswith("# version:"):
                            has_version = True
                            try: current_ver_in_file = target_lines[0].strip().split(":", 1)[1].strip()
                            except: pass
                    except: pass
                
                eu_action = ""
                
                # --- SCRIPT MODE (.pyw) ---
                if not is_frozen_exe:
                    if not os.path.exists(eu_path): pass
                    elif not has_version:
                        target_lines.insert(0, f"# version: {CURRENT_VERSION}\n")
                        with open(eu_path, "w", encoding="utf-8") as f: f.writelines(target_lines)
                        eu_action = "Header Added (Script)"
                    elif current_ver_in_file != CURRENT_VERSION:
                        target_lines[0] = f"# version: {CURRENT_VERSION}\n"
                        with open(eu_path, "w", encoding="utf-8") as f: f.writelines(target_lines)
                        eu_action = "Header Updated (Script)"
                
                # --- FROZEN EXE MODE ---
                else:
                    internal_eu = get_internal_path(os.path.join("list", "eu.txt"))
                    
                    if not os.path.exists(eu_path):
                        if os.path.exists(internal_eu):
                            shutil.copy2(internal_eu, eu_path)
                            eu_action = "Restored from Bundle (Missing)"
                    
                    elif not has_version or current_ver_in_file != CURRENT_VERSION:
                         # Version Mismatch -> Smart Merge
                         if os.path.exists(internal_eu):
                             try:
                                 # 1. Read Bundle Domains
                                 bundle_domains = set()
                                 with open(internal_eu, "r", encoding="utf-8") as f:
                                     for line in f:
                                         clean = line.split('#')[0].strip()
                                         if clean and not line.strip().startswith("#"): bundle_domains.add(clean)

                                 # 2. Read User Domains
                                 user_domains = set()
                                 with open(eu_path, "r", encoding="utf-8") as f:
                                     for line in f:
                                         clean = line.split('#')[0].strip()
                                         if clean and not line.strip().startswith("#"): user_domains.add(clean)
                                 
                                 # 3. Merge
                                 merged = sorted(list(user_domains.union(bundle_domains)))
                                 new_count = len(merged) - len(user_domains)
                                 
                                 # 4. Write merged content
                                 with open(eu_path, "w", encoding="utf-8") as f:
                                     f.write(f"# version: {CURRENT_VERSION}\n")
                                     for d in merged: f.write(f"{d}\n")
                                 eu_action = f"Merged Update (v{current_ver_in_file}->v{CURRENT_VERSION}, +{new_count} new domains)"
                             except:
                                 shutil.copy2(internal_eu, eu_path)
                                 eu_action = "Restored from Bundle (Merge Failed)"

                if eu_action:
                    logs.append(f"[Init] eu.txt: {eu_action}")
            except Exception as e:
                logs.append(f"[Init] Ошибка проверки версии eu.txt: {e}")

            # === 1.5.6 RU List Version Management (Smart Merge) ===
            try:
                ru_path = os.path.join(base_dir, "list", "ru.txt")
                is_frozen_exe = getattr(sys, 'frozen', False)
                
                # Check existing file
                target_lines = []
                has_version = False
                current_ver_in_file = None
                
                if os.path.exists(ru_path):
                    try:
                        with open(ru_path, "r", encoding="utf-8") as f:
                            target_lines = f.readlines()
                        if target_lines and target_lines[0].strip().startswith("# version:"):
                            has_version = True
                            try: current_ver_in_file = target_lines[0].strip().split(":", 1)[1].strip()
                            except: pass
                    except: pass
                
                ru_action = ""
                
                # --- SCRIPT MODE (.pyw) ---
                if not is_frozen_exe:
                    if not os.path.exists(ru_path): pass
                    elif not has_version:
                        target_lines.insert(0, f"# version: {CURRENT_VERSION}\n")
                        with open(ru_path, "w", encoding="utf-8") as f: f.writelines(target_lines)
                        ru_action = "Header Added (Script)"
                    elif current_ver_in_file != CURRENT_VERSION:
                        target_lines[0] = f"# version: {CURRENT_VERSION}\n"
                        with open(ru_path, "w", encoding="utf-8") as f: f.writelines(target_lines)
                        ru_action = "Header Updated (Script)"
                
                # --- FROZEN EXE MODE ---
                else:
                    internal_ru = get_internal_path(os.path.join("list", "ru.txt"))
                    
                    if not os.path.exists(ru_path):
                        if os.path.exists(internal_ru):
                            shutil.copy2(internal_ru, ru_path)
                            ru_action = "Restored from Bundle (Missing)"
                    
                    elif not has_version or current_ver_in_file != CURRENT_VERSION:
                         # Version Mismatch -> Smart Merge
                         if os.path.exists(internal_ru):
                             try:
                                 # 1. Read Bundle Domains
                                 bundle_domains = set()
                                 with open(internal_ru, "r", encoding="utf-8") as f:
                                     for line in f:
                                         clean = line.split('#')[0].strip()
                                         if clean and not line.strip().startswith("#"): bundle_domains.add(clean)

                                 # 2. Read User Domains
                                 user_domains = set()
                                 with open(ru_path, "r", encoding="utf-8") as f:
                                     for line in f:
                                         clean = line.split('#')[0].strip()
                                         if clean and not line.strip().startswith("#"): user_domains.add(clean)
                                 
                                 # 3. Merge
                                 merged = sorted(list(user_domains.union(bundle_domains)))
                                 new_count = len(merged) - len(user_domains)
                                 
                                 # 4. Write merged content
                                 with open(ru_path, "w", encoding="utf-8") as f:
                                     f.write(f"# version: {CURRENT_VERSION}\n")
                                     for d in merged: f.write(f"{d}\n")
                                 ru_action = f"Merged Update (v{current_ver_in_file}->v{CURRENT_VERSION}, +{new_count} new domains)"
                             except:
                                 shutil.copy2(internal_ru, ru_path)
                                 ru_action = "Restored from Bundle (Merge Failed)"

                if ru_action:
                    logs.append(f"[Init] ru.txt: {ru_action}")
            except Exception as e:
                logs.append(f"[Init] Ошибка проверки версии ru.txt: {e}")

            # === 1.6 Standardized Strat JSON Versioning ===
            try:
                # Список ожидаемых JSON в папке strat
                # Можно брать все, но strategies.json - особое исключение
                strat_dir_internal = get_internal_path("strat")
                expected_jsons = []
                if os.path.exists(strat_dir_internal):
                    expected_jsons = [f for f in os.listdir(strat_dir_internal) if f.endswith(".json")]
                
                # Добавим дефолтные, если вдруг internal не прочитался (для Script mode)
                defaults = ["youtube.json", "discord.json", "general.json", "strategies.json"]
                for d in defaults:
                    if d not in expected_jsons: expected_jsons.append(d)
                
                is_frozen_exe = getattr(sys, 'frozen', False)
                
                for json_file in expected_jsons:
                     target_path = os.path.join(base_dir, "strat", json_file)
                     internal_path = get_internal_path(os.path.join("strat", json_file))
                     
                     j_action = ""
                     
                     try:
                         # Load current
                         current_data = {}
                         has_ver_key = False
                         cur_ver = None
                         
                         if os.path.exists(target_path):
                             try:
                                 with open(target_path, "r", encoding="utf-8") as f:
                                     current_data = json.load(f)
                                     if isinstance(current_data, dict):
                                         cur_ver = current_data.get("version")
                                         if "version" in current_data: has_ver_key = True
                             except: pass # corrupted
                         
                         # === EXCEPTION: strategies.json ===
                         if json_file == "strategies.json":
                             # Special logic: Preserve content on update in EXE
                             if not is_frozen_exe:
                                 # SCRIPT: Update Header
                                 if not os.path.exists(target_path): pass
                                 elif cur_ver != CURRENT_VERSION:
                                     current_data["version"] = CURRENT_VERSION
                                     save_json_safe(target_path, current_data)
                                     j_action = "Version Updated (Script)"
                             else:
                                 # EXE
                                 if not os.path.exists(target_path):
                                     if os.path.exists(internal_path):
                                         shutil.copy2(internal_path, target_path)
                                         j_action = "Restored from Bundle (Missing)"
                                 elif not has_ver_key:
                                      # No version -> Restore
                                      if os.path.exists(internal_path):
                                         shutil.copy2(internal_path, target_path)
                                         j_action = "Restored from Bundle (No Version)"
                                 elif cur_ver != CURRENT_VERSION:
                                      # Version Mismatch -> Force Replace from Bundle (User Request: No Backup)
                                      if os.path.exists(internal_path):
                                         shutil.copy2(internal_path, target_path)
                                         j_action = f"Restored from Bundle (Version Mismatch {cur_ver}->{CURRENT_VERSION})"
                                      
                         # === STANDARD JSON (youtube.json, etc.) ===
                         else:
                             if not is_frozen_exe:
                                 # SCRIPT: Update Header
                                 if not os.path.exists(target_path): pass
                                 elif cur_ver != CURRENT_VERSION:
                                     current_data["version"] = CURRENT_VERSION
                                     save_json_safe(target_path, current_data)
                                     j_action = "Version Updated (Script)"
                             else:
                                 # EXE: Force Replace
                                 if not os.path.exists(target_path):
                                     if os.path.exists(internal_path):
                                         shutil.copy2(internal_path, target_path)
                                         j_action = "Restored from Bundle (Missing)"
                                 elif cur_ver != CURRENT_VERSION: # incl has_ver_key=False (cur_ver=None)
                                      if os.path.exists(internal_path):
                                         shutil.copy2(internal_path, target_path)
                                         j_action = "Restored from Bundle (Version Mismatch)"
                         
                         if j_action:
                             logs.append(f"[Init] {json_file}: {j_action}")
                             
                     except Exception as ex_j:
                         logs.append(f"[Init] Error checking {json_file}: {ex_j}")

            except Exception as e:
                logs.append(f"[Init] Strat JSON check error: {e}")

            
            # Write if needed - REMOVED (Broken Legacy Code)
            # if should_rewrite: ...
            
            # Cleanup old version file
            try:
                ov_path = os.path.join(base_dir, "list", "general.version")
                if os.path.exists(ov_path): os.remove(ov_path)
            except: pass


            # === 1.1 Exclude List Version Management (list/exclude.txt) ===
            try:
                ex_path = os.path.join(base_dir, "list", "exclude.txt")
                
                # Check execution mode
                is_frozen_exe = getattr(sys, 'frozen', False)

                # --- Script Mode (.pyw) ---
                if not is_frozen_exe:
                    # Logic: Ensure Header is present and up-to-date
                    target_lines = []
                    if os.path.exists(ex_path):
                        with open(ex_path, "r", encoding="utf-8") as f:
                             target_lines = f.readlines()
                    
                    msg = ""
                    if not target_lines:
                        # Case: Empty or Missing -> Create with Header
                        target_lines = [f"# version: {CURRENT_VERSION}\n"]
                        msg = "Create Header"
                        # Ensure dir exists just in case
                        os.makedirs(os.path.dirname(ex_path), exist_ok=True)
                    elif target_lines[0].strip().startswith("# version:"):
                         # Case: Header exists -> Check version
                         v_str = target_lines[0].strip().split(":", 1)[1].strip()
                         if v_str != CURRENT_VERSION:
                             target_lines[0] = f"# version: {CURRENT_VERSION}\n"
                             msg = "Update Header"
                    else:
                         # Case: No Header -> Prepend
                         target_lines.insert(0, f"# version: {CURRENT_VERSION}\n")
                         msg = "Append Header"
                    
                    if msg:     
                         with open(ex_path, "w", encoding="utf-8") as f:
                             f.writelines(target_lines)

                # --- Frozen EXE Mode ---
                else:
                    internal_ex = get_internal_path(os.path.join("list", "exclude.txt"))
                    
                    # 1. Read Target (User File)
                    target_lines = []
                    target_ver = None
                    target_domains = set()
                    
                    if os.path.exists(ex_path):
                        with open(ex_path, "r", encoding="utf-8") as f:
                             target_lines = f.readlines()
                        
                        # Parse
                        if target_lines and target_lines[0].strip().startswith("# version:"):
                            try: target_ver = target_lines[0].strip().split(":", 1)[1].strip()
                            except: pass
                        
                        for line in target_lines:
                             c = line.split('#')[0].strip()
                             if c: target_domains.add(c)
                    
                    # 2. Decision
                    needs_update = False
                    
                    if not os.path.exists(ex_path):
                        # Case A: Missing -> Full Copy from Bundle
                        if os.path.exists(internal_ex):
                            shutil.copy2(internal_ex, ex_path)
                            logs.append(f"Создан exclude.txt (v{CURRENT_VERSION})")
                    
                    elif not target_ver:
                        # Case B: No Version -> Replace with Bundle (as requested)
                        if os.path.exists(internal_ex):
                            shutil.copy2(internal_ex, ex_path)
                            logs.append(f"Пересоздан exclude.txt (нет версии) -> v{CURRENT_VERSION}")
                            
                    elif target_ver != CURRENT_VERSION:
                        # Case C: Old/Diff Version -> Fix Header + Supplement List
                        # Read Source Bundle
                        source_lines = []
                        if os.path.exists(internal_ex):
                             with open(internal_ex, "r", encoding="utf-8") as f:
                                 source_lines = f.readlines()
                        
                        # Prepare new content
                        new_lines = []
                        # 1. New Header
                        new_lines.append(f"# version: {CURRENT_VERSION}\n")
                        
                        # 2. Existing User Content (skip old header if present)
                        for i, line in enumerate(target_lines):
                             if i == 0 and line.strip().startswith("# version:"): continue
                             new_lines.append(line)
                        
                        # 3. Append Missing from Bundle
                        # Iterate source lines to find missing domains
                        added_count = 0
                        first_add = True
                        
                        for line in source_lines:
                             c = line.split('#')[0].strip()
                             # Ignore source comments/empty lines for the purpose of "missing domain" check
                             if c and c not in target_domains:
                                 # It's a new domain!
                                 if first_add:
                                     new_lines.append(f"\n# --- New from v{CURRENT_VERSION} ---\n")
                                     first_add = False
                                 
                                 # We append the original line from source (formatting preserved) 
                                 # OR just the clean domain? 
                                 # Source line might be "doubleclick.net # ad tracker"
                                 # Ideally preserve source comment.
                                 new_lines.append(line)
                                 
                                 target_domains.add(c) # Prevent duplicates
                                 added_count += 1
                        
                        # Write
                        with open(ex_path, "w", encoding="utf-8") as f:
                             f.writelines(new_lines)
                        
                        if added_count > 0:
                             logs.append(f"exclude.txt обновлен (v{target_ver}->v{CURRENT_VERSION}): добавлено {added_count} записей")
                        else:
                             logs.append(f"exclude.txt обновлена версия (v{target_ver}->v{CURRENT_VERSION})")

            except Exception as e:
                logs.append(f"Ошибка обновления exclude.txt: {e}")


            # === 2. JSON Version Injection & Hard Reset Logic (v0.997) ===
            
            # Special logic for 0.997: Force Reset to clean up old mess
            # If we detect files WITHOUT version or Old Version, and we are 0.997, we DELETE them.
            # This ensures they are recreated from the Bundle later.
            # For 0.998+, we will just update the version.

            json_files_to_check = []
            strat_files = []
            
            for fname in os.listdir(strat_dir):
                if fname.lower().endswith(".json"):
                    fpath = os.path.join(strat_dir, fname)
                    json_files_to_check.append(fpath)
                    strat_files.append(fpath)
            
            temp_dir = os.path.join(base_dir, "temp")
            # FIX: Do NOT check/update temp state files (strategies_evolution, learning_data) here.
            # They should manage themselves. Checking them forces "updated version" logs on every launch.
            
            for fpath in json_files_to_check:
                try:
                    data = load_json_robust(fpath, None)
                    if not isinstance(data, dict):
                        if os.path.exists(fpath): os.remove(fpath)
                        continue
                    
                    ver = data.get("version")
                    
                    # === STANDARD UPDATE LOGIC (Future) ===
                    
                    fname = os.path.basename(fpath)
                    
                    # Файлы, которые используют НОВЫЙ формат (сервисные)
                    # Требуют структуру: {"version": "...", "strategies": [...]}
                    service_files = ["youtube.json", "discord.json", "cloudflare.json", 
                                    "whatsapp.json", "warp.json", "general.json"]
                    
                    # Файлы, которые используют СТАРЫЙ формат (не требуют миграции)
                    # Структура: {"service": [...args...], "hard_1": [...], ...}
                    legacy_format_files = ["strategies.json", "boost.json"]
                    
                    if not ver:
                        # Если версии нет, сохраняем файл, добавив версию (для 0.998+)
                        data["version"] = CURRENT_VERSION
                        save_json_safe(fpath, data)
                        logs.append(f"Файл {fname} обновлен до v{CURRENT_VERSION}")
                        continue
                    
                    if ver != CURRENT_VERSION:
                        # === FORCE REPLACE: Критические файлы полностью заменяем при обновлении ===
                        force_replace_files = ["discord.json"]
                        
                        if fname in force_replace_files:
                            try:
                                bundled_file = get_internal_path(os.path.join("strat", fname))
                                if os.path.exists(bundled_file):
                                    shutil.copy2(bundled_file, fpath)
                                    logs.append(f"Заменён конфиг {fname} (v{ver} -> v{CURRENT_VERSION})")
                                    continue  # Skip to next file
                            except Exception as e:
                                logs.append(f"Ошибка замены {fname}: {e}")
                        
                        # Проверяем, требуется ли миграция формата
                        needs_format_migration = False
                        
                        if fname in service_files:
                            # Проверяем формат: новый формат должен иметь ключ "strategies"
                            if "strategies" not in data:
                                needs_format_migration = True
                                logs.append(f"Обнаружен устаревший формат {fname}, требуется миграция")
                        
                        if needs_format_migration:
                            # Заменяем файл из bundle (внутренних ресурсов EXE)
                            try:
                                bundled_file = get_internal_path(os.path.join("strat", fname))
                                if os.path.exists(bundled_file):
                                    shutil.copy2(bundled_file, fpath)
                                    logs.append(f"Обновлен формат конфига {fname} (v{CURRENT_VERSION})")
                                else:
                                    # Если bundle не найден, просто обновляем версию
                                    data["version"] = CURRENT_VERSION
                                    save_json_safe(fpath, data)
                                    logs.append(f"Обновлена версия конфига {fname} (bundle не найден)")
                            except Exception as e:
                                logs.append(f"Ошибка миграции {fname}: {e}")
                        else:
                            # Формат актуален, просто обновляем номер версии
                            data["version"] = CURRENT_VERSION
                            save_json_safe(fpath, data)
                            # Не логируем для файлов со старым форматом (strategies.json, boost.json)
                            if fname not in legacy_format_files:
                                logs.append(f"Обновлена версия конфига {fname}")
                except: pass
            
            # === 3. Restore Default Strategies (Standard Logic for strategies.json) ===
            # Dynamically load defaults from BUNDLED strategies.json inside EXE
            try:
                bundled_strat_path = get_internal_path(os.path.join("strat", "strategies.json"))
                if os.path.exists(bundled_strat_path):
                     snap = load_json_robust(bundled_strat_path, {})
                     if isinstance(snap, dict):
                         # Normalize snapshot if needed
                         for k, v in snap.items():
                             if isinstance(v, dict) and "args" in v: snap[k] = v["args"]
                         DEFAULT_STRATEGIES.update(snap)
                else:
                     logs.append(f"Debug: Bundle not found at {bundled_strat_path}")
            except Exception as e:
                logs.append(f"Bundle Load Error: {e}")

            strat_path = os.path.join(strat_dir, "strategies.json")
            data = load_json_robust(strat_path, {})
            
            modified = False
            restored_keys = []
            
            def restore_missing_strategies(strat_path):
                # FIX: No restoration in script mode
                if not getattr(sys, 'frozen', False):
                    return []

                updated = []
                # If no strategies file, create empty one to prevent crashes (or handle in _start_nova_service)
                if not os.path.exists(strat_path):
                     try:
                         with open(strat_path, "w", encoding="utf-8") as f: json.dump({}, f)
                     except: pass

                # OLD Restore logic removed/restricted
                # Only restore if completely empty/missing in EXE mode if needed
                # For now, relying on deploy_infrastructure which should ideally copy embedded strategies.json
                
                return updated
            
            # Call the new function
            restored_keys = restore_missing_strategies(strat_path)
            if restored_keys:
                logs.append(f"Восстановлены стратегии (из EXE): {', '.join(restored_keys)}")
            
            return logs

        except Exception as e:
            print(f"[Init] Ошибка восстановления стратегий: {e}")
            return logs

    def get_base_dir():
        """Возвращает папку, где лежит EXE файл (или скрипт)."""
        # FIX: Приоритет sys.executable для Nuitka/PyInstaller Frozen
        if getattr(sys, 'frozen', False):
             return os.path.dirname(os.path.abspath(sys.executable))
        # Fallback for script mode
        return os.path.dirname(os.path.abspath(sys.argv[0]))

    def get_internal_path(filename_or_folder):
        """Возвращает путь к ресурсу ВНУТРИ временной папки распакованного EXE."""
        if getattr(sys, 'frozen', False):
            # PyInstaller uses _MEIPASS
            if hasattr(sys, '_MEIPASS'):
                 return os.path.join(sys._MEIPASS, filename_or_folder)
            # Nuitka uses __file__ directory
            return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename_or_folder)
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), filename_or_folder)

    def calculate_file_hash(filepath, algorithm="sha256"):
        """Вычисляет хэш файла."""
        import hashlib
        hash_func = hashlib.new(algorithm)
        try:
            with open(filepath, "rb") as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except: return None

    def deploy_infrastructure():
        """
        Развертывает папки из EXE.
        """
        logs = []
        base_dir = get_base_dir()
        
        # Skip deployment in script mode (Dev Mode Protection)
        # FIX: Check both sys.frozen and Nuitka's __compiled__ flag
        is_compiled_check = getattr(sys, 'frozen', False) or "__compiled__" in globals()
        
        if not is_compiled_check:
             # Double check to prevent accidental non-deployment in broken builds
             return logs
        
        # === ROBUST RESOURCE FINDER ===
        # Sometimes Nuitka/PyInstaller extraction paths vary.
        # We search for 'winws.exe' to locate the real root of resources.
        internal_root = os.path.dirname(os.path.abspath(__file__))
        if hasattr(sys, '_MEIPASS'): internal_root = sys._MEIPASS
        
        real_bin_dir = None
        
        # 1. Check standard path
        p1 = os.path.join(internal_root, "bin", WINWS_FILENAME)
        if os.path.exists(p1): 
            real_bin_dir = os.path.join(internal_root, "bin") # Standard
            
        # 2. Recursive search if missing
        if not real_bin_dir:
             for root, dirs, files in os.walk(internal_root):
                 if WINWS_FILENAME in files:
                     real_bin_dir = root
                     # Adjust internal_root assuming structure .../bin/winws.exe
                     internal_root = os.path.dirname(root)
                     break
                     
        if not real_bin_dir:
             # FATAL: Could not find payload
             pass
        else:
             # Log successful discovery
             pass

        # Helper to get path relative to discovered root
        def get_rel_path(folder_name):
            return os.path.join(internal_root, folder_name)
        
        # === STARTUP OPTIMIZATION: Check Version Marker ===
        # If version matches and winws.exe exists, skip heavy file scanning
        marker_path = os.path.join(base_dir, "temp", ".nova_infra_version")
        winws_path = os.path.join(base_dir, "bin", WINWS_FILENAME)
        
        needs_deploy = True
        try:
            if os.path.exists(marker_path) and os.path.exists(winws_path):
                with open(marker_path, "r") as f:
                    if f.read().strip() == CURRENT_VERSION:
                        needs_deploy = False
        except: pass

        if not needs_deploy:
            # FIX: Force deploy for driver update check
            pass 

        # 1. Создаем папку temp
        temp_path = os.path.join(base_dir, "temp")
        if not os.path.exists(temp_path):
            try: os.makedirs(temp_path)
            except: pass

        # 2. Список папок (img исключена, она остается внутри)
        # FIX: Removed 'bin' because it is downloaded at runtime
        folders_to_deploy = ["fake", "list", "strat", "ip"] # img removed per request
        
        for folder in folders_to_deploy:
            target_folder_path = os.path.join(base_dir, folder)
            
            # Use discovered root
            internal_source = get_rel_path(folder)
            
            # Если внутренней папки нет (например, при запуске скрипта без сборки), пропускаем
            if not os.path.exists(internal_source):
                if folder == "bin": 
                    # Показываем окно с ошибкой, чтобы видеть путь даже без консоли
                    try:
                        ctypes.windll.user32.MessageBoxW(0, f"Critical: Internal 'bin' folder missing.\nPath: {internal_source}", "Nova Deploy Error", 0x10)
                    except: pass
                
                # DEBUG: Log missing internal path info to file
                try:
                    with open(os.path.join(base_dir, "nova_deploy_debug.txt"), "a") as f:
                         f.write(f"MISSING INTERNAL: {folder}\nPath: {internal_source}\nStart: {os.path.dirname(os.path.abspath(__file__))}\n\n")
                         # List what IS there
                         parent = os.path.dirname(internal_source)
                         if os.path.exists(parent):
                             f.write(f"Parent ({parent}) items: {os.listdir(parent)}\n")
                except: pass
                
                continue

            # DIAGNOSTIC: Проверяем, есть ли winws.exe внутри временной папки
            if folder == "bin":
                internal_winws = os.path.join(internal_source, WINWS_FILENAME)
                if not os.path.exists(internal_winws):
                    try: ctypes.windll.user32.MessageBoxW(0, f"Critical Build Error: 'winws.exe' is missing.\nPath: {internal_winws}", "Nova Internal Error", 0x10)
                    except: pass

            # Если папки назначения нет - создаем
            if not os.path.exists(target_folder_path):
                try:
                    os.makedirs(target_folder_path)
                    # Если папка новая, просто копируем всё содержимое
                    for item in os.listdir(internal_source):
                        s = os.path.join(internal_source, item)
                        d = os.path.join(target_folder_path, item)
                        if os.path.isdir(s):
                            shutil.copytree(s, d, dirs_exist_ok=True)
                        else:
                            shutil.copy2(s, d)
                    logs.append(f"Создана папка: {folder}")
                    continue
                except Exception as e:
                    print(f"[Setup Error] Ошибка создания {folder}: {e}")
                    continue

            # Если папка уже есть, применяем умную логику
            if folder == "fake":
                # FAKE: Только добавляем новые, не перезаписываем существующие
                try:
                    new_item_count = 0
                    for item in os.listdir(internal_source):
                        s = os.path.join(internal_source, item)
                        d = os.path.join(target_folder_path, item)
                        if not os.path.exists(d):
                             if os.path.isdir(s): shutil.copytree(s, d)
                             else: shutil.copy2(s, d)
                             new_item_count += 1
                    if new_item_count > 0: logs.append(f"Fake: добавлено {new_item_count} файлов")
                except: pass

            elif folder == "bin":
                 # BIN: Проверяем winws.exe на размер, остальное не трогаем если есть
                 try:
                    updated_bins = 0
                    for item in os.listdir(internal_source):
                        s = os.path.join(internal_source, item)
                        d = os.path.join(target_folder_path, item)
                        
                        is_winws = (item.lower() == WINWS_FILENAME.lower())
                        
                        if is_winws:
                            # Hard Update for winws.exe (Size Check)
                            if os.path.exists(d):
                                try:
                                    if os.path.getsize(s) != os.path.getsize(d):
                                        shutil.copy2(s, d)
                                        updated_bins += 1
                                except: pass
                            else: shutil.copy2(s, d)
                        else:
                            # Soft Update for DLLs/Drivers (Only add missing)
                            if not os.path.exists(d): shutil.copy2(s, d)
                                
                    if updated_bins > 0: logs.append(f"Bin: обновлено {updated_bins} исполняемых файлов")
                 except: pass

            else:
                # Для list, strat, ip: умное обновление
                try:
                    for item in os.listdir(internal_source):
                        s = os.path.join(internal_source, item)
                        d = os.path.join(target_folder_path, item)

                        # 1. Если файла нет - просто копируем
                        if not os.path.exists(d):
                            if os.path.isfile(s):
                                shutil.copy2(s, d)
                                logs.append(f"Добавлен новый файл конфигурации: {item}")
                            continue
                        
                        # 2. Если файл есть - проверяем тип
                        if item.endswith(".txt"):
                            try:
                                with open(s, "r", encoding="utf-8") as f: src_lines = f.readlines()
                                with open(d, "r", encoding="utf-8") as f: dst_lines = f.readlines()
                                
                                src_ver = "0.0"
                                if src_lines and "version:" in src_lines[0]: src_ver = src_lines[0].split(":")[1].strip()
                                
                                dst_ver = "0.0"
                                if dst_lines and "version:" in dst_lines[0]: dst_ver = dst_lines[0].split(":")[1].strip()
                                
                                def vt(v): 
                                    try: return tuple(map(int, v.split('.')))
                                    except: return (0,)
                                
                                # Logic for general.txt
                                if item == "general.txt":
                                    # Policy: Version < 1.9 -> Hard Reset
                                    if vt(dst_ver) < vt("1.9"):
                                        shutil.copy2(s, d)
                                        logs.append(f"List: Полный сброс {item} (v{dst_ver} -> v{src_ver})")
                                    else:
                                        # Policy: Version >= 1.9 -> Merge
                                        merged = set()
                                        for l in dst_lines: 
                                            if l.strip() and not l.startswith("#"): merged.add(l.strip())
                                        for l in src_lines:
                                            if l.strip() and not l.startswith("#"): merged.add(l.strip())
                                        
                                        with open(d, "w", encoding="utf-8") as f:
                                            f.write(f"# version: {src_ver}\n")
                                            for dom in sorted(list(merged)): f.write(f"{dom}\n")
                                        logs.append(f"List: Обновлен {item} (Merge v{dst_ver} -> v{src_ver})")

                                # Logic for cloudflare.txt
                                elif item == "cloudflare.txt":
                                    # Policy: If internal version is newer -> Replace
                                    # If no version in file (dst_ver=0.0) -> Replace
                                    if vt(dst_ver) < vt(src_ver):
                                        # Force Replace but ensure header matches source
                                        with open(d, "w", encoding="utf-8") as f:
                                            # If source has no header, add it? Assuming source has header.
                                            # If source is raw list, we should prepend header.
                                            if "version:" not in src_lines[0]:
                                                f.write(f"# version: {src_ver}\n")
                                                f.writelines(src_lines)
                                            else:
                                                f.writelines(src_lines)
                                        logs.append(f"List: Полный сброс {item} (v{dst_ver} -> v{src_ver})")
                                
                                else:
                                    # Default behavior for other txt files (e.g. broken ones)
                                    pass
                                    
                            except: pass

                        elif item.endswith(".json"):
                            # Strategies.json Smart Update
                            if item == "strategies.json":
                                try:
                                    js_src = load_json_robust(s, {})
                                    js_dst = load_json_robust(d, {})
                                    
                                    src_ver = js_src.get("version", "0.0")
                                    dst_ver = js_dst.get("version", "0.0")
                                    
                                    # Helper to compare versions
                                    def vt(v): 
                                        try: return tuple(map(int, v.split('.')))
                                        except: return (0,)

                                    # Policy: Version < 1.8 -> Hard Reset (Structure changed)
                                    if vt(dst_ver) < vt("1.8"):
                                        shutil.copy2(s, d)
                                        logs.append(f"Strat: Полный сброс {item} (v{dst_ver} -> v{src_ver})")
                                    else:
                                        # Policy: Version >= 1.8 -> Soft Update (Merge keys + Update Version)
                                        changed = False
                                        
                                        # 1. Update Version
                                        if dst_ver != src_ver:
                                            js_dst["version"] = src_ver
                                            changed = True
                                            
                                        # 2. Add missing top-level keys (new services)
                                        for k, v in js_src.items():
                                            if k not in js_dst:
                                                js_dst[k] = v
                                                changed = True
                                                
                                        if changed:
                                            save_json_safe(d, js_dst)
                                            logs.append(f"Strat: Обновлен {item} (v{dst_ver} -> v{src_ver})")
                                except: pass
                            else:
                                # Other JSONs (Legacy behavior - fill missing keys)
                                try:
                                    js_src = load_json_robust(s, {})
                                    js_dst = load_json_robust(d, {})
                                    changed = False
                                    for k, v in js_src.items():
                                        if k not in js_dst:
                                            js_dst[k] = v
                                            changed = True
                                    if changed:
                                        save_json_safe(d, js_dst)
                                        logs.append(f"Strat: дополнен {item}")
                                except: pass

                except Exception as e:
                    pass

        # FIX: Проверка успешности развертывания критических файлов (DISABLED: Downloaded later)
        if False and not os.path.exists(winws_path):
            debug_info = f"Target: {winws_path}\nInternal Source: {get_internal_path('bin')}\nBase Dir: {base_dir}\nArgv[0]: {sys.argv[0]}"
            try: ctypes.windll.user32.MessageBoxW(0, f"Critical Error: winws.exe not found after setup.\n\n{debug_info}", "Nova Setup Failed", 0x10)
            except: pass
            
        # FIX: Create winws_test.exe for background checks (Process Isolation)
        try:
             winws_test_path = os.path.join(base_dir, "bin", "winws_test.exe")
             if os.path.exists(winws_path):
                 # FIX: Sync version! If sizes differ (update happened), delete test exe
                 if os.path.exists(winws_test_path):
                     try:
                         if os.path.getsize(winws_test_path) != os.path.getsize(winws_path):
                             os.remove(winws_test_path)
                             logs.append("Обновлен тестовый модуль: winws_test.exe (синхронизация версии)")
                     except: pass
                 
                 # Create/Update if missing
                 if not os.path.exists(winws_test_path):
                    shutil.copy2(winws_path, winws_test_path)
                    logs.append("Восстановлен тестовый модуль: winws_test.exe")
        except: pass
        
        # === MARK SUCCESSFUL DEPLOY ===
        try:
             with open(marker_path, "w") as f: f.write(CURRENT_VERSION)
        except: pass

        return logs

    # Обновляем URL обновлений (как ты просил)
    UPDATE_URL = "https://confeden.github.io/nova_updates/version.json"

    # ================= МОДУЛЬ: NOVA_BOOT =================
    # Глобальное состояние
    is_closing = False
    process = None
    config_lock = threading.Lock()
    # Lock for serializing WinWS startup (Driver Init Race Condition Fix)
    winws_startup_lock = threading.Lock()
    is_scanning = False # Флаг выполнения сканирования/подбора
    last_strategy_check_time = 0.0  # Время последней проверки стратегий (для изоляции DNS-проверок)
    is_service_active = False # Флаг активности сервиса (STOP/START)
    is_restarting = False # Флаг перезапуска (Hot Swap)
    is_vpn_active = False
    was_service_active_before_vpn = False
    OLD_VERSION_CLEANED = False # Флаг успешной очистки старой версии

    # === НОВОЕ: Адаптивная система подбора стратегий ===
    visited_domains_stats = {}  # domain -> {visits_week, last_visit, total_visits, priority}
    visited_domains_lock = threading.Lock()
    
    strategies_evolution = {}  # strategy_name -> {original_params, current_success_rate, modifications_tried, ...}
    strategies_evolution_lock = threading.Lock()
    
    ip_history = []  # [{ip, timestamp, strategies_working_count}, ...]
    ip_history_lock = threading.Lock()
    
    last_recheck_ip = None  # Последний IP на котором проводился полный переподбор
    last_full_recheck_date = None  # Дата последней полной переверификации без смены IP
    
    # === НОВОЕ: Состояние ExcludeMonitor (однократная проверка на IP) ===
    exclude_auto_checked_domains = {}  # ip -> set(domains_checked_for_this_ip)
    exclude_auto_checked_lock = threading.Lock()
    EXCLUDE_AUTO_CHECKED_FILE = "temp/exclude_auto_checked.json"
    background_connection_semaphore = threading.Semaphore(32) # Лимит фоновых подключений
    
    # Конфигурация
    CONFIG_FILENAME = "window_config.json"
    STRATEGIES_FILENAME = "strategies.json"
    HARD_LIST_FILENAME = "hard.txt"
    BLOCKED_LIST_FILENAME = "list/ru.txt"
    VISITED_DOMAINS_FILE = "temp/visited_domains_stats.json"
    STRATEGIES_EVOLUTION_FILE = "temp/strategies_evolution.json"
    IP_HISTORY_FILE = "temp/ip_history.json"
    LEARNING_DATA_FILE = os.path.join(get_base_dir(), "temp", "learning_data.json")

    # === NEW: Service Run ID for zombie thread suppression ===
    SERVICE_RUN_ID = 0
    
    # === VOICE TUNNEL MANAGER ===
    sing_box_manager = None # Will be initialized in main


    # ================= WARP & PROXY MANAGER =================
    # Alternative Cloudflare WARP ports
    # Port 443 FIRST: works with QUIC bypass (user confirmed official WARP client works on 443)
    # Port 2408 is default but often blocked
    WARP_PORTS = [443, 500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 
                  908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 
                  987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 
                  1387, 1843, 2371, 2506, 3138, 3476, 3581, 3854, 4177, 
                  4198, 4233, 5279, 5956]
    
    CLOUDFLARE_CIDRS = [
        "162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24", 
        "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24"
    ]
    
    class SingBoxManager:
        """Manages sing-box for surgical routing of specific apps (Voice/UDP) into WARP."""
        def __init__(self, log_func=None):
            self.log_func = log_func or print
            self.bin_dir = os.path.join(get_base_dir(), "bin")
            self.temp_dir = os.path.join(get_base_dir(), "temp")
            self.exe_path = os.path.join(self.bin_dir, "sing-box.exe")
            self.config_path = os.path.join(self.temp_dir, "sing-box-conf.json")
            self.log_path = os.path.join(self.temp_dir, "sing-box.log")
            self.stderr_path = os.path.join(self.temp_dir, "sing-box.stderr.log")
            self.warp_native_profile_path = os.path.join(self.temp_dir, "warp-native-profile.json")
            self.process = None
            self.max_log_size = 8 * 1024 * 1024
            self._warp_udp_diag_done = False
            self._app_proxy_hint_done = False
            self._using_wireguard_outbound = False
            self._wg_socks_mode_logged = False
            self._log_mode_hint_done = False
            self._activity_monitor_thread = None
            self._activity_monitor_stop = threading.Event()
            self._seen_call_udp_apps = {}
            self._seen_tcp_apps = set()
            self._seen_tcp_fallback_apps = set()
            self._activity_ip_nets = {"Telegram": [], "Discord": [], "WhatsApp": []}
            self._last_dns_hint_app = None
            self._last_dns_hint_ts = 0.0
            self._opera_tcp_fallback_outbound = None
            # Optional TCP fallback through local HTTP proxy 1371 for messenger bootstrap flows.
            # Enabled by default because some hosts (notably WhatsApp Web/Desktop bootstrap) can fail via WARP SOCKS.
            # Set NOVA_ALLOW_1371_TCP_FALLBACK=0 to force pure WARP SOCKS TCP.
            self._allow_1371_tcp_fallback = str(
                os.environ.get("NOVA_ALLOW_1371_TCP_FALLBACK", "0")
            ).strip().lower() in ("1", "true", "yes", "on")
            self._auto_disable_wg_on_crash = str(
                os.environ.get("NOVA_WG_AUTODISABLE", "1")
            ).strip().lower() in ("1", "true", "yes", "on")
            self._force_disable_native_wg = False
            self._wg_disable_notice_logged = False
            self._wg_exit_timestamps = []
            # Performance knobs (defaults tuned for lower CPU on average desktops).
            def _env_bool(name, default):
                raw = os.environ.get(name, None)
                if raw is None:
                    return bool(default)
                return str(raw).strip().lower() in ("1", "true", "yes", "on")
            def _env_int(name, default, min_v, max_v):
                raw = os.environ.get(name, None)
                if raw is None:
                    return int(default)
                try:
                    val = int(str(raw).strip())
                except:
                    return int(default)
                if val < min_v:
                    val = min_v
                if val > max_v:
                    val = max_v
                return int(val)
            # Default to balanced mode for maximum compatibility (Discord/WhatsApp/TG bootstrap + voice).
            # Low-CPU remains available via NOVA_SINGBOX_LOW_CPU=1.
            self._low_cpu_mode = _env_bool("NOVA_SINGBOX_LOW_CPU", False)
            # Keep sniff enabled by default even in low-cpu mode: improves domain matching
            # for Discord/WhatsApp bootstrap and voice edge-cases.
            self._tun_sniff_enabled = _env_bool("NOVA_SINGBOX_SNIFF", True)
            self._tun_route_cap = _env_int(
                "NOVA_SINGBOX_TUN_CAP",
                160 if self._low_cpu_mode else 0,
                0,
                4096
            )
            self._wg_workers = _env_int(
                "NOVA_SINGBOX_WG_WORKERS",
                1 if self._low_cpu_mode else 2,
                1,
                8
            )
            # Discord voice compatibility (opt-in):
            # forcing Discord TCP over WG can improve voice on some networks,
            # but may break startup/login on others.
            self._discord_tcp_via_wg = _env_bool("NOVA_DISCORD_TCP_VIA_WG", False)
            # Default Discord UDP path should be WARP WG; direct/winws remains opt-in emergency mode.
            self._discord_udp_direct = _env_bool("NOVA_DISCORD_UDP_DIRECT", False)
            # Keep Discord TCP on WARP SOCKS by default; 1371 fallback is opt-in for edge ISPs.
            self._discord_tcp_fallback_1371 = _env_bool("NOVA_DISCORD_TCP_FALLBACK_1371", False)
            # Resolve current Discord edges to /32 at startup to improve capture on dynamic IP pools.
            self._discord_dns_warmup = _env_bool("NOVA_DISCORD_DNS_WARMUP", True)
            # Keep sing-box disk writes low in normal user mode.
            self._persist_main_log = _env_bool(
                "NOVA_SINGBOX_LOG_FILE",
                (not self._low_cpu_mode)
            )
            self._activity_monitor_enabled = _env_bool(
                "NOVA_SINGBOX_ACTIVITY_MONITOR",
                (not self._low_cpu_mode)
            )
            if self._activity_monitor_enabled and not self._persist_main_log:
                self._persist_main_log = True
            self._persist_stderr_log = _env_bool(
                "NOVA_SINGBOX_STDERR_LOG",
                IS_DEBUG_MODE and (not self._low_cpu_mode)
            )
            self._perf_mode_logged = False
            self._lifecycle_lock = threading.RLock()
            self._startup_in_progress = False
            self._startup_deadline = 0.0
            self._startup_started_ts = 0.0

        def _set_startup_state(self, active, timeout_sec=0.0):
            now = time.time()
            if active:
                self._startup_in_progress = True
                self._startup_started_ts = now
                self._startup_deadline = now + max(0.0, float(timeout_sec or 0.0))
            else:
                self._startup_in_progress = False
                self._startup_deadline = 0.0
                self._startup_started_ts = 0.0

        def is_startup_in_progress(self):
            with self._lifecycle_lock:
                if not self._startup_in_progress:
                    return False
                deadline = float(self._startup_deadline or 0.0)
                if deadline and time.time() > deadline:
                    self._set_startup_state(False)
                    return False
                return True

        def _detect_target_app_from_path(self, process_path):
            try:
                p = str(process_path or "").strip().lower()
                if not p:
                    return None
                if "telegram" in p or "ayugram" in p or "tdesktop" in p:
                    return "Telegram"
                if "discord" in p:
                    return "Discord"
                if "whatsapp" in p:
                    return "WhatsApp"
                # WhatsApp Desktop frequently uses WebView2 runtime process.
                if "msedgewebview2.exe" in p:
                    return "WhatsApp"
                # Update.exe by path association.
                if "update.exe" in p or "updater.exe" in p:
                    if "discord" in p:
                        return "Discord"
                    if "telegram" in p or "ayugram" in p:
                        return "Telegram"
                    if "whatsapp" in p:
                        return "WhatsApp"
            except:
                pass
            return None

        def _load_activity_ip_nets(self):
            """Build lightweight app CIDR maps for endpoint-based fallback detection."""
            try:
                import ipaddress
                base_dir = get_base_dir()
                ip_dir = os.path.join(base_dir, "ip")

                def _read_cidrs(patterns):
                    out = set()
                    for pat in patterns:
                        try:
                            for p in glob.glob(pat):
                                with open(p, "r", encoding="utf-8", errors="ignore") as f:
                                    for line in f:
                                        raw = line.split("#")[0].strip()
                                        if not raw:
                                            continue
                                        try:
                                            if "/" in raw:
                                                net = ipaddress.ip_network(raw, strict=False)
                                            else:
                                                ip = ipaddress.ip_address(raw)
                                                suffix = "/32" if ip.version == 4 else "/128"
                                                net = ipaddress.ip_network(f"{ip}{suffix}", strict=False)
                                            out.add(str(net))
                                        except:
                                            continue
                        except:
                            continue
                    return out

                tg_defaults = {
                    "149.154.160.0/20",
                    "149.154.164.0/22",
                    "149.154.172.0/22",
                    "91.108.4.0/22",
                    "91.108.8.0/22",
                    "91.108.12.0/22",
                    "91.108.16.0/22",
                    "91.108.20.0/22",
                    "91.108.56.0/22",
                    "185.138.252.0/22",
                    "185.104.210.0/24",
                }
                dc_defaults = {
                    "162.159.128.0/20",
                    "188.114.96.0/20",
                    "35.186.224.0/20",
                    "66.22.192.0/20",
                    "66.22.208.0/20",
                    "66.22.224.0/20",
                    "66.22.240.0/20",
                }
                wa_defaults = {
                    "31.13.0.0/16",
                    "57.144.0.0/14",
                    "66.220.144.0/20",
                    "69.63.176.0/20",
                    "69.171.224.0/19",
                    "74.119.76.0/22",
                    "102.132.0.0/16",
                    "103.4.96.0/22",
                    "129.134.0.0/16",
                    "157.240.0.0/16",
                    "163.70.0.0/16",
                    "173.252.0.0/16",
                    "179.60.0.0/16",
                    "185.60.0.0/16",
                    "204.15.20.0/22",
                }

                tg_cidrs = set(tg_defaults)
                tg_cidrs.update(
                    _read_cidrs(
                        [
                            os.path.join(ip_dir, "telegram*.txt"),
                            os.path.join(ip_dir, "ip_telegram*.txt"),
                        ]
                    )
                )
                dc_cidrs = set(dc_defaults)
                dc_cidrs.update(_read_cidrs([os.path.join(ip_dir, "discord*.txt")]))
                wa_cidrs = set(wa_defaults)
                wa_cidrs.update(_read_cidrs([os.path.join(ip_dir, "whatsapp*.txt")]))

                def _prune_activity_infra(cidrs):
                    out = set()
                    try:
                        blocked = [ipaddress.ip_network("77.111.244.0/22", strict=False)]
                    except:
                        blocked = []
                    for raw in cidrs:
                        try:
                            net = ipaddress.ip_network(str(raw).strip(), strict=False)
                        except:
                            continue
                        conflict = False
                        for b in blocked:
                            try:
                                if net.overlaps(b):
                                    conflict = True
                                    break
                            except:
                                continue
                        if not conflict:
                            out.add(str(net))
                    return out

                tg_cidrs = _prune_activity_infra(tg_cidrs)
                dc_cidrs = _prune_activity_infra(dc_cidrs)
                wa_cidrs = _prune_activity_infra(wa_cidrs)

                def _to_nets(cidrs):
                    nets = []
                    for c in cidrs:
                        try:
                            nets.append(ipaddress.ip_network(c, strict=False))
                        except:
                            continue
                    return nets

                self._activity_ip_nets = {
                    "Telegram": _to_nets(tg_cidrs),
                    "Discord": _to_nets(dc_cidrs),
                    "WhatsApp": _to_nets(wa_cidrs),
                }
            except:
                self._activity_ip_nets = {"Telegram": [], "Discord": [], "WhatsApp": []}

        def _classify_app_by_endpoint(self, endpoint):
            """Fallback app detection when process path is absent in logs."""
            try:
                import ipaddress
                ep = str(endpoint or "").strip().lower()
                if not ep:
                    return None

                # Remove brackets and trailing metadata.
                if ep.startswith("[") and "]" in ep:
                    ep = ep[1:ep.index("]")]
                if ep.count(":") == 1 and "." in ep:
                    ep = ep.split(":", 1)[0]

                # Domain hints.
                if any(x in ep for x in ["telegram", "tdesktop", "t.me"]):
                    return "Telegram"
                if "discord" in ep:
                    return "Discord"
                if "whatsapp" in ep or "wa.me" in ep:
                    return "WhatsApp"

                # IP hints.
                try:
                    ip = ipaddress.ip_address(ep)
                except:
                    return None

                # Ignore Opera proxy endpoint pool in endpoint-only app detection.
                try:
                    if ip in ipaddress.ip_network("77.111.244.0/22", strict=False):
                        return None
                except:
                    pass

                for app_name, nets in self._activity_ip_nets.items():
                    try:
                        for n in nets:
                            if ip in n:
                                return app_name
                    except:
                        continue
            except:
                return None
            return None

        def _extract_conn_id(self, line):
            try:
                m = re.search(r"\[(\d+)\s", line or "")
                if m:
                    return m.group(1)
            except:
                pass
            return None

        def _extract_endpoint(self, line):
            try:
                m = re.search(r"outbound(?: packet)? connection to ([^\\s]+)", line or "", re.IGNORECASE)
                if m:
                    return m.group(1).strip()
                m = re.search(r"inbound(?: packet)? connection to ([^\\s]+)", line or "", re.IGNORECASE)
                if m:
                    return m.group(1).strip()
            except:
                pass
            return None

        def _stop_activity_monitor(self):
            try:
                self._activity_monitor_stop.set()
                t = self._activity_monitor_thread
                if t and t.is_alive():
                    t.join(timeout=0.5)
            except:
                pass
            self._activity_monitor_thread = None

        def _activity_monitor_worker(self, start_offset=0):
            conn_to_app = {}
            conn_to_endpoint = {}
            endpoint_owner = {}
            endpoint_owner_ts = {}
            dns_conn_ids = set()
            last_target_app = None
            last_target_app_ts = 0.0
            app_seen_ts = {"Telegram": 0.0, "Discord": 0.0, "WhatsApp": 0.0}

            def _endpoint_key(raw_endpoint):
                try:
                    ep = str(raw_endpoint or "").strip().lower()
                    if not ep:
                        return ""
                    if ep.startswith("[") and "]" in ep:
                        ep = ep[1:ep.index("]")]
                    elif ep.count(":") == 1 and "." in ep:
                        ep = ep.split(":", 1)[0]
                    return ep
                except:
                    return ""

            offset = max(0, int(start_offset or 0))
            self._last_dns_hint_app = None
            self._last_dns_hint_ts = 0.0
            while not self._activity_monitor_stop.is_set():
                # Stop monitor when process exits.
                if not (self.process and self.process.poll() is None):
                    return

                if not os.path.exists(self.log_path):
                    time.sleep(0.15)
                    continue

                try:
                    file_size = os.path.getsize(self.log_path)
                    if offset > file_size:
                        offset = 0
                except:
                    offset = 0

                try:
                    with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                        try:
                            f.seek(offset)
                        except:
                            offset = 0
                            f.seek(0)

                        while not self._activity_monitor_stop.is_set():
                            line = f.readline()
                            if not line:
                                # Stop promptly on process exit.
                                if not (self.process and self.process.poll() is None):
                                    return
                                time.sleep(0.12)
                                continue

                            try:
                                offset = f.tell()
                            except:
                                pass

                            line = line.strip()
                            if not line:
                                continue
                            ll = line.lower()

                            # DNS hints for app association when process-path isn't emitted for a flow.
                            try:
                                if "dns:" in ll and (" exchanged " in ll or " cached " in ll):
                                    if any(x in ll for x in ["whatsapp", "wa.me", "cdn.whatsapp.net"]):
                                        self._last_dns_hint_app = "WhatsApp"
                                        self._last_dns_hint_ts = time.time()
                                    elif any(x in ll for x in ["discord.com", "discordapp", "discordcdn", "discord.media", "discord.gg"]):
                                        self._last_dns_hint_app = "Discord"
                                        self._last_dns_hint_ts = time.time()
                                    elif any(x in ll for x in ["telegram", "tdesktop", "telegra.ph", "t.me"]):
                                        self._last_dns_hint_app = "Telegram"
                                        self._last_dns_hint_ts = time.time()
                            except:
                                pass

                            conn_id = self._extract_conn_id(line)
                            endpoint = self._extract_endpoint(line)

                            # Remember inbound destination per-connection to classify later outbound lines.
                            if conn_id and "inbound/tun[tun-in]: inbound packet connection to " in ll:
                                if endpoint:
                                    conn_to_endpoint[conn_id] = endpoint
                                    if str(endpoint).endswith(":53"):
                                        dns_conn_ids.add(conn_id)

                            if "found process path:" in ll:
                                try:
                                    path_part = line.split("found process path:", 1)[1].strip()
                                except:
                                    path_part = ""
                                app = self._detect_target_app_from_path(path_part)
                                if app:
                                    last_target_app = app
                                    last_target_app_ts = time.time()
                                    app_seen_ts[app] = time.time()
                                    if conn_id:
                                        conn_to_app[conn_id] = app
                                continue

                            app = None
                            app_source = None
                            if not endpoint and conn_id and conn_id in conn_to_endpoint:
                                endpoint = conn_to_endpoint.get(conn_id)
                            if conn_id and conn_id in conn_to_app:
                                app = conn_to_app.get(conn_id)
                                app_source = "conn"
                            if not app and last_target_app and (time.time() - last_target_app_ts) <= 2.0:
                                app = last_target_app
                                app_source = "recent_process"
                            if not app:
                                app = self._classify_app_by_endpoint(endpoint)
                                if app:
                                    app_source = "endpoint"
                            if not app and self._last_dns_hint_app and (time.time() - self._last_dns_hint_ts) <= 8.0:
                                app = self._last_dns_hint_app
                                app_source = "dns"
                            if not app:
                                continue

                            # Endpoint/DNS-only guesses are noisy; require very recent process confirmation.
                            if app_source in ("endpoint", "dns"):
                                if (time.time() - app_seen_ts.get(app, 0.0)) > 6.0:
                                    continue
                            app_seen_ts[app] = time.time()

                            # Skip infrastructure DNS noise: sing-box.exe generates 100k+ DNS packets
                            # through direct that pollute the UDP detection if associated with messenger conn_ids.
                            is_dns_noise = False
                            if conn_id and conn_id in dns_conn_ids and "outbound packet connection" in ll:
                                is_dns_noise = True
                            elif ":53" in line and "outbound/direct" in ll and "outbound packet" in ll:
                                is_dns_noise = True
                            if is_dns_noise:
                                continue

                            is_udp_direct = "outbound/direct[direct]" in ll and "outbound packet connection" in ll
                            is_udp_tun = "outbound/direct[warp-tun-udp]" in ll and "outbound packet connection" in ll
                            is_udp_wg = ("outbound/wireguard[" in ll or "endpoint/wireguard[" in ll) and "outbound packet connection" in ll
                            is_udp_socks = "outbound/socks[warp-socks]" in ll and "outbound packet connection" in ll
                            if is_udp_tun or is_udp_wg or is_udp_socks or is_udp_direct:
                                # UDP call telemetry must not rely on weak heuristics,
                                # otherwise Discord-only calls can be mislabeled as Telegram/WhatsApp.
                                if app_source in ("recent_process", "dns"):
                                    continue
                                if not endpoint and conn_id and conn_id in conn_to_endpoint:
                                    endpoint = conn_to_endpoint.get(conn_id)
                                ep_key = _endpoint_key(endpoint)
                                if ep_key:
                                    if app_source == "conn":
                                        endpoint_owner[ep_key] = app
                                        endpoint_owner_ts[ep_key] = time.time()
                                    elif app_source == "endpoint":
                                        owner = endpoint_owner.get(ep_key)
                                        owner_ts = float(endpoint_owner_ts.get(ep_key, 0.0) or 0.0)
                                        if owner and owner != app and (time.time() - owner_ts) <= 180.0:
                                            continue
                                # Prefer TUN/WG reports; direct without peer is often DNS/control-plane noise.
                                if is_udp_tun:
                                    path = "CloudflareWARP"
                                    rank = 2
                                elif is_udp_wg:
                                    path = "WARP WG"
                                    rank = 3
                                elif is_udp_socks:
                                    path = "WARP SOCKS"
                                    rank = 1
                                else:
                                    path = "direct/winws"
                                    rank = 0
                                    if not endpoint or str(endpoint).endswith(":53"):
                                        continue

                                prev_rank = int(self._seen_call_udp_apps.get(app, -1))
                                if rank > prev_rank:
                                    self._seen_call_udp_apps[app] = rank
                                    peer = endpoint if endpoint else "unknown-endpoint"
                                    if prev_rank < 0:
                                        self.log_func(f"[SingBox] [Call] {app} UDP через {path} активен ({peer}).")
                                    else:
                                        self.log_func(f"[SingBox] [Call] {app} UDP переключён на {path} ({peer}).")
                                continue

                            if ("outbound/http[opera-1371]" in ll or "outbound/http[opera-http-1371]" in ll) and "outbound connection to" in ll:
                                if app not in self._seen_tcp_fallback_apps:
                                    self._seen_tcp_fallback_apps.add(app)
                                    self.log_func(f"[SingBox] [TCP] {app} TCP через Opera 1371 (fallback) активен.")
                                continue

                            is_tcp_wg = ("outbound/wireguard[" in ll or "endpoint/wireguard[" in ll) and "outbound connection to" in ll
                            is_tcp_socks = "outbound/socks[warp-socks]" in ll and "outbound connection to" in ll
                            if is_tcp_wg or is_tcp_socks:
                                if app not in self._seen_tcp_apps:
                                    self._seen_tcp_apps.add(app)
                                    path = "WG (Native)" if is_tcp_wg else "WARP SOCKS"
                                    self.log_func(f"[SingBox] [TCP] {app} TCP через {path} активен.")
                                continue
                except:
                    time.sleep(0.2)
                    continue

        def _start_activity_monitor(self, start_offset=0):
            self._stop_activity_monitor()
            self._load_activity_ip_nets()
            self._activity_monitor_stop.clear()
            self._seen_call_udp_apps = {}
            self._seen_tcp_apps = set()
            self._seen_tcp_fallback_apps = set()
            self._activity_monitor_thread = threading.Thread(
                target=self._activity_monitor_worker,
                args=(start_offset,),
                daemon=True
            )
            self._activity_monitor_thread.start()

        def _rotate_log_if_needed(self):
            try:
                if not os.path.exists(self.log_path):
                    return
                size = os.path.getsize(self.log_path)
                if size <= self.max_log_size:
                    return
                old_path = self.log_path + ".1"
                try:
                    if os.path.exists(old_path):
                        os.remove(old_path)
                except:
                    pass
                os.replace(self.log_path, old_path)
                self.log_func(f"[SingBox] Лог ротирован ({size // (1024*1024)} MB -> sing-box.log.1).")
            except:
                pass

        def _read_file_tail(self, path, max_lines=8):
            out = []
            try:
                if not os.path.exists(path):
                    return out
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    out = [ln.strip() for ln in f.readlines()[-max_lines:] if ln.strip()]
            except:
                out = []
            return out

        def _report_runtime_exit(self, exit_code=None, context="runtime"):
            try:
                if exit_code is not None:
                    self.log_func(f"[SingBox] Процесс завершился ({context}, код: {exit_code}).")
                else:
                    self.log_func(f"[SingBox] Процесс завершился ({context}).")
            except:
                pass

            sb_tail = self._read_file_tail(self.log_path, max_lines=8)
            if sb_tail:
                self.log_func("[SingBox] [Diag] Последние строки sing-box.log:")
                for ln in sb_tail:
                    self.log_func(f"[SingBox] {ln}")

            err_tail = self._read_file_tail(self.stderr_path, max_lines=8)
            if err_tail:
                self.log_func("[SingBox] [Diag] Последние строки sing-box.stderr.log:")
                for ln in err_tail:
                    self.log_func(f"[SingBox] {ln}")

        def _handle_runtime_exit(self, exit_code=None, context="runtime"):
            self._report_runtime_exit(exit_code=exit_code, context=context)
            if not self._auto_disable_wg_on_crash:
                return
            if not self._using_wireguard_outbound:
                return
            if self._force_disable_native_wg:
                return

            now = time.time()
            self._wg_exit_timestamps = [t for t in self._wg_exit_timestamps if (now - t) < 180]
            self._wg_exit_timestamps.append(now)
            if len(self._wg_exit_timestamps) >= 3:
                self._force_disable_native_wg = True
                self._wg_disable_notice_logged = False
                self.log_func("[SingBox] [WG] Частые падения с native WireGuard. Временно отключаем WG-UDP и используем direct/winws.")

        def _load_warp_native_profile(self):
            try:
                if not os.path.exists(self.warp_native_profile_path):
                    return None
                with open(self.warp_native_profile_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                required = ["private_key", "peer_public_key", "server", "local_addresses", "ports"]
                if not all(k in data for k in required):
                    return None

                old_ports_raw = list(data.get("ports", []))
                ports = []
                for p in data.get("ports", []):
                    try:
                        p = int(p)
                        if 1 <= p <= 65535:
                            ports.append(p)
                    except:
                        continue

                if not ports:
                    ports = [443, 500, 1701, 4500]
                # Normalize legacy profiles: always keep stable preferred ports and drop blocked 2408.
                ports = [p for p in ports if p != 2408]
                for p in [443, 500, 1701, 4500]:
                    if p not in ports:
                        ports.append(p)
                normalized_ports = list(dict.fromkeys(ports))
                data["ports"] = normalized_ports

                addrs = [str(x).strip() for x in (data.get("local_addresses") or []) if str(x).strip()]
                if not addrs:
                    return None
                data["local_addresses"] = addrs

                # Sanitize server: prefer host endpoint if cached server IP looks non-Cloudflare.
                server = str(data.get("server") or "").strip()
                server_host = str(data.get("server_host") or "").strip()
                fixed = False
                profile_dirty = False
                if not server:
                    server = server_host or "engage.cloudflareclient.com"
                    fixed = True
                elif self._looks_like_ip(server) and not self._is_plausible_warp_endpoint(server):
                    if server_host:
                        server = server_host
                        fixed = True
                if fixed:
                    data["server"] = server
                    profile_dirty = True
                # Persist normalized port set for legacy cached profiles.
                try:
                    old_norm = []
                    for p in old_ports_raw:
                        try:
                            p = int(p)
                            if 1 <= p <= 65535:
                                old_norm.append(p)
                        except:
                            continue
                    old_norm = [p for p in old_norm if p != 2408]
                    old_norm = list(dict.fromkeys(old_norm))
                    if old_norm != normalized_ports:
                        profile_dirty = True
                except:
                    pass

                if profile_dirty:
                    try:
                        self._save_warp_native_profile(data)
                    except:
                        pass
                return data
            except:
                return None

        def _save_warp_native_profile(self, profile):
            try:
                os.makedirs(self.temp_dir, exist_ok=True)
                with open(self.warp_native_profile_path, "w", encoding="utf-8") as f:
                    json.dump(profile, f, indent=2, ensure_ascii=False)
                return True
            except:
                return False

        def _get_warp_bin_signature(self):
            try:
                p = os.path.join(self.bin_dir, "warp-svc.exe")
                st = os.stat(p)
                return {
                    "path": os.path.abspath(p),
                    "size": int(st.st_size),
                    "mtime": int(st.st_mtime),
                }
            except:
                return None

        def _should_refresh_warp_native_profile(self, profile):
            try:
                force = str(os.environ.get("NOVA_WG_PROFILE_REFRESH", "")).strip().lower() in ("1", "true", "yes", "on")
                if force:
                    return True

                if not isinstance(profile, dict):
                    return True

                # Safety TTL: refresh daily to avoid stale/broken registrations after client reinstalls.
                created_at = int(profile.get("created_at") or 0)
                if created_at <= 0 or (time.time() - created_at) > 24 * 3600:
                    return True

                old_sig = profile.get("warp_bin_sig")
                now_sig = self._get_warp_bin_signature()
                if now_sig and isinstance(old_sig, dict):
                    if int(old_sig.get("mtime", -1)) != int(now_sig.get("mtime", -2)) or int(old_sig.get("size", -1)) != int(now_sig.get("size", -2)):
                        return True
                elif now_sig and not old_sig:
                    # Legacy profile without binary signature.
                    return True
            except:
                return True
            return False

        def _generate_wg_keypair(self):
            try:
                result = subprocess.run(
                    [self.exe_path, "generate", "wg-keypair"],
                    capture_output=True,
                    text=True,
                    timeout=20,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    cwd=self.bin_dir
                )
                if result.returncode != 0:
                    return None, None, (result.stderr or result.stdout or "unknown error").strip()

                priv = None
                pub = None
                for line in (result.stdout or "").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if line.lower().startswith("privatekey:"):
                        priv = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("publickey:"):
                        pub = line.split(":", 1)[1].strip()

                if not priv or not pub:
                    return None, None, "wg-keypair parse failed"

                return priv, pub, ""
            except Exception as e:
                return None, None, str(e)

        def _looks_like_ip(self, value):
            try:
                import ipaddress
                ipaddress.ip_address(str(value).strip())
                return True
            except:
                return False

        def _is_plausible_warp_endpoint(self, value):
            """Quick sanity check to avoid selecting random poisoned endpoint IPs."""
            try:
                import ipaddress
                ip = ipaddress.ip_address(str(value).strip())
                if ip.version == 4:
                    s = str(ip)
                    return s.startswith("162.159.") or s.startswith("188.114.")
                s = str(ip).lower()
                return s.startswith("2606:4700:")
            except:
                # Hostnames are acceptable (engage.cloudflareclient.com).
                return True

        def _is_local_port_open(self, port):
            try:
                import socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.4)
                    return s.connect_ex(("127.0.0.1", int(port))) == 0
            except:
                return False

        def _register_warp_native_profile(self):
            try:
                import base64
                import requests
                from datetime import datetime, timezone

                priv, pub, key_err = self._generate_wg_keypair()
                if not priv or not pub:
                    self.log_func(f"[SingBox] [WG] Не удалось сгенерировать WG ключи: {key_err}")
                    return None

                payload = {
                    "key": pub,
                    "install_id": "",
                    "fcm_token": "",
                    "tos": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    "type": "a",
                    "model": "PC",
                    "locale": "en-US",
                    "warp_enabled": True,
                }
                headers = {
                    "User-Agent": "okhttp/3.12.1",
                    "CF-Client-Version": "a-6.30-3596",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }

                endpoints = [
                    "https://api.cloudflareclient.com/v0/reg",
                    "https://api.cloudflareclient.com./v0/reg",
                ]
                response = None
                last_error = ""
                # Strategy-only mode: no Opera proxy fallback for Cloudflare registration.
                for url in endpoints:
                    try:
                        response = requests.post(
                            url,
                            json=payload,
                            headers=headers,
                            timeout=20,
                            proxies={"http": None, "https": None},
                        )
                        if response.status_code == 200:
                            break
                        last_error = f"strategy:{response.status_code}"
                    except Exception as e:
                        last_error = f"strategy:{e}"
                        response = None

                if not response or response.status_code != 200:
                    self.log_func(f"[SingBox] [WG] Не удалось зарегистрировать native профиль: {last_error or 'unknown error'}")
                    return None

                body = response.json()
                result = body.get("result") or {}
                config = result.get("config") or {}
                peers = config.get("peers") or []
                if not peers:
                    self.log_func("[SingBox] [WG] Cloudflare API не вернул peers.")
                    return None

                peer0 = peers[0] or {}
                peer_pub = str(peer0.get("public_key") or "").strip()
                endpoint = peer0.get("endpoint") or {}
                host = str(endpoint.get("host") or "").strip()
                host_only = host.split(":", 1)[0].strip() if host else ""
                endpoint_v4 = str(endpoint.get("v4") or "").strip()
                endpoint_v4 = endpoint_v4.split(":", 1)[0].strip() if endpoint_v4 else ""
                server = host_only or ""
                if not server:
                    if endpoint_v4 and self._is_plausible_warp_endpoint(endpoint_v4):
                        server = endpoint_v4
                    else:
                        server = "engage.cloudflareclient.com"

                ports = []
                for p in (endpoint.get("ports") or []):
                    try:
                        p = int(p)
                        if 1 <= p <= 65535:
                            ports.append(p)
                    except:
                        continue
                for p in [443, 500, 1701, 4500]:
                    if p not in ports:
                        ports.append(p)
                ports = list(dict.fromkeys(ports))

                iface = (config.get("interface") or {}).get("addresses") or {}
                local_addresses = []
                v4 = str(iface.get("v4") or "").strip()
                v6 = str(iface.get("v6") or "").strip()
                if v4:
                    local_addresses.append(f"{v4}/32")
                if v6:
                    local_addresses.append(f"{v6}/128")
                if not local_addresses or not peer_pub:
                    self.log_func("[SingBox] [WG] Недостаточно данных профиля (local addresses / peer key).")
                    return None

                reserved = None
                client_id = config.get("client_id")
                if isinstance(client_id, str) and client_id.strip():
                    try:
                        pad = "=" * ((4 - len(client_id) % 4) % 4)
                        raw = base64.b64decode(client_id + pad)
                        if len(raw) >= 3:
                            reserved = [int(raw[0]), int(raw[1]), int(raw[2])]
                    except:
                        reserved = None

                profile = {
                    "created_at": int(time.time()),
                    "registration_id": result.get("id"),
                    "token": result.get("token"),
                    "private_key": priv,
                    "public_key": pub,
                    "peer_public_key": peer_pub,
                    "server": server,
                    "server_host": host_only,
                    "server_v4": endpoint_v4,
                    "ports": ports,
                    "local_addresses": local_addresses,
                    "reserved": reserved,
                    "last_good_port": (
                        443 if 443 in ports else
                        (500 if 500 in ports else
                         (1701 if 1701 in ports else
                          (4500 if 4500 in ports else (ports[0] if ports else 443))))
                    ),
                    "warp_bin_sig": self._get_warp_bin_signature(),
                }

                if self._save_warp_native_profile(profile):
                    self.log_func(f"[SingBox] [WG] Создан native профиль WARP (портов: {len(ports)}).")
                return profile
            except Exception as e:
                self.log_func(f"[SingBox] [WG] Ошибка регистрации native профиля: {e}")
                return None

        def _get_warp_native_profile(self):
            profile = self._load_warp_native_profile()
            if profile:
                if self._should_refresh_warp_native_profile(profile):
                    self.log_func("[SingBox] [WG] Обновление native профиля WARP...")
                    fresh = self._register_warp_native_profile()
                    if fresh:
                        return fresh
                    self.log_func("[SingBox] [WG] Не удалось обновить профиль, используем сохранённый.")
                return profile
            return self._register_warp_native_profile()

        def _is_local_http_proxy_alive(self, port=1371, timeout=1.2):
            """Lightweight local parser probe without upstream endpoint dials."""
            return is_local_http_proxy_responsive(port=port, timeout=timeout)

        def _is_local_http_proxy_upstream_ready(self, port=1371, timeout=2.0):
            """One-shot upstream probe used only for optional TCP fallback gating."""
            import socket
            try:
                with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout) as s:
                    s.settimeout(timeout)
                    req = (
                        "CONNECT chatgpt.com:443 HTTP/1.1\r\n"
                        "Host: chatgpt.com:443\r\n"
                        "Proxy-Connection: close\r\n\r\n"
                    ).encode("ascii", errors="ignore")
                    s.sendall(req)
                    data = s.recv(192) or b""
                    return data.startswith(b"HTTP/")
            except:
                return False

        def _is_local_http_proxy_stable(self, port=1371):
            """
            Conservative probe for optional Opera fallback.
            We only enable TCP fallback when 1371 is actually stable.
            """
            local_ok = 0
            for _ in range(3):
                if self._is_local_http_proxy_alive(port=port, timeout=1.0):
                    local_ok += 1
                time.sleep(0.15)
            if local_ok < 2:
                return False

            upstream_ok = 0
            for _ in range(2):
                if self._is_local_http_proxy_upstream_ready(port=port, timeout=2.0):
                    upstream_ok += 1
                time.sleep(0.2)
            return upstream_ok >= 1

        def _build_warp_outbounds(self):
            """Build WARP outbounds:
            - TCP: WARP SOCKS (1370) as primary route.
            - UDP voice: native WireGuard (preferred), direct/winws as last resort.
            - Optional TCP fallback for bootstrap via local Opera proxy (1371).
            """
            self._using_wireguard_outbound = False
            self._opera_tcp_fallback_outbound = None

            warp_socks = {
                "type": "socks",
                "tag": "warp-socks",
                "server": "127.0.0.1",
                "server_port": int(globals().get('WARP_PORT', 1370)),
                "version": "4",
                "domain_strategy": "ipv4_only"
            }

            outbounds = [warp_socks]
            target_tcp = "warp-socks"
            # Стратегия UDP для мессенджеров в режиме WARP SOCKS:
            #
            # Возвращаемся на "direct" (winws), т.к. WARP SOCKS не умеет в UDP.
            target_udp = "direct"
            self.log_func(f"[SingBox] [Route] UDP голос → {target_udp} (обработка через системный winws).")

            # Optional TCP bootstrap fallback via local Opera proxy.
            if self._allow_1371_tcp_fallback:
                self._opera_tcp_fallback_outbound = "opera-1371"
                outbounds.append(
                    {
                        "type": "http",
                        "tag": self._opera_tcp_fallback_outbound,
                        "server": "127.0.0.1",
                        "server_port": 1371
                    }
                )
                try:
                    if not self._is_local_http_proxy_stable(port=1371):
                        self.log_func("[SingBox] [TCP-Fallback] Порт 1371 пока недоступен: fallback-правила применены и начнут работать после восстановления 1371.")
                except:
                    pass

            outbounds.append({"type": "direct", "tag": "direct"})
            self.log_func(f"[SingBox] [Route] TCP → {target_tcp} (WARP MASQUE). UDP голос → {target_udp}.")
            return outbounds, [], target_udp, target_tcp


        def create_config(self):
            """Generates sing-box config securely from scratch on every run."""
            try:
                # Ensure path is always fresh/absolute pointing to TEMP
                self.config_path = os.path.join(self.temp_dir, "sing-box-conf.json")
                if not os.path.exists(self.temp_dir): os.makedirs(self.temp_dir, exist_ok=True)
                import ipaddress
                import socket
                import random

                def _read_domains(path):
                    out = set()
                    try:
                        if not os.path.exists(path):
                            return out
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                raw = line.split("#")[0].strip().lower()
                                if not raw:
                                    continue
                                if raw.startswith("*."):
                                    raw = raw[2:]
                                raw = raw.lstrip(".").rstrip(".")
                                # Ignore IP/CIDR in domain loader.
                                if "/" in raw:
                                    continue
                                try:
                                    ipaddress.ip_address(raw)
                                    continue
                                except:
                                    pass
                                out.add(raw)
                    except:
                        pass
                    return out

                def _read_ip_cidrs(path):
                    out = set()
                    try:
                        if not os.path.exists(path):
                            return out
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                raw = line.split("#")[0].strip()
                                if not raw:
                                    continue
                                try:
                                    if "/" in raw:
                                        net = ipaddress.ip_network(raw, strict=False)
                                        out.add(str(net))
                                    else:
                                        ip = ipaddress.ip_address(raw)
                                        suffix = "/32" if ip.version == 4 else "/128"
                                        out.add(f"{ip}{suffix}")
                                except:
                                    continue
                    except:
                        pass
                    return out

                def _read_ip_cidrs_glob(patterns):
                    out = set()
                    try:
                        for pat in patterns:
                            for p in glob.glob(pat):
                                out.update(_read_ip_cidrs(p))
                    except:
                        pass
                    return out

                def _read_domains_glob(patterns):
                    out = set()
                    try:
                        for pat in patterns:
                            for p in glob.glob(pat):
                                out.update(_read_domains(p))
                    except:
                        pass
                    return out

                def _resolve_domains_to_ipv4_cidrs(domains, max_domains=24, max_per_domain=8):
                    """Resolve a compact set of dynamic domains to /32 routes."""
                    out = set()
                    try:
                        candidates = []
                        for d in sorted(set(domains or [])):
                            ds = str(d or "").strip().lower()
                            if ds and "/" not in ds and " " not in ds:
                                candidates.append(ds)
                        if max_domains > 0:
                            candidates = candidates[:max_domains]
                    except:
                        candidates = []
                    for domain in candidates:
                        try:
                            _, _, ips = socket.gethostbyname_ex(domain)
                        except:
                            continue
                        added = 0
                        for ip in ips or []:
                            ip_s = str(ip).strip()
                            try:
                                ip_obj = ipaddress.ip_address(ip_s)
                            except:
                                continue
                            if ip_obj.version != 4:
                                continue
                            out.add(f"{ip_s}/32")
                            added += 1
                            if max_per_domain > 0 and added >= max_per_domain:
                                break
                    return out

                def _filter_tun_route_cidrs(cidrs):
                    """
                    Keep TUN capture surgical:
                    - drop invalid CIDRs
                    - drop overly broad prefixes to avoid hijacking unrelated traffic
                    - split moderate /16-/19 ranges into /20 to keep routes specific
                    """
                    out = set()
                    for raw in cidrs:
                        try:
                            net = ipaddress.ip_network(str(raw).strip(), strict=False)
                        except:
                            continue
                        if net.version == 4:
                            if self._low_cpu_mode:
                                # In low-cpu keep medium ranges as-is (>= /16) to preserve Discord/WhatsApp reachability,
                                # but still reject very broad captures (/0-/15).
                                if net.prefixlen < 16:
                                    continue
                                out.add(str(net))
                                continue
                            if net.prefixlen < 20:
                                # Balanced mode: split moderate broad ranges to /20.
                                # Avoid huge hijacks like /10, but allow /14-/19 for messenger CDNs.
                                if 14 <= net.prefixlen <= 19:
                                    try:
                                        for sn in net.subnets(new_prefix=20):
                                            out.add(str(sn))
                                    except:
                                        pass
                                continue
                        if net.version == 6 and net.prefixlen < 32:
                            continue
                        out.add(str(net))
                    return out

                def _cap_route_cidrs(cidrs, cap):
                    """Keep route sets bounded to reduce sing-box routing overhead on weak CPUs."""
                    try:
                        cap = int(cap or 0)
                    except:
                        cap = 0
                    normalized = set()
                    for raw in cidrs:
                        txt = str(raw or "").strip()
                        if txt:
                            normalized.add(txt)
                    if cap <= 0 or len(normalized) <= cap:
                        return normalized

                    def _key(raw):
                        try:
                            net = ipaddress.ip_network(raw, strict=False)
                            family = 0 if net.version == 4 else 1
                            # Keep more specific prefixes first, then stable lexical order.
                            return (family, -int(net.prefixlen), str(net.network_address), raw)
                        except:
                            return (9, 0, raw, raw)

                    ordered = sorted(normalized, key=_key)
                    return set(ordered[:cap])

                def _prune_infra_conflicts(cidrs):
                    """
                    Remove infra/control-plane networks that must never be captured by NovaVoice TUN.
                    This prevents sing-box self-capture loops for Opera proxy endpoints.
                    """
                    out = set()
                    try:
                        blocked = [
                            ipaddress.ip_network("77.111.244.0/22", strict=False),
                        ]
                    except:
                        blocked = []
                    for raw in cidrs:
                        try:
                            net = ipaddress.ip_network(str(raw).strip(), strict=False)
                        except:
                            continue
                        conflict = False
                        for b in blocked:
                            try:
                                if net.overlaps(b):
                                    conflict = True
                                    break
                            except:
                                continue
                        if not conflict:
                            out.add(str(net))
                    return out

                # Keep internal Nova tooling explicitly out of tunnel/proxy routing.
                bypass_processes = [
                    "winws.exe",
                    "winws",
                    "winws_test.exe",
                    "winws_test",
                    "sing-box.exe",
                    "sing-box",
                    "warp-svc.exe",
                    "warp-svc",
                    "warp-cli.exe",
                    "warp-cli",
                    "opera-proxy.windows-amd64",
                    "opera-proxy.windows-amd64.exe",
                    "opera-proxy.exe",
                    "opera-proxy",
                ]
                # Infra processes must stay direct and never be loop-routed by domain/ip fallback rules.
                infra_bypass_processes = [
                    "winws.exe",
                    "winws",
                    "winws_test.exe",
                    "winws_test",
                    "sing-box.exe",
                    "sing-box",
                    "warp-svc.exe",
                    "warp-svc",
                    "warp-cli.exe",
                    "warp-cli",
                    "opera-proxy.windows-amd64",
                    "opera-proxy.windows-amd64.exe",
                    "opera-proxy.exe",
                    "opera-proxy",
                ]
                infra_bypass_path_regex = [
                    r"(?i)^.*\\winws(?:_test)?\.exe$",
                    r"(?i)^.*\\sing-box\.exe$",
                    r"(?i)^.*\\warp-svc\.exe$",
                    r"(?i)^.*\\warp-cli\.exe$",
                    r"(?i)^.*\\opera-proxy(?:\.windows-amd64)?\.exe$",
                ]
                # Target application processes that should go through WARP.
                target_processes = [
                    "Discord.exe",
                    "Discord",
                    "discord.exe",
                    "discord",
                    "DiscordCanary.exe",
                    "DiscordCanary",
                    "discordcanary.exe",
                    "discordcanary",
                    "DiscordPTB.exe",
                    "DiscordPTB",
                    "discordptb.exe",
                    "discordptb",
                    "Telegram.exe",
                    "Telegram",
                    "telegram.exe",
                    "telegram",
                    "AyuGram.exe",
                    "AyuGram",
                    "ayugram.exe",
                    "ayugram",
                    "WhatsApp.exe",
                    "WhatsApp",
                    "whatsapp.exe",
                    "whatsapp",
                    "WhatsApp.Root.exe",
                    "WhatsApp.Root",
                    "whatsapp.root.exe",
                    "whatsapp.root",
                    # WhatsApp Desktop can emit network via WebView2 runtime.
                    # Safe here because TUN captures only messenger target subnets.
                    "msedgewebview2.exe",
                    "msedgewebview2",
                    # Telegram helper/runtime variants
                    "TelegramDesktop.exe",
                    "Telegram Desktop.exe",
                    "QtWebEngineProcess.exe",
                    "telegramdesktop.exe",
                    "telegram desktop.exe",
                    "qtwebengineprocess.exe",
                ]

                # Telegram/AyuGram UDP should prefer native WG when available.
                telegram_udp_processes = [
                    "Telegram.exe",
                    "Telegram",
                    "telegram.exe",
                    "telegram",
                    "AyuGram.exe",
                    "AyuGram",
                    "ayugram.exe",
                    "ayugram",
                    "TelegramDesktop.exe",
                    "Telegram Desktop.exe",
                    "QtWebEngineProcess.exe",
                    "telegramdesktop.exe",
                    "telegram desktop.exe",
                    "qtwebengineprocess.exe",
                ]
                # Discord/WhatsApp voice can use native WG UDP path.
                discord_whatsapp_udp_processes = [
                    "Discord.exe",
                    "Discord",
                    "discord.exe",
                    "discord",
                    "DiscordCanary.exe",
                    "DiscordCanary",
                    "discordcanary.exe",
                    "discordcanary",
                    "DiscordPTB.exe",
                    "DiscordPTB",
                    "discordptb.exe",
                    "discordptb",
                    "WhatsApp.exe",
                    "WhatsApp",
                    "whatsapp.exe",
                    "whatsapp",
                    "WhatsApp.Root.exe",
                    "WhatsApp.Root",
                    "whatsapp.root.exe",
                    "whatsapp.root",
                    "msedgewebview2.exe",
                    "msedgewebview2",
                ]

                # Route helper processes by install path, not only by executable name.
                target_app_path_regex = [
                    r"(?i)^.*\\discord(?:canary|ptb)?\\.*\.exe$",
                    r"(?i)^.*\\telegram(?: desktop)?\\.*\.exe$",
                    r"(?i)^.*\\telegram.*\\.*\.exe$",
                    r"(?i)^.*\\ayugram\\.*\.exe$",
                    r"(?i)^.*\\whatsapp\\.*\.exe$",
                    r"(?i)^.*\\windowsapps\\[^\\]*whatsapp[^\\]*\\whatsapp\.root\.exe$",
                    r"(?i)^.*\\whatsapp\.root\.exe$",
                    r"(?i)^.*\\msedgewebview2\.exe$",
                ]
                telegram_path_regex = [
                    r"(?i)^.*\\telegram(?: desktop)?\\.*\.exe$",
                    r"(?i)^.*\\telegram.*\\.*\.exe$",
                    r"(?i)^.*\\ayugram\\.*\.exe$",
                ]
                discord_whatsapp_path_regex = [
                    r"(?i)^.*\\discord(?:canary|ptb)?\\.*\.exe$",
                    r"(?i)^.*\\whatsapp\\.*\.exe$",
                    r"(?i)^.*\\windowsapps\\[^\\]*whatsapp[^\\]*\\whatsapp\.root\.exe$",
                    r"(?i)^.*\\whatsapp\.root\.exe$",
                    r"(?i)^.*\\msedgewebview2\.exe$",
                ]
                discord_processes = [
                    "Discord.exe",
                    "Discord",
                    "discord.exe",
                    "discord",
                    "DiscordCanary.exe",
                    "DiscordCanary",
                    "discordcanary.exe",
                    "discordcanary",
                    "DiscordPTB.exe",
                    "DiscordPTB",
                    "discordptb.exe",
                    "discordptb",
                ]
                discord_path_regex = [
                    r"(?i)^.*\\discord(?:canary|ptb)?\\.*\.exe$",
                ]
                whatsapp_processes = [
                    "WhatsApp.exe",
                    "WhatsApp",
                    "whatsapp.exe",
                    "whatsapp",
                    "WhatsApp.Root.exe",
                    "WhatsApp.Root",
                    "whatsapp.root.exe",
                    "whatsapp.root",
                    "msedgewebview2.exe",
                    "msedgewebview2",
                ]
                whatsapp_path_regex = [
                    r"(?i)^.*\\whatsapp\\.*\.exe$",
                    r"(?i)^.*\\windowsapps\\[^\\]*whatsapp[^\\]*\\whatsapp\.root\.exe$",
                    r"(?i)^.*\\whatsapp\.root\.exe$",
                    r"(?i)^.*\\msedgewebview2\.exe$",
                ]

                # Update.exe is too generic; route only if path belongs to target apps.
                update_path_regex = [
                    r"(?i)^.*\\discord(?:canary|ptb)?\\update\.exe$",
                    r"(?i)^.*\\discord(?:canary|ptb)?\\updater\.exe$",
                    r"(?i)^.*\\appdata\\local\\discord(?:canary|ptb)?\\update\.exe$",
                    r"(?i)^.*\\appdata\\local\\discord(?:canary|ptb)?\\updater\.exe$",
                    r"(?i)^.*\\telegram(?: desktop)?\\update\.exe$",
                    r"(?i)^.*\\telegram(?: desktop)?\\updater\.exe$",
                    r"(?i)^.*\\appdata\\local\\telegram(?: desktop)?\\update\.exe$",
                    r"(?i)^.*\\appdata\\local\\telegram(?: desktop)?\\updater\.exe$",
                    r"(?i)^.*\\ayugram\\update\.exe$",
                    r"(?i)^.*\\ayugram\\updater\.exe$",
                    r"(?i)^.*\\appdata\\local\\ayugram\\update\.exe$",
                    r"(?i)^.*\\appdata\\local\\ayugram\\updater\.exe$",
                    r"(?i)^.*\\whatsapp\\update\.exe$",
                    r"(?i)^.*\\whatsapp\\updater\.exe$",
                    r"(?i)^.*\\appdata\\local\\whatsapp\\update\.exe$",
                    r"(?i)^.*\\appdata\\local\\whatsapp\\updater\.exe$",
                ]
                telegram_update_path_regex = [
                    r"(?i)^.*\\telegram(?: desktop)?\\update\.exe$",
                    r"(?i)^.*\\telegram(?: desktop)?\\updater\.exe$",
                    r"(?i)^.*\\appdata\\local\\telegram(?: desktop)?\\update\.exe$",
                    r"(?i)^.*\\appdata\\local\\telegram(?: desktop)?\\updater\.exe$",
                    r"(?i)^.*\\ayugram\\update\.exe$",
                    r"(?i)^.*\\ayugram\\updater\.exe$",
                    r"(?i)^.*\\appdata\\local\\ayugram\\update\.exe$",
                    r"(?i)^.*\\appdata\\local\\ayugram\\updater\.exe$",
                ]
                discord_whatsapp_update_path_regex = [
                    r"(?i)^.*\\discord(?:canary|ptb)?\\update\.exe$",
                    r"(?i)^.*\\discord(?:canary|ptb)?\\updater\.exe$",
                    r"(?i)^.*\\appdata\\local\\discord(?:canary|ptb)?\\update\.exe$",
                    r"(?i)^.*\\appdata\\local\\discord(?:canary|ptb)?\\updater\.exe$",
                    r"(?i)^.*\\whatsapp\\update\.exe$",
                    r"(?i)^.*\\whatsapp\\updater\.exe$",
                    r"(?i)^.*\\appdata\\local\\whatsapp\\update\.exe$",
                    r"(?i)^.*\\appdata\\local\\whatsapp\\updater\.exe$",
                ]
                discord_update_path_regex = [
                    r"(?i)^.*\\discord(?:canary|ptb)?\\update\.exe$",
                    r"(?i)^.*\\discord(?:canary|ptb)?\\updater\.exe$",
                    r"(?i)^.*\\appdata\\local\\discord(?:canary|ptb)?\\update\.exe$",
                    r"(?i)^.*\\appdata\\local\\discord(?:canary|ptb)?\\updater\.exe$",
                ]
                whatsapp_update_path_regex = [
                    r"(?i)^.*\\whatsapp\\update\.exe$",
                    r"(?i)^.*\\whatsapp\\updater\.exe$",
                    r"(?i)^.*\\appdata\\local\\whatsapp\\update\.exe$",
                    r"(?i)^.*\\appdata\\local\\whatsapp\\updater\.exe$",
                ]
                generic_update_process_names = [
                    "Update.exe", "Update", "service_update.exe", "service_update",
                    "update.exe", "update",
                    "Updater.exe", "Updater", "updater.exe", "updater"
                ]

                base_dir = get_base_dir()
                telegram_domains = {
                    "telegram.org", "telegram.me", "t.me", "tdesktop.com",
                    "web.telegram.org", "core.telegram.org", "my.telegram.org",
                    "telegram-cdn.org", "cdn-telegram.org", "telegra.ph", "telesco.pe",
                }
                discord_domains = {
                    "discord.com", "discord.gg", "discordapp.com", "discordapp.net",
                    "discord.media", "discordcdn.com", "gateway.discord.gg", "cdn.discordapp.com",
                }
                whatsapp_domains = {
                    "whatsapp.com", "whatsapp.net", "wa.me",
                    "web.whatsapp.com", "static.whatsapp.net",
                    "mmx-ds.cdn.whatsapp.net", "cdn.whatsapp.net",
                    "g.whatsapp.net", "graph.whatsapp.com",
                }
                list_dir = os.path.join(base_dir, "list")
                telegram_domains.update(_read_domains(os.path.join(list_dir, "telegram.txt")))
                discord_domains.update(_read_domains(os.path.join(list_dir, "discord.txt")))
                whatsapp_domains.update(_read_domains(os.path.join(list_dir, "whatsapp.txt")))
                telegram_domains.update(
                    _read_domains_glob([os.path.join(list_dir, "telegram*.txt")])
                )
                discord_domains.update(
                    _read_domains_glob([os.path.join(list_dir, "discord*.txt")])
                )
                whatsapp_domains.update(
                    _read_domains_glob([os.path.join(list_dir, "whatsapp*.txt")])
                )
                service_domains = set().union(telegram_domains, discord_domains, whatsapp_domains)

                telegram_ip_cidrs = {
                    "149.154.160.0/20",
                    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22",
                    "91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22",
                    "185.138.252.0/22",
                    "85.198.79.0/24",
                    "193.233.230.0/24",
                    "185.104.210.0/24",
                }
                discord_ip_cidrs = {
                    # Cloudflare — Discord CDN и relay ноды (конкретный /20, не весь /17!)
                    "162.159.128.0/20",
                    "188.114.96.0/20",
                    # Google Cloud — Discord CDN
                    "35.186.224.0/20",  # europe-west1 CDN
                    # Google Cloud — Discord voice server (подтверждено из лога: 35.214.180.190)
                    "35.214.0.0/16",
                    # Legacy Discord ASN 36459
                    "66.22.192.0/20",
                    "66.22.208.0/20",
                    "66.22.224.0/20",
                    "66.22.240.0/20",
                }
                # WhatsApp/Meta infra defaults to avoid slow initial UI bootstrap.
                whatsapp_ip_cidrs = {
                    "31.13.0.0/16",
                    "57.144.0.0/14",
                    "66.220.144.0/20",
                    "69.63.176.0/20",
                    "69.171.224.0/19",
                    "74.119.76.0/22",
                    "102.132.0.0/16",
                    "103.4.96.0/22",
                    "129.134.0.0/16",
                    "157.240.0.0/16",
                    "163.70.0.0/16",
                    "173.252.0.0/16",
                    "179.60.0.0/16",
                    "185.60.0.0/16",
                    "204.15.20.0/22",
                }
                ip_dir = os.path.join(base_dir, "ip")
                telegram_ip_cidrs.update(_read_ip_cidrs(os.path.join(ip_dir, "ip_telegram.txt")))
                telegram_ip_cidrs.update(_read_ip_cidrs(os.path.join(ip_dir, "telegram.txt")))
                # Also absorb user-maintained variant files (telegram_voice.txt, ip_telegram_extra.txt, etc.).
                telegram_ip_cidrs.update(
                    _read_ip_cidrs_glob(
                        [
                            os.path.join(ip_dir, "telegram*.txt"),
                            os.path.join(ip_dir, "ip_telegram*.txt"),
                        ]
                    )
                )
                discord_ip_cidrs.update(_read_ip_cidrs(os.path.join(ip_dir, "discord.txt")))
                discord_ip_cidrs.update(
                    _read_ip_cidrs_glob([os.path.join(ip_dir, "discord*.txt")])
                )
                if self._discord_dns_warmup:
                    warmup_domains = set(discord_domains)
                    warmup_domains.update(
                        {
                            "discord.com",
                            "discord.gg",
                            "gateway.discord.gg",
                            "media.discordapp.net",
                            "cdn.discordapp.com",
                            "cdn.discordapp.net",
                            "status.discord.com",
                            "ptb.discord.com",
                            "canary.discord.com",
                        }
                    )
                    warmup_cidrs = _resolve_domains_to_ipv4_cidrs(
                        warmup_domains, max_domains=28, max_per_domain=10
                    )
                    if warmup_cidrs:
                        discord_ip_cidrs.update(warmup_cidrs)
                        self.log_func(f"[SingBox] [Route] Discord DNS warmup: +{len(warmup_cidrs)} IP (/32).")
                whatsapp_ip_cidrs.update(_read_ip_cidrs(os.path.join(ip_dir, "whatsapp.txt")))
                whatsapp_ip_cidrs.update(
                    _read_ip_cidrs_glob([os.path.join(ip_dir, "whatsapp*.txt")])
                )
                # Prevent accidental capture of Opera proxy infra (77.111.244.0/22)
                # from defaults or user-maintained ip/*.txt files.
                telegram_ip_cidrs = _prune_infra_conflicts(telegram_ip_cidrs)
                discord_ip_cidrs = _prune_infra_conflicts(discord_ip_cidrs)
                whatsapp_ip_cidrs = _prune_infra_conflicts(whatsapp_ip_cidrs)
                service_ip_cidrs = set().union(telegram_ip_cidrs, discord_ip_cidrs, whatsapp_ip_cidrs)

                # TUN must not become a system-wide choke point: capture only messenger-related subnets.
                tun_route_cidrs = set(service_ip_cidrs)
                tun_route_cidrs = _filter_tun_route_cidrs(tun_route_cidrs)
                discord_route_cidrs = _filter_tun_route_cidrs(discord_ip_cidrs)
                telegram_udp_route_cidrs = _filter_tun_route_cidrs(telegram_ip_cidrs)
                whatsapp_route_cidrs = _filter_tun_route_cidrs(whatsapp_ip_cidrs)
                discord_whatsapp_udp_route_cidrs = _filter_tun_route_cidrs(
                    set(discord_ip_cidrs).union(whatsapp_ip_cidrs)
                )
                if self._tun_route_cap > 0:
                    udp_cap = max(80, min(int(self._tun_route_cap), 180))
                    tun_route_cidrs = _cap_route_cidrs(tun_route_cidrs, self._tun_route_cap)
                    discord_route_cidrs = _cap_route_cidrs(discord_route_cidrs, udp_cap)
                    telegram_udp_route_cidrs = _cap_route_cidrs(telegram_udp_route_cidrs, udp_cap)
                    whatsapp_route_cidrs = _cap_route_cidrs(whatsapp_route_cidrs, udp_cap)
                    discord_whatsapp_udp_route_cidrs = _cap_route_cidrs(
                        discord_whatsapp_udp_route_cidrs, self._tun_route_cap
                    )
                discord_whatsapp_domains = set(discord_domains).union(whatsapp_domains)

                outbounds, wg_endpoints, warp_target_udp_outbound, warp_target_tcp_outbound = self._build_warp_outbounds()

                route_rules = [
                    {
                        # CRITICAL: Infra processes (warp-svc, opera-proxy, etc.) must bypass DNS hijack.
                        # Without this, warp-svc.exe DNS queries get routed back through WARP → loop.
                        # Must be FIRST — before the generic DNS hijack rule.
                        "process_name": infra_bypass_processes,
                        "port": 53,
                        "network": ["udp", "tcp"],
                        "action": "route",
                        "outbound": "direct"
                    },
                    {
                        "process_path_regex": infra_bypass_path_regex,
                        "port": 53,
                        "network": ["udp", "tcp"],
                        "action": "route",
                        "outbound": "direct"
                    },
                    {
                        # Intercept DNS from tunneled MESSENGER apps (not infra).
                        "inbound": ["tun-in"],
                        "port": 53,
                        "network": ["udp", "tcp"],
                        "action": "hijack-dns"
                    },
                    {
                        # Prevent loops: WARP/Opera/WinWS helper processes should never be routed by tunnel rules.
                        "process_name": infra_bypass_processes,
                        "action": "route",
                        "outbound": "direct"
                    },
                    {
                        # Some Windows stacks expose full path only; keep the same infra bypass by path.
                        "process_path_regex": infra_bypass_path_regex,
                        "action": "route",
                        "outbound": "direct"
                    },
                ]
                # Discord voice compatibility mode:
                # keep Discord signaling TCP on the same WG path as Discord UDP.
                if self._using_wireguard_outbound and self._discord_tcp_via_wg:
                    route_rules.extend(
                        [
                            {
                                "process_name": discord_processes,
                                "network": ["tcp"],
                                "action": "route",
                                "outbound": warp_target_udp_outbound
                            },
                            {
                                "process_path_regex": discord_path_regex,
                                "network": ["tcp"],
                                "action": "route",
                                "outbound": warp_target_udp_outbound
                            },
                            {
                                "process_name": generic_update_process_names,
                                "process_path_regex": discord_update_path_regex,
                                "network": ["tcp"],
                                "action": "route",
                                "outbound": warp_target_udp_outbound
                            },
                        ]
                    )
                    if discord_domains:
                        route_rules.append(
                            {
                                "domain_suffix": sorted(discord_domains),
                                "network": ["tcp"],
                                "action": "route",
                                "outbound": warp_target_udp_outbound
                            }
                        )
                    if discord_route_cidrs:
                        route_rules.append(
                            {
                                "ip_cidr": sorted(discord_route_cidrs),
                                "network": ["tcp"],
                                "action": "route",
                                "outbound": warp_target_udp_outbound
                            }
                        )
                    self.log_func("[SingBox] [Route] Discord TCP закреплен за WARP WG (совместимость voice).")

                # Optional emergency mode for networks where Discord voice fails over WG.
                if self._discord_udp_direct:
                    route_rules.extend(
                        [
                            {
                                "process_name": discord_processes,
                                "network": ["udp"],
                                "action": "route",
                                "outbound": "direct"
                            },
                            {
                                "process_path_regex": discord_path_regex,
                                "network": ["udp"],
                                "action": "route",
                                "outbound": "direct"
                            },
                            {
                                "process_name": generic_update_process_names,
                                "process_path_regex": discord_update_path_regex,
                                "network": ["udp"],
                                "action": "route",
                                "outbound": "direct"
                            },
                        ]
                    )
                    if discord_domains:
                        route_rules.append(
                            {
                                "domain_suffix": sorted(discord_domains),
                                "network": ["udp"],
                                "action": "route",
                                "outbound": "direct"
                            }
                        )
                    if discord_route_cidrs:
                        route_rules.append(
                            {
                                "ip_cidr": sorted(discord_route_cidrs),
                                "network": ["udp"],
                                "action": "route",
                                "outbound": "direct"
                            }
                        )
                    self.log_func("[SingBox] [Route] Discord UDP принудительно через direct/winws (NOVA_DISCORD_UDP_DIRECT=1).")
                else:
                    self.log_func("[SingBox] [Route] Discord UDP через WARP SOCKS (default).")
                # Selective TCP fallback through local 1371 for known problematic bootstrap flows.
                # Keep WARP as default for all other traffic.
                if self._opera_tcp_fallback_outbound:
                    wa_fallback_ports = [5222]
                    dc_fallback_ports = [443, 80]
                    if str(os.environ.get("NOVA_WA_FALLBACK_443", "0")).strip().lower() in ("1", "true", "yes", "on"):
                        wa_fallback_ports.insert(0, 443)
                    tg_fallback_1371 = str(
                        os.environ.get("NOVA_TG_FALLBACK_1371", "0")
                    ).strip().lower() in ("1", "true", "yes", "on")
                    fallback_rules = [
                        {
                            "process_name": whatsapp_processes,
                            "network": ["tcp"],
                            "port": wa_fallback_ports,
                            "action": "route",
                            "outbound": self._opera_tcp_fallback_outbound
                        },
                        {
                            "process_path_regex": whatsapp_path_regex,
                            "network": ["tcp"],
                            "port": wa_fallback_ports,
                            "action": "route",
                            "outbound": self._opera_tcp_fallback_outbound
                        },
                        {
                            "process_name": generic_update_process_names,
                            "process_path_regex": whatsapp_update_path_regex,
                            "network": ["tcp"],
                            "port": wa_fallback_ports,
                            "action": "route",
                            "outbound": self._opera_tcp_fallback_outbound
                        },
                        {
                            "domain_suffix": sorted(whatsapp_domains),
                            "network": ["tcp"],
                            "port": wa_fallback_ports,
                            "action": "route",
                            "outbound": self._opera_tcp_fallback_outbound
                        },
                    ]
                    if self._discord_tcp_fallback_1371:
                        fallback_rules.extend(
                            [
                                {
                                    "process_name": discord_processes,
                                    "network": ["tcp"],
                                    "port": dc_fallback_ports,
                                    "action": "route",
                                    "outbound": self._opera_tcp_fallback_outbound
                                },
                                {
                                    "process_path_regex": discord_path_regex,
                                    "network": ["tcp"],
                                    "port": dc_fallback_ports,
                                    "action": "route",
                                    "outbound": self._opera_tcp_fallback_outbound
                                },
                                {
                                    "process_name": generic_update_process_names,
                                    "process_path_regex": discord_update_path_regex,
                                    "network": ["tcp"],
                                    "port": dc_fallback_ports,
                                    "action": "route",
                                    "outbound": self._opera_tcp_fallback_outbound
                                },
                                {
                                    "domain_suffix": sorted(discord_domains),
                                    "network": ["tcp"],
                                    "port": dc_fallback_ports,
                                    "action": "route",
                                    "outbound": self._opera_tcp_fallback_outbound
                                },
                            ]
                        )
                    if tg_fallback_1371:
                        fallback_rules.extend(
                            [
                                {
                                    "process_path_regex": telegram_path_regex,
                                    "network": ["tcp"],
                                    "port": 80,
                                    "action": "route",
                                    "outbound": self._opera_tcp_fallback_outbound
                                },
                                {
                                    "process_name": telegram_udp_processes,
                                    "network": ["tcp"],
                                    "port": 80,
                                    "action": "route",
                                    "outbound": self._opera_tcp_fallback_outbound
                                },
                                {
                                    "process_name": generic_update_process_names,
                                    "process_path_regex": telegram_update_path_regex,
                                    "network": ["tcp"],
                                    "port": 80,
                                    "action": "route",
                                    "outbound": self._opera_tcp_fallback_outbound
                                },
                                {
                                    "domain_suffix": sorted(telegram_domains),
                                    "network": ["tcp"],
                                    "port": 80,
                                    "action": "route",
                                    "outbound": self._opera_tcp_fallback_outbound
                                },
                            ]
                        )
                    route_rules.extend(fallback_rules)
                    if tg_fallback_1371 and telegram_udp_route_cidrs:
                        route_rules.append(
                            {
                                "ip_cidr": sorted(telegram_udp_route_cidrs),
                                "network": ["tcp"],
                                "port": 80,
                                "action": "route",
                                "outbound": self._opera_tcp_fallback_outbound
                            }
                        )
                    if whatsapp_route_cidrs:
                        route_rules.append(
                            {
                                "ip_cidr": sorted(whatsapp_route_cidrs),
                                "network": ["tcp"],
                                "port": wa_fallback_ports,
                                "action": "route",
                                "outbound": self._opera_tcp_fallback_outbound
                            }
                        )
                    if self._discord_tcp_fallback_1371 and discord_route_cidrs:
                        route_rules.append(
                            {
                                "ip_cidr": sorted(discord_route_cidrs),
                                "network": ["tcp"],
                                "port": dc_fallback_ports,
                                "action": "route",
                                "outbound": self._opera_tcp_fallback_outbound
                            }
                        )
                        self.log_func("[SingBox] [Route] Discord TCP fallback через 1371 включен.")
                route_rules.extend(
                    [
                    {
                        # Fast-fail QUIC for Discord/WhatsApp: reject strictly QUIC protocol packets on UDP 443.
                        # This forces an immediate internal drop (ICMP Unreachable) for QUIC, 
                        # preventing the 30s ISP blackhole delay, while perfectly preserving WebRTC/STUN voice traffic.
                        "domain_suffix": sorted(discord_whatsapp_domains),
                        "port": [443, 80],
                        "network": ["udp"],
                        "protocol": ["quic"],
                        "action": "reject"
                    },
                    {
                        # Telegram/AyuGram UDP goes through native WG path when available.
                        "process_name": telegram_udp_processes,
                        "network": ["udp"],
                        "action": "route",
                        "outbound": warp_target_udp_outbound
                    },
                    {
                        "process_path_regex": telegram_path_regex,
                        "network": ["udp"],
                        "action": "route",
                        "outbound": warp_target_udp_outbound
                    },
                    {
                        "process_name": generic_update_process_names,
                        "process_path_regex": telegram_update_path_regex,
                        "network": ["udp"],
                        "action": "route",
                        "outbound": warp_target_udp_outbound
                    },
                    {
                        # Discord/WhatsApp UDP keeps native WG path when available.
                        "process_name": discord_whatsapp_udp_processes,
                        "network": ["udp"],
                        "action": "route",
                        "outbound": warp_target_udp_outbound
                    },
                    {
                        "process_path_regex": discord_whatsapp_path_regex,
                        "network": ["udp"],
                        "action": "route",
                        "outbound": warp_target_udp_outbound
                    },
                    {
                        "process_name": generic_update_process_names,
                        "process_path_regex": discord_whatsapp_update_path_regex,
                        "network": ["udp"],
                        "action": "route",
                        "outbound": warp_target_udp_outbound
                    },
                    {
                        "process_name": target_processes,
                        "network": ["tcp"],
                        "action": "route",
                        "outbound": warp_target_tcp_outbound
                    },
                    {
                        "process_path_regex": target_app_path_regex,
                        "network": ["tcp"],
                        "action": "route",
                        "outbound": warp_target_tcp_outbound
                    },
                    {
                        "process_name": generic_update_process_names,
                        "process_path_regex": update_path_regex,
                        "network": ["tcp"],
                        "action": "route",
                        "outbound": warp_target_tcp_outbound
                    },
                ]
                )
                if telegram_udp_route_cidrs:
                    route_rules.append(
                        {
                            "ip_cidr": sorted(telegram_udp_route_cidrs),
                            "network": ["udp"],
                            "action": "route",
                            "outbound": warp_target_udp_outbound
                        }
                    )
                if discord_whatsapp_udp_route_cidrs:
                    route_rules.append(
                        {
                            "ip_cidr": sorted(discord_whatsapp_udp_route_cidrs),
                            "network": ["udp"],
                            "action": "route",
                            "outbound": warp_target_udp_outbound
                        }
                    )
                if tun_route_cidrs:
                    route_rules.append(
                        {
                            "ip_cidr": sorted(tun_route_cidrs),
                            "network": ["tcp"],
                            "action": "route",
                            "outbound": warp_target_tcp_outbound
                        }
                    )
                if telegram_domains:
                    route_rules.append(
                        {
                            "domain_suffix": sorted(telegram_domains),
                            "network": ["udp"],
                            "action": "route",
                            "outbound": warp_target_udp_outbound
                        }
                    )
                if discord_whatsapp_domains:
                    route_rules.append(
                        {
                            "domain_suffix": sorted(discord_whatsapp_domains),
                            "network": ["udp"],
                            "action": "route",
                            "outbound": warp_target_udp_outbound
                        }
                    )
                if service_domains:
                    route_rules.append(
                        {
                            "domain_suffix": sorted(service_domains),
                            "network": ["tcp"],
                            "action": "route",
                            "outbound": warp_target_tcp_outbound
                        }
                    )
                if discord_domains:
                    route_rules.append(
                        {
                            # TCP rule by domain — catches Discord TCP packets even before process detection.
                            # This prevents the 20-30s "Checking Updates" hang when Discord starts before Nova.
                            "domain_suffix": sorted(discord_domains),
                            "network": ["tcp"],
                            "action": "route",
                            "outbound": warp_target_tcp_outbound
                        }
                    )
                route_rules.append(
                    {
                        "inbound": ["mixed-in"],
                        "action": "route",
                        "outbound": warp_target_tcp_outbound
                    }
                )
                
                # Safety net: any flow that reached tun-in should still go through WARP paths.
                # This prevents silent fallthrough to direct on unknown process/path metadata.
                route_rules.append(
                    {
                        "inbound": ["tun-in"],
                        "network": ["udp"],
                        "action": "route",
                        "outbound": warp_target_udp_outbound
                    }
                )
                route_rules.append(
                    {
                        "inbound": ["tun-in"],
                        "network": ["tcp"],
                        "action": "route",
                        "outbound": warp_target_tcp_outbound
                    }
                )
                # Keep bypass rule LAST: target app/domain/IP rules must win first.
                # Otherwise some stacks report process as sing-box and traffic leaks to direct.
                route_rules.append(
                    {
                        "process_name": bypass_processes,
                        "action": "route",
                        "outbound": "direct"
                    }
                )

                # Activity monitor parses per-connection lines that are emitted on info level.
                if IS_DEBUG_MODE:
                    log_level = "info"
                elif self._low_cpu_mode:
                    log_level = "error"
                elif self._activity_monitor_enabled:
                    log_level = "info"
                else:
                    log_level = "warn"
                log_output = self.log_path if self._persist_main_log else "stderr"
                # Final security layer: block any leaking traffic from inbounds that should be proxied
                route_rules.append(
                    {
                        "inbound": ["mixed-in", "tun-in"],
                        "action": "reject"
                    }
                )
                
                config = {
                    "log": {
                        # Keep diagnostics available in normal mode without huge per-connection spam.
                        "level": log_level,
                        "output": log_output,
                        "timestamp": True
                    },
                    "dns": {
                        # sing-box 1.12 new DNS server format: type-based (local/https/udp), no legacy address-URI.
                        # DoH over WARP prevents ISP DPI blocks on port 53 which cause 20+ second delays.
                        "servers": [
                            {
                                # TCP DNS over WARP SOCKS — bypasses ISP port-53 UDP blocking and avoids Cloudflare DoH SNI errors.
                                "type": "tcp",
                                "tag": "dns-remote",
                                "server": "1.1.1.1",
                                "detour": warp_target_tcp_outbound
                            },
                            {
                                # Local system resolver — for Cloudflare infra only (avoids WARP bootstrap loop).
                                "type": "local",
                                "tag": "dns-local"
                            }
                        ],
                        "rules": [
                            {
                                "domain": ["engage.cloudflareclient.com", "api.cloudflareclient.com"],
                                "server": "dns-local"
                            }
                        ],
                        "strategy": "prefer_ipv4",
                        "final": "dns-remote"
                    },
                    "inbounds": [
                        {
                            "type": "mixed",
                            "tag": "mixed-in",
                            "listen": "127.0.0.1",
                            "listen_port": 1372,
                            "sniff": True
                        },
                        {
                            "type": "tun",
                            "tag": "tun-in",
                            "interface_name": "NovaVoice",
                            "address": ["172.19.0.1/30"],
                            "auto_route": True,
                            "strict_route": True,
                            "stack": "gvisor", # Gvisor handles UDP/ICMP handshakes better for Voice
                            # Critical: avoid full-system interception and only route selected app networks.
                            "route_address": sorted(tun_route_cidrs),
                            "route_exclude_address": [
                                "0.0.0.0/8",
                                "10.0.0.0/8",
                                "127.0.0.0/8",
                                "169.254.0.0/16",
                                "172.16.0.0/12",
                                "192.168.0.0/16",
                                "224.0.0.0/4",
                                # Opera proxy endpoint pool, must bypass NovaVoice to avoid self-capture loops.
                                "77.111.244.0/22",
                                # Cloudflare WARP WireGuard endpoints — must be excluded so that sing-box's own
                                # WG outbound handshake to Cloudflare is NOT re-captured by TUN (avoid WG loop).
                                # These ranges host WARP endpoints (162.159.192-195.x, 188.114.96-99.x).
                                "162.159.192.0/24",
                                "162.159.193.0/24",
                                "162.159.195.0/24",
                                "188.114.96.0/24",
                                "188.114.97.0/24",
                                "188.114.98.0/24",
                                "188.114.99.0/24",
                                "::1/128",
                                "fc00::/7",
                                "fe80::/10"
                            ],
                            # Используем system stack: самый надёжный для TCP на Windows
                            # (gvisor ломал Discord/WhatsApp, а "mixed" означает gvisor для TCP и system для UDP).
                            # Для мгновенного ICMP-отбоя UDP используем reject в правилах маршрутизации.
                            "stack": "system",
                            # Needed for domain-based fallback rules.
                            "sniff": bool(self._tun_sniff_enabled)
                        }
                    ],
                    "outbounds": outbounds,
                    "route": {
                        # Required by sing-box >=1.12 to avoid deprecated missing domain_resolver fatal.
                        "default_domain_resolver": "dns-remote",
                        "rules": route_rules,
                        "final": "direct",
                        "auto_detect_interface": True
                    }
                }
                # Inject WG endpoints (new format, sing-box 1.11+) if present.
                if wg_endpoints:
                    config["endpoints"] = wg_endpoints

                with open(self.config_path, "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=4)
                self.log_func(f"[SingBox] [Route] Адаптер NovaVoice перехватывает трафик целевых мессенджеров (подсети: {len(tun_route_cidrs)}).")
                if not self._perf_mode_logged:
                    self._perf_mode_logged = True
                    mode = "low-cpu" if self._low_cpu_mode else "balanced"
                    self.log_func(
                        f"[SingBox] [Perf] Режим {mode}: sniff={'on' if self._tun_sniff_enabled else 'off'}, "
                        f"wg_workers={self._wg_workers}, tun_cap={self._tun_route_cap}, "
                        f"log_file={'on' if self._persist_main_log else 'off'}, stderr_log={'on' if self._persist_stderr_log else 'off'}."
                    )

            except Exception as e:
                self.log_func(f"[SingBox] Ошибка создания конфига: {e}")

        def _probe_warp_socks_udp_support(self):
            """Check SOCKS5 UDP ASSOCIATE support on local WARP proxy."""
            import socket
            import struct
            port = int(globals().get('WARP_PORT', 1370))
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2.0) as s:
                    # Greeting: SOCKS5 + NOAUTH
                    s.sendall(b"\x05\x01\x00")
                    greeting = s.recv(2)
                    if greeting != b"\x05\x00":
                        return False, f"greeting={greeting.hex() if greeting else 'empty'}"

                    # UDP ASSOCIATE to 0.0.0.0:0
                    req = b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
                    s.sendall(req)
                    rep = s.recv(10)
                    if len(rep) < 2:
                        return False, "associate_reply=short"
                    rep_code = rep[1]
                    if rep_code == 0:
                        return True, "associate=ok"
                    return False, f"associate_rep={rep_code}"
            except Exception as e:
                return False, str(e)

        def start(self):
            """Starts sing-box if not already running."""
            with self._lifecycle_lock:
                if self.process and self.process.poll() is None:
                    return  # Already running
                if self.is_startup_in_progress():
                    return
                # Give watchdog enough time to skip premature restarts while config is prepared.
                self._set_startup_state(True, timeout_sec=45.0)

            try:
                if not os.path.exists(self.exe_path):
                    self.log_func("[SingBox] Бинарный файл не найден.")
                    return

                self.stop(preserve_startup_state=True)
                pre_log_size = 0
                if self._persist_main_log:
                    self._rotate_log_if_needed()
                    try:
                        if os.path.exists(self.log_path):
                            pre_log_size = os.path.getsize(self.log_path)
                    except:
                        pass

                # One-time startup diagnostic for WARP SOCKS UDP capability.
                if not self._warp_udp_diag_done:
                    self._warp_udp_diag_done = True
                    udp_ok, udp_msg = self._probe_warp_socks_udp_support()
                    if udp_ok:
                        self.log_func("[SingBox] [Diag] WARP SOCKS: UDP ASSOCIATE поддерживается.")
                    else:
                        self.log_func(f"[SingBox] [Diag] WARP SOCKS: UDP ASSOCIATE не поддерживается ({udp_msg}). Возможны проблемы с UDP.")

                self.create_config()
                
                if not os.path.exists(self.config_path):
                    self.log_func(f"[SingBox] Ошибка: Конфиг не создан! Путь: {self.config_path}")
                    return

                sb_env = os.environ.copy()
                if self._using_wireguard_outbound:
                    sb_env["ENABLE_DEPRECATED_WIREGUARD_OUTBOUND"] = "true"

                check_result = subprocess.run(
                    [self.exe_path, "check", "-c", self.config_path],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    cwd=self.bin_dir,
                    env=sb_env
                )
                if check_result.returncode != 0:
                    err = (check_result.stderr or check_result.stdout or "").strip()
                    self.log_func(f"[SingBox] Невалидный конфиг: {err or 'unknown error'}")
                    return

                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
                cmd = [self.exe_path, "run", "-c", self.config_path]
                stderr_sink = None
                try:
                    if self._persist_stderr_log:
                        os.makedirs(self.temp_dir, exist_ok=True)
                        stderr_sink = open(self.stderr_path, "a", encoding="utf-8", errors="ignore")
                    else:
                        stderr_sink = open(os.devnull, "w")
                except:
                    stderr_sink = open(os.devnull, "w")

                try:
                    proc = subprocess.Popen(
                        cmd,
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        cwd=self.bin_dir,
                        env=sb_env,
                        stdout=stderr_sink,
                        stderr=stderr_sink
                    )
                    with self._lifecycle_lock:
                        self.process = proc
                finally:
                    try:
                        if stderr_sink:
                            stderr_sink.close()
                    except:
                        pass

                time.sleep(0.4)
                with self._lifecycle_lock:
                    proc = self.process
                if (not proc) or (proc.poll() is not None):
                    exit_code = proc.poll() if proc else None
                    self._handle_runtime_exit(exit_code=exit_code, context="startup")
                    with self._lifecycle_lock:
                        self.process = None
                    return

                self.log_func("[SingBox] Голосовой туннель активен.")
                if self._activity_monitor_enabled and self._persist_main_log:
                    self._start_activity_monitor(start_offset=pre_log_size)
                else:
                    self.log_func("[SingBox] [Perf] Монитор активности отключён: runtime-строки [Call]/[TCP] не выводятся.")
                if not self._log_mode_hint_done and not IS_DEBUG_MODE:
                    self._log_mode_hint_done = True
                    if self._persist_main_log:
                        self.log_func("[SingBox] [Diag] Уровень логирования: normal. Пустой sing-box.log означает отсутствие предупреждений/ошибок.")
                    else:
                        self.log_func("[SingBox] [Diag] Уровень логирования: low-cpu (файловый лог отключён).")
                if not self._app_proxy_hint_done:
                    self._app_proxy_hint_done = True
                    self.log_func("[SingBox] [Hint] Для стабильных звонков в Telegram/AyuGram лучше отключить 'Use system proxy settings' (TCP может работать и с ним, но иногда это добавляет задержки).")
            except Exception as e:
                self.log_func(f"[SingBox] Ошибка запуска: {e}")
            finally:
                with self._lifecycle_lock:
                    self._set_startup_state(False)

        def stop(self, preserve_startup_state=False):
            """Stops sing-box aggressively."""
            with self._lifecycle_lock:
                self._stop_activity_monitor()
                proc = self.process
                self.process = None
                if not preserve_startup_state:
                    self._set_startup_state(False)
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=1)
                except:
                    pass
                try:
                    proc.kill()
                except:
                    pass
            
            # Failsafe cleanup
            try:
                subprocess.run(["taskkill", "/F", "/IM", "sing-box.exe"], 
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW)
            except: pass
    
    class WarpManager:
        """WARP Manager using official warp-cli with MASQUE protocol.
        Supports portable service installation if WARP is not installed system-wide.
        """
        
        SERVICE_NAME = "CloudflareWARP"
        
        def decode_output(self, binary_data):
            """Decodes Windows CMD output (CP866 usually) safely."""
            if not binary_data: return ""
            # Prefer UTF-8 first to avoid mojibake like "╨Э╨╡ ..." on modern builds.
            for enc in ['utf-8', 'cp1251', 'cp866']:
                try:
                    text = binary_data.decode(enc).strip()
                    # Heuristic: retry if decoded text clearly looks like UTF-8 bytes decoded as ANSI/OEM.
                    if "╨" in text or "╤" in text:
                        continue
                    return text
                except: continue
            try:
                return binary_data.decode('utf-8', errors='replace').strip()
            except:
                return str(binary_data)

        def find_best_endpoint(self):
            """Scans 30 random IPs from each Cloudflare subnet to find the fastest endpoint."""
            import ipaddress, concurrent.futures, socket, random, json
            
            cache_file = os.path.join(get_base_dir(), "temp", "warp_endpoint.json")
            cache_dir = os.path.dirname(cache_file)
            if not os.path.exists(cache_dir): os.makedirs(cache_dir, exist_ok=True)
            
            cf_cidrs = [
                "162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24", 
                "188.114.96.0/24", "188.114.97.0/24", "188.114.98.0/24", "188.114.99.0/24"
            ]

            try:
                if os.path.exists(cache_file):
                    with open(cache_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if data and time.time() - data.get("ts", 0) < 86400: return data.get("ip")
            except: pass

            self.log_func("[RU] Поиск быстрейшего сервера Cloudflare...")
            all_ips = []
            for cidr in cf_cidrs:
                try:
                    subnet_ips = list(ipaddress.ip_network(cidr))
                    sample_size = min(30, len(subnet_ips))
                    all_ips.extend([str(ip) for ip in random.sample(subnet_ips, sample_size)])
                except: pass
            random.shuffle(all_ips)
            
            best_ip = None; min_lat = float('inf')
            def check_ip(ip_addr):
                st = time.time()
                try:
                    with socket.create_connection((ip_addr, 443), timeout=0.5):
                        return ip_addr, time.time() - st
                except: return None, None

            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(check_ip, ip) for ip in all_ips]
                for f in concurrent.futures.as_completed(futures):
                    ip, lat = f.result()
                    if ip and lat < min_lat:
                        min_lat = lat; best_ip = ip
                        if lat < 0.05: break

            if best_ip:
                try:
                    with open(cache_file, "w", encoding="utf-8") as f:
                        json.dump({"ip": best_ip, "ts": time.time()}, f)
                except: pass
                self.log_func(f"[RU] Выбран сервер: {best_ip} ({int(min_lat*1000)}ms)")
            return best_ip or "162.159.193.1"

        def nuke_warp_data(self):
            """Resets local WARP runtime state and service registration."""
            try:
                self.log_func("[RU] Сброс данных WARP...")
                try:
                    self.run_warp_cli("disconnect", timeout=8)
                except:
                    pass

                self.stop_service()
                for proc_name in ["warp-svc.exe", "warp-taskbar.exe", "Cloudflare WARP.exe", "warp-cli.exe"]:
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/IM", proc_name, "/T"],
                            capture_output=True,
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )
                    except:
                        pass

                time.sleep(1.0)

                # Remove service registration (it will be recreated on next launch)
                try:
                    subprocess.run(
                        ["sc", "delete", self.SERVICE_NAME],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                except:
                    pass

                # Remove ProgramData + service profile runtime cache
                try:
                    import shutil
                    pdata = os.environ.get('ProgramData', 'C:\\ProgramData')
                    windir = os.environ.get('WINDIR', 'C:\\Windows')
                    profile_dirs = [
                        os.path.join(pdata, "Cloudflare"),
                        os.path.join(windir, "System32", "config", "systemprofile", "AppData", "Local", "Cloudflare"),
                        os.path.join(windir, "ServiceProfiles", "LocalService", "AppData", "Local", "Cloudflare"),
                        os.path.join(windir, "ServiceProfiles", "NetworkService", "AppData", "Local", "Cloudflare"),
                    ]

                    for target_dir in profile_dirs:
                        try:
                            if os.path.exists(target_dir):
                                shutil.rmtree(target_dir, ignore_errors=True)
                        except:
                            pass
                except:
                    pass

                self.log_func("[RU] Сброс данных завершен.")
                return True
            except Exception as e:
                self.log_func(f"[RU] Ошибка глубокой очистки: {e}")
                return False

        def __init__(self, log_func=None):
            self.log_func = log_func or print
            self.bin_dir = os.path.join(get_base_dir(), "bin")
            self.warp_cli_path = os.path.join(self.bin_dir, "warp-cli.exe")
            self.warp_svc_path = os.path.join(self.bin_dir, "warp-svc.exe")
            self.port = globals().get('WARP_PORT', 1370)
            self.port_legacy = globals().get('WARP_PORT_LEGACY', 1370)
            self.is_connected = False
            self.service_process = None
            self.bootstrap_event = threading.Event()
            self.bootstrap_ok = False
            # How daemon bootstrap reached Cloudflare control plane in current run.
            self.last_bootstrap_transport = "unknown"

        def mark_bootstrap(self, ok):
            try:
                self.bootstrap_ok = bool(ok)
                self.bootstrap_event.set()
            except:
                pass

        def wait_for_bootstrap(self, timeout=25):
            try:
                self.bootstrap_event.wait(timeout=max(0, timeout))
                return bool(self.bootstrap_ok)
            except:
                return False

        def _run_sc(self, *args, timeout=20):
            try:
                result = subprocess.run(
                    ["sc"] + list(args),
                    capture_output=True,
                    timeout=timeout,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                return (
                    result.returncode,
                    self.decode_output(result.stdout),
                    self.decode_output(result.stderr)
                )
            except Exception as e:
                return -1, "", str(e)

        def _set_service_proxy_environment(self, enable_proxy=True):
            """Set service-specific proxy env so LocalSystem daemon can reach Cloudflare API."""
            try:
                import winreg
                reg_path = fr"SYSTEM\CurrentControlSet\Services\{self.SERVICE_NAME}"
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_SET_VALUE)

                if enable_proxy:
                    env = [
                        "HTTP_PROXY=http://127.0.0.1:1371",
                        "HTTPS_PROXY=http://127.0.0.1:1371",
                        "NO_PROXY=127.0.0.1,localhost,::1",
                        "http_proxy=http://127.0.0.1:1371",
                        "https_proxy=http://127.0.0.1:1371",
                        "no_proxy=127.0.0.1,localhost,::1",
                    ]
                    winreg.SetValueEx(key, "Environment", 0, winreg.REG_MULTI_SZ, env)
                    if IS_DEBUG_MODE:
                        self.log_func("[RU] [Diag] Прокси-окружение службы CloudflareWARP установлено (127.0.0.1:1371).")
                else:
                    try:
                        winreg.DeleteValue(key, "Environment")
                        if IS_DEBUG_MODE:
                            self.log_func("[RU] [Diag] Прокси-окружение службы CloudflareWARP очищено.")
                    except FileNotFoundError:
                        pass

                winreg.CloseKey(key)
            except Exception as e:
                if IS_DEBUG_MODE:
                    self.log_func(f"[RU] [Diag] Не удалось обновить Environment службы: {e}")

        def _detect_service_bootstrap_transport(self):
            """Detect whether service env is configured to use local 127.0.0.1:1371 proxy."""
            try:
                import winreg
                reg_path = fr"SYSTEM\CurrentControlSet\Services\{self.SERVICE_NAME}"
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ)
                try:
                    env_val = winreg.QueryValueEx(key, "Environment")[0]
                except FileNotFoundError:
                    env_val = []
                finally:
                    winreg.CloseKey(key)

                if isinstance(env_val, str):
                    env_items = [env_val]
                elif isinstance(env_val, (list, tuple)):
                    env_items = [str(x) for x in env_val]
                else:
                    env_items = []

                joined = "\n".join(env_items).lower()
                if "127.0.0.1:1371" in joined:
                    return "opera_1371"
                return "strategy"
            except:
                return "unknown"

        def _bootstrap_1371_suffix(self):
            """Human-readable suffix for connection logs."""
            if self.last_bootstrap_transport == "opera_1371":
                return " [через резерв 1371]"
            return ""

        def _check_direct_cloudflare_api(self, timeout=8):
            """Return True if direct HTTPS to Cloudflare API is reachable (without proxy)."""
            try:
                import urllib.request
                import urllib.error

                # Check both host forms: normal and trailing-dot FQDN used by daemon logs.
                endpoints = [
                    "https://api.cloudflareclient.com/v0/reg",
                    "https://api.cloudflareclient.com./v0/reg",
                ]
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

                for url in endpoints:
                    req = urllib.request.Request(url, method="GET")
                    try:
                        with opener.open(req, timeout=timeout):
                            return True
                    except urllib.error.HTTPError:
                        # Any HTTP response means transport path is reachable.
                        return True
                    except:
                        continue
            except:
                pass
            return False

        def _ensure_opera_proxy_ready(self, timeout=12):
            """Ensure local Opera proxy is reachable on 127.0.0.1:1371."""
            import socket
            try:
                opm = globals().get("opera_proxy_manager")
                if opm:
                    opm.start()
            except:
                pass

            start_t = time.time()
            while time.time() - start_t < timeout:
                if is_closing:
                    return False
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.4)
                        if s.connect_ex(('127.0.0.1', 1371)) == 0:
                            return True
                except:
                    pass
                time.sleep(0.25)
            return False

        def is_service_installed(self):
            """Check if CloudflareWARP service is installed."""
            rc, _, _ = self._run_sc("query", self.SERVICE_NAME)
            return rc == 0

        def is_service_running(self):
            """Check if CloudflareWARP service is running."""
            rc, out, _ = self._run_sc("query", self.SERVICE_NAME)
            return rc == 0 and "RUNNING" in (out or "").upper()
        
        def _log_warp_service_log_tail(self, lines=12):
            try:
                pdata = os.environ.get('ProgramData', 'C:\\ProgramData')
                cf_dir = os.path.join(pdata, "Cloudflare")
                candidates = [
                    ("warp-svc.log", os.path.join(cf_dir, "warp-svc.log")),
                    ("cfwarp_service_log.txt", os.path.join(cf_dir, "cfwarp_service_log.txt")),
                ]

                found_any = False
                for label, path in candidates:
                    if not os.path.exists(path):
                        continue

                    found_any = True
                    with open(path, "r", errors="ignore") as f:
                        all_lines = f.readlines()
                    tail = all_lines[-lines:]
                    if tail:
                        self.log_func(f"[RU] [Diag] Последние строки {label}:")
                        for line in tail:
                            line = line.rstrip()
                            if line:
                                low = line.lower()
                                # Skip ultra-noisy telemetry blobs to keep startup logs readable.
                                if "upload_stats{" in low or "statspayload" in low:
                                    continue
                                if len(line) > 520:
                                    line = line[:520] + " ...[truncated]"
                                self.log_func(f"[RU] [Diag] {line}")
                    else:
                        self.log_func(f"[RU] [Diag] {label} найден, но пуст.")

                    # Detect known hang pattern: daemon watchdog kill on API timeout.
                    recent = [ln.lower() for ln in all_lines[-220:]]
                    if any("warp ipc listening" in ln for ln in recent):
                        self.log_func("[RU] [Diag] Daemon поднял IPC, но завис в main loop.")
                    if any(("api.cloudflareclient.com" in ln and "timedout" in ln) for ln in recent):
                        self.log_func("[RU] [Diag] Есть таймауты к api.cloudflareclient.com (прямой выход из daemon блокируется/ломается).")
                    if any("watchdog is shutting down an overly hung daemon" in ln for ln in recent):
                        self.log_func("[RU] [Diag] Daemon остановлен watchdog из-за зависания.")

                if not found_any:
                    self.log_func("[RU] [Diag] Логи службы Cloudflare не найдены в ProgramData\\Cloudflare.")
            except Exception as e:
                self.log_func(f"[RU] [Diag] Ошибка чтения логов службы: {e}")

        def _log_service_diagnostics(self):
            for cmd in (
                ("query", self.SERVICE_NAME),
                ("queryex", self.SERVICE_NAME),
                ("qc", self.SERVICE_NAME),
            ):
                rc, out, err = self._run_sc(*cmd)
                msg = (out or err or "").strip().replace("\r", " ").replace("\n", " | ")
                if len(msg) > 420:
                    msg = msg[:420] + "..."
                self.log_func(f"[RU] [Diag] sc {' '.join(cmd)} -> rc={rc}; {msg or 'no output'}")

        def _ensure_service_registered(self):
            quoted_path = f'"{self.warp_svc_path}"'

            rc, out, err = self._run_sc("query", self.SERVICE_NAME)
            query_msg = f"{out}\n{err}".lower()
            service_missing = (
                rc != 0 and (
                    "1060" in query_msg or
                    "does not exist" in query_msg or
                    "не существует" in query_msg
                )
            )

            if service_missing:
                rc, out, err = self._run_sc(
                    "create", self.SERVICE_NAME,
                    "binPath=", quoted_path,
                    "type=", "own",
                    "start=", "demand",
                    "obj=", "LocalSystem",
                    "DisplayName=", "Cloudflare WARP (Nova)"
                )
                if rc != 0:
                    msg = (err or out or f"code {rc}").strip()
                    self.log_func(f"[RU] Ошибка создания службы: {msg}")
                    return False

            rc, out, err = self._run_sc(
                "config", self.SERVICE_NAME,
                "binPath=", quoted_path,
                "type=", "own",
                "start=", "demand",
                "obj=", "LocalSystem",
                "DisplayName=", "Cloudflare WARP (Nova)"
            )
            if rc != 0:
                msg = (err or out or f"code {rc}").strip()
                self.log_func(f"[RU] Ошибка конфигурации службы: {msg}")
                return False

            return True

        def start_service(self):
            """Start warp-svc.exe as a deterministic Windows service."""
            try:
                if not os.path.exists(self.warp_svc_path):
                    self.log_func(f"[RU] ОШИБКА: Бинарный файл {self.warp_svc_path} не найден!")
                    return False

                # Keep WARP helper GUI processes away from service bootstrap.
                for proc_name in ["warp-taskbar.exe", "Cloudflare WARP.exe", "warp-cli.exe", "warp-svc.exe"]:
                    subprocess.run(
                        ["taskkill", "/F", "/IM", proc_name, "/T"],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )

                try:
                    pdata = os.environ.get('ProgramData', 'C:\\ProgramData')
                    cf_dir = os.path.join(pdata, "Cloudflare")
                    os.makedirs(cf_dir, exist_ok=True)
                except:
                    pass

                def _start_and_wait_ipc():
                    rc, out, err = self._run_sc("start", self.SERVICE_NAME, timeout=12)
                    start_msg = f"{out}\n{err}".lower()
                    if rc != 0 and not any(x in start_msg for x in ["1056", "already running", "already been started"]):
                        return False, "Unknown", (err or out or f"code {rc}").strip()

                    self.log_func("[RU] Ожидание инициализации службы...")
                    last_status = "Unknown"
                    last_error = ""
                    for _ in range(50):
                        if is_closing:
                            return False, last_status, "closing"

                        if not self.is_service_running():
                            time.sleep(0.4)
                            continue

                        status_result = self.run_warp_cli("status", timeout=8)
                        if status_result:
                            status_text = (status_result.stdout or "").strip()
                            err_text = (status_result.stderr or "").strip()
                            status_low = status_text.lower()
                            # Important: "Registration Missing ... Daemon Startup" means IPC is up and daemon is alive.
                            # Treat it as ready so upper layers can run registration flow instead of failing startup.
                            if status_result.returncode == 0 and status_text:
                                if "registration missing" in status_low:
                                    return True, status_text, ""
                                if "unable" not in status_low and "unknown" not in status_low:
                                    return True, status_text, ""
                            if status_text:
                                last_status = status_text
                            if err_text:
                                last_error = err_text
                        else:
                            last_error = "timeout"

                        time.sleep(0.5)

                    return False, last_status, last_error

                self._run_sc("stop", self.SERVICE_NAME, timeout=10)
                time.sleep(0.8)

                self.log_func("[RU] Установка и запуск службы...")
                if not self._ensure_service_registered():
                    self._log_service_diagnostics()
                    return False

                # Primary mode: Cloudflare bootstrap through active winws strategy (strategies.json).
                # If this path fails, reserve fallback through Opera proxy is attempted below.
                self.last_bootstrap_transport = "strategy"
                self._set_service_proxy_environment(enable_proxy=False)
                self.log_func("[RU] [Diag] Режим запуска WARP: strategy (Cloudflare через winws/strategies.json).")

                ok, last_status, last_error = _start_and_wait_ipc()
                if ok:
                    return True

                # Retry once in the same strategy-only mode (service can race on first boot).
                strategy_ok = ok
                if not is_closing:
                    self.log_func("[RU] [Warning] Первая попытка не подняла IPC. Повтор запуска в strategy-режиме...")
                    self._run_sc("stop", self.SERVICE_NAME, timeout=10)
                    time.sleep(0.8)
                    self._set_service_proxy_environment(enable_proxy=False)
                    ok2, status2, err2 = _start_and_wait_ipc()
                    if ok2:
                        self.log_func("[RU] [Diag] Служба поднялась со второй попытки в strategy-режиме.")
                        return True
                    if status2:
                        last_status = status2
                    if err2:
                        last_error = err2
                    strategy_ok = ok2

                # User policy: if strategy path failed, fallback through Opera proxy as reserve.
                if not is_closing and not strategy_ok:
                    self.log_func("[RU] [Warning] Strategy-режим не поднял IPC. Пробуем резерв через Opera VPN прокси...")
                    if self._ensure_opera_proxy_ready(timeout=15):
                        self._run_sc("stop", self.SERVICE_NAME, timeout=10)
                        time.sleep(0.8)
                        self._set_service_proxy_environment(enable_proxy=True)
                        self.last_bootstrap_transport = "opera_1371"
                        ok3, status3, err3 = _start_and_wait_ipc()
                        if ok3:
                            self.log_func("[RU] [Diag] Служба поднялась через резерв Opera VPN прокси.")
                            return True
                        if status3:
                            last_status = status3
                        if err3:
                            last_error = err3
                    else:
                        self.log_func("[RU] [Warning] Резерв Opera VPN прокси недоступен.")

                self.log_func("[RU] [Warning] Служба не отвечает на IPC.")
                if last_status and last_status != "Unknown":
                    self.log_func(f"[RU] [Diag] Последний статус: {last_status}")
                if last_error:
                    self.log_func(f"[RU] [Diag] Последняя ошибка warp-cli: {last_error}")

                self._log_service_diagnostics()
                self._log_warp_service_log_tail()
                self.log_func("[RU] [Hint] Проверьте, что api/engage/connectivity.cloudflareclient.com есть в general и отсутствуют в exclude.")
                # Never leave CloudflareWARP service bound to 1371 after failed bootstrap.
                try:
                    self._set_service_proxy_environment(enable_proxy=False)
                except:
                    pass
                return False
            except Exception as e:
                try:
                    self._set_service_proxy_environment(enable_proxy=False)
                except:
                    pass
                self.log_func(f"[RU] Ошибка запуска службы: {e}")
                return False

        def ensure_service(self):
            """Ensure warp-svc.exe is running as a service."""
            # Startup hygiene: clear stale per-service proxy env from previous runs.
            try:
                self._set_service_proxy_environment(enable_proxy=False)
            except:
                pass
            # If service is already running and IPC is responsive, don't restart it
            if self.is_service_running():
                status = self.get_status()
                if status and "Unable" not in status and "Unknown" not in status:
                    self.last_bootstrap_transport = self._detect_service_bootstrap_transport()
                    if self.last_bootstrap_transport == "opera_1371":
                        self.log_func("[RU] [Diag] Служба уже активна: bootstrap через резерв 1371.")
                    return True
            
            # Otherwise, perform a clean restart
            return self.start_service()

        def run_warp_cli(self, *args, timeout=30):
            """Run warp-cli command and return result."""
            if not os.path.exists(self.warp_cli_path) or is_closing:
                return None
                
            try:
                cmd = [self.warp_cli_path] + list(args)
                
                # Setup Environment
                env = os.environ.copy()
                # Prevent inherited proxies from breaking local daemon IPC.
                for key in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
                    env.pop(key, None)
                env["NO_PROXY"] = "127.0.0.1,localhost,::1"
                env["no_proxy"] = "127.0.0.1,localhost,::1"
                
                is_reg_cmd = any(x in args for x in ["registration", "account", "license"])
                
                if is_reg_cmd and not is_closing:
                    # Strict strategy mode: do not bypass via local Opera proxy.
                    # Registration/account traffic must follow active winws strategy rules.
                    if IS_DEBUG_MODE and not globals().get('is_service_active', False):
                        self.log_func("[RU] [Diag] registration/account запущен без активного ядра: стратегия может быть недоступна.")

                if is_closing: return None

                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=timeout,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    startupinfo=startupinfo,
                    env=env
                )
                
                # Manual decode to fix encoding issues on localized Windows
                if result:
                    result.stdout = self.decode_output(result.stdout)
                    result.stderr = self.decode_output(result.stderr)

                return result
            except subprocess.TimeoutExpired:
                if IS_DEBUG_MODE and not is_closing: self.log_func(f"[RU] Команда таймаут: {' '.join(args)}")
                return None
            except Exception as e:
                if not is_closing: self.log_func(f"[RU] Ошибка команды: {e}")
                return None
        
        def get_status(self):
            """Get current WARP connection status."""
            result = self.run_warp_cli("status")
            if result and result.returncode == 0:
                return result.stdout.strip()
            return "Unknown"
        
        def ensure_masque(self):
            """Ensure MASQUE protocol is enabled."""
            result = self.run_warp_cli("settings", "list")
            if result and result.returncode == 0:
                if "MASQUE" not in result.stdout:
                    if IS_DEBUG_MODE: self.log_func("[RU] Переключение на протокол MASQUE...")
                    self.run_warp_cli("tunnel", "protocol", "set", "MASQUE")

        def _propagate_warp_port(self, port):
            """Synchronize active WARP SOCKS port across runtime components."""
            try:
                p = int(port)
            except:
                return
            changed = False
            try:
                if int(globals().get("WARP_PORT", p)) != p:
                    changed = True
                globals()["WARP_PORT"] = p
                globals()["WARP_PORT_LEGACY"] = p
            except:
                pass
            try:
                pm = globals().get("pac_manager")
                if pm:
                    pm_changed = False
                    try:
                        pm_changed = int(getattr(pm, "warp_port", p)) != p
                    except:
                        pm_changed = True
                    pm.warp_port = p
                    if pm_changed or changed:
                        try:
                            pm.generate_pac()
                            pm.refresh_system_options()
                        except:
                            pass
            except:
                pass

        def _get_proxy_port_candidates(self):
            out = []
            seen = set()

            def _add(v):
                try:
                    iv = int(v)
                except:
                    return
                if not (1 <= iv <= 65535):
                    return
                if iv in seen:
                    return
                seen.add(iv)
                out.append(iv)

            _add(self.port)
            _add(self.port_legacy)
            for p in (1370, 1372, 1374, 1080, 10808):
                _add(p)

            raw = str(os.environ.get("NOVA_WARP_PORT_CANDIDATES", "")).strip()
            if raw:
                for part in raw.replace(";", ",").split(","):
                    _add(part.strip())
            return out

        def _try_alternate_proxy_ports(self):
            """Try alternate local SOCKS ports when current port won't open on this host."""
            start_port = self.port
            for cand in self._get_proxy_port_candidates():
                prev = self.port
                if cand != prev:
                    self.log_func(f"[RU] [Diag] Пробуем резервный SOCKS порт {cand}...")
                if not self.set_proxy_port(cand):
                    continue
                self.set_proxy_mode()

                deadline = time.time() + 3.0
                while time.time() < deadline:
                    if self.is_port_open(cand):
                        self._propagate_warp_port(cand)
                        if cand != prev:
                            self.log_func(f"[RU] [Diag] Активирован резервный SOCKS порт {cand}.")
                        return True
                    time.sleep(0.25)
            # Restore original preference if no candidate produced a listener.
            if self.port != start_port:
                self.set_proxy_port(start_port)
                self.set_proxy_mode()
            return False
        
        def set_proxy_port(self, port):
            """Set WARP proxy port."""
            result = self.run_warp_cli("proxy", "port", str(port))
            if result and result.returncode == 0:
                self.port = port
                self._propagate_warp_port(port)
                self.log_func(f"[RU] Настройки порта ({port}) отправлены.")
                return True
            else:
                err = result.stderr.strip() if result else "Unknown error"
                self.log_func(f"[RU] ОШИБКА установки порта прокси {port}: {err}")
            return False
        
        def set_proxy_mode(self):
            """Set WARP to proxy mode (SOCKS on 1370)."""
            result = self.run_warp_cli("mode", "proxy")
            if result and result.returncode == 0:
                self.log_func("[RU] Команда режима прокси отправлена.")
                return True
            else:
                err = result.stderr.strip() if result else "Unknown error"
                self.log_func(f"[RU] ОШИБКА активации режима прокси: {err}")
            return False

        def _start_voice_tunnel(self):
            """Start sing-box tunnel with explicit diagnostics."""
            global sing_box_manager
            try:
                if not sing_box_manager:
                    self.log_func("[SingBox] Менеджер не инициализирован, запуск пропущен.")
                    return

                if sing_box_manager.process and sing_box_manager.process.poll() is None:
                    self.log_func("[SingBox] Голосовой туннель уже активен.")
                    return

                self.log_func("[SingBox] Запуск голосового туннеля...")
                sing_box_manager.start()

                if not (sing_box_manager.process and sing_box_manager.process.poll() is None):
                    self.log_func("[SingBox] Старт не подтвержден (процесс не активен).")
            except Exception as e:
                self.log_func(f"[SingBox] Ошибка запуска голосового туннеля: {e}")
        
        def start(self):
            """Connect to WARP using MASQUE protocol (Stable Version)."""
            global sing_box_manager
            if hasattr(self, '_is_starting_now') and self._is_starting_now:
                return
            
            self._is_starting_now = True
            self.bootstrap_ok = False
            try:
                self.bootstrap_event.clear()
            except:
                pass
            my_run_id = SERVICE_RUN_ID
            
            try:
                # Ensure service is running
                if not self.ensure_service():
                    self.mark_bootstrap(False)
                    self.log_func("[RU] Не удалось запустить службу!")
                    return

                # Wait for daemon to be responsive
                status = "Unknown"
                for i in range(40): # Up to 12s (40 * 0.3s)
                    if is_closing or SERVICE_RUN_ID != my_run_id: return
                    status = self.get_status()
                    status_low = (status or "").lower()
                    if status and ("registration missing" in status_low or ("unable" not in status_low and "unknown" not in status_low)):
                        break
                    
                    # if i > 0 and i % 30 == 0:
                    #     # self.log_func(f"[RU] Проверка связи с демоном ({int(i*0.3)} сек)...")
                    #     pass
                        
                    time.sleep(0.3)

                if SERVICE_RUN_ID != my_run_id: return
                if "Unable to connect" in status or "Unknown" in status:
                    # Newer daemon builds can intermittently timeout on `status`
                    # while IPC for other commands remains healthy.
                    reg_probe = self.run_warp_cli("registration", "show", timeout=8)
                    if not reg_probe or reg_probe.returncode != 0:
                        self.mark_bootstrap(False)
                        self.log_func("[RU] Ошибка: Служба WARP не отвечает.")
                        return
                    if IS_DEBUG_MODE:
                        self.log_func("[RU] [Diag] status вернул Unknown, но IPC отвечает (registration show OK). Продолжаем.")
                else:
                    self.mark_bootstrap(True)

                # Check if registration is needed
                if "Registration Missing" in status:
                    self.log_func("[RU] Регистрация устройства...")
                    reg_success = False
                    for attempt in range(2): 
                        if is_closing or SERVICE_RUN_ID != my_run_id: return
                        if attempt > 0: time.sleep(1.5)
                        
                        result = self.run_warp_cli("registration", "new")
                        out = result.stdout.strip() if (result and result.stdout) else ""
                        err = result.stderr.strip() if (result and result.stderr) else ""
                        last_error = f"{err} {out}".strip() or "Unknown error"

                        if result and result.returncode == 0:
                            self.log_func("[RU] Устройство зарегистрировано.")
                            reg_success = True
                            break
                        else:
                            if "IPC call hit a timeout" in last_error or "Error communicating with daemon" in last_error:
                                self.log_func(f"[RU] Служба занята (попытка {attempt+1}/2).")
                                time.sleep(2)
                                continue

                            if any(x in last_error.lower() for x in ["old registration", "registration delete", "already exists", "conflict"]):
                                self.log_func("[RU] Очистка старой регистрации...")
                                self.run_warp_cli("registration", "delete")
                                time.sleep(1.0)
                                continue 
                        time.sleep(1)
                    
                    if not reg_success:
                        self.mark_bootstrap(False)
                        self.log_func(f"[RU] Ошибка регистрации: {last_error}")
                        return
                    status = self.get_status()
                
                # --- CONFIGURATION ---
                if SERVICE_RUN_ID != my_run_id: return
                
                # FORCE RESET: Clear any manual endpoint/port leftovers from previous experiments
                self.run_warp_cli("tunnel", "endpoint", "reset")
                self.run_warp_cli("tunnel", "protocol", "reset")
                self.run_warp_cli("tunnel", "masque-options", "reset")
                
                self.ensure_masque()
                self.set_proxy_port(self.port)
                self.set_proxy_mode()

                # Check if already connected
                if "Connected" in status:
                    connected_now = False
                    if self.is_port_open(self.port):
                        self.log_func(f"[RU] {self.port} готов{self._bootstrap_1371_suffix()}")
                        connected_now = True
                    else:
                        connected_now = self.wait_for_connection(timeout=10)

                    self.is_connected = bool(connected_now)

                    # Start Voice Tunnel even when WARP was already connected before this run.
                    if connected_now:
                        self._start_voice_tunnel()
                    else:
                        self.log_func(f"[RU] [Warning] WARP статус Connected, но порт {self.port} недоступен.")
                    return
                
                # --- CONNECT ATTEMPTS ---
                # First, try default endpoint without overrides (most stable for new warp-cli builds).
                self.log_func("[RU] Подключение: MASQUE endpoint default (Auto)...")
                self.run_warp_cli("tunnel", "endpoint", "reset")
                self.run_warp_cli("tunnel", "protocol", "set", "MASQUE")
                self.run_warp_cli("tunnel", "masque-options", "set", "h3-with-h2-fallback")
                self.run_warp_cli("connect")
                if self.wait_for_connection(timeout=25):
                    self.is_connected = True
                    self._start_voice_tunnel()
                    return
                self.run_warp_cli("disconnect")
                time.sleep(0.8)

                # Safer fallback: avoid explicit endpoint overrides (recent builds can produce IPv6 :0 states).
                fallback_attempts = [
                    ("MASQUE", "MASQUE h2-only", ("tunnel", "masque-options", "set", "h2-only")),
                    ("MASQUE", "MASQUE h3-only", ("tunnel", "masque-options", "set", "h3-only")),
                    ("WireGuard", "WireGuard (Auto)", ("tunnel", "masque-options", "reset")),
                ]

                for proto_cli, attempt_label, tune_cmd in fallback_attempts:
                    if is_closing or SERVICE_RUN_ID != my_run_id: return
                    self.run_warp_cli("tunnel", "endpoint", "reset")
                    if tune_cmd:
                        tune_res = self.run_warp_cli(*tune_cmd)
                        if not tune_res or tune_res.returncode != 0:
                            msg = (tune_res.stderr.strip() if tune_res else "timeout/unknown")
                            self.log_func(f"[RU] [Diag] Не удалось применить {' '.join(tune_cmd)}: {msg}")

                    self.log_func(f"[RU] Подключение: {attempt_label} (fallback)...")
                    proto_res = self.run_warp_cli("tunnel", "protocol", "set", proto_cli)
                    if not proto_res or proto_res.returncode != 0:
                        msg = (proto_res.stderr.strip() if proto_res else "timeout/unknown")
                        self.log_func(f"[RU] [Diag] Не удалось применить protocol {proto_cli}: {msg}")
                    # Some warp-cli builds reset local proxy mode/port after tunnel tweaks.
                    self.set_proxy_port(self.port)
                    self.set_proxy_mode()
                    self.run_warp_cli("connect")
                    if self.wait_for_connection(timeout=20):
                        self.is_connected = True
                        self._start_voice_tunnel()
                        return
                    self.run_warp_cli("disconnect")
                    time.sleep(0.8)

                # Restore defaults before giving up.
                self.run_warp_cli("tunnel", "endpoint", "reset")
                self.run_warp_cli("tunnel", "masque-options", "reset")
                self.run_warp_cli("tunnel", "protocol", "reset")
                
                self.log_func("[RU] [Warning] Все попытки подключения исчерпаны.")
            
            except Exception as e:
                self.log_func(f"[RU] КРИТИЧЕСКАЯ ОШИБКА WARP: {e}")
                import traceback
                if IS_DEBUG_MODE: traceback.print_exc()

            finally:
                if not self.bootstrap_event.is_set():
                    self.mark_bootstrap(False)
                self._is_starting_now = False

        def stop_service(self):
            """Stop WARP service and clean up."""
            try:
                # Stop Voice Tunnel first
                global sing_box_manager
                if sing_box_manager:
                    sing_box_manager.stop()
                    
                subprocess.run(["sc", "stop", self.SERVICE_NAME], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
            except: pass

        def is_port_open(self, port):
            import socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                return result == 0
            except: return False

        def wait_for_connection(self, timeout=20):
            import time
            start_time = time.time()
            port_open_streak = 0
            proxy_repair_attempts = 0
            last_proxy_repair_ts = 0.0
            alt_ports_checked = False
            while time.time() - start_time < timeout:
                # Primary success signal: local SOCKS proxy is listening.
                port_open = self.is_port_open(self.port)
                if port_open:
                    port_open_streak += 1
                else:
                    port_open_streak = 0

                # Try extracting tunnel details even when `status` is flaky (IPC timeout).
                if port_open:
                    details = ""
                    stats_res = self.run_warp_cli("tunnel", "stats", timeout=8)
                    if stats_res and stats_res.returncode == 0:
                        stats_out = self.decode_output(stats_res.stdout)
                        import re

                        # Current CLI uses "Tunnel Protocol:", older builds had "Protocol:".
                        proto_match = re.search(r"(?:Tunnel\s+)?Protocol:\s*(.+)", stats_out, re.IGNORECASE)
                        proto_str = proto_match.group(1).strip() if proto_match else "Unknown"

                        # Current CLI uses "Endpoints: <ip>, ...".
                        ip_match = re.search(r"Endpoints:\s*([^\s,]+)", stats_out, re.IGNORECASE)
                        ip_str = ip_match.group(1).strip() if ip_match else "Unknown"

                        masked_ip = ip_str
                        conn_type = "Unknown"

                        if "." in ip_str and ":" not in ip_str:
                            conn_type = "IPv4"
                            parts = ip_str.split(".")
                            if len(parts) == 4:
                                masked_ip = f"***.***.{parts[2]}.{parts[3]}"
                        elif ":" in ip_str:
                            conn_type = "IPv6"
                            masked_ip = "IPv6:***"

                        details = f" {masked_ip} {proto_str} ({conn_type})"
                        self.log_func(f"[RU] {self.port} готов{details}{self._bootstrap_1371_suffix()}")
                        self.is_connected = True
                        return True

                    # If stats API is temporarily unavailable but SOCKS is stable, accept as connected.
                    if port_open_streak >= 2:
                        self.log_func(f"[RU] {self.port} готов{self._bootstrap_1371_suffix()}")
                        self.is_connected = True
                        return True

                status = self.get_status()
                status_low = (status or "").lower()
                if "connected" in status_low:
                    now_ts = time.time()
                    elapsed = now_ts - start_time
                    if (
                        not port_open
                        and elapsed >= 5
                        and proxy_repair_attempts < 2
                        and (now_ts - last_proxy_repair_ts) >= 4
                    ):
                        proxy_repair_attempts += 1
                        last_proxy_repair_ts = now_ts
                        self.log_func(
                            f"[RU] [Diag] Статус Connected, но порт {self.port} закрыт. Повторяем mode proxy/port ({proxy_repair_attempts}/2)..."
                        )
                        self.set_proxy_port(self.port)
                        self.set_proxy_mode()
                    if (
                        not port_open
                        and elapsed >= 10
                        and proxy_repair_attempts >= 2
                        and not alt_ports_checked
                    ):
                        alt_ports_checked = True
                        self.log_func("[RU] [Diag] Базовый порт недоступен. Пытаемся подобрать резервный SOCKS порт...")
                        try:
                            if self._try_alternate_proxy_ports():
                                # Re-check immediately after switching port.
                                if self.is_port_open(self.port):
                                    self.log_func(f"[RU] [Diag] Резервный порт {self.port} активен.")
                                    continue
                        except Exception as e:
                            if IS_DEBUG_MODE:
                                self.log_func(f"[RU] [Diag] Ошибка подбора резервного порта: {e}")
                    if IS_DEBUG_MODE:
                        self.log_func(f"[RU] Статус Connected, порт {self.port} пока закрыт...")
                elif "ipc call hit a timeout" in status_low or "error communicating with daemon" in status_low:
                    if IS_DEBUG_MODE:
                        self.log_func("[RU] [Diag] status IPC timeout (ожидание, tunnel может уже подниматься)...")
                else:
                    if IS_DEBUG_MODE:
                        self.log_func(f"[RU] Статус: {status}...")
                time.sleep(1)

            final_status = self.get_status()
            self.log_func(f"[RU] [Warning] WARP не перешел в рабочий режим за {timeout} сек. Статус: {final_status}. Порт {self.port} закрыт.")
            return False
        
        def stop(self):
            """Disconnect from WARP but keep the service running for faster restart."""
            # Always stop sing-box tunnel, otherwise it can keep routing/logging after Nova stop.
            try:
                global sing_box_manager
                if sing_box_manager:
                    sing_box_manager.stop()
            except:
                pass

            # Do not keep CloudflareWARP service pinned to local proxy when Nova is stopped.
            try:
                self._set_service_proxy_environment(enable_proxy=False)
            except:
                pass

            if is_closing:
                # When closing the app, just disconnect. 
                # We LEAVE the service running intentionally to speed up next launch.
                try: self.run_warp_cli("disconnect")
                except: pass
                self.is_connected = False
                return

            self.log_func("[RU] Отключение...")
            self.run_warp_cli("disconnect")
            self.is_connected = False


    class PacManager:
        def __init__(self, log_func=None):
            self.log_func = log_func or print
            self.pac_file = os.path.join(get_base_dir(), "temp", "nova.pac")
            self.server_port = 1369
            self.server_thread = None
            self.httpd = None
            self.warp_port = int(globals().get("WARP_PORT", 1370))
            self.registry_backup = {}
            self._last_route_signature = None
            self._last_eu_route_state = None
            self._last_openai_route_state = None
            self._last_proxy_diag_state = None
            self._winhttp_backup_dump = None
            self._winhttp_proxy_applied = False

        def _load_domain_list(self, filepath):
            """Load domains from a text file."""
            domains = set()
            if os.path.exists(filepath):
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        d = line.split('#')[0].strip().lower()
                        if not d:
                            continue
                        # Normalize common user input formats: URL, wildcard, path.
                        d = d.replace("\\", "/")
                        if "://" in d:
                            d = d.split("://", 1)[1]
                        d = d.split("/", 1)[0]
                        d = d.split(":", 1)[0]
                        if d.startswith("*."):
                            d = d[2:]
                        d = d.strip(".")
                        if d and "." in d:
                            domains.add(d)
            return domains

        def _run_netsh(self, args, timeout=8):
            try:
                result = subprocess.run(
                    ["netsh"] + list(args),
                    capture_output=True,
                    timeout=timeout,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                out = (result.stdout or b"").decode("utf-8", errors="ignore")
                err = (result.stderr or b"").decode("utf-8", errors="ignore")
                return result.returncode, out, err
            except Exception as e:
                return -1, "", str(e)

        def _ensure_winhttp_backup(self):
            if self._winhttp_backup_dump is not None:
                return
            rc, out, err = self._run_netsh(["winhttp", "dump"], timeout=8)
            if rc == 0 and out.strip():
                self._winhttp_backup_dump = out
            else:
                self._winhttp_backup_dump = "pushd winhttp\r\nreset proxy\r\npopd\r\n"
                if IS_DEBUG_MODE:
                    self.log_func(f"[System] [Diag] Не удалось снять backup WinHTTP dump: {err or out or rc}")

        def _apply_winhttp_proxy(self):
            """Route WinHTTP/CLI clients via 1371 while Nova is active."""
            try:
                self._ensure_winhttp_backup()
                rc, out, err = self._run_netsh(
                    [
                        "winhttp", "set", "proxy",
                        "proxy-server=127.0.0.1:1371",
                        "bypass-list=localhost;127.0.0.1;::1;<local>"
                    ],
                    timeout=8
                )
                if rc == 0:
                    self._winhttp_proxy_applied = True
                    if IS_DEBUG_MODE:
                        self.log_func("[System] WinHTTP прокси направлен на 127.0.0.1:1371.")
                elif IS_DEBUG_MODE:
                    self.log_func(f"[System] [Diag] WinHTTP set proxy failed: {err or out or rc}")
            except Exception as e:
                if IS_DEBUG_MODE:
                    self.log_func(f"[System] [Diag] Ошибка применения WinHTTP proxy: {e}")

        def _restore_winhttp_proxy(self):
            """Restore original WinHTTP proxy settings from backup dump."""
            if not self._winhttp_proxy_applied:
                return
            try:
                self._ensure_winhttp_backup()
                restore_file = os.path.join(get_base_dir(), "temp", "winhttp_restore.txt")
                with open(restore_file, "w", encoding="utf-8", newline="\r\n") as f:
                    f.write(self._winhttp_backup_dump or "pushd winhttp\r\nreset proxy\r\npopd\r\n")
                rc, out, err = self._run_netsh(["-f", restore_file], timeout=10)
                if rc == 0:
                    if IS_DEBUG_MODE:
                        self.log_func("[System] WinHTTP прокси восстановлен.")
                elif IS_DEBUG_MODE:
                    self.log_func(f"[System] [Diag] WinHTTP restore failed: {err or out or rc}")
            except Exception as e:
                if IS_DEBUG_MODE:
                    self.log_func(f"[System] [Diag] Ошибка восстановления WinHTTP proxy: {e}")
            finally:
                self._winhttp_proxy_applied = False

        def _load_ip_list(self, filepath):
            """Load IPs/CIDR from file and return list of [ip, mask/prefix, version] for PAC."""
            import ipaddress
            res = []
            if os.path.exists(filepath):
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.split('#')[0].strip()
                        if not line: continue
                        try:
                            # If just IP, default to /32 or /128
                            if '/' not in line: 
                                if ':' in line: line += '/128'
                                else: line += '/32'
                                
                            net = ipaddress.ip_network(line, strict=False)
                            
                            if net.version == 4:
                                # IPv4: [IP, Mask, 4] for isInNet
                                res.append( [str(net.network_address), str(net.netmask), 4] )
                            elif net.version == 6:
                                # IPv6: [IP, PrefixLen, 6] for isInNetEx
                                res.append( [str(net.network_address), str(net.prefixlen), 6] )
                        except: pass
            return res

        def is_port_open(self, port):
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                return s.connect_ex(('127.0.0.1', port)) == 0

        def _is_http_proxy_alive(self, port, timeout=1.5):
            """Verify local HTTP proxy socket/parser responsiveness with low-impact local probe."""
            return is_local_http_proxy_responsive(port=port, timeout=timeout)

        def generate_pac(self):
            """Generates PAC file with smart failover logic."""
            try:
                base = get_base_dir()
                ru_domains = self._load_domain_list(os.path.join(base, "list", "ru.txt"))
                eu_domains = self._load_domain_list(os.path.join(base, "list", "eu.txt"))
                # Domains that must never use WARP SOCKS fallback (Codex/OpenAI often returns 403 via 1370 path).
                openai_domains = {
                    "chatgpt.com",
                    "openai.com",
                    "api.openai.com",
                    "auth.openai.com",
                    "platform.openai.com",
                    "oaistatic.com",
                    "oaiusercontent.com",
                }
                discord_domains = self._load_domain_list(os.path.join(base, "list", "discord.txt"))
                ru_ips = self._load_ip_list(os.path.join(base, "ip", "ru.txt"))
                discord_ips = self._load_ip_list(os.path.join(base, "ip", "discord.txt"))
                ru_ips.extend(discord_ips)
                
                # Check Warp status for optimized routing
                warp_active = self.is_port_open(self.warp_port)
                opera_port_open = self.is_port_open(1371)
                opera_proxy_ok = self._is_http_proxy_alive(1371) if opera_port_open else False
                opera_active = bool(opera_port_open and opera_proxy_ok)
                # Keep WinHTTP in sync with actual 1371 health (avoid dead proxy in CLI tools).
                try:
                    if opera_active:
                        if not self._winhttp_proxy_applied:
                            self._apply_winhttp_proxy()
                    else:
                        if self._winhttp_proxy_applied:
                            self._restore_winhttp_proxy()
                except:
                    pass
                
                # Routing strings for EU domains: STRICTLY Opera VPN only (1371).
                # No fallback to WARP to ensure specific geo-routing.
                if opera_active:
                    eu_route = "PROXY 127.0.0.1:1371; SOCKS5 127.0.0.1:1"
                else:
                    # Kill-switch for EU domains if Opera is down.
                    eu_route = "SOCKS5 127.0.0.1:1"

                # Routing strings for RU domains: Try WARP, then Opera.
                if warp_active:
                    ru_route_parts = [
                        f"PROXY 127.0.0.1:1372", # Via SingBox for DoH resolution to prevent 30s port 53 DPI timeouts
                        f"SOCKS5 127.0.0.1:{self.warp_port}" # Direct WARP SOCKS fallback
                    ]
                    if opera_active:
                        ru_route_parts.append("PROXY 127.0.0.1:1371")
                    # NO DIRECT fallback for RU to prevent IP leak. Use a blackhole proxy.
                    ru_route_parts.append("SOCKS5 127.0.0.1:1") 
                    ru_route = "; ".join(ru_route_parts)
                else:
                    # Warp down: use Opera if available, otherwise Blackhole (No direct leak)
                    ru_route = "PROXY 127.0.0.1:1371; SOCKS5 127.0.0.1:1" if opera_active else "SOCKS5 127.0.0.1:1"
                
                # EU route is already set above. Keeping variable consistency.
                pass
                # Strict route for OpenAI/Codex: always 1371.
                # No fallback to 1370/DIRECT to avoid blocked/WARP-403 paths.
                openai_route = "PROXY 127.0.0.1:1371; SOCKS5 127.0.0.1:1"
                
                import json
                ru_ips_js = json.dumps(ru_ips)
                ru_js = "{" + ",".join(f'"{d}":1' for d in ru_domains) + "}"
                eu_js = "{" + ",".join(f'"{d}":1' for d in eu_domains) + "}"
                openai_js = "{" + ",".join(f'"{d}":1' for d in openai_domains) + "}"
                discord_js = "{" + ",".join(f'"{d}":1' for d in discord_domains) + "}"
                
                pac_content = f"""
    function FindProxyForURL(url, host) {{
    host = (host || "").toLowerCase();
    if (host.length > 1 && host.charAt(host.length - 1) === ".") {{
        host = host.substring(0, host.length - 1);
    }}
    var ru = {ru_js};
    var eu = {eu_js};
    var openai = {openai_js};
    var discord = {discord_js};
    var ru_ips = {ru_ips_js};
    
    var isIpV4 = /^\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}$/.test(host);
    var isIpV6 = (host.indexOf(':') > -1);
    
    if (isIpV4 || isIpV6) {{
        for (var i = 0; i < ru_ips.length; i++) {{
            var entry = ru_ips[i];
            var ver = entry[2];
            if (ver === 4 && isIpV4) {{
                if (isInNet(host, entry[0], entry[1])) {{
                    return "{ru_route}";
                }}
            }} else if (ver === 6 && isIpV6) {{
                if (typeof isInNetEx === 'function') {{
                    if (isInNetEx(host, entry[0] + "/" + entry[1])) {{
                        return "{ru_route}";
                    }}
                }}
            }}
        }}
    }}
    
    function matchDomain(list, h) {{
        if (list[h]) return true;
        var pos = h.indexOf('.');
        while (pos > -1) {{
            var suffix = h.substring(pos + 1);
            if (list[suffix]) return true;
            pos = h.indexOf('.', pos + 1);
        }}
        return false;
    }}
    
    // OpenAI/Codex path must stay on 1371-only route to avoid 403 via WARP SOCKS.
    if (matchDomain(openai, host)) return "{openai_route}";
    if (matchDomain(ru, host)) return "{ru_route}";
    if (matchDomain(discord, host)) return "{ru_route}";
    if (matchDomain(eu, host)) return "{eu_route}";
    
    return "DIRECT";
}}
"""
                with open(self.pac_file, "w", encoding="utf-8") as f:
                    f.write(pac_content)

                route_signature = (bool(warp_active), bool(opera_active))
                if route_signature != self._last_route_signature:
                    self._last_route_signature = route_signature
                    # Force OS and browsers to immediately re-fetch the PAC file
                    self.refresh_system_options()

                # Log routing states only when they change.
                eu_route_state = "opera" if opera_active else "down"
                if eu_route_state != self._last_eu_route_state:
                    self._last_eu_route_state = eu_route_state
                    if opera_active:
                        self.log_func("[PAC] EU маршрут: PROXY 127.0.0.1:1371 (Opera VPN ONLY)")
                    else:
                        self.log_func("[PAC] EU маршрут: SOCKS5 127.0.0.1:1 (Kill-switch: Opera недоступна)")

                # Define RU route state for logging (includes RU + Discord)
                ru_route_state = "warp+opera" if warp_active and opera_active else ("warp" if warp_active else ("opera" if opera_active else "down"))
                if ru_route_state != getattr(self, "_last_ru_route_state", None):
                    self._last_ru_route_state = ru_route_state
                    if ru_route_state == "warp+opera":
                        self.log_func(f"[PAC] RU маршрут: PROXY 127.0.0.1:1372; SOCKS5 127.0.0.1:{self.warp_port} (Warp Priority); PROXY 127.0.0.1:1371")
                    elif ru_route_state == "warp":
                        self.log_func(f"[PAC] RU маршрут: PROXY 127.0.0.1:1372; SOCKS5 127.0.0.1:{self.warp_port} (Warp Only)")
                    elif ru_route_state == "opera":
                        self.log_func("[PAC] RU маршрут: PROXY 127.0.0.1:1371 (Opera VPN fallback)")
                    else:
                        self.log_func("[PAC] RU маршрут: SOCKS5 127.0.0.1:1 (Kill-switch: Warp/Opera недоступны)")

                # Trigger refresh if statuses changed
                status_signature = (bool(warp_active), bool(opera_active))
                if status_signature != getattr(self, "_last_status_signature", None):
                    self._last_status_signature = status_signature
                    self.refresh_system_options()

                openai_route_state = "opera" if opera_active else "strict_down"
                if openai_route_state != self._last_openai_route_state:
                    self._last_openai_route_state = openai_route_state
                    if openai_route_state == "opera":
                        self.log_func("[PAC] OpenAI/Codex маршрут: PROXY 127.0.0.1:1371 (strict, без fallback).")
                    else:
                        self.log_func("[PAC] OpenAI/Codex маршрут: PROXY 127.0.0.1:1371 (strict; 1371 недоступен/не отвечает, ожидается ошибка подключения).")

                proxy_diag_state = (bool(opera_port_open), bool(opera_proxy_ok))
                if proxy_diag_state != self._last_proxy_diag_state:
                    self._last_proxy_diag_state = proxy_diag_state
                    if opera_port_open and not opera_proxy_ok:
                        self.log_func("[PAC] [Diag] Порт 1371 открыт, но HTTP-прокси не отвечает корректно.")
                    elif not opera_port_open:
                        self.log_func("[PAC] [Diag] Порт 1371 недоступен: EU маршрут ожидает восстановления Opera VPN.")
            except Exception as e:
                self.log_func(f"[PAC] Ошибка генерации: {e}")

        def start_server(self):
            """Starts a simple HTTP server to serve the PAC file."""
            if self.server_thread and self.server_thread.is_alive():
                return

            bind_event = threading.Event()
            bind_error = [None]  # mutable container for error

            def run():
                from http.server import SimpleHTTPRequestHandler
                import socketserver

                class PacHandler(SimpleHTTPRequestHandler):
                    def do_GET(self_handler):
                        try:
                            if self_handler.path.startswith("/nova.pac"):
                                if os.path.exists(self.pac_file):
                                    self_handler.send_response(200)
                                    self_handler.send_header('Content-type', 'application/x-ns-proxy-autoconfig')
                                    self_handler.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
                                    self_handler.send_header('Pragma', 'no-cache')
                                    self_handler.send_header('Expires', '0')
                                    self_handler.end_headers()
                                    with open(self.pac_file, 'rb') as f:
                                        self_handler.wfile.write(f.read())
                                else:
                                    self_handler.send_error(404)
                            else:
                                self_handler.send_error(404)
                        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
                            # Benign: client closed connection early
                            pass
                        except Exception:
                            # Other errors also shouldn't crash the server thread
                            pass

                    def log_message(self, format, *args): pass # Silence standard access logs
                    
                    # Override to silence technical socket errors from being printed to stderr
                    def handle_error(self_handler, request, client_address):
                        pass 

                try:
                    socketserver.TCPServer.allow_reuse_address = True
                    # Threaded server prevents false watchdog negatives under concurrent PAC fetches.
                    class SilentThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
                        daemon_threads = True
                        allow_reuse_address = True
                        request_queue_size = 64

                        def handle_error(self, request, client_address):
                            pass  # Silence benign socket resets/timeouts.

                    self.httpd = SilentThreadingTCPServer(("127.0.0.1", self.server_port), PacHandler)
                    bind_event.set()  # Signal successful binding
                    self.httpd.serve_forever()
                except Exception as e:
                    bind_error[0] = e
                    bind_event.set()  # Signal failure too

            self.generate_pac() # Initial gen
            self.server_thread = threading.Thread(target=run, daemon=True)
            self.server_thread.start()
            bind_event.wait(timeout=5)  # Wait for binding result
            
            if bind_error[0]:
                self.log_func(f"[PAC] Ошибка запуска сервера на порту {self.server_port}: {bind_error[0]}")
            else:
                if IS_DEBUG_MODE: self.log_func(f"[PAC] Сервер запущен на порту {self.server_port}")

        def _is_pac_server_alive(self, timeout=1.5):
            """Check that PAC server is reachable and serves a valid PAC payload."""
            import socket
            for _ in range(3):
                try:
                    with socket.create_connection(("127.0.0.1", int(self.server_port)), timeout=timeout) as s:
                        s.settimeout(timeout)
                        req = (
                            "GET /nova.pac HTTP/1.1\r\n"
                            "Host: 127.0.0.1\r\n"
                            "Connection: close\r\n\r\n"
                        ).encode("ascii", errors="ignore")
                        s.sendall(req)
                        data = b""
                        while len(data) < 8192:
                            chunk = s.recv(2048)
                            if not chunk:
                                break
                            data += chunk
                            if b"\r\n\r\n" in data and b"FindProxyForURL" in data:
                                break
                        txt = data.decode("latin1", errors="ignore")
                        up = txt.upper()
                        if ("HTTP/1.1 200" in up or "HTTP/1.0 200" in up) and (
                            ("FindProxyForURL" in txt) or ("FINDPROXYFORURL" in up)
                        ):
                            return True
                except:
                    pass
                time.sleep(0.12)
            return False

        def stop_server(self):
            """Stops PAC HTTP server to avoid stale AutoConfig usage after Nova stop."""
            try:
                if self.httpd:
                    try:
                        self.httpd.shutdown()
                    except:
                        pass
                    try:
                        self.httpd.server_close()
                    except:
                        pass
                    self.httpd = None
                if self.server_thread and self.server_thread.is_alive():
                    try:
                        self.server_thread.join(timeout=1.5)
                    except:
                        pass
                self.server_thread = None
                if IS_DEBUG_MODE:
                    self.log_func("[PAC] Сервер остановлен.")
            except Exception as e:
                if IS_DEBUG_MODE:
                    self.log_func(f"[PAC] Ошибка остановки сервера: {e}")

        def set_system_proxy(self):
            """Configures Windows to use the PAC file."""
            try:
                # Backup current settings
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ)
                    try:
                        self.registry_backup['AutoConfigURL'] = winreg.QueryValueEx(key, 'AutoConfigURL')[0]
                    except:
                        pass
                    try:
                        self.registry_backup['AutoDetect'] = winreg.QueryValueEx(key, 'AutoDetect')[0]
                    except:
                        pass
                    try:
                        self.registry_backup['ProxyEnable'] = winreg.QueryValueEx(key, 'ProxyEnable')[0]
                    except:
                        pass
                    try:
                        self.registry_backup['ProxyServer'] = winreg.QueryValueEx(key, 'ProxyServer')[0]
                    except:
                        pass
                    try:
                        self.registry_backup['ProxyOverride'] = winreg.QueryValueEx(key, 'ProxyOverride')[0]
                    except:
                        pass
                    try:
                        winreg.CloseKey(key)
                    except:
                        pass
                except: pass
                try:
                    # If ProxyEnable was 1, we should remember that? 
                    # Actually, if we use AutoConfig, ProxyEnable is usually ignored or works with it.
                    # Safe bet: Just set AutoConfigURL.
                    pass 
                except: pass
                
                # Set new settings
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE)
                pac_url = f"http://127.0.0.1:{self.server_port}/nova.pac"
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
                # Keep system switches explicitly enabled for PAC scenarios.
                # Some Windows builds ignore AutoConfigURL when AutoDetect is off.
                try:
                    winreg.SetValueEx(key, "AutoDetect", 0, winreg.REG_DWORD, 1)
                except:
                    pass
                try:
                    # Keep static proxy disabled so browsers follow PAC routing rules strictly.
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                except:
                    pass
                try:
                    winreg.CloseKey(key)
                except:
                    pass
                
                # Notify system
                # InternetSetOption needed to flush cache, but python wrapper implies ctypes.
                # Simple registry change might require a browser restart or refresh.
                # To make it instant, we call InternetSetOption.
                self.refresh_system_options()
                # Apply WinHTTP proxy only when 1371 is actually usable.
                try:
                    if self._is_http_proxy_alive(1371):
                        self._apply_winhttp_proxy()
                except:
                    pass
                
                if IS_DEBUG_MODE: self.log_func("[System] Системный прокси настроен на Nova PAC.")
            except Exception as e:
                self.log_func(f"[System] Ошибка настройки прокси: {e}")

        def restore_system_proxy(self):
            """Restores original settings - forcibly clears Nova proxy settings."""
            try:
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_WRITE | winreg.KEY_READ)
                
                # Check current AutoConfigURL - only clear if it's Nova's PAC
                try:
                    current_pac = winreg.QueryValueEx(key, "AutoConfigURL")[0]
                    if "nova.pac" in current_pac or "127.0.0.1:1371" in current_pac:
                        # It's Nova's PAC - delete it
                        try:
                            winreg.DeleteValue(key, "AutoConfigURL")
                            self.log_func("[System] AutoConfigURL удалён.")
                        except WindowsError as e:
                            self.log_func(f"[System] Ошибка удаления AutoConfigURL: {e}")
                except FileNotFoundError:
                    # AutoConfigURL doesn't exist - that's fine
                    pass
                except Exception as e:
                    self.log_func(f"[System] Ошибка чтения AutoConfigURL: {e}")
                
                # Also clear ProxyServer if it's pointing to Nova
                try:
                    current_proxy = winreg.QueryValueEx(key, "ProxyServer")[0]
                    if "127.0.0.1:1370" in current_proxy or "127.0.0.1:1371" in current_proxy:
                        winreg.DeleteValue(key, "ProxyServer")
                        self.log_func("[System] ProxyServer удалён.")
                except FileNotFoundError:
                    pass
                except Exception as e:
                    pass  # ProxyServer might not exist

                # Restore backed-up switch values where available.
                try:
                    if "AutoDetect" in self.registry_backup:
                        winreg.SetValueEx(key, "AutoDetect", 0, winreg.REG_DWORD, int(self.registry_backup.get("AutoDetect", 0)))
                except:
                    pass
                try:
                    if "ProxyEnable" in self.registry_backup:
                        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, int(self.registry_backup.get("ProxyEnable", 0)))
                except:
                    pass
                try:
                    old_proxy_server = self.registry_backup.get("ProxyServer")
                    if old_proxy_server:
                        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, str(old_proxy_server))
                    elif "ProxyServer" in self.registry_backup:
                        # Explicitly clear empty backed value.
                        try:
                            winreg.DeleteValue(key, "ProxyServer")
                        except:
                            pass
                except:
                    pass
                try:
                    if "ProxyOverride" in self.registry_backup:
                        old_override = self.registry_backup.get("ProxyOverride")
                        if old_override:
                            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, str(old_override))
                        else:
                            try:
                                winreg.DeleteValue(key, "ProxyOverride")
                            except:
                                pass
                except:
                    pass
                
                winreg.CloseKey(key)
                self.refresh_system_options()
                self._restore_winhttp_proxy()
                self.log_func("[System] Настройки прокси восстановлены.")
            except Exception as e:
                self.log_func(f"[System] Ошибка восстановления прокси: {e}")

        def refresh_system_options(self):
            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
                # Refresh PAC cache-busting token only when Nova PAC is already active.
                # Never recreate AutoConfigURL after it was intentionally removed.
                try:
                    current_pac = winreg.QueryValueEx(key, "AutoConfigURL")[0]
                    if isinstance(current_pac, str) and "nova.pac" in current_pac.lower():
                        pac_url = f"http://127.0.0.1:{self.server_port}/nova.pac?t={int(time.time())}"
                        winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
                except FileNotFoundError:
                    pass
                except:
                    pass
                winreg.CloseKey(key)
                
                INTERNET_OPTION_SETTINGS_CHANGED = 39
                INTERNET_OPTION_REFRESH = 37
                ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
                ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
            except: pass


    # [REMOVED] Duplicate SingBoxManager class was here. 
    # The correct implementation is now at the top of the file (around line 1480).
    # This suppression fixes the "run keygen first" error and enables the new voice routing logic.


    class OperaProxyManager:
        """Manages opera-proxy process for HTTP proxy."""
        
        def __init__(self, log_func=None, port=1371, country="EU"):
            self.log_func = log_func or print
            self.port = port
            self.country = country
            self.process = None
            self.f_log = None
            self.owns_process = False
            self.using_external = False
            self.exe_path = os.path.join(get_base_dir(), "bin", "opera-proxy.windows-amd64.exe")
            self._last_pac_sync_state = None
            # Grace window for slow proxy bootstrap (registration/retries).
            self._startup_grace_deadline = 0.0
            self._started_at_ts = 0.0

        def _is_port_open_local(self):
            try:
                import socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    return s.connect_ex(("127.0.0.1", int(self.port))) == 0
            except:
                return False

        def _is_http_proxy_alive(self, timeout=1.5):
            return is_local_http_proxy_responsive(port=self.port, timeout=timeout)

        def _has_recent_log_activity(self, max_age_sec=45):
            """True when opera.log is being updated recently (proxy is still progressing)."""
            try:
                path = getattr(self, "log_file", None)
                if not path:
                    return False
                if not os.path.exists(path):
                    return False
                return (time.time() - os.path.getmtime(path)) <= float(max_age_sec)
            except:
                return False

        def _sync_pac_state(self, force=False):
            """Refresh PAC when 1371 readiness changes, so browser routing never gets stale."""
            try:
                port_alive = self._is_port_open_local()
                proxy_alive = self._is_http_proxy_alive() if port_alive else False
                state = bool(port_alive and proxy_alive)
                if (not force) and self._last_pac_sync_state is not None and state == self._last_pac_sync_state:
                    return
                self._last_pac_sync_state = state
                pm = globals().get("pac_manager")
                if pm:
                    pm.generate_pac()
                    pm.refresh_system_options()
                    state_text = "доступен" if state else "недоступен"
                    self.log_func(f"[PAC] Обновлен: порт {self.port} {state_text}.")
            except Exception as e:
                safe_trace(f"[EU] PAC sync error: {e}")
        
        def start(self):
            """Start opera-proxy process."""
            def _close_log_handle():
                try:
                    if self.f_log:
                        self.f_log.close()
                except:
                    pass
                self.f_log = None

            def _terminate_managed_process(debug_reason=None):
                if debug_reason and IS_DEBUG_MODE:
                    self.log_func(debug_reason)
                try:
                    if self.process and self.process.poll() is None:
                        self.process.terminate()
                        try:
                            self.process.wait(timeout=2.0)
                        except:
                            try:
                                self.process.kill()
                            except:
                                pass
                except:
                    pass
                self.process = None
                self.owns_process = False
                self._startup_grace_deadline = 0.0
                self._started_at_ts = 0.0
                _close_log_handle()

            # If we already have a process handle, validate real proxy health.
            # A live PID alone is insufficient (can be hung and still keep the port open).
            if self.process and self.process.poll() is None:
                port_alive = self._is_port_open_local()
                proxy_alive = self._is_http_proxy_alive(timeout=1.0) if port_alive else False
                if port_alive and proxy_alive:
                    if IS_DEBUG_MODE:
                        self.log_func("[EU] Уже запущен.")
                    self.using_external = False
                    self.owns_process = True
                    self._startup_grace_deadline = 0.0
                    self._sync_pac_state(force=True)
                    return
                now_ts = time.time()
                in_grace = bool(self._startup_grace_deadline and now_ts < self._startup_grace_deadline)
                if in_grace:
                    # Keep process alive during bootstrap; health may be unavailable while registration retries.
                    self.using_external = False
                    self.owns_process = True
                    self._sync_pac_state(force=True)
                    return
                # Even after grace, do not kill an active process while it keeps progressing in log.
                # discover/registration retries can legitimately exceed initial grace on bad routes.
                if self._has_recent_log_activity(max_age_sec=60):
                    self.using_external = False
                    self.owns_process = True
                    self._sync_pac_state(force=True)
                    return
                _terminate_managed_process("[EU] Обнаружен зависший локальный proxy. Перезапуск...")
            elif self.process and self.process.poll() is not None:
                self.process = None
                self.owns_process = False
                _close_log_handle()
             
            if not os.path.exists(self.exe_path):
                self.log_func("[EU] Файл не найден!")
                return

            # If port is already listening:
            # - adopt only healthy external proxy
            # - otherwise try to recover by launching managed proxy
            if self._is_port_open_local():
                if self._is_http_proxy_alive(timeout=1.0):
                    self.owns_process = False
                    if not self.using_external:
                        self.log_func(f"[EU] Используется внешний прокси на порту {self.port}.")
                    self.using_external = True
                    self._startup_grace_deadline = 0.0
                    self._sync_pac_state(force=True)
                    return
                else:
                    # Do not force takeover of already adopted external proxy on transient failures.
                    if self.using_external and not self.owns_process:
                        if IS_DEBUG_MODE:
                            self.log_func(f"[EU] Внешний прокси {self.port} временно не отвечает. Принудительный takeover пропущен.")
                        self._sync_pac_state(force=True)
                        return
                    self.log_func(f"[EU] Порт {self.port} открыт, но прокси не отвечает. Попытка перезапуска локального proxy...")
            self.using_external = False
            
            # FIX: Force kill any orphan processes to free the port (bind error 10048)
            for proc_name in [
                "opera-proxy.windows-amd64.exe",
                "opera-proxy.windows-amd64",
                "opera-proxy.exe",
                "opera-proxy",
            ]:
                try:
                    subprocess.run(
                        ["taskkill", "/F", "/IM", proc_name],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                except:
                    pass
            # If unknown process still keeps the port, we cannot bind here.
            if self._is_port_open_local():
                self.owns_process = False
                self.using_external = True
                self._sync_pac_state(force=True)
                if IS_DEBUG_MODE:
                    self.log_func(f"[EU] Порт {self.port} занят сторонним процессом, takeover невозможен.")
                return
            
            try:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
                cmd = [
                    self.exe_path,
                    "-bind-address", f"127.0.0.1:{self.port}",
                    "-country", self.country
                ]
                
                # FIX: Redirect output to file for debugging
                log_dir = os.path.join(get_base_dir(), "temp")
                if not os.path.exists(log_dir): os.makedirs(log_dir)
                self.log_file = os.path.join(log_dir, "opera.log")
                _close_log_handle()
                 
                # Open file for writing (subprocess will inherit handle)
                self.f_log = open(self.log_file, "w")
                
                self.process = subprocess.Popen(
                    cmd,
                    stdout=self.f_log,
                    stderr=subprocess.STDOUT,
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                self._started_at_ts = time.time()
                self._startup_grace_deadline = self._started_at_ts + 120.0
                # Synchronous readiness wait:
                # watchdog/startup callers should receive a deterministic state.
                run_id = SERVICE_RUN_ID
                ready = False
                start_t = time.time()
                while time.time() - start_t < 15:
                    if is_closing or SERVICE_RUN_ID != run_id or not is_service_active:
                        break
                    if self.process and self.process.poll() is not None:
                        break
                    port_alive = self._is_port_open_local()
                    proxy_alive = self._is_http_proxy_alive(timeout=0.8) if port_alive else False
                    if port_alive and proxy_alive:
                        ready = True
                        break
                    time.sleep(0.4)

                if ready:
                    if IS_DEBUG_MODE:
                        self.log_func(f"[EU] Запущен на порту {self.port} (регион: {self.country})")
                    self.log_func(f"[EU] {self.port} готов")
                    self.owns_process = True
                    self.using_external = False
                    self._startup_grace_deadline = 0.0
                    self._sync_pac_state(force=True)
                    return

                if self.process and self.process.poll() is not None:
                    if IS_DEBUG_MODE:
                        self.log_func(f"[EU] Процесс завершился сразу после запуска (код: {self.process.returncode}).")
                    self.process = None
                    self._startup_grace_deadline = 0.0
                    self._started_at_ts = 0.0
                    _close_log_handle()
                else:
                    # Keep managed process alive: opera registration may need >15s with retries.
                    if IS_DEBUG_MODE:
                        self.log_func("[EU] Предупреждение: Порт 1371 не открылся вовремя. Ожидаем завершения инициализации в фоне.")
                    self.owns_process = True
                    self.using_external = False
                    self._sync_pac_state(force=True)
                    return
                self.owns_process = False
                self._sync_pac_state(force=True)
                 
            except Exception as e:
                self.owns_process = False
                self._startup_grace_deadline = 0.0
                self._started_at_ts = 0.0
                self.log_func(f"[EU] Ошибка запуска: {e}")
        
        def stop(self):
            """Stop opera-proxy process."""
            # Do not terminate user-provided external proxy.
            if self.using_external and not self.owns_process:
                # If we still hold a live process handle, it is not truly external for this run.
                try:
                    if self.process and self.process.poll() is None:
                        self.using_external = False
                    else:
                        if IS_DEBUG_MODE:
                            self.log_func(f"[EU] Внешний прокси {self.port} оставлен запущенным.")
                        self.using_external = False
                        self.process = None
                        self._sync_pac_state(force=True)
                        return
                except:
                    pass

            owned_before_stop = bool(self.owns_process)
            if self.process:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                except:
                    try: self.process.kill()
                    except: pass
                self.process = None
                self.owns_process = False
                self._startup_grace_deadline = 0.0
                self._started_at_ts = 0.0
                if IS_DEBUG_MODE: self.log_func("[EU] Остановлен.")

            # Failsafe cleanup for orphaned proxy processes.
            if owned_before_stop:
                for proc_name in [
                    "opera-proxy.windows-amd64.exe",
                    "opera-proxy.windows-amd64",
                    "opera-proxy.exe",
                    "opera-proxy",
                ]:
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/IM", proc_name],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=subprocess.CREATE_NO_WINDOW
                        )
                    except:
                        pass

            try:
                if self.f_log:
                    self.f_log.close()
                    self.f_log = None
            except:
                pass
            self._sync_pac_state(force=True)


    # Global Managers
    warp_manager = None
    pac_manager = None
    opera_proxy_manager = None








    def ensure_structure():
        base_dir = get_base_dir()
        for folder in ["bin", "list", "ip", "strat", "temp", "img", "fake"]:
            path = os.path.join(base_dir, folder)
            if not os.path.exists(path): os.makedirs(path)

        files = {
            "youtube.txt": "youtube.com\ngooglevideo.com\n",
            "discord.txt": "discord.com\ndiscord.gg\n",
            "telegram.txt": "telegram.org\ntelegram.me\n",
            "whatsapp.txt": "whatsapp.com\nwa.me\n",
            "cloudflare.txt": "cloudflare.com\n",
            "general.txt": "twitter.com\ninstagram.com\n",
            "exclude.txt": ""
        }
        res = {}
        
        # === EMBEDDED DEFAULTS (Minimal Skeleton) ===
        DEFAULT_STRATEGIES = {
            "youtube": [],
            "discord": [],
            "warp": [],
            "voice": ["--wf-udp=443,1024-65535", "--dpi-desync=fake", "--dpi-desync-fooling=badsum"],
            "cloudflare": [],
            "telegram": [],
            "whatsapp": [],
            "general": [],
            "version": CURRENT_VERSION
        }
        
        DEFAULT_DISCORD = {
            "version": CURRENT_VERSION,
            "strategies": []
        }
        
        for name, content in files.items():
            path = os.path.join(base_dir, "list", name)
            if not os.path.exists(path) or (name == "general.txt" and os.path.getsize(path) == 0):
                # Ensure it has version header on creation
                if not content.startswith("# version:"):
                    content = f"# version: {CURRENT_VERSION}\n" + content
                with open(path, "w", encoding="utf-8") as f: f.write(content)
            res[f"list_{name.split('.')[0]}"] = path
            
        # PROACTIVE HEADER INJECTION: force # version: {CURRENT_VERSION} on ALL .txt lists
        list_dir_path = os.path.join(base_dir, "list")
        if os.path.exists(list_dir_path):
            try:
                for f in os.listdir(list_dir_path):
                    if f.endswith(".txt"):
                        f_path = os.path.join(list_dir_path, f)
                        try:
                            with open(f_path, "r", encoding="utf-8") as text_file:
                                lines = text_file.readlines()
                            if not lines:
                                lines = [f"# version: {CURRENT_VERSION}\n"]
                            elif lines[0].startswith("# version:"):
                                if lines[0].strip() == f"# version: {CURRENT_VERSION}":
                                    continue
                                lines[0] = f"# version: {CURRENT_VERSION}\n"
                            else:
                                lines.insert(0, f"# version: {CURRENT_VERSION}\n")
                            with open(f_path, "w", encoding="utf-8") as text_file:
                                text_file.writelines(lines)
                        except: pass
            except: pass
            
        # === FIX: Config Auto-Update Logic ===
        def check_and_update_config(filename, default_data, validation_callback=None):
            fpath = os.path.join(base_dir, "strat", filename)
            should_update = False
            
            try:
                if not os.path.exists(fpath):
                    # ONLY create default file if we are in FROZEN (EXE) mode
                    # If running as .pyw script, we DO NOT want to generate defaults
                    if getattr(sys, 'frozen', False):
                        should_update = True
                    else:
                        # Script mode: just return empty if file missing, do not create
                        return
                else:
                    with open(fpath, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                        if not content:
                            should_update = True
                        else:
                            try:
                                d = json.loads(content)
                                if isinstance(d, list):
                                    should_update = True # Legacy format -> Update
                                elif isinstance(d, dict):
                                    # 1. Version Check
                                    file_ver = d.get("version", "0.0")
                                    if file_ver < CURRENT_VERSION:
                                        should_update = True
                                    # 2. Content Validation (if version matches but content is wrong)
                                    elif validation_callback and not validation_callback(d):
                                        should_update = True
                                else:
                                    should_update = True
                            except json.JSONDecodeError:
                                should_update = True
            except Exception:
                should_update = True
                    
            if should_update:
                try:
                    print(f"[Config] Updating {filename}...")
                    if os.path.exists(fpath):
                        os.remove(fpath)
                    
                    with open(fpath, "w", encoding="utf-8") as f:
                        json.dump(default_data, f, indent=4, ensure_ascii=False)
                    print(f"[Config] {filename} updated successfully.")
                except Exception as e:
                    print(f"Error updating {filename}: {e}")

        check_and_update_config(STRATEGIES_FILENAME, DEFAULT_STRATEGIES)
        check_and_update_config("discord.json", DEFAULT_DISCORD)

        # === НОВОЕ: Создаем необходимые temp файлы с версионированием ===
        temp_files = {
            "exclude_auto.txt": "",
            "hard.txt": "",
            "visited_domains_stats.json": json.dumps({"version": CURRENT_VERSION}),
            "strategies_evolution.json": json.dumps({"version": CURRENT_VERSION}),
            "ip_history.json": json.dumps({"version": CURRENT_VERSION, "history": []}), # Array wrapper? No, let's keep it consistent dict or list? ip_history usually list. Warning.
            # ip_history code usually expects list. Adding version logic to list file is tricky. 
            # Let's skip ip_history for now or wrap it. History usually just list of IPs.
            "ip_history.json": "[]", 
            
            "checker_state.json": json.dumps({"version": CURRENT_VERSION}),
            "ip_cache_state.json": json.dumps({"version": CURRENT_VERSION}),
            "direct_check_cache.json": json.dumps({"version": CURRENT_VERSION}),
            "window_state.json": json.dumps({"version": CURRENT_VERSION}),
            "learning_data.json": json.dumps({"version": CURRENT_VERSION})
        }
        
        for name, content in temp_files.items():
            path = os.path.join(base_dir, "temp", name)
            
            # 1. Version Check & Cleanup (JSON only)
            # FIX: Exclude persistent data files from aggressive wipe
            protected_files = ["ip_history.json", "learning_data.json", "checker_state.json"]
            if os.path.exists(path) and name.endswith(".json") and name not in protected_files:
                try:
                    with open(path, "r", encoding="utf-8") as f:
                         d = json.load(f)
                         if isinstance(d, dict):
                             v = d.get("version")
                             if v != CURRENT_VERSION:
                                 os.remove(path) # Delete old version
                                 # log_func not available here yet, print or silent? Silent is safest in init.
                         else:
                             # Not a dict (maybe corrupted or old format)
                             os.remove(path)
                except:
                    # Corrupted file
                    try: os.remove(path)
                    except: pass
            
            # 2. Create if missing
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            else:
                # Восстановление поврежденных/пустых JSON файлов
                # FIX: Don't check getsize == 0 blindly. Trust version check above.
                pass

                pass
        
        res["list_exclude_auto"] = os.path.join(base_dir, "temp", "exclude_auto.txt")
        res["ip_exclude"] = os.path.join(base_dir, "ip", "exclude.txt")
        if not os.path.exists(res["ip_exclude"]):
            with open(res["ip_exclude"], "w") as f: pass
        res["ip_telegram"] = os.path.join(base_dir, "ip", "ip_telegram.txt")
        
        res["ip_general"] = os.path.join(base_dir, "ip", "general.txt")
        if not os.path.exists(res["ip_general"]):
             with open(res["ip_general"], "w") as f: pass # No header to prevent winws crash

        res["strat_json"] = os.path.join(base_dir, "strat", STRATEGIES_FILENAME)
        res["strat_boost"] = os.path.join(base_dir, "strat", "boost.json")
        if not os.path.exists(res["strat_boost"]):
             with open(res["strat_boost"], "w", encoding="utf-8") as f: f.write("{}")
        
        res["bin_yt"] = os.path.join(base_dir, "fake", "4.bin")
        res["bin_yt_ok"] = os.path.exists(res["bin_yt"])
        res["bin_quic"] = os.path.join(base_dir, "fake", "quic_initial_www_google_com.bin")
        res["bin_dc"] = os.path.join(base_dir, "fake", "tls_clienthello_5.bin")
        res["bin_dc_ok"] = os.path.exists(res["bin_dc"])
        
        res["list_hard"] = os.path.join(base_dir, "temp", HARD_LIST_FILENAME)
        res["list_rkn"] = os.path.join(base_dir, "list", "rkn.txt")
        res["temp_strategy_builder_state"] = os.path.join(base_dir, "temp", "strategy_builder_state.json")
        res["temp_strategy_builder_ips"] = os.path.join(base_dir, "temp", "strategy_builder_ips.txt")
        
        return res

    def ensure_warp_control_exclusions(log_func=None):
        """Ensure WARP control hosts are processed by active General strategy (not excluded)."""
        try:
            base_dir = get_base_dir()
            ex_path = os.path.join(base_dir, "list", "exclude.txt")
            gen_path = os.path.join(base_dir, "list", "general.txt")

            # Cloudflare control-plane hosts used during WARP bootstrap/registration.
            # Keep BOTH normal and trailing-dot FQDN forms (daemon logs often use trailing dot).
            control_domains = {
                "api.cloudflareclient.com",
                "api.cloudflareclient.com.",
                "engage.cloudflareclient.com",
                "engage.cloudflareclient.com.",
                "connectivity.cloudflareclient.com",
                "connectivity.cloudflareclient.com.",
                "notifications.cloudflareclient.com",
                "notifications.cloudflareclient.com.",
            }
            general_required = sorted(control_domains)
            # Do not maintain synthetic/non-DNS entries here:
            # DomainCleaner will always remove them and produce noisy logs.
            required_excludes = []

            ex_lines = []
            if os.path.exists(ex_path):
                with open(ex_path, "r", encoding="utf-8") as f:
                    ex_lines = f.read().splitlines()

            new_ex_lines = []
            removed_from_exclude = 0
            existing_ex = set()

            for ln in ex_lines:
                raw = ln.strip()
                if not raw:
                    new_ex_lines.append(ln)
                    continue
                if raw.startswith("#"):
                    new_ex_lines.append(ln)
                    continue

                if raw.lower() in control_domains:
                    removed_from_exclude += 1
                    continue
                if raw.lower() == "connectivity-check.warp-svc":
                    removed_from_exclude += 1
                    continue

                existing_ex.add(raw.lower())
                new_ex_lines.append(raw)

            added_excludes = 0
            for d in required_excludes:
                if d.lower() not in existing_ex:
                    new_ex_lines.append(d)
                    existing_ex.add(d.lower())
                    added_excludes += 1

            exclude_changed = (new_ex_lines != ex_lines) or (not os.path.exists(ex_path))
            if exclude_changed:
                with open(ex_path, "w", encoding="utf-8") as f:
                    for ln in new_ex_lines:
                        f.write(f"{ln}\n")

            # Ensure API endpoint is in general list for default strategy processing.
            gen_lines = []
            if os.path.exists(gen_path):
                with open(gen_path, "r", encoding="utf-8") as f:
                    gen_lines = f.read().splitlines()

            existing_gen = {ln.strip().lower() for ln in gen_lines if ln.strip() and not ln.strip().startswith("#")}
            added_to_general = 0
            for d in general_required:
                if d.lower() not in existing_gen:
                    gen_lines.append(d)
                    existing_gen.add(d.lower())
                    added_to_general += 1

            if added_to_general:
                with open(gen_path, "w", encoding="utf-8") as f:
                    for ln in gen_lines:
                        f.write(f"{ln}\n")

            if log_func and (exclude_changed or added_to_general):
                log_func(
                    f"[Init] Маршрутизация Cloudflare API: general +{added_to_general}, "
                    f"exclude -{removed_from_exclude}, служебных exclude +{added_excludes}"
                )
        except Exception as e:
            if log_func and IS_DEBUG_MODE:
                log_func(f"[Init] Не удалось обновить правила Cloudflare API: {e}")

    def load_strategies_from_file(filepath):
        if not os.path.exists(filepath): return {}
        try:
            with open(filepath, "r", encoding="utf-8") as f: 
                data = json.load(f)
                
                # FIX: Versioned Load (Discard < 0.997) - ONLY FOR FROZEN BUILD
                # In script mode, we accept any valid JSON to allow testing without version headers
                is_frozen = getattr(sys, 'frozen', False)
                if is_frozen and isinstance(data, dict):
                    ver = data.get("version", "0.0")
                    if ver < "0.997": return {}
                return data
        except: return {}

    def load_json_robust(filepath, default=None):
        """Надежная загрузка JSON с защитой от сбоев и восстановлением."""
        if default is None: default = {}
        if not os.path.exists(filepath): return default
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content: return default
                return json.loads(content)
        except json.JSONDecodeError:
            try: # Бэкап битого файла
                shutil.copy(filepath, filepath + ".bak")
            except: pass
            return default
        except Exception: return default

    def save_json_safe(filepath, data):
        """Безопасное сохранение JSON (атомарная запись)."""
        if not data and os.path.exists(filepath):
             # Защита от записи пустого файла поверх существующего
             current_size = os.path.getsize(filepath)
             if current_size > 10: # Если в файле что-то есть (>10 байт), не перезаписываем пустотой
                 return
        try:
            temp_path = filepath + ".tmp"
            with open(temp_path, "w", encoding="utf-8") as f: json.dump(data, f, indent=4)
            os.replace(temp_path, filepath)
        except: pass

    # === EVOLUTION LEARNING SYSTEM ===
    LEARNING_DATA_PATH = os.path.join(get_base_dir(), "temp", "learning_data.json")
    _learning_data_lock = threading.RLock()
    _learning_data_cache = None

    def load_learning_data():
        """Загружает данные обучения из temp/learning_data.json с использованием кэша"""
        global _learning_data_cache
        with _learning_data_lock:
            if _learning_data_cache is not None:
                return _learning_data_cache

            default = {
                "version": CURRENT_VERSION, # Sync with App Version
                "last_updated": 0,
                "argument_stats": {},
                "combo_stats": {},
                "bin_stats": {},
                "service_stats": {},
                "checked_hashes": {}  # hash -> {timestamp, score} для отслеживания перепроверок
            }
            _learning_data_cache = load_json_robust(LEARNING_DATA_PATH, default)
            
            # Ensure defaults exist
            for k, v in default.items():
                if k not in _learning_data_cache:
                    _learning_data_cache[k] = v
            
            return _learning_data_cache

    def flush_learning_data():
        """Сбрасывает кэш обучения на диск"""
        global _learning_data_cache
        with _learning_data_lock:
            if _learning_data_cache:
                _learning_data_cache["last_updated"] = time.time()
                save_json_safe(LEARNING_DATA_PATH, _learning_data_cache)

    def save_learning_data(data):
        """Сохраняет данные обучения (обновляет кэш и сбрасывает на диск)"""
        global _learning_data_cache
        with _learning_data_lock:
            _learning_data_cache = data
        flush_learning_data()
    
    def update_learning_stats(args, score, max_score, service="general", bin_files_used=None, logger=None):
        """Обновляет статистику обучения после проверки стратегии"""
        # CRITICAL FIX: Use Lock for END-TO-END Read-Modify-Write cycle to prevent race conditions
        with _learning_data_lock:
            try:
                data = load_learning_data()

                success_rate = score / max_score if max_score > 0 else 0
                
                # 1. Обновляем статистику аргументов
                for arg in args:
                    if not isinstance(arg, str): continue
                    if arg == "--new": continue
                    
                    # Извлекаем базовый ключ (без значения для некоторых)
                    key = arg
                    if "=" in arg:
                        base = arg.split("=")[0]
                        # Для repeats и ttl сохраняем полное значение
                        if "repeats" in base or "ttl" in base:
                            key = arg
                        else:
                            key = base
                    else:
                        key = arg
                
                    if key not in data["argument_stats"]:
                        data["argument_stats"][key] = {"uses": 0, "successes": 0, "total_score": 0}
                    
                    data["argument_stats"][key]["uses"] += 1
                    data["argument_stats"][key]["successes"] += score
                    data["argument_stats"][key]["total_score"] += success_rate
            
                # 2. Обновляем статистику bin-файлов
                if bin_files_used:
                    for bf in bin_files_used:
                        bn = os.path.basename(bf)
                        if bn not in data["bin_stats"]:
                            data["bin_stats"][bn] = {"uses": 0, "successes": 0, "total_score": 0}
                        data["bin_stats"][bn]["uses"] += 1
                        data["bin_stats"][bn]["successes"] += score
                        data["bin_stats"][bn]["total_score"] += success_rate
                
                # 3. Обновляем статистику сервиса
                if service not in data["service_stats"]:
                    data["service_stats"][service] = {"best_score": 0, "total_checks": 0}
                data["service_stats"][service]["total_checks"] += 1
                if score > data["service_stats"][service].get("best_score", 0):
                    data["service_stats"][service]["best_score"] = score
                
                # No save to disk here.
                data["last_updated"] = time.time()
                
            except Exception as e:
                if logger: logger(f"[Learning-Error] Update failed: {e}")
                pass
    
    def get_argument_success_rate(arg_key, learning_data=None):
        """Возвращает коэффициент успешности аргумента (0-1)"""
        if learning_data is None:
            learning_data = load_learning_data()
        stats = learning_data.get("argument_stats", {}).get(arg_key, {})
        uses = stats.get("uses", 0)
        if uses == 0: return 0.5  # Неизвестный - средний приоритет
        return stats.get("total_score", 0) / uses
    
    def can_recheck_strategy(args_hash, days_threshold=7):
        """Проверяет можно ли перепроверить стратегию (прошло ли 7 дней)"""
        data = load_learning_data()
        checked = data.get("checked_hashes", {}).get(args_hash, {})
        if not checked: return True
        last_check = checked.get("timestamp", 0)
        return (time.time() - last_check) > (days_threshold * 24 * 3600)
    
    def mark_strategy_checked(args_hash, score):
        """Помечает стратегию как проверенную"""
        try:
            data = load_learning_data()
            if "checked_hashes" not in data:
                data["checked_hashes"] = {}
            data["checked_hashes"][args_hash] = {"timestamp": time.time(), "score": score}
            # Ограничиваем размер кэша (хранить последние 500)
            if len(data["checked_hashes"]) > 500:
                sorted_hashes = sorted(data["checked_hashes"].items(), 
                                      key=lambda x: x[1].get("timestamp", 0))
                data["checked_hashes"] = dict(sorted_hashes[-500:])
            save_learning_data(data)
        except: pass


    def is_ip_address(s):
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s.strip()))

    def get_registered_domain(domain):
        d = domain.lower().strip()
        
        if is_ip_address(d): return d
        
        if '://' in d: d = d.split('://')[1]
        if '/' in d: d = d.split('/')[0]
        if ':' in d: d = d.split(':')[0]
        
        parts = d.split('.')
        if len(parts) < 2: return d
        
        compound_suffixes = {'com', 'co', 'net', 'org', 'gov', 'edu', 'ac', 'pp', 'msk', 'spb'}
        
        last_part = parts[-1]
        second_last = parts[-2]
        
        if len(last_part) == 2:
            if second_last in compound_suffixes and len(parts) >= 3:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:])
            
        return ".".join(parts[-2:])

    def load_config():
        default_conf = {"main_geometry": None, "log_size": None, "last_exclude_check_time": 0, "last_exclude_mtime": 0}
        acquired = config_lock.acquire(timeout=2)
        if not acquired: return default_conf
        try:
            config_path = os.path.join(get_base_dir(), CONFIG_FILENAME)
            loaded_conf = load_json_robust(config_path, {})
            return {**default_conf, **loaded_conf}
        except: 
            return default_conf
        finally: 
            config_lock.release()

    def save_config(geometry=None, log_size=None, exclude_check_info=None):
        blocking_mode = not is_closing
        if not config_lock.acquire(blocking=blocking_mode): return 
        try:
            config_path = os.path.join(get_base_dir(), CONFIG_FILENAME)
            current_conf = {"main_geometry": None, "log_size": None, "last_exclude_check_time": 0, "last_exclude_mtime": 0}
            if os.path.exists(config_path):
                try: 
                    with open(config_path, "r") as f: 
                        current_conf.update(json.load(f))
                except: pass
            
            if geometry: current_conf["main_geometry"] = geometry
            if log_size: 
                match = re.match(r"(\d+)x(\d+)", log_size)
                if match:
                    current_conf["log_size"] = f"{match.group(1)}x{match.group(2)}"
            if exclude_check_info:
                current_conf["last_exclude_check_time"] = exclude_check_info["time"]
                current_conf["last_exclude_mtime"] = exclude_check_info["mtime"]
            
            with open(config_path, "w") as f:
                json.dump(current_conf, f)
                f.flush()
                os.fsync(f.fileno())
        except: pass
        finally: config_lock.release()

    def is_admin():
        try: return ctypes.windll.shell32.IsUserAnAdmin()
        except: return False

    def check_single_instance():
        kernel32 = ctypes.windll.kernel32
        force_instance_mode = ("--force-instance" in sys.argv or "--restart" in sys.argv)
        attempts = 40 if force_instance_mode else 10
        for i in range(attempts): 
            app_mutex = kernel32.CreateMutexW(None, False, "Nova_Unique_Mutex_Lock")
            last_err = kernel32.GetLastError()
            
            if last_err == 183: # ERROR_ALREADY_EXISTS
                kernel32.CloseHandle(app_mutex)
                if force_instance_mode:
                    # During restart, wait for old process to exit and free mutex.
                    time.sleep(0.25)
                    continue
                try:
                    # Пытаемся найти окно по частичному соответствию заголовка
                    def enum_windows_proc(hwnd, lParam):
                        window_text = ctypes.create_unicode_buffer(512)
                        ctypes.windll.user32.GetWindowTextW(hwnd, window_text, 512)
                        if f"Nova v" in window_text.value:
                            ctypes.windll.user32.ShowWindow(hwnd, 9) # SW_RESTORE
                            ctypes.windll.user32.SetForegroundWindow(hwnd)
                            return False # Stop enumeration
                        return True
                    
                    EnumWindows = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
                    ctypes.windll.user32.EnumWindows(EnumWindows(enum_windows_proc), 0)
                    sys.exit(0)
                except: pass
                
                time.sleep(0.3)
                continue
            return app_mutex
        
        try:
            temp_root = tk.Tk(); temp_root.withdraw(); temp_root.attributes("-topmost", True)
            if force_instance_mode:
                msg = "Перезапуск не смог получить mutex экземпляра Nova.\n\nЗавершите зависшие процессы pythonw.exe / Nova.exe и запустите Nova снова."
            else:
                msg = "Программа уже запущена!\n\nПроверьте системный трей (возле часов) или завершите процессы pythonw.exe / Nova.exe в Диспетчере задач."
            messagebox.showerror("Nova - Ошибка запуска", msg)
            temp_root.destroy()
        except: pass
        sys.exit(1)

    class POINT(ctypes.Structure): _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
    def is_monitor_available(x, y):
        return ctypes.windll.user32.MonitorFromPoint(POINT(int(x), int(y)), 0) != 0

    def check_internet_connection():
        # Проверяем интернет через разрешение известных доменов и подключение к ним
        known_hosts = ["www.google.com", "www.cloudflare.com", "www.microsoft.com"]
        for host in known_hosts:
            # check_cache=False, чтобы это была реальная проверка сети, а не кэша
            ip, _ = dns_manager.resolve(host, dns_manager.burst_limiter, check_cache=False)
            if ip:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(3)
                        s.connect((ip, 80))
                    return True
                except:
                    continue
        return False

    # ================= МОДУЛЬ: NOVA_LOGIC =================

    # === Потокобезопасный ограничитель скорости ===
    class RateLimiter:
        """Обеспечивает ограничение скорости для вызовов в многопоточной среде."""
        def __init__(self, calls_per_second):
            self.calls_per_second = calls_per_second
            self.timestamps = deque()
            self.lock = threading.Lock()

        def acquire(self):
            with self.lock:
                now = time.monotonic()
                
                # Удаляем старые временные метки, которые вышли за пределы окна в 1 секунду
                while self.timestamps and now - self.timestamps[0] > 1.0:
                    self.timestamps.popleft()

                if len(self.timestamps) >= self.calls_per_second:
                    # Если лимит достигнут, вычисляем время ожидания до старейшей метки
                    wait_time = (self.timestamps[0] + 1.0) - now
                    if wait_time > 0:
                        # Разблокируем на время ожидания, чтобы не блокировать другие потоки
                        self.lock.release()
                        time.sleep(wait_time)
                        self.lock.acquire()
                        # После ожидания нужно снова проверить и очистить, т.к. состояние могло измениться
                        now = time.monotonic()
                        while self.timestamps and now - self.timestamps[0] > 1.0:
                            self.timestamps.popleft()
                
                self.timestamps.append(now)

    # === Центральный менеджер DNS ===
    class DNSManager:
        """
        Централизованно управляет DNS-запросами, кэшированием, ограничением скорости,
        используя системный DNS.
        """
        def __init__(self, base_dir):
            self.base_dir = base_dir
            
            # Ограничители скорости
            self.cleanup_limiter = RateLimiter(5)
            self.burst_limiter = RateLimiter(50)
            
            # Кэш для 24-часового ограничения
            self.cache_path = os.path.join(self.base_dir, "temp", "dns_check_cache.json")
            self.dns_cache = {}  # { "domain": {"ip": "x.x.x.x", "timestamp": float} }
            self.cache_lock = threading.Lock()
            self.load_cache()

        def load_cache(self):
            """Загружает кэш DNS из файла."""
            with self.cache_lock:
                self.dns_cache = load_json_robust(self.cache_path, {})

        def save_cache(self):
            """Сохраняет кэш DNS в файл."""
            with self.cache_lock:
                save_json_safe(self.cache_path, self.dns_cache)

        def resolve(self, domain, limiter, check_cache=True):
            """
            Разрешает домен в IP-адрес, используя системный DNS,
            ограничение скорости и кэширование.

            Args:
                domain (str): Домен для разрешения.
                limiter (RateLimiter): Экземпляр ограничителя скорости.
                check_cache (bool): Учитывать ли 24-часовой кэш.

            Returns:
                tuple: (IP-адрес или None, статус 'ok'/'cached_ok'/'no_dns'/'error').
            """
            now = time.time()
            domain = domain.lower()

            if check_cache:
                with self.cache_lock:
                    if domain in self.dns_cache and (now - self.dns_cache[domain]["timestamp"] < 86400):
                        cached_ip = self.dns_cache[domain].get("ip")
                        return cached_ip, "cached_ok" if cached_ip else "cached_no_dns"

            if limiter: limiter.acquire()
            
            ip_address = None
            
            try:
                # Используем стандартный системный резолвер
                ip_address = socket.gethostbyname(domain)
            except socket.gaierror:
                # gaierror - основная ошибка для "не найден" или "ошибка разрешения"
                return self._update_cache(domain, None), "no_dns"
            except Exception:
                # Любые другие исключения (например, таймауты, если они случатся)
                return self._update_cache(domain, None), "error"

            return self._update_cache(domain, ip_address), "ok"

        def _update_cache(self, domain, ip_address):
            """Обновляет кэш с новым результатом и возвращает IP."""
            with self.cache_lock:
                self.dns_cache[domain] = {
                    "ip": ip_address,
                    "timestamp": time.time()
                }
            return ip_address
        
        def validate_domain_exists(self, domain, limiter):
            """
            Проверяет существование домена через каскадный DNS с агрессивной политикой:
            - Удаление при ПЕРВОМ NXDOMAIN (не ждем остальные DNS)
            - Переход к следующему DNS только при таймауте (5 сек)
            - Использует выделенный порт 16450 для изоляции от проверок стратегий
            
            Args:
                domain (str): Домен для проверки
                limiter (RateLimiter): Ограничитель скорости
            
            Returns:
                bool: True если домен существует, False если получен NXDOMAIN
            """
            import socket
            import struct
            import random as rand
            
            domain = domain.lower().strip()
            if not domain:
                return False
            
            limiter.acquire()
            
            # Dedicated DNS check port (isolated from strategy checks 16000-16009)
            DNS_CHECK_PORT = 16450
            
            # Cascade DNS servers
            dns_servers = [
                ("8.8.8.8", "Google DNS"),
                ("1.1.1.1", "Cloudflare DNS"),
                (None, "System DNS")
            ]
            
            for dns_ip, dns_name in dns_servers:
                try:
                    if dns_ip:
                        # Try with specific DNS using socket with custom source port
                        try:
                            # Create socket with specific source port
                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            
                            # Try to bind to dedicated port, or pick a random one in the safe range (16451-16499)
                            # to support parallel validation while bypassing winws
                            bound = False
                            try:
                                sock.bind(('0.0.0.0', DNS_CHECK_PORT))
                                bound = True
                            except:
                                for _ in range(10): # Try 10 random ports in the safe range
                                    try:
                                        alt_port = rand.randint(16451, 16499)
                                        sock.bind(('0.0.0.0', alt_port))
                                        bound = True
                                        break
                                    except: continue
                            
                            if not bound:
                                # Fallback: let OS pick a port if safe range is exhausted
                                try: sock.bind(('0.0.0.0', 0))
                                except: pass

                            sock.settimeout(5.0)  # 5 second timeout
                            
                            # Manual DNS query (simplified A record query)
                            # Build DNS query packet
                            transaction_id = rand.randint(0, 65535)
                            flags = 0x0100  # Standard query
                            questions = 1
                            answer_rrs = 0
                            authority_rrs = 0
                            additional_rrs = 0
                            
                            header = struct.pack('!HHHHHH', transaction_id, flags, questions, 
                                               answer_rrs, authority_rrs, additional_rrs)
                            
                            # Encode domain name
                            question = b''
                            for part in domain.split('.'):
                                question += bytes([len(part)]) + part.encode('ascii')
                            question += b'\x00'  # End of domain
                            question += struct.pack('!HH', 1, 1)  # Type A, Class IN
                            
                            query = header + question
                            
                            # Send query to DNS server
                            sock.sendto(query, (dns_ip, 53))
                            
                            # Receive response
                            try:
                                data, _ = sock.recvfrom(512)
                                sock.close()
                                
                                # Parse response flags
                                response_flags = struct.unpack('!H', data[2:4])[0]
                                rcode = response_flags & 0x000F
                                
                                if rcode == 3:  # NXDOMAIN
                                    return False  # Domain doesn't exist - DELETE IT
                                elif rcode == 0:  # NOERROR
                                    return True  # Domain exists
                                else:
                                    # Other error, try next DNS
                                    continue
                                    
                            except socket.timeout:
                                sock.close()
                                # Timeout - try next DNS server
                                continue
                                
                        except Exception:
                            # Error with manual DNS query, fallback to gethostbyname
                            pass
                    
                    # Fallback: Use system DNS with socket.gethostbyname
                    try:
                        socket.gethostbyname(domain)
                        return True  # Domain exists
                    except socket.gaierror as e:
                        # Check error type
                        if hasattr(e, 'errno'):
                            if e.errno == socket.EAI_NONAME or e.errno == -2:
                                return False  # NXDOMAIN - DELETE IT
                        # Check error message
                        error_msg = str(e).lower()
                        if 'name or service not known' in error_msg or 'no such host' in error_msg:
                            return False  # NXDOMAIN - DELETE IT
                        # Other error - try next DNS
                        continue
                    except socket.timeout:
                        # Timeout - try next DNS
                        continue
                    except Exception:
                        # Other error - try next DNS
                        continue
                        
                except Exception:
                    # Error with this DNS server - try next
                    continue
            
            # All DNS servers timed out or failed - KEEP domain (don't delete on network errors)
            return True
    
    def check_internet_connectivity():
        """
        Check internet connectivity using Google's official endpoint.
        Returns True if internet is available, False otherwise.
        Uses http://connectivitycheck.gstatic.com/generate_204
        """
        try:
            response = requests.get(
                "http://connectivitycheck.gstatic.com/generate_204",
                timeout=3,
                allow_redirects=False
            )
            # Google returns 204 No Content if internet is working
            return response.status_code == 204
        except:
            return False

    def smart_update_general(new_domains_list=None):
        with general_list_lock:
            filepath = os.path.join(get_base_dir(), "list", "general.txt")
            preserve_exact_domains = {
                "api.cloudflareclient.com", "api.cloudflareclient.com.",
                "engage.cloudflareclient.com", "engage.cloudflareclient.com.",
                "connectivity.cloudflareclient.com", "connectivity.cloudflareclient.com.",
                "notifications.cloudflareclient.com", "notifications.cloudflareclient.com.",
            }
            
            current_lines = []
            version_header = f"# version: {CURRENT_VERSION}\n"
            
            if os.path.exists(filepath):
                with open(filepath, "r", encoding="utf-8") as f:
                    current_lines = f.readlines()
            
            # Extract existing version header if present
            if current_lines and current_lines[0].strip().startswith("# version:"):
                version_header = current_lines[0]  # Preserve existing header
            
            unique_domains = set()
            for line in current_lines:
                raw = line.split('#')[0].strip() # Skip comments
                if not raw:
                    continue
                raw_l = raw.lower()
                if raw_l in preserve_exact_domains:
                    unique_domains.add(raw_l)
                else:
                    unique_domains.add(get_registered_domain(raw))
                
            if new_domains_list:
                for d in new_domains_list:
                    raw_new = str(d).split('#')[0].strip().lower()
                    if not raw_new:
                        continue
                    if raw_new in preserve_exact_domains:
                        unique_domains.add(raw_new)
                    else:
                        clean_new = get_registered_domain(raw_new)
                        if clean_new:
                            unique_domains.add(clean_new)
            
            sorted_list = sorted(list(unique_domains))
            
            # Build new content: Version header + sorted domains
            new_content = [version_header]
            for item in sorted_list: 
                new_content.append(item + "\n")
                
            old_content_stripped = [line.strip() for line in current_lines if not line.strip().startswith("#")]
            new_content_stripped = [line.strip() for line in new_content if not line.strip().startswith("#")]
            
            # Compare only domains, ignoring headers for content check
            if old_content_stripped == new_content_stripped:
                return False
                
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.writelines(new_content)
                
                if new_domains_list:
                    print(f"[General] Добавлен(ы) новый(е) домен(ы). Файл general.txt ОБНОВЛЕН.")
                else:
                    print(f"[General] Файл general.txt ОБНОВЛЕН (сортировка/удаление дубликатов).")
                return True
            except Exception as e: 
                print(f"ERR: Не удалось сохранить general.txt: {e}")
                return False

    def add_to_hard_list(domain):
        filepath = os.path.join(get_base_dir(), "temp", HARD_LIST_FILENAME)
        try:
            with open(filepath, "a", encoding="utf-8") as f:
                ts = time.strftime('%d.%m.%Y в %H:%M')
                f.write(f"{domain} # Не удалось разблокировать (Auto-Detect {ts})\n")
            
            print(f"[HardList] Домен {domain} добавлен в hard.txt.")
            return True
        except: return False

    def check_unblock_success(domain):
        url = f"https://{domain}"
        import requests
        import urllib3
        # Отключаем предупреждения SSL
        try: urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except: pass
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36", "Connection": "keep-alive"}
        try:
            # Используем DNSManager для проверки существования домена
            ip, _ = dns_manager.resolve(domain, dns_manager.burst_limiter, check_cache=False)
            if not ip:
                return False
            
            session = requests.Session()
            session.trust_env = False
            with session.get(url, headers=headers, timeout=(10, 10), stream=True, allow_redirects=True, verify=False) as response:
                if response.status_code < 400:
                    return True
                else:
                    return False
        except:
            return False

    # ================= МОДУЛЬ: LOG_FILTER =================
    def should_ignore(line):
        text_lower = line.lower().strip()
        
        if not text_lower: return True

        # 1. ВАЖНОЕ (Белый список)
        critical_markers = [
            "panic", "fatal", "could not read", "error", "fail", "must specify", "unknown option",
            "не удается", "не найдено", "ошибка"
        ]
        
        if any(m in text_lower for m in critical_markers):
            if "decryption failed" in text_lower or "crypto failed" in text_lower:
                return True
            return False

        # 2. ФИЛЬТРЫ (Черный список)
        starts_with_filters = (
            "github version", "read", "adding low-priority", "we have", "profile",
            "loading", "loaded", "lists summary", "hostlist file", "ipset file",
            "splits summary", "windivert", "!impostor", "initializing",
            "(", ")", "outbound", "inbound", "and", "or",
            "packet: id=", "ip4:", "ip6:", "tcp: len=", "udp: len=",
            "using cached desync", "desync profile", "* ipset check", "* hostlist check",
            "hostlist check", "reassemble", "starting reassemble", "delay desync",
            "discovering", "sending delayed", "replaying", "replay ip4", "replay ip6",
            "dpi desync src=", "multisplit pos", "normalized multisplit", "seqovl",
            "sending multisplit", "sending original", "dropping", "not applying tampering",
            "desync profile changed", "tls", "quic initial", "packet contains",
            "incoming ttl", "forced wssize", "req retrans", 
            "auto hostlist", 
            "sending fake[1]", "changing ip_id", "[d:", "discovered l7",
            "hostname:", "discovered hostname", "all multisplit pos", "sending",
            "applying tampering", "resending original",
            '"outbound and !loopback'
        )
        
        if text_lower.startswith(starts_with_filters):
            return True
        
        if text_lower.startswith("outbound and !loopback"):
            return True

        contains_filters = [
            "exclude hostlist", "include hostlist", "exclude ipset",
            "desync_any_proto is not set", "initial defrag crypto failed",
            "delayed packets", "fail counter", "threshold reached",
            "--wf-raw", "fake[1] applied",
            "session id length mismatch"
        ]
        
        if any(f in text_lower for f in contains_filters):
            return True

        return False

    def get_line_tag(line):
        text_lower = line.lower()

        if line.startswith("!!! [AUTO]"): return "normal"
        if "[StrategyBuilder]" in line: return "info"
        if "[DomainCleaner]" in line:
            return "info"
        if any(x in line for x in ["[Check]", "[Check-Init]", "[Evo]", "[Evo-Init]", "[Evo-PreCheck]", "[Evo-1]", "[Init]"]): 
            return "info"
        if ("[RU]" in line and "статус:" in text_lower and "connecting" in text_lower) or ("happy eyeballs" in text_lower):
            return "warning"
        
        # Специальное выделение проблем для [RU], [EU], [SingBox]
        if any(cat in line for cat in ["[RU]", "[EU]", "[SingBox]"]):
            if any(x in text_lower for x in ["ошибка", "error", "fail", "не удается", "не найден", "не удалось", "exception", "warning", "warn", "остановка", "падение"]):
                return "error"

        if any(x in text_lower for x in ["err:", "error", "dead", "crash", "could not read", "fatal", "panic", "must specify", "unknown option", "не удается", "не найдено", "repair", "ремонт"]):
            return "error"
        # Detect WinDivert-related codes only as standalone diagnostics (avoid false matches in IP:port like :3478).
        if re.search(r'(?<!\d)(177|34)(?!\d)', text_lower) and any(k in text_lower for k in ["код", "code", "exit", "windivert", "driver"]):
            return "error"
        
        if "fail" in text_lower:
            return "fail"
        
        if "ok (" in text_lower:
            return "normal"
        
        if any(x in text_lower for x in ["успешное подключение", "успешно инициализирован", "ядро активно"]):
            return "normal"
        
        if any(x in text_lower for x in ["пропуск", "удаление", "отмена", "инфо", "успешно"]):
            return "info"
            
        return "normal"


    # ================= МОДУЛЬ: NOVA_PAYLOAD_GEN =================
    def create_tls_client_hello(hostname):
        """Генерирует валидный TLS 1.3 ClientHello с указанным SNI."""
        hostname_bytes = hostname.encode('utf-8')
        
        tls_ver = b'\x03\x03'
        handshake_type = b'\x01'
        
        client_random = os.urandom(32)
        
        session_id_len = b'\x20'
        session_id = os.urandom(32)
        
        ciphers = bytes.fromhex("130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035")
        ciphers_len = struct.pack("!H", len(ciphers))
        
        compression = b'\x01\x00'
        
        extensions = b''
        
        ext_sni_type = b'\x00\x00'
        sni_data = struct.pack("!H", len(hostname_bytes) + 3) + b'\x00' + struct.pack("!H", len(hostname_bytes)) + hostname_bytes
        ext_sni_len = struct.pack("!H", len(sni_data))
        extensions += ext_sni_type + ext_sni_len + sni_data
        
        ext_ver_type = b'\x00\x2b'
        ver_data = b'\x03\x02\x03\x04\x03\x03'
        ext_ver_len = struct.pack("!H", len(ver_data))
        extensions += ext_ver_type + ext_ver_len + ver_data

        current_len = 38 + len(ciphers) + len(extensions)
        pad_len = 512 - current_len
        if pad_len > 0:
            ext_pad_type = b'\x00\x15'
            pad_data = b'\x00' * pad_len
            ext_pad_len = struct.pack("!H", len(pad_data))
            extensions += ext_pad_type + ext_pad_len + pad_data

        extensions_len = struct.pack("!H", len(extensions))
        handshake_body = tls_ver + client_random + session_id_len + session_id + ciphers_len + ciphers + compression + extensions_len + extensions
        handshake_len = struct.pack("!I", len(handshake_body))[1:]
        handshake_msg = handshake_type + handshake_len + handshake_body
        record_len = struct.pack("!H", len(handshake_msg))
        record = b'\x16\x03\x01' + record_len + handshake_msg
        
        return record
    def sanitize_filename(domain):
        return domain.replace(".", "_")

    def payload_worker(log_callback):
        """Фоновый процесс генерации фейков (Только TLS)."""
        time.sleep(5)
        
        paths = ensure_structure()
        bin_dir = os.path.join(get_base_dir(), "fake")
        exclude_file = paths['list_exclude']
        
        while not is_closing:
            try:
                # FIX: Disabled scanning of exclude.txt (User Request: reduce load + unnecessary fakes)
                # Just sleep to keep thread alive but idle (or valid logic if needed later)
                time.sleep(3600)
                
                # FIX: Disabled scanning of exclude.txt (User Request: reduce load + unnecessary fakes)
                # Just sleep to keep thread alive but idle (or valid logic if needed later)
                time.sleep(3600)
                
            except Exception as e:
                # log_callback(f"[PayloadGen ERROR] Критическая ошибка: {e}")
                time.sleep(60)

    # ================= КОНФИГУРАЦИЯ GUI =================
    LOG_MAX_LINES = 10000
    
    def detect_system_theme():
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            val, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            return "light" if val == 1 else "dark"
        except: return "light"

    SYSTEM_THEME = detect_system_theme()

    COLOR_BLUEBERRY_YOGURT = "#DCD0FF"
    COLOR_BG = "#F0F0F0"
    COLOR_TEXT_NORMAL = "#13A10E"
    COLOR_TEXT_ERROR = "#FFA500"
    COLOR_TEXT_INFO = "#AAAAAA"
    COLOR_TEXT_FAIL = "#FF4444"

    log_window = None
    log_text_widget = None
    auto_scroll_enabled = True 
    app_mutex = None
    early_log_buffer = []  # Buffer for logs before log_window is created
    cached_log_size = "700x450"
    btn_logs = None
    
    BROWSER_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Ch-Ua": '"Not A(Brand";v="24", "Chromium";v="132", "Google Chrome";v="132"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive"
    }

    # ================= GUI УТИЛИТЫ =================

    WINDOW_STATE_FILE = os.path.join(get_base_dir(), "temp", "window_state.json")

    def load_window_state():
        try:
            if os.path.exists(WINDOW_STATE_FILE):
                with open(WINDOW_STATE_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
        except: pass
        return {}

    def save_window_state(**kwargs):
        try:
            current = load_window_state()
            current.update(kwargs)
            os.makedirs(os.path.dirname(WINDOW_STATE_FILE), exist_ok=True)
            with open(WINDOW_STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(current, f)
        except: pass

    class ModernScrollbar(tk.Canvas):
        def __init__(self, master, command=None, **kwargs):
            # Цвета скроллбара в зависимости от темы Windows
            if SYSTEM_THEME == "dark":
                self.bg_color = "#000000" # Фон трека (сливается с логом)
                self.thumb_color = "#444444"
                self.hover_color = "#666666"
            else:
                self.bg_color = "#F0F0F0" # Светлый трек для светлой темы
                self.thumb_color = "#CDCDCD"
                self.hover_color = "#A6A6A6"
            
            super().__init__(master, bg=self.bg_color, width=12, highlightthickness=0, **kwargs)
            self.command = command
            self.y_lo = 0.0
            self.y_hi = 1.0
            self.is_hover = False
            
            self.bind("<Button-1>", self._on_click)
            self.bind("<B1-Motion>", self._on_drag)
            self.bind("<Enter>", self._on_enter)
            self.bind("<Leave>", self._on_leave)
            self.bind("<Configure>", self._draw)

        def set(self, lo, hi):
            self.y_lo = float(lo); self.y_hi = float(hi)
            self._draw()

        def _draw(self, event=None):
            self.delete("all"); w = self.winfo_width(); h = self.winfo_height()
            if h == 0: return
            thumb_h = max(20, h * (self.y_hi - self.y_lo))
            thumb_y = h * self.y_lo
            pad = 3; x1 = pad; x2 = w - pad; y1 = thumb_y; y2 = thumb_y + thumb_h
            if y2 > h: y2 = h; y1 = max(0, y2 - thumb_h)
            color = self.hover_color if self.is_hover else self.thumb_color
            r = (x2 - x1) / 2
            self.create_oval(x1, y1, x2, y1 + 2*r, fill=color, outline=color)
            self.create_oval(x1, y2 - 2*r, x2, y2, fill=color, outline=color)
            self.create_rectangle(x1, y1 + r, x2, y2 - r, fill=color, outline=color)

        def _on_click(self, event):
            h = self.winfo_height(); 
            if h == 0: return
            if event.y / h < self.y_lo: self.command("scroll", -1, "pages") if self.command else None
            elif event.y / h > self.y_hi: self.command("scroll", 1, "pages") if self.command else None
            else: self._drag_start_y = event.y; self._drag_start_lo = self.y_lo
        def _on_drag(self, event):
            if hasattr(self, '_drag_start_y') and self.command: self.command("moveto", self._drag_start_lo + (event.y - self._drag_start_y) / self.winfo_height())
        def _on_enter(self, e): self.is_hover = True; self._draw()
        def _on_leave(self, e): self.is_hover = False; self._draw()

    # === OPTIMIZED WINDOW ALIGNMENT ===
    def get_monitor_work_area(center_x, center_y):
        """Возвращает рабочую область монитора (без панели задач) для заданной точки."""
        try:
            class RECT(ctypes.Structure): _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), ("right", ctypes.c_long), ("bottom", ctypes.c_long)]
            class MONITORINFO(ctypes.Structure): _fields_ = [("cbSize", ctypes.c_long), ("rcMonitor", RECT), ("rcWork", RECT), ("dwFlags", ctypes.c_long)]
            pt = POINT(center_x, center_y)
            hMonitor = ctypes.windll.user32.MonitorFromPoint(pt, 2) # MONITOR_DEFAULTTONEAREST = 2
            mi = MONITORINFO(); mi.cbSize = ctypes.sizeof(MONITORINFO)
            ctypes.windll.user32.GetMonitorInfoW(hMonitor, ctypes.byref(mi))
            return mi.rcWork.left, mi.rcWork.top, mi.rcWork.right, mi.rcWork.bottom
        except:
            return 0, 0, root.winfo_screenwidth(), root.winfo_screenheight()

    def calc_log_window_pos(mx, my, mw, mh, log_w, log_h, mon_left, mon_right, current_side=None):
        """Рассчитывает позицию окна логов (справа или слева) с гистерезисом."""
        # Calculate potential availability
        right_x = mx + mw
        right_ok = (right_x + log_w <= mon_right)
        
        left_x = mx - log_w
        left_ok = (left_x >= mon_left)

        # Decision Logic (Sticky Side)
        side = "right" # default
        
        if current_side == "left":
            if left_ok: side = "left" # Stick to left if possible
            elif right_ok: side = "right" # Switch to right if left fails
            else: side = "right" # Fallback
        elif current_side == "right":
            if right_ok: side = "right" # Stick to right if possible
            elif left_ok: side = "left" # Switch to left if right fails
            else: side = "right" # Fallback
        else:
            # No history (first run or reset)
            if right_ok: side = "right"
            elif left_ok: side = "left"
            else: side = "right"
        
        # Final Assign
        if side == "right": new_x = right_x
        else: new_x = left_x
        
        new_y = my # Верхняя граница совпадает
        return new_x, new_y, side

    def align_log_window_to_main(event=None, forced_main_geom=None, cached_mon_bounds=None):
        global cached_log_size
        if not log_window or not root: return
        if event and event.widget != root: return
        
        try:
            # Получаем геометрию основного окна
            if forced_main_geom:
                mx, my, mw, mh = forced_main_geom
            else:
                main_geom = root.geometry()
                match = re.match(r"(\d+)x(\d+)\+([-\d]+)\+([-\d]+)", main_geom)
                if not match: return
                mw, mh = int(match.group(1)), int(match.group(2))
                mx, my = int(match.group(3)), int(match.group(4))

            # Получаем размеры лога
            log_size_str = cached_log_size.split('+')[0]
            lw, lh = 700, 450
            m_log = re.match(r"(\d+)x(\d+)", log_size_str)
            if m_log: lw, lh = int(m_log.group(1)), int(m_log.group(2))

            # Определяем границы монитора (кэш или запрос)
            if cached_mon_bounds:
                mon_left, mon_top, mon_right, mon_bottom = cached_mon_bounds
            else:
                mon_left, mon_top, mon_right, mon_bottom = get_monitor_work_area(mx + mw // 2, my + 10)

            # Расчет
            cur_side = getattr(log_window, "current_side", None)
            new_x, new_y, side = calc_log_window_pos(mx, my, mw, mh, lw, lh, mon_left, mon_right, cur_side)
            log_window.current_side = side # Save state
            
            # Применение
            log_window.geometry(f"{lw}x{lh}+{new_x}+{new_y}")
            
            # Обновление UI элементов (кнопка, грип)
            if btn_logs:
                if side == "right": btn_logs.move_to(mw - 10, mh - 10, "se")
                else: btn_logs.move_to(10, mh - 10, "sw")
            
            if hasattr(log_window, "sizegrip"):
                if side == "right":
                    log_window.sizegrip.set_side("right")
                    log_window.sizegrip.place(relx=1.0, rely=1.0, anchor="se", x=0, y=0)
                else:
                    log_window.sizegrip.set_side("left")
                    log_window.sizegrip.place(relx=0.0, rely=1.0, anchor="sw", x=0, y=0)
                    
        except Exception as e:
            # print(f"Align error: {e}")
            pass

    def get_autostart_cmd():
        """Проверяет наличие записи автозапуска в реестре"""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
            try:
                cmd, _ = winreg.QueryValueEx(key, "NovaApplication")
                winreg.CloseKey(key)
                return cmd
            except FileNotFoundError:
                winreg.CloseKey(key)
                return None
        except Exception:
            return None

    def toggle_startup(log_func=None):
        """Переключает состояние автозапуска"""
        try:
            start_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
            
            # Определяем пути
            base_dir = get_base_dir()
            potential_exe = os.path.join(base_dir, "Nova.exe")
            if not os.path.exists(potential_exe):
                potential_exe = os.path.join(base_dir, "nova.exe")
            
            if getattr(sys, 'frozen', False):
                # Скомпилированная версия (EXE)
                exe_path = os.path.abspath(sys.executable)
                cmd_to_add = f'"{exe_path}" --minimized'
            elif os.path.exists(potential_exe):
                # Мы в режиме скрипта, но рядом есть Nova.exe - используем его для автозапуска
                cmd_to_add = f'"{os.path.abspath(potential_exe)}" --minimized'
            else:
                # Режим скрипта .pyw
                exe_path = os.path.abspath(sys.executable)
                script_path = os.path.abspath(__file__)
                cmd_to_add = f'"{exe_path}" "{script_path}" --minimized'

            # Проверяем текущее наличие
            exists = False
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, start_key, 0, winreg.KEY_READ)
                try:
                    current_cmd, _ = winreg.QueryValueEx(key, "NovaApplication")
                    exists = True
                except FileNotFoundError:
                    exists = False
                winreg.CloseKey(key)
            except: 
                exists = False

            # Открываем для записи
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, start_key, 0, winreg.KEY_WRITE)
            
            if exists:
                try:
                    winreg.DeleteValue(key, "NovaApplication")
                    if log_func: log_func("[Autostart] Автозапуск отключен (запись удалена)")
                    else: print("[Autostart] Disabled")
                except Exception as e:
                    if log_func: log_func(f"[Autostart] Ошибка при удалении: {e}")
            else:
                try:
                    winreg.SetValueEx(key, "NovaApplication", 0, winreg.REG_SZ, cmd_to_add)
                    if log_func: log_func(f"[Autostart] Автозапуск включен: {cmd_to_add}")
                    else: print(f"[Autostart] Enabled: {cmd_to_add}")
                except Exception as e:
                    if log_func: log_func(f"[Autostart] Ошибка при записи: {e}")
            
            winreg.CloseKey(key)
        except Exception as e:
            if log_func: log_func(f"[Autostart] Ошибка реестра: {e}")
            else: print(f"[Autostart] Registry Error: {e}")

    def ensure_log_window_created():
        global log_window, log_text_widget, cached_log_size
        if log_window and tk.Toplevel.winfo_exists(log_window): return
        
        try:
            state = load_window_state()
            cached_log_size = state.get("log_size", "700x450")
        except: pass

        log_window = tk.Toplevel(root)
        
        # FIX: Force apply cached size immediately to prevent "tiny window" issue
        if cached_log_size:
            try:
                 # Extract size only (ignore position for now)
                 sz = cached_log_size.split('+')[0]
                 log_window.geometry(sz)
            except: pass
            
        log_window.withdraw() # Скрываем сразу после создания, чтобы избежать белого мерцания
        log_window.title("Лог событий")
        try:
            icon_path = get_internal_path("icon.ico")
            if os.path.exists(icon_path):
                log_window.iconbitmap(icon_path)
        except: pass
        log_window.configure(bg="#000000")
        log_window.transient(root)
        log_window.protocol("WM_DELETE_WINDOW", hide_log_window)
        # FIX: Ensure log window is NOT topmost by default (keeps it attached but not forced top)
        log_window.attributes('-topmost', False)

        # === Scroll Control Bindings ===
        def on_log_enter(e): LOG_SCROLL_STATE["in_window"] = True
        def on_log_leave(e): 
            LOG_SCROLL_STATE["in_window"] = False
            LOG_SCROLL_STATE["last_leave"] = time.time()
        def on_log_focus_in(e): LOG_SCROLL_STATE["focused"] = True
        def on_log_focus_out(e): LOG_SCROLL_STATE["focused"] = False

        log_window.bind("<Enter>", on_log_enter)
        log_window.bind("<Leave>", on_log_leave)
        log_window.bind("<FocusIn>", on_log_focus_in)
        log_window.bind("<FocusOut>", on_log_focus_out)

        align_log_window_to_main()
        
        try:
            log_window.update_idletasks() # Ensure HWND is valid
            use_dark = 1 if SYSTEM_THEME == "dark" else 0
            # Try getting window handle directly
            hwnd = ctypes.windll.user32.GetParent(log_window.winfo_id())
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(use_dark)), 4)
            # Also try setting for the toplevel itself just in case
            # hwnd_top = log_window.winfo_id() 
            # ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd_top, 20, ctypes.byref(ctypes.c_int(use_dark)), 4)
        except: pass
        
        def save_log_size(event):
            global cached_log_size
            if event.widget == log_window:
                geom = log_window.geometry()
                current_size = geom.split('+')[0]
                if current_size != cached_log_size:
                    cached_log_size = current_size
                    # save_window_state(log_size=geom) # Оптимизация: сохраняем только при выходе

        log_window.bind('<Configure>', save_log_size)
        root.bind('<Configure>', align_log_window_to_main)
        
        # === НОВОЕ: Кнопка Telegram внизу (добавляем ПЕРЕД контентом) ===
        bottom_frame = tk.Frame(log_window, bg="#1a1a1a", height=21)  # 150% от высоты строки
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=0, pady=0)
        bottom_frame.pack_propagate(False)  # Закрепляем высоту
        
        # FIX: Add resize grip for easier resizing
        # FIX: Add resize grip for easier resizing (Theme Aware)
        try:
            style = ttk.Style()
            style.theme_use('clam') # Clam supports custom background colors
            
            # Check system theme (Global variable SYSTEM_THEME must be defined in main)
            # Default to dark if not found
            is_dark_theme = True
            try: 
                if globals().get("SYSTEM_THEME", "dark") != "dark": is_dark_theme = False
            except: pass
            
            grip_bg = "#1a1a1a" if is_dark_theme else "#f0f0f0"
            style.configure("TSizegrip", background=grip_bg)
        except: pass

        class ResizeGrip(tk.Canvas):
            def __init__(self, parent, **kwargs):
                # Increased size to match bottom_frame height (approx 21-24px) for better clickability
                super().__init__(parent, width=24, height=21, highlightthickness=0, bg=parent["bg"], **kwargs)
                self.parent = parent
                self.side = "right"
                self._draw()
                self.bind("<Enter>", self._on_enter)
                self.bind("<Leave>", self._on_leave)
                self.bind("<ButtonPress-1>", self._on_drag_start)
                self.bind("<B1-Motion>", self._on_drag)
                
            def set_side(self, side):
                self.side = side
                self.config(cursor="size_nw_se" if side == "right" else "size_ne_sw")
                self._draw()
                
            def _draw(self):
                self.delete("all")
                w = int(self["width"])
                h = int(self["height"])
                # Dots color
                c = "#666666" 
                
                # Draw dots forming a triangle
                # Pushed strictly to the corner (margin ~2px)
                if self.side == "right":
                    # Triangle in SE corner (Right)
                    # Coordinates relative to w, h
                    # Bottom row (y = h-3)
                    coords = [
                        (w-3, h-3), (w-7, h-3), (w-11, h-3),
                        (w-3, h-7), (w-7, h-7),
                        (w-3, h-11)
                    ]
                else:
                    # Triangle in SW corner (Left)
                    # Bottom row (y = h-3)
                    coords = [
                        (2, h-3), (6, h-3), (10, h-3),
                        (2, h-7), (6, h-7),
                        (2, h-11)
                    ]
                    
                for x, y in coords:
                    self.create_rectangle(x, y, x+2, y+2, fill=c, outline="")

            def _on_enter(self, e): pass
            def _on_leave(self, e): pass
            
            def _on_drag_start(self, event):
                self._start_x = event.x_root
                self._start_y = event.y_root
                self._start_geom = log_window.geometry()
                
            def _on_drag(self, event):
                try:
                    dx = event.x_root - self._start_x
                    dy = event.y_root - self._start_y
                    
                    # Parse current geometry
                    current_w = log_window.winfo_width()
                    current_h = log_window.winfo_height()
                    
                    x = log_window.winfo_x()
                    y = log_window.winfo_y()
                    
                    if self.side == "left":
                        # Logic for left-side resize:
                        # Dragging left (negative dx) -> Increase width, Move X left
                        # Dragging right (positive dx) -> Decrease width, Move X right (if width > min)
                        
                        new_w = current_w - dx
                        new_x = x + dx
                        new_h = current_h + dy
                        
                        if new_w >= 400 and new_h >= 200:
                            log_window.geometry(f"{new_w}x{new_h}+{new_x}+{y}")
                            self._start_x = event.x_root
                            self._start_y = event.y_root
                    else:
                        new_w = current_w + dx
                        new_h = current_h + dy
                        if new_w >= 400 and new_h >= 200:
                            log_window.geometry(f"{new_w}x{new_h}+{x}+{y}")
                            self._start_x = event.x_root
                            self._start_y = event.y_root
                            
                except: pass

        sizegrip = ResizeGrip(bottom_frame)
        # Using PLACE to ensure it's in the corner regardless of packing
        sizegrip.place(relx=1.0, rely=1.0, anchor="se", x=0, y=0) 
        log_window.sizegrip = sizegrip # Save reference
        
        def open_telegram_chat():
            """Открывает чат Telegram"""
            try:
                # Проверяем наличие обработчика tg:// в реестре
                import winreg
                winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"tg\shell\open\command")
                # Если ключ существует - открываем в приложении
                os.startfile("tg://resolve?domain=nova_txt")
            except (FileNotFoundError, OSError):
                # Если обработчика нет - открываем в браузере
                try:
                    import webbrowser
                    webbrowser.open("https://t.me/nova_txt")
                except Exception as e:
                    print(f"[Log] Ошибка открытия ссылки: {e}")
        
        # Кнопка-текст "Перейти в чат"
        chat_button = tk.Label(bottom_frame, text="→ Telegram чат", fg=COLOR_BLUEBERRY_YOGURT, bg="#1a1a1a", 
                              font=("Segoe UI", 11, "bold"), cursor="hand2", padx=10, pady=2)
        chat_button.pack(side=tk.RIGHT, padx=10, pady=2)
        chat_button.bind("<Button-1>", lambda e: open_telegram_chat())
        chat_button.bind("<Enter>", lambda e: chat_button.config(fg="white", bg="#2a2a2a"))
        chat_button.bind("<Leave>", lambda e: chat_button.config(fg=COLOR_BLUEBERRY_YOGURT, bg="#1a1a1a"))
        
        # Используем Frame для компоновки текста и кастомного скроллбара
        content_frame = tk.Frame(log_window, bg="#000000")
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ModernScrollbar(content_frame)
        log_text_widget = tk.Text(content_frame, wrap=tk.WORD, font=("Consolas", 11, "bold"), bg="#000000", fg="#E0E0E0", yscrollcommand=scrollbar.set, bd=0, highlightthickness=0)
        scrollbar.command = log_text_widget.yview
        
        log_text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        for tag, col in [("normal", COLOR_TEXT_NORMAL), ("error", COLOR_TEXT_ERROR), ("info", COLOR_TEXT_INFO), ("fail", COLOR_TEXT_FAIL)]:
            log_text_widget.tag_config(tag, foreground=col)

        log_text_widget.tag_config("warning", foreground="#E6C200") # Тускло-желтый для предупреждений
        
        # FIX: Track manual scrolling to prevent unwanted autoscroll
        def on_mouse_wheel(e):
            # User scrolled manually -> disable autoscroll
            LOG_SCROLL_STATE["user_scrolled"] = True
            # Check if scrolled to bottom -> re-enable autoscroll
            try:
                if log_text_widget.yview()[1] >= 0.99:  # Within 1% of bottom
                    LOG_SCROLL_STATE["user_scrolled"] = False
            except: pass
            # Return "break" to prevent event propagation if needed
            # return "break"
        
        log_text_widget.bind("<MouseWheel>", on_mouse_wheel)
        
        # Стиль для ссылок обновления (желтый + подчеркивание)
        log_text_widget.tag_config("link_yellow", foreground="#FFD700", underline=True)
        log_text_widget.tag_bind("link_yellow", "<Enter>", lambda e: log_text_widget.config(cursor="hand2"))
        log_text_widget.tag_bind("link_yellow", "<Leave>", lambda e: log_text_widget.config(cursor=""))

        log_text_widget.tag_config("clickable_cmd", foreground=COLOR_TEXT_NORMAL, underline=True)
        
        def copy_command(event):
            try:
                index = log_text_widget.index(f"@{event.x},{event.y}")
                start_index = log_text_widget.tag_prevrange("clickable_cmd", index)[0]
                end_index = log_text_widget.tag_nextrange("clickable_cmd", start_index)[1]
                text = log_text_widget.get(start_index, end_index).strip() 
                root.clipboard_clear(); root.clipboard_append(text); root.update()
            except: pass
            return "break" 
            
        def copy_selection(event=None):
            try:
                if log_text_widget.tag_ranges("sel"):
                    text = log_text_widget.get("sel.first", "sel.last")
                    root.clipboard_clear(); root.clipboard_append(text); root.update()
                return "break"
            except: return "break"

        def select_all(event=None):
            try:
                # Принудительно устанавливаем фокус на виджет перед выделением
                log_text_widget.focus_set()
                log_text_widget.tag_add("sel", "1.0", "end")
                return "break"
            except: return "break"
            
        def handle_key_press(event):
            if (event.state & 4) and (event.keycode == 67 or event.keysym.lower() == 'c'): 
                copy_selection(); return "break"
            if (event.state & 4) and (event.keycode == 65 or event.keysym.lower() == 'a'): 
                select_all(); return "break"
            if event.keysym in ["Prior", "Next", "Up", "Down", "Left", "Right", "Home", "End"]: return None
            return "break"

        context_menu = tk.Menu(log_window, tearoff=0)
        context_menu.add_command(label="Копировать", command=copy_selection)
        context_menu.add_command(label="Выделить все", command=select_all)
        context_menu.add_separator()

        # === Autostart Option ===
        autostart_log_var = tk.BooleanVar()
        def toggle_autostart_wrapper():
            # Use separate thread to ensure UI is not blocked
            threading.Thread(target=toggle_startup, args=(log_print,), daemon=True).start()

        def update_autostart_label():
            is_auto = get_autostart_cmd() is not None
            autostart_log_var.set(is_auto)

        context_menu.add_checkbutton(label="Автозапуск Nova", variable=autostart_log_var, command=toggle_autostart_wrapper)
        context_menu.configure(postcommand=update_autostart_label)
        context_menu.add_separator()

        def force_reset_warp_ui():
            global warp_manager
            if warp_manager:
                def run_nuke():
                    warp_manager.nuke_warp_data()
                    log_print("[RU] Сброс WARP выполнен. Перезапустите программу.")
                threading.Thread(target=run_nuke, daemon=True).start()


        
        # restart_nova moved to GLOBAL scope to be accessible from all menus
        pass 
        
        context_menu.add_command(label="Перезапустить Nova", command=restart_nova)

        log_text_widget.tag_bind("clickable_cmd", "<Button-1>", copy_command)
        log_text_widget.bind("<Button-3>", lambda e: (context_menu.post(e.x_root, e.y_root), "break")[1])
        log_text_widget.bind("<Key>", handle_key_press)
        
        log_text_widget.bind_all("<Control-c>", copy_selection)
        log_text_widget.bind_all("<Control-C>", copy_selection)
        log_text_widget.bind_all("<Control-a>", select_all)
        log_text_widget.bind_all("<Control-A>", select_all)

        # Flush early log buffer now that log_window is ready
        global early_log_buffer
        if early_log_buffer:
            for msg in early_log_buffer:
                try: _safe_log_insert(msg)
                except: pass
            early_log_buffer = []


    def show_log_window(): 
        ensure_log_window_created()
        align_log_window_to_main()
        
        log_window.deiconify()
        log_window.lift()
        log_window.attributes('-topmost', False)
        
        # Применяем тёмную тему ПОСЛЕ показа окна с минимальной задержкой
        # (окно должно быть видимым для корректного применения DWM атрибута)
        def apply_theme():
            try:
                use_dark = 1 if SYSTEM_THEME == "dark" else 0
                hwnd = ctypes.windll.user32.GetParent(log_window.winfo_id())
                ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(use_dark)), 4)
            except: pass
        root.after(10, apply_theme)
        
        btn_logs.config(text="Скрыть лог")


    def hide_log_window(): 
        if log_window: log_window.withdraw()
        btn_logs.config(text="Показать лог")

    def toggle_log_window():
        ensure_log_window_created()
        if log_window.state() == "normal": hide_log_window()
        else: show_log_window()
    
    # === SCROLL LOGIC HELPER ===
    LOG_SCROLL_STATE = {
        "in_window": False,
        "focused": False,
        "last_leave": 0,
        "user_scrolled": False  # FIX: Track manual scroll
    }

    def should_auto_scroll():
        try:
             # 1. Not focused -> Auto Scroll
             if not LOG_SCROLL_STATE["focused"]: return True
             # 2. In window -> Pause
             if LOG_SCROLL_STATE["in_window"]: return False
             # 3. User manually scrolled -> Pause until they scroll to bottom
             if LOG_SCROLL_STATE["user_scrolled"]: return False
             # 4. Delay
             if time.time() - LOG_SCROLL_STATE["last_leave"] < 1.0: return False
             return True
        except: return True

    def should_suppress_strategy_noise(line):
        """
        Hide verbose strategy-checker/evolution logs in normal mode.
        Keep important milestones and all warnings/errors.
        """
        try:
            if IS_DEBUG_MODE:
                return False

            text = str(line or "").strip()
            if not text:
                return False
            ll = text.lower()
            has_progress_bar = ("█" in text or "░" in text) and ("[check]" in ll or "[evo" in ll)

            # Never suppress obvious problem signals.
            if any(x in ll for x in [
                "ошибка", "error", "fail", "failed", "warning", "warn",
                "крит", "fatal", "panic", "упал", "crash", "не удалось"
            ]):
                return False

            # Keep progress bars visible in normal mode.
            if has_progress_bar:
                return False

            # Hide noisy strategy/evolution namespaces in normal mode.
            noisy_namespaces = [
                "[debug-check]",
                "[evo-",
                "[evo]",
                "[evo-weight]",
                "[evo-debug]",
                "[sorter",
                "[score-save]",
                "[score-saver-direct]",
                "[strategychecker-debug]",
                "[pruner",
            ]
            if any(ns in ll for ns in noisy_namespaces):
                return True

            # Hide per-strategy score ticks without bars.
            if ("[check]" in ll or "[evo" in ll) and "✓" in text and re.search(r"\b\d+/\d+\b", text):
                return True

            # For [Check], keep only key high-level milestones in normal mode.
            if "[check]" in ll:
                keep_check = [
                    "обнаружена смена ip",
                    "проверка не требуется",
                    "запуск полной проверки стратегий",
                    "подбор полностью завершен",
                    "очистка завершена",
                    "процесс остановлен пользователем",
                    "найдена более сильная стратегия",
                    "эволюция нашла улучшения",
                    "ядро перезапущено",
                ]
                if any(k in ll for k in keep_check):
                    return False
                return True

            # Additional chatter often emitted around strategy persistence.
            noisy_phrases = [
                "восстановлено",
                "baselines",
                "сохранение результатов тестирования",
                "сохранено",
                "кандидатов",
                "проверка текущих стратегий",
                "принудительная очистка",
                "финальная очистка стратегий",
                "подготовка к эволюции",
                "сгенерировано",
            ]
            if any(p in ll for p in noisy_phrases):
                return True
        except:
            return False
        return False


    def log_print(message):
        if should_suppress_strategy_noise(message):
            return
        try: sys.__stdout__.write(message + '\n')
        except: pass
        if root:
            root.after(0, lambda m=message: _safe_log_insert(m))

    def _safe_log_insert(string):
        global early_log_buffer
        if should_suppress_strategy_noise(string):
            return
        string = mask_ips_in_text(string)
        lw_exists = log_window and tk.Toplevel.winfo_exists(log_window)
        
        if lw_exists:
            try:
                # FIX: Enable widget before insert (might be disabled by LiveProgressManager)
                log_text_widget.configure(state=tk.NORMAL)
                
                if int(log_text_widget.index('end-1c').split('.')[0]) > LOG_MAX_LINES:
                    log_text_widget.delete('1.0', '101.0')
                
                tag = get_line_tag(string)
                
                ts = time.strftime("%H:%M:%S")
                log_text_widget.insert(tk.END, f"{ts} {string.strip()}\n", tag)
                if should_auto_scroll(): log_text_widget.see(tk.END)
                
                # FIX: Restore disabled state
                log_text_widget.configure(state=tk.DISABLED)
            except: pass
        else:
            # Buffer logs until log_window is created
            if len(early_log_buffer) < 500:
                early_log_buffer.append(string)

    class RedirectText(object):
        def write(self, string):
            try:
                if root:
                    root.after(0, lambda: self._safe_write(string))
            except (NameError, AttributeError):
                pass # Root not created yet

        def _safe_write(self, string):
            string = mask_ips_in_text(string)
            if should_suppress_strategy_noise(string): return
            if should_ignore(string): return
            
            # === TIMESTAMP ADDED ===
            ts = time.strftime("%H:%M:%S")
            string_to_insert = f"{ts} {string.strip()}\n"
            if log_window and tk.Toplevel.winfo_exists(log_window):
                try:
                    if int(log_text_widget.index('end-1c').split('.')[0]) > LOG_MAX_LINES:
                        log_text_widget.delete('1.0', '101.0')
                    tag = get_line_tag(string_to_insert)
                    if "could not read" in string_to_insert.lower():
                        tag = "error"
                    log_text_widget.insert(tk.END, string_to_insert, tag)
                    if should_auto_scroll(): log_text_widget.see(tk.END)
                except: pass

        def flush(self): pass
    
    sys.stdout = RedirectText()

    # ================= LIVE PROGRESS MANAGER =================
    class LiveProgressManager:
        def __init__(self):
            self.active_lines = {} # id -> mark_name
            self.lock = threading.Lock()

        def create_line(self, line_id, initial_text):
            if not root: return
            root.after(0, lambda: self._safe_create(line_id, initial_text))

        def _safe_create(self, line_id, initial_text):
            try:
                initial_text = mask_ips_in_text(initial_text)
                with self.lock:
                    log_text_widget.configure(state=tk.NORMAL)
                    # Ensure newline if needed
                    if log_text_widget.get("end-2c") != "\n":
                        log_text_widget.insert(tk.END, "\n")
                    
                    # 1. Insert Timestamp (Static)
                    ts = time.strftime("%H:%M:%S")
                    log_text_widget.insert(tk.END, f"{ts} ", "info")
                    
                    # 2. Set Mark for Updateable Part
                    idx = log_text_widget.index("end-1c")
                    mark_name = f"live_{line_id}"
                    log_text_widget.mark_set(mark_name, idx)
                    log_text_widget.mark_gravity(mark_name, tk.LEFT)
                    
                    # 3. Insert Initial Text
                    log_text_widget.insert(tk.END, f"{initial_text}\n", "info")
                    
                    self.active_lines[line_id] = mark_name
                    log_text_widget.configure(state=tk.DISABLED)
                    if should_auto_scroll(): log_text_widget.see(tk.END)
            except: pass

        def update_line(self, line_id, new_text, is_final=False):
            if not root: return
            root.after(0, lambda: self._safe_update(line_id, new_text, is_final))

        def _safe_update(self, line_id, text, is_final):
            try:
                text = mask_ips_in_text(text)
                with self.lock:
                    if line_id not in self.active_lines: return
                    mark_name = self.active_lines[line_id]
                    
                    log_text_widget.configure(state=tk.NORMAL)
                    
                    # Get start from mark
                    idx = log_text_widget.index(mark_name)
                    # Get end of that line
                    line_index = idx.split('.')[0]
                    line_end = f"{line_index}.end"
                    
                    # Delete old content (Preserving timestamp which is before mark)
                    log_text_widget.delete(idx, line_end)
                    
                    # Insert new content
                    log_text_widget.insert(idx, text, "info")
                    
                    if is_final:
                        log_text_widget.mark_unset(mark_name)
                        del self.active_lines[line_id]
                    
                    log_text_widget.configure(state=tk.DISABLED)
            except: pass
        
        def log_message(self, message):
            """Log a static message (not a progress line)"""
            if not root: return
            if should_suppress_strategy_noise(message): return
            root.after(0, lambda: self._safe_log_message(message))
        
        def _safe_log_message(self, message):
            try:
                with self.lock:
                    log_text_widget.configure(state=tk.NORMAL)
                    # Ensure newline if needed
                    if log_text_widget.get("end-2c") != "\n":
                        log_text_widget.insert(tk.END, "\n")
                    
                    # Insert timestamp + message
                    ts = time.strftime("%H:%M:%S")
                    log_text_widget.insert(tk.END, f"{ts} {message}\n", "info")
                    
                    log_text_widget.configure(state=tk.DISABLED)
                    if should_auto_scroll(): log_text_widget.see(tk.END)
            except: pass

    # ================= HELPERS =================
    def get_progress_bar(score, active, total, width=20):
        # uses fractions for visual consistency
        if total == 0:
            return " " * width
        
        # Clamp inputs to prevent overflow artifacts
        if score > total: score = total
        # Ensure that active doesn't exceed "remaining"
        if active > total - score: active = total - score
        
        ratio_success = score / total
        ratio_active = active / total

        success_chars = int(ratio_success * width)
        
        # FIX: Check if 'metric active' is effectively 'remaining'
        # e.g. score + active >= total or very close. 
        # But even if not, we try to visually fill nicely.
        
        # Alternative approach: Calculate solid chars independently?
        # No, "gap" is determined by (width - success - active).
        # We want to avoid 1-char gaps if they are rounding errors.
        
        active_chars = int(ratio_active * width)

        # FIX: If active + score == total (meaning full coverage), we MUST fill the bar.
        # This handles cases like 35/100 or 12/16 where rounding leaves a 1-char hole.
        if score + active >= total:
             active_chars = width - success_chars
             
        # Guard against negative active_chars if success took everything (though ratio check prevents this mostly)
        if active_chars < 0: active_chars = 0
        
        # Strict Clamp to width (Safety)
        total_chars = success_chars + active_chars
        if total_chars > width:
            # overflow? reduce active first
            excess = total_chars - width
            active_chars = max(0, active_chars - excess)
            total_chars = success_chars + active_chars
            if total_chars > width:
                success_chars = max(0, width - active_chars)

        gap_chars = width - success_chars - active_chars
        if gap_chars < 0: gap_chars = 0
        
        bar = "█" * success_chars + "░" * active_chars + " " * gap_chars
        return bar   

    progress_manager = LiveProgressManager()


    # ================= VPN ДЕТЕКТОР =================
    
    def is_vpn_active_func():
        """Проверяет наличие активных VPN/Туннельных интерфейсов (PowerShell)."""
        try:
            # Используем PowerShell для получения всех активных адаптеров
            # Мы проверяем как Name, так и InterfaceDescription
            cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, InterfaceDescription | ConvertTo-Json"]
            
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            
            try:
                output = subprocess.check_output(cmd, startupinfo=startupinfo, creationflags=subprocess.CREATE_NO_WINDOW, stderr=subprocess.DEVNULL, timeout=5).decode('utf-8', errors='ignore')
                if not output.strip(): return False
                
                adapters = json.loads(output)
                if isinstance(adapters, dict): adapters = [adapters] # Handle single adapter case
            except:
                return False

            # Расширенный список ключевых слов для обнаружения VPN
            keywords = ["vpn", "wireguard", "openvpn", "tun", "tap", "zerotier", "tailscale", "secu", "fortinet", "cisco", "hamachi", "amnezia", "warp", "cloudflare", "privado", "mullvad", "nord", "proton"]
            
            # Exclusions (white list)
            # Nova's own TUN adapters (NovaVoice / CloudflareWARP) must not trigger VPN auto-pause.
            exclusions = ["radmin", "novavoice", "nova voice", "cloudflarewarp", "cloudflare warp"] 

            for adapter in adapters:
                name = str(adapter.get("Name", "")).lower()
                desc = str(adapter.get("InterfaceDescription", "")).lower()
                combined = name + " " + desc
                
                # Пропускаем, если адаптер в белом списке
                if any(ex in combined for ex in exclusions):
                     continue

                # Если найдено совпадение с ключевым словом
                if any(k in combined for k in keywords):
                    # log_print(f"[VPN Debug] Найдено совпадение: {combined}")
                    return True
            return False
        except: return False

    def vpn_monitor_worker(log_func):
        """Monitors for VPN connections and pauses/resumes the service."""
        global is_vpn_active, was_service_active_before_vpn, is_service_active, is_closing
        
        # Initial check delay
        time.sleep(1)
        
        while not is_closing:
            try:
                vpn_is_currently_active = is_vpn_active_func()

                if vpn_is_currently_active and not is_vpn_active:
                    log_func("[VPN Detector] Обнаружен активный VPN. Работа приостановлена.")
                    is_vpn_active = True
                    was_service_active_before_vpn = is_service_active
                    
                    if is_service_active: 
                        # silent=True, чтобы не спамить в лог об остановке, так как мы выше уже написали причину
                        stop_nova_service(silent=True)
                    
                    if root: 
                        root.after(0, lambda: (status_label.config(text="ПАУЗА (VPN)", fg=COLOR_TEXT_ERROR), btn_toggle.config(state=tk.DISABLED)))
                        
                elif not vpn_is_currently_active and is_vpn_active:
                    log_func("[VPN Detector] VPN отключен. Возобновление работы...")
                    is_vpn_active = False
                    
                    def restore_ui():
                        btn_toggle.config(state=tk.NORMAL)
                        if not was_service_active_before_vpn:
                            status_label.config(text="ГОТОВ К ЗАПУСКУ", fg="#cccccc")

                    if root: root.after(0, restore_ui)
                    
                    if was_service_active_before_vpn: 
                        log_func("[VPN Detector] Автозапуск Nova...")
                        start_nova_service()
            except Exception as e: 
                log_func(f"[VPN Detector] Ошибка в цикле мониторинга: {e}")
            
            # Optimized check interval: 3 seconds (was 15)
            # This significantly reduces the delay between VPN disconnect and Nova resume
            time.sleep(3)

    # ================= ФОНОВАЯ ПРОВЕРКА ДОСТУПНОСТИ =================
    
    check_queue = queue.Queue()
    checked_domains_cache = {} # domain -> timestamp
    
    check_cache = {}
    check_cache_lock = threading.Lock()
    auto_excluded_domains = set()
    special_strategy_domains = set()
    service_strategy_domains = set()
    exclude_file_lock = threading.Lock() 
    CHECK_CACHE_FILE = os.path.join(get_base_dir(), "temp", "direct_check_cache.json")
    PENDING_CHECKS_FILE = os.path.join(get_base_dir(), "temp", "pending_checks.json")
    IP_CACHE_FILE = os.path.join(get_base_dir(), "temp", "ip_exclude_auto.txt")
    
    pending_exclude_domains = set()
    pending_exclude_lock = threading.Lock()
    batch_timer_start = 0
    ip_cache_lock = threading.Lock()
    hard_list_lock = threading.Lock()
    general_list_lock = threading.Lock()

    # ================= PORT MANAGEMENT (Unified 16000-16500) =================
    
    # Audit Ports (16400-16500)
    audit_ports_queue = queue.Queue()
    for _p in range(16400, 16500): 
        if _p == 16450: continue # Skip reserved cleaner port
        audit_ports_queue.put(_p)
        
    # Strategy Ports (16000-16400, Step 10)
    # Used by advanced_strategy_checker_worker
    strategy_ports_queue = queue.Queue()
    STRATEGY_PORT_STEP = 10
    for _p in range(16000, 16400, STRATEGY_PORT_STEP):
        strategy_ports_queue.put(_p)
        
    # Global Background Limit (32) and Priority Control
    BACKGROUND_SEM = threading.Semaphore(32)
    audit_running_event = threading.Event()
    
    # ================= MIGRATED UTILS =================

    class RateLimiter:
        def __init__(self, limit_per_sec):
            self.limit = float(limit_per_sec)
            self.tokens = float(limit_per_sec)
            self.last_update = time.time()
            self.lock = threading.Lock()
            
        def acquire(self):
            with self.lock:
                now = time.time()
                elapsed = now - self.last_update
                self.tokens += elapsed * self.limit
                if self.tokens > self.limit: self.tokens = self.limit
                self.last_update = now
                
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                else:
                    wait = (1.0 - self.tokens) / self.limit
                    time.sleep(wait)
                    self.tokens = 0.0
                    self.last_update = time.time()

    BACKGROUND_RATE_LIMITER = RateLimiter(32)
        
    # ================= TRAY LOGIC =================
    TRAY_ICON = None
    
    def on_tray_open(icon, item):
        try:
            root.deiconify()
            root.state('normal')
            root.lift()
            root.attributes('-topmost', True)
            root.after(50, lambda: root.attributes('-topmost', False))
            icon.stop()
        except: pass

    def on_tray_quit(icon, item):
        try:
            icon.stop()
            # on_closing() # Avoid direct circular call or early call
            # Just signal app to close?
            # Better: use root.event_generate("WM_DELETE_WINDOW")?
            # Or assume on_closing handles it.
            # actually we called on_closing() in original code, but we must ensure it is defined.
            # If on_tray_quit is called, on_closing MUST be defined by then (runtime).
            root.quit() 
            os._exit(0)
        except: pass

    def init_tray_icon():
        global TRAY_ICON
        try:
            image_path = get_internal_path(os.path.join("img", "icon.ico"))
            # Fallback if specific icon not found, try bin or use default
            if not os.path.exists(image_path):
                 image_path = get_internal_path("icon.ico")
            
            if os.path.exists(image_path):
                image = Image.open(image_path)
            else:
                # Create simple colored rectangle if no icon
                image = Image.new('RGB', (64, 64), color = (73, 109, 137))

            menu = (pystray.MenuItem('Открыть', on_tray_open, default=True), pystray.MenuItem('Выход', on_tray_quit))
            TRAY_ICON = pystray.Icon("name", image, "Nova", menu)
            TRAY_ICON.run()
        except Exception as e:
            safe_trace(f"Tray Error: {e}")
            # Restore window if tray fails
            root.after(0, lambda: root.deiconify())

    def minimize_to_tray(event=None):
        # Only minimize if state is 'iconic' (minimized) and we are not already shutting down
        if root.state() == 'iconic':
            try:
                if TRAY_SUPPORT:
                   root.withdraw() # Hide window
                   threading.Thread(target=init_tray_icon, daemon=True).start()
                else:
                   pass # Standard minimize behavior (do nothing special)
            except: pass

    # Bind minimize event
    # <Unmap> is triggered when window is minimized OR hidden. We need to distinguish.
    # checking root.state() inside the event handler is the key.
    # root.bind("<Unmap>", lambda e: minimize_to_tray(e) if root.state() == 'iconic' else None)


    # Clean up tray on exit
    def cleanup_tray():
        global TRAY_ICON
        if TRAY_ICON:
            try: TRAY_ICON.stop()
            except: pass

    # Hook into existing on_closing to ensure tray is removed
    # original_on_closing = on_closing
    # def new_on_closing():
    #     cleanup_tray()
    #     original_on_closing()
    
    # root.protocol("WM_DELETE_WINDOW", new_on_closing)

    # ================= GUI UTILS =================

    
    def ip_in_network(ip, net):
        try:
            ip_addr = struct.unpack('>I', socket.inet_aton(ip))[0]
            net_addr, bits = net.split('/')
            net_addr = struct.unpack('>I', socket.inet_aton(net_addr))[0]
            mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
            return (ip_addr & mask) == (net_addr & mask)
        except:
            return False

    def is_warp_ip(ip):
        try:
            warp_ip_path = os.path.join(get_base_dir(), "ip", "warp.txt")
            if not os.path.exists(warp_ip_path): return False
            
            with open(warp_ip_path, "r", encoding="utf-8") as f:
                networks = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            
            for net in networks:
                if "/" in net and ip_in_network(ip, net):
                    return True
        except: pass
        return False

    # ================= УМНЫЙ ПЕРЕЗАПУСК (SMART RESTART) =================
    # Global Process Status: "Running", "Restarting", "Stopped"
    nova_service_status = "Running"
    
    last_restart_time = 0
    restart_scheduled = False
    restart_requested_event = threading.Event()
    restart_postponed = False

    def perform_restart_sequence():
        global last_restart_time, restart_scheduled, nova_service_status
        if is_closing: return
        
        nova_service_status = "Restarting"
        if IS_DEBUG_MODE: log_print("[Auto-Restart-Debug] Start perform_restart_sequence")
        if not process:
            if IS_DEBUG_MODE: log_print("[Auto-Restart-Debug] No process, returning")
            restart_scheduled = False
            return

        log_print("[Auto-Restart] Применение новых правил (exclude_auto)...")
        stop_nova_service(silent=True, restart_mode=True)
        if IS_DEBUG_MODE: log_print("[Auto-Restart-Debug] Stop command sent")
        if root: 
            root.after(1500, lambda: start_nova_service(silent=True))
            if IS_DEBUG_MODE: log_print("[Auto-Restart-Debug] Start scheduled in 1500ms")
        else:
            log_print("[Auto-Restart-Debug] Root is None, cannot schedule start")
        
        last_restart_time = time.time()
        restart_scheduled = False
        if IS_DEBUG_MODE: log_print("[Auto-Restart-Debug] End perform_restart_sequence")

    def schedule_smart_restart():
        global last_restart_time, restart_scheduled, restart_postponed
        if restart_scheduled: return
        
        if is_scanning:
            restart_postponed = True
            restart_requested_event.set()
            log_print("[Auto-Restart] Запрошен перезапуск. Ожидание паузы фоновых задач...")
            return
        
        # Если мы здесь, значит сканирование не идет или приостановлено.
        # Сбрасываем событие запроса, чтобы разблокировать ждущие потоки
        restart_requested_event.clear()
        
        current_time = time.time()
        time_diff = current_time - last_restart_time
        
        restart_scheduled = True
        if time_diff >= 10:
            if root: root.after(0, perform_restart_sequence)
        else:
            delay_ms = int((10 - time_diff) * 1000)
            if root: root.after(delay_ms, perform_restart_sequence)
            log_print(f"[Auto-Restart] Перезапуск запланирован через {delay_ms/1000:.1f} сек.")

    def check_scan_status_loop():
        global restart_postponed
        if restart_postponed and not is_scanning:
            restart_postponed = False
            schedule_smart_restart()
            if root: root.after(3000, lambda: restart_requested_event.clear())
        if root: root.after(1000, check_scan_status_loop)

    # --- ФИЛЬТР МУСОРНЫХ ДОМЕНОВ ---
    def is_garbage_domain(domain):
        domain = domain.lower().rstrip('.')
        # Базовая проверка на валидность (убраны все черные списки)
        if not domain or len(domain) > 255 or not re.match(r"^[a-z0-9.-]+$", domain):
            return True
        if '.' not in domain: # Домен должен иметь хотя бы одну точку (TLD)
            return True
        return False

    def is_domain_excluded(domain):
        if domain in auto_excluded_domains: return True
        parts = domain.split('.')
        # Проверяем всех родителей (например, для a.b.c.com проверим b.c.com и c.com)
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in auto_excluded_domains:
                return True
        return False

    def is_special_domain(domain):
        if domain in special_strategy_domains: return True
        parts = domain.split('.')
        # Проверяем всех родителей (например, для a.b.c.com проверим b.c.com и c.com)
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in special_strategy_domains:
                return True
        return False

    def is_service_domain_only(domain):
        """Проверяет, принадлежит ли домен к сервисным стратегиям (youtube, discord и т.д.)."""
        if domain in service_strategy_domains: return True
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in service_strategy_domains:
                return True
        return False

    def _remove_domain_from_file(domain_to_remove, file_path, lock=None, rewrite_lines=None):
        """Потокобезопасно удаляет домен из файла или перезаписывает его новым содержимым."""
        def operation():
            if not os.path.exists(file_path): return False
            try:
                if rewrite_lines is not None:
                    # Режим перезаписи: просто записываем новые строки
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.writelines(rewrite_lines)
                    return True
                
                # Режим удаления одной строки
                if not domain_to_remove: return False
                
                with open(file_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                
                new_lines = [l for l in lines if l.split('#')[0].strip().lower() != domain_to_remove.lower()]
                
                if len(new_lines) < len(lines):
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.writelines(new_lines)
                    return True
            except: pass
            return False

        if lock:
            with lock:
                return operation()
        else:
            return operation()

    def load_auto_exclude(log_func=None):
        global auto_excluded_domains
        new_set = set()
        try:
            path = os.path.join(get_base_dir(), "temp", "exclude_auto.txt")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    for line in f:
                        d = line.strip().lower()
                        if d and not d.startswith("#"):
                            new_set.add(d)
        except: pass
        try:
            path = os.path.join(get_base_dir(), "list", "exclude.txt")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    for line in f:
                        d = line.strip().lower()
                        if d and not d.startswith("#"):
                            new_set.add(d)
        except: pass
        auto_excluded_domains = new_set
        if log_func:
             log_func(f"[Init] Загружено {len(new_set)} доменов из исключений.")

    def load_special_strategy_domains(log_func=None):
        global special_strategy_domains, service_strategy_domains
        special_strategy_domains = set()
        service_strategy_domains = set()
        protected_strategies = ["youtube", "discord", "whatsapp", "telegram", "cloudflare", "warp", "voice", "games"]
        base_dir = get_base_dir()
        count = 0
        
        # Загружаем стандартные защищенные стратегии
        for strat in protected_strategies:
            list_path = os.path.join(base_dir, "list", f"{strat}.txt")
            if os.path.exists(list_path):
                try:
                    with open(list_path, "r", encoding="utf-8") as f:
                        for line in f:
                            d = line.strip().split('#')[0].strip().lower()
                            if d:
                                special_strategy_domains.add(d)
                                service_strategy_domains.add(d)
                                count += 1
                except: pass
        
        # Загружаем домены из general.txt (чтобы они сразу попадали в статистику без проверки)
        general_path = os.path.join(base_dir, "list", "general.txt")
        if os.path.exists(general_path):
            try:
                with open(general_path, "r", encoding="utf-8") as f:
                    for line in f:
                        d = line.strip().split('#')[0].strip().lower()
                        if d: special_strategy_domains.add(d)
            except: pass
        
        # Загружаем домены из hard_X стратегий (они тоже специализированные)
        for i in range(1, 13):
            hard_name = f"hard_{i}"
            domains = load_hard_strategy_domains(hard_name)
            for d in domains:
                if d not in special_strategy_domains:
                    special_strategy_domains.add(d)
                    count += 1
        
        # Загружаем домены из boost_X стратегий
        for i in range(1, 13):
            boost_name = f"boost_{i}"
            domains = load_hard_strategy_domains(boost_name) # Используем ту же функцию загрузки
            for d in domains:
                if d not in special_strategy_domains:
                    special_strategy_domains.add(d)
                    count += 1
        
        if log_func and count > 0:
            log_func(f"[Init] Загружено {count} защищенных доменов из спец. стратегий и hard_X.")

    def init_checker_system(log_func):
        global check_cache
        load_auto_exclude(log_func)
        load_special_strategy_domains(log_func)
        
        load_exclude_auto_checked() # Загружаем прогресс проверки исключений
        # Загружаем и очищаем hard_X стратегии
        cleanup_hard_lists(log_func)
        
        check_cache = load_json_robust(CHECK_CACHE_FILE, {})
        
        try:
            if os.path.exists(PENDING_CHECKS_FILE):
                with open(PENDING_CHECKS_FILE, "r", encoding="utf-8") as f:
                    saved_queue = json.load(f)
                if saved_queue:
                    log_func(f"[Init] Восстановлено {len(saved_queue)} доменов из очереди проверки.")
                    for d in saved_queue:
                        if d not in checked_domains_cache:
                            checked_domains_cache[d] = time.time()
                            check_queue.put(d)
                try: os.remove(PENDING_CHECKS_FILE)
                except: pass
        except: pass

    def clean_hard_list():
        filepath = os.path.join(get_base_dir(), "temp", HARD_LIST_FILENAME)
        if not os.path.exists(filepath): return
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = []
            removed = 0
            for line in lines:
                d = line.split('#')[0].strip()
                if d and is_garbage_domain(d):
                    removed += 1
                    continue
                new_lines.append(line)
            if removed > 0:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                print(f"[Cleaner] Удалено {removed} мусорных доменов из hard.txt")
        except: pass

    def background_checker_worker(log_func):
        """Воркер, который в фоне проверяет доступность доменов из очереди."""
        global batch_timer_start
        last_cache_save = time.time()
        unsaved_changes = 0
        while not is_closing:
            try:
                # Блокирующее получение задачи из очереди с таймаутом
                domain = check_queue.get(timeout=1)
    
                # Если сервис выключен, возвращаем задачу и ждем, чтобы не потерять ее
                if not is_service_active:
                    check_queue.put(domain)
                    time.sleep(2)
                    continue
                
                # Пропускаем домены, которые уже в исключениях или являются мусором
                if is_domain_excluded(domain) or is_garbage_domain(domain):
                    continue
    
                current_time = time.time()
                with check_cache_lock:
                    # Пропускаем, если домен проверялся менее суток назад
                    if domain in check_cache and (current_time - check_cache.get(domain, 0) < 86400):
                        continue
                
                is_special = is_special_domain(domain)
                port = 0
                if not is_special:
                    try:
                        # Пытаемся получить порт для проверки немедленно
                        port = audit_ports_queue.get_nowait()
                    except queue.Empty:
                        # Если портов нет, возвращаем задачу в очередь и ждем
                        log_func("[CheckWorker] Нет свободных портов для проверки, ожидание...")
                        check_queue.put(domain) 
                        time.sleep(5)
                        continue
                
                try:
                    status, diag = detect_throttled_load(domain, port)
                finally:
                    # Всегда возвращаем порт в пул, если он был взят
                    if not is_special and port != 0:
                        audit_ports_queue.put(port)
    
                # Всегда кэшируем результат проверки, чтобы не проверять снова в течение 24 часов
                with check_cache_lock:
                    check_cache[domain] = current_time
                    unsaved_changes += 1
                    
                    # Сохраняем кэш пачками или по таймауту для снижения нагрузки на диск
                    if unsaved_changes >= 10 or (time.time() - last_cache_save > 30 and unsaved_changes > 0):
                        save_json_safe(CHECK_CACHE_FILE, check_cache)
                        last_cache_save = time.time()
                        unsaved_changes = 0
    
                if status == "blocked":
                    # Добавляем запись о посещении заблокированного домена
                    record_domain_visit(domain)
                    
                    if is_special:
                        log_func(f"[Check] Защищенный домен {domain} сбоит [{diag}]. В экстренный подбор.")
                    else:
                        log_func(f"[Warning] {domain} заблокирован/замедлен [{diag}]. Запуск экстренного подбора...")
                        # Сразу сохраняем в hard.txt для надежности
                        add_to_hard_list_safe(domain)
                    
                    # Отправляем домен на экстренный анализ, который сам добавит его в hard.txt если нужно
                    urgent_analysis_queue.put(domain)
                    matcher_wakeup_event.set()
    
                elif status == "ok":
                    # Только обычные домены могут попасть в авто-исключения
                    if not is_special:
                        with pending_exclude_lock:
                            if not pending_exclude_domains:
                                batch_timer_start = time.time()
                            if domain not in pending_exclude_domains:
                                pending_exclude_domains.add(domain)
                                log_func(f"[Check] {domain} доступен. В очереди на добавление в исключения...")
                
                # Статусы "no_dns" и "error" просто игнорируются, но домен кэшируется, чтобы избежать повторных проверок.
                # DomainCleaner позже разберется с "no_dns".
    
            except queue.Empty:
                # Очередь пуста, это нормальное состояние. Просто ждем следующей задачи.
                continue
            except Exception as e:
                log_func(f"[CheckWorker ERROR] Критическая ошибка в цикле: {e}")
                time.sleep(5) # Ждем немного в случае серьезного сбоя
    def batch_exclude_worker(log_func):
        global batch_timer_start
        while not is_closing:
            try:
                time.sleep(1) # Проверяем каждую секунду
                
                domains_to_process = []
                with pending_exclude_lock:
                    # Если есть домены и прошло достаточно времени
                    if pending_exclude_domains and (time.time() - batch_timer_start >= 10):
                        domains_to_process = list(pending_exclude_domains)
                        pending_exclude_domains.clear()
                
                if not domains_to_process:
                    continue
                
                # Если идет сканирование, откладываем обработку
                if is_scanning:
                    restart_requested_event.set()
                    # log_func("[Auto-Exclude] Пауза для ожидания завершения сканирования стратегий...")
                    # Возвращаем домены в очередь, чтобы не потерять
                    with pending_exclude_lock:
                        pending_exclude_domains.update(domains_to_process)
                    time.sleep(2) # Ждем и повторяем (быстрее реакция)
                    continue
                
                log_func(f"[Auto-Exclude] Проверка и обработка {len(domains_to_process)} доменов для исключения...")
                
                validated_domains = []
                for d in domains_to_process:
                    if is_closing: break
                    
                    port = 0
                    try: port = audit_ports_queue.get(timeout=1)
                    except queue.Empty: continue # Нет портов, пропустим домен в этот раз
                    
                    try:
                        status, diag = detect_throttled_load(d, port)
                    finally:
                        if port > 0: audit_ports_queue.put(port)
    
                    if status == "ok":
                        validated_domains.append(d)
                    elif status == "blocked":
                        log_func(f"[Auto-Exclude] {d} замедлен/заблокирован [{diag}] при перепроверке. Отправка на анализ.")
                        # Вместо прямого добавления в hard.txt, отправляем в очередь анализа
                        urgent_analysis_queue.put(d)
                        matcher_wakeup_event.set()
                    else: # error или no_dns
                        log_func(f"[Auto-Exclude] {d} вернул ошибку [{diag}] при перепроверке. Игнорируем.")
                
                if not validated_domains:
                    continue
    
                newly_added_domains = []
                for d in validated_domains:
                    if add_to_auto_exclude(d):
                        newly_added_domains.append(d)
                        log_func(f"[Auto-Exclude] {d} добавлен в исключения.")
                
                if not newly_added_domains:
                    continue
                
                log_func(f"[Auto-Exclude] Разрешение IP для {len(newly_added_domains)} новых доменов...")
                resolved_ips = set()
                for d in newly_added_domains:
                    ip, _ = dns_manager.resolve(d, dns_manager.burst_limiter, check_cache=True)
                    if ip and not is_warp_ip(ip):
                        resolved_ips.add(ip)
                
                if resolved_ips:
                    try:
                        with ip_cache_lock:
                            with open(IP_CACHE_FILE, "a", encoding="utf-8") as f:
                                f.write("\n" + "\n".join(resolved_ips))
                            os.utime(IP_CACHE_FILE, None) # Обновляем дату изменения файла
                    except Exception as e:
                        log_func(f"[Auto-Exclude] Ошибка записи IP: {e}")
                
                log_func("[Auto-Exclude] Перезапуск фильтрации для применения новых исключений...")
                if root: root.after(0, schedule_smart_restart)
    
            except Exception as e:
                log_func(f"[BatchExclude ERROR] Критическая ошибка в цикле: {e}")
                # В случае ошибки, возвращаем домены (если они были) обратно в очередь
                if 'domains_to_process' in locals() and domains_to_process:
                    with pending_exclude_lock:
                        pending_exclude_domains.update(domains_to_process)
                time.sleep(10) # Пауза в случае сбоя
    def resolve_and_append_ip(domain, log_func=None):
        try:
            resolved_ips = set()
            infos = socket.getaddrinfo(domain, 0, 0, socket.SOCK_STREAM)
            for info in infos:
                ip = info[4][0]
                if '%' in ip: ip = ip.split('%')[0]
                if is_warp_ip(ip): continue # Защита IP WARP
                resolved_ips.add(ip)
            
            if resolved_ips:
                with ip_cache_lock:
                    with open(IP_CACHE_FILE, "a", encoding="utf-8") as f:
                        f.write("\n" + "\n".join(resolved_ips))
                    os.utime(IP_CACHE_FILE, None) # Обновляем дату изменения файла
        except: pass

    def ip_exclude_updater(log_func):
        """Фоновый процесс обновления IP-адресов для списка исключений."""
        global last_full_update, is_closing
        
        # USER_REQUEST: Отключить резолвинг IP для списка исключений (Steam slowdown fix)
        ENABLE_IP_EXCLUDE_RESOLVING = False
        
        while not is_closing:
            try:
                if not ENABLE_IP_EXCLUDE_RESOLVING:
                    # log_func("[IP Exclude] Резолвинг отключен.") # Optional spam prevention
                    time.sleep(3600)
                    continue

                state_file = os.path.join(get_base_dir(), "temp", "ip_cache_state.json")
                last_full_update = 0
                
                if os.path.exists(state_file):
                    try:
                        with open(state_file, "r") as f:
                            last_full_update = json.load(f).get("last_update", 0)
                    except: pass

                if not os.path.exists(IP_CACHE_FILE):
                    need_update = True
                elif time.time() - last_full_update > 86400:
                    need_update = True
                # FIX: Removed mtime check that was bypassing 24h cooldown
                # Old logic: if exclude.txt was modified -> force update
                # New logic: Only update once per 24h, regardless of file changes
                # Files are merged at startup anyway, so IP resolution can wait
                
                # Проверка на дисбаланс количества доменов и IP (защита от пустого кэша)
                if not need_update and os.path.exists(IP_CACHE_FILE) and os.path.exists(paths['list_exclude_auto']):
                    try:
                        with open(IP_CACHE_FILE, 'r', encoding='utf-8') as f:
                            ip_cnt = sum(1 for line in f if line.strip())
                        with open(paths['list_exclude_auto'], 'r', encoding='utf-8') as f:
                            dom_cnt = sum(1 for line in f if line.strip())
                        if dom_cnt > 10 and ip_cnt < (dom_cnt * 0.5):
                            log_func(f"[IP Exclude] Мало IP ({ip_cnt}) для {dom_cnt} доменов. Принудительное обновление...")
                            need_update = True
                    except: pass
                
                if need_update:
                    log_func("[IP Exclude] Фоновое обновление IP для доменов-исключений...")
                    domains_to_resolve = set()
                    for fpath in [paths['list_exclude'], paths['list_exclude_auto'], paths['ip_exclude']]:
                        if os.path.exists(fpath):
                            try:
                                with open(fpath, "r", encoding="utf-8") as f:
                                    for line in f:
                                        d = line.strip().split('#')[0].strip()
                                        if d: domains_to_resolve.add(d)
                            except: pass

                    if domains_to_resolve and not is_closing:
                        log_func(f"[IP Exclude] Найдено {len(domains_to_resolve)} доменов. Запуск мягкого резолвинга...")
                        resolved_ips = set()
                        
                        for i, d in enumerate(list(domains_to_resolve)):
                            if is_closing: break
                            if i > 0 and i % 50 == 0:
                                log_func(f"[IP Exclude] ... обработано {i}/{len(domains_to_resolve)}")
                            
                            # Используем DNSManager. check_cache=True для эффективности.
                            ip, _ = dns_manager.resolve(d, dns_manager.burst_limiter, check_cache=True)
                            
                            if ip and not is_warp_ip(ip):
                                resolved_ips.add(ip)
                        
                        if not is_closing:
                            try:
                                os.makedirs(os.path.dirname(IP_CACHE_FILE), exist_ok=True)
                                with ip_cache_lock:
                                    with open(IP_CACHE_FILE, "w", encoding="utf-8") as f:
                                        f.write("\n".join(resolved_ips))
                                    # Сохраняем время полного обновления
                                    with open(state_file, "w") as f:
                                        json.dump({"last_update": time.time()}, f)
                                log_func(f"[IP Exclude] Обновление IP завершено. Сохранено {len(resolved_ips)} адресов.")
                            except: pass
            except Exception as e:
                log_func(f"[IP Exclude ERROR] Критическая ошибка в цикле: {e}")

            # Пауза 1 час перед следующей проверкой (24ч кулдаун проверяется внутри)
            for _ in range(3600):
                if is_closing: return
                time.sleep(1)

    def domain_cleaner_worker(log_func):
        """Периодически проверяет все списки на 'мертвые' домены и удаляет их."""
        return # DISABLED per user request to prevent accidental deletion during network issues
        
        while not is_closing:
            try:
                # Wait for 10-minute cooldown after strategy checks
                while not is_closing:
                    time_since_last = time.time() - last_strategy_check_time
                    if time_since_last >= 600:  # 10 minutes
                        break
                    
                    if is_closing:
                        break
                    
                    # Wait and check periodically
                    time.sleep(30)  # Check every 30 seconds
                
                if is_closing:
                    break
                
                # Start domain validation
                base_dir = get_base_dir()
                list_dir = os.path.join(base_dir, "list")
                
                # State File
                progress_state_file = os.path.join(base_dir, "temp", "domain_cleaner_progress.json")
                files_to_check = glob.glob(os.path.join(list_dir, "*.txt"))
                
                # Load State
                saved_state = {}
                try: saved_state = load_json_robust(progress_state_file, {})
                except: pass

                dead_domains_found = set()
                total_checked = 0

                if IS_DEBUG_MODE: log_func("[DomainCleaner] Запуск проверки доменов на доступность...")

                for file_path in files_to_check:
                    if is_closing: break
                    
                    # CRITICAL: Stop if strategy checks started (Suspend)
                    if is_scanning:
                        if IS_DEBUG_MODE: log_func("[DomainCleaner] Проверка приостановлена (началась проверка стратегий)")
                        while not is_closing and is_scanning: time.sleep(10)
                        # Resume loop (state preserved or reloaded below)

                    fname = os.path.basename(file_path)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                        
                        # Resume Index
                        start_idx = 0
                        if fname in saved_state:
                            start_idx = saved_state[fname].get("idx", 0)
                            # Validity check (file shrank?)
                            if start_idx >= len(lines): start_idx = 0
                        
                        if start_idx > 0:
                             if IS_DEBUG_MODE: log_func(f"[DomainCleaner] Возобновление проверки {fname} с позиции {start_idx}...")

                        lock = general_list_lock if "general" in fname else None
                        batch_dead = set()
                        lines_processed_count = 0 
                        deleted_in_session = 0 
                        progress_path = os.path.join(base_dir, "temp", f"cleaner_{fname}.json")
                        total_checked = 0
                        dead_domains_found = set()

                        
                        def flush_batch_cleaner():
                            nonlocal deleted_in_session
                            if not batch_dead: return
                            try:
                                def _update():
                                    if not os.path.exists(file_path): return 0
                                    with open(file_path, "r", encoding="utf-8") as f: cur = f.readlines()
                                    out = []
                                    rem = 0
                                    for ln in cur:
                                        d = ln.split('#')[0].strip().lower().split('/')[0].split(':')[0]
                                        if d in batch_dead: rem += 1
                                        else: out.append(ln)
                                    if rem > 0:
                                        with open(file_path, "w", encoding="utf-8") as f:
                                            f.writelines(out)
                                            f.flush()
                                            os.fsync(f.fileno())
                                        if IS_DEBUG_MODE: log_func(f"[DomainCleaner] Удалено {rem} несуществующих доменов из {os.path.basename(file_path)}.")
                                    return rem

                                if lock: 
                                    with lock: r = _update()
                                else: r = _update()
                                
                                deleted_in_session += r
                                batch_dead.clear()
                            except Exception as ex:
                                log_func(f"[DomainCleaner] Ошибка сохранения: {ex}")

                        # Use ThreadPoolExecutor for parallel domain validation (Efficiency optimization)
                        chunk_size = 30
                        with ThreadPoolExecutor(max_workers=8) as executor:
                            for i in range(start_idx, len(lines), chunk_size):
                                if is_closing: break
                                
                                # Periodically check for cooldown and suspend
                                t_diff = time.time() - last_strategy_check_time
                                if t_diff < 600:
                                    flush_batch_cleaner()
                                    cur_idx = max(0, i - deleted_in_session)
                                    saved_state[fname] = {"idx": cur_idx, "timestamp": int(time.time())}
                                    try: save_json_safe(progress_state_file, saved_state)
                                    except: pass
                                    if IS_DEBUG_MODE: log_func(f"[DomainCleaner] Пауза (активность стратегий)")
                                    break
                                
                                if is_scanning:
                                    if IS_DEBUG_MODE: log_func("[DomainCleaner] Проверка приостановлена (началась проверка стратегий)")
                                    while not is_closing and is_scanning: time.sleep(10)
                                    if is_closing: break

                                chunk = lines[i : i + chunk_size]
                                domains_in_chunk = []
                                for offset, line in enumerate(chunk):
                                    line_s = line.strip()
                                    if not line_s or line_s.startswith('#'): continue
                                    d_part = line_s.split('/')[0].split(':')[0].strip().lower()
                                    if not d_part or '.' not in d_part: continue
                                    domains_in_chunk.append(d_part)

                                if not domains_in_chunk:
                                    continue

                                # Map domains to validation tasks
                                futures = {executor.submit(dns_manager.validate_domain_exists, d, dns_manager.cleanup_limiter): d for d in domains_in_chunk}
                                
                                for future in as_completed(futures):
                                    if is_closing: break
                                    d_part = futures[future]
                                    try:
                                        # exists = future.result()
                                        # total_checked += 1
                                        # if not exists:
                                        #     batch_dead.add(d_part)
                                        #     dead_domains_found.add(d_part)
                                        #     if IS_DEBUG_MODE: log_func(f"[DomainCleaner] {d_part} не существует")
                                        #     
                                        #     if len(batch_dead) >= 10:
                                        #         flush_batch_cleaner()
                                        pass
                                    except Exception:
                                        # Silent fail for individual DNS queries
                                        pass
                                
                                # Progress tracking (every chunk)
                                cur_idx = max(0, (i + len(chunk)) - deleted_in_session)
                                try: save_json_safe(progress_path, {"idx": cur_idx})
                                except: pass
                        
                        flush_batch_cleaner()
                        
                        if not is_closing and (time.time() - last_strategy_check_time >= 600):
                             if os.path.exists(progress_path): 
                                 try: os.remove(progress_path)
                                 except: pass

                    except Exception as e:
                        # Silent error handling
                        pass

                # Log summary
                if dead_domains_found:
                    if IS_DEBUG_MODE: log_func(f"[DomainCleaner] Проверка завершена: удалено {len(dead_domains_found)} доменов из {total_checked} проверенных")
                else:
                    if IS_DEBUG_MODE: log_func(f"[DomainCleaner] Проверка завершена: проверено {total_checked} доменов, мёртвых не найдено")
                
                # Pause for 24 hours ONLY after the last file check
                if files_to_check and file_path == files_to_check[-1]:
                    if IS_DEBUG_MODE: log_func("[DomainCleaner] Полный цикл завершен. Сон 24 часа.")
                    for _ in range(86400):
                        if is_closing: break
                        time.sleep(1)
                else:
                    time.sleep(1) # Fast transition to next file

            except Exception as e:
                # Silent error
                time.sleep(3600)


    def sort_and_distribute_results(results, log_func=None):
        """
        Sorts results and redistributes them:
        1. General pool -> Top 12 to hard_X, rest to general.json (sorted)
        2. Special pools -> Sort inside service.json
        """
        base_dir = get_base_dir()
        strat_path = os.path.join(base_dir, "strat", "strategies.json")
        
        # 1. Group by Service
        grouped = {}
        for score, strat, svc in results:
            if svc not in grouped: grouped[svc] = []
            grouped[svc].append((score, strat))
            
        # 2. Process General
        if "general" in grouped:
            gen_results = grouped["general"]
            gen_results.sort(key=lambda x: x[0], reverse=True)
            
            try:
                # Load current main config
                data = load_json_robust(strat_path, {})
                
                # Assign Top 12 to hard_1...hard_12
                # Note: We overwrite existing hard_X definitions with the new best ones
                for i in range(12):
                    h_key = f"hard_{i+1}"
                    if i < len(gen_results):
                        # Use args from the best strategy
                        data[h_key] = gen_results[i][1]['args']
                    else:
                        # Keep existing or leave as is if not enough results
                        pass
                
                # Assign remaining to "general" list
                # Use a set to avoid duplicates
                new_general_list = []
                seen_args = set()
                
                # Start from index 12 (after hard slots)
                for i in range(12, len(gen_results)):
                    args = gen_results[i][1]['args']
                    t_args = tuple(args)
                    if t_args not in seen_args:
                        new_general_list.append(args)
                        seen_args.add(t_args)
                
                data["general"] = new_general_list
                save_json_safe(strat_path, data)
                if log_func: log_func(f"[Sorter] General: Топ-12 стратегий назначены в hard_X, остальные отсортированы.")
            except Exception as e:
                if log_func: log_func(f"[Sorter] Ошибка сохранения general: {e}")

        # 3. Process Special Services
        for svc in grouped:
            if svc == "general": continue
            
            # Sort this service's results
            s_results = grouped[svc]
            s_results.sort(key=lambda x: x[0], reverse=True)
            
            svc_file = os.path.join(base_dir, "strat", f"{svc}.json")
            if os.path.exists(svc_file):
                try:
                    # Load existing strategies to prevent data loss if some tests failed (returned None)
                    existing_strategies = load_json_robust(svc_file, [])
                    existing_map = {}
                    
                    # 1. Check Modern Format {"strategies": [...]}
                    if isinstance(existing_strategies, dict) and "strategies" in existing_strategies:
                        for s in existing_strategies["strategies"]:
                            existing_map[tuple(s['args'])] = s
                    
                    # 2. Check (My Previous) List Format
                    elif isinstance(existing_strategies, list):
                        for s in existing_strategies:
                            existing_map[tuple(s['args'])] = s
                            
                    # 3. Check Legacy Dict Format
                    elif isinstance(existing_strategies, dict):
                        # FIX: Handle legacy Dict format {"name": [args], ...}
                        # Convert to List format internal representation [{"name": name, "args": args}]
                        for k, v in existing_strategies.items():
                            if k == "version": continue
                            if isinstance(v, list):
                                existing_map[tuple(v)] = {"name": k, "args": v}

                    # We expect a list of dicts: [{"name":..., "args":...}, ...]
                    # We will reconstruct this list based on sorted results
                    new_list = []
                    seen_args = set()
                    
                    # 1. Add successfully tested strategies (Sorted by Score)
                    for score, strat in s_results:
                         t_args = tuple(strat['args'])
                         if t_args not in seen_args:
                             new_list.append(strat) # Keep original name/struct
                             seen_args.add(t_args)
                    
                    # 2. Add remaining strategies from file that were NOT in results (e.g. crashed/skipped)
                    # This prevents deleting strategies that returned None during test
                    for t_args, strat in existing_map.items():
                        if t_args not in seen_args:
                            new_list.append(strat)
                            seen_args.add(t_args)

                    if new_list:
                        # FIX: Save in MODERN FORMAT {"version": "...", "strategies": [...]}
                        final_data = {
                            "version": CURRENT_VERSION,
                            "strategies": new_list
                        }
                        save_json_safe(svc_file, final_data)
                        best_strat = new_list[0]
                        best_score = s_results[0][0]
                        if log_func: 
                            # Extract previous best name for comparison
                            if isinstance(existing_strategies, dict) and "strategies" in existing_strategies:
                                prev_best_name = existing_strategies["strategies"][0].get("name", "None") if existing_strategies["strategies"] else "None"
                            elif isinstance(existing_strategies, list) and existing_strategies:
                                prev_best_name = existing_strategies[0].get("name", "None")
                            else:
                                prev_best_name = "Unknown"
                                
                            new_best = best_strat.get('name', 'Unknown')
                            diff = "CHANGED" if new_best != prev_best_name else "SAME"
                            
                            log_func(f"[Sorter] {svc}: Top={diff} ({prev_best_name} -> {new_best}). Score: {best_score}. Saved: {len(new_list)}.")
                except Exception as e:
                     if log_func: log_func(f"[Sorter] Ошибка сортировки {svc}: {e}")
    
    STANDBY_LOG_TIMERS = {} # ThreadId -> timestamp

    def advanced_strategy_checker_worker(log_func):
        global is_closing, is_scanning, restart_requested_event, is_service_active, last_strategy_check_time
        import random
        import shutil
        import glob
        import json
        import queue
        import concurrent.futures
        import hashlib
        import time as time_sys
        time = time_sys # FIX: Initialize local 'time' variable to prevent "free variable" errors in closures
        
        # Обертываем всю логику в бесконечный цикл для мониторинга смены IP
        was_active = False # State to detect service start/restart transitions
        log_func("[Trace] Advanced Strategy Checker STARTED")
        if not hasattr(advanced_strategy_checker_worker, "last_loaded_state_sig"):
            advanced_strategy_checker_worker.last_loaded_state_sig = None

        # Capture Run ID to die if Service restarts
        my_run_id = SERVICE_RUN_ID
        
        while not is_closing:
            # Zombie Killer
            if SERVICE_RUN_ID != my_run_id:
                if IS_DEBUG_MODE: log_func(f"[Check] Stopping zombie thread (RunID {my_run_id} != {SERVICE_RUN_ID})")
                break
                
            try:
                # Re-enable trace with rate limit (1 log per 3 sec)
                if not hasattr(advanced_strategy_checker_worker, "last_loop_log"):
                     advanced_strategy_checker_worker.last_loop_log = 0
                
                # HEARTBEAT: Log every 10 seconds to confirm liveness
                current_loop_ts = time_sys.time()
                if current_loop_ts - advanced_strategy_checker_worker.last_loop_log > 10:
                     # Using print() as fallback if log_func is dead
                     if IS_DEBUG_MODE: print(f"[Checker-Heartbeat] Loop Active. Service={is_service_active}")
                     advanced_strategy_checker_worker.last_loop_log = current_loop_ts

                if is_vpn_active:
                    # debug_file_log("VPN Active, sleep 5")
                    time_sys.sleep(5)
                    continue

                if not is_service_active:
                    # debug_file_log("Service Inactive, sleep 1")
                    time_sys.sleep(1)
                    continue
                
                # log_func(f"[Trace] Cycle Start. RunID={SERVICE_RUN_ID}")
                current_run_id = SERVICE_RUN_ID

                
                # === Init: Prepare isolated test executable ===
                try:
                    exe_name = WINWS_FILENAME
                    test_exe_name = "winws_test.exe"
                    exe_path = os.path.join(get_base_dir(), "bin", exe_name)
                    test_exe_path = os.path.join(get_base_dir(), "bin", test_exe_name)
                    
                    # FIX: Don't overwrite if exists to avoid race conditions
                    if os.path.exists(exe_path) and not os.path.exists(test_exe_path):
                        shutil.copy2(exe_path, test_exe_path)
                except Exception as e:
                    # Ignore benign errors if file is busy
                    # log_func(f"[Check] Ошибка подготовки ядра: {e}")
                    pass
                
                # === CRITICAL HEALTH CHECK ===
                # Check if main winws.exe is still running. If not, restart immediately.
                if process and process.poll() is not None and is_service_active:
                     exit_code = process.poll()
                     log_func(f"[Check] КРИТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ: Основной процесс winws.exe упал (код {exit_code}). Перезапуск...")
                     
                     # FIX: Auto-repair driver if service is disabled (Code 34 / 0x422) or missing (Code 177)
                     if exit_code == 34 or exit_code == 177:
                         log_func(f"[Check] Обнаружена проблема с драйвером (Code {exit_code}). Запуск восстановления...")
                         try: repair_windivert_driver(log_func)
                         except: pass
                         time.sleep(2.0) # Give driver time to settle

                     is_service_active = False # Flag as down
                     perform_restart_sequence()
                     continue
                # =============================

                # Если идет экстренный подбор, приостанавливаем общую проверку
                if not urgent_analysis_queue.empty() or matcher_wakeup_event.is_set():
                    time.sleep(2)
                    continue

                base_dir = get_base_dir()
                rkn_path = os.path.join(base_dir, "list", "rkn.txt")
                strat_path = os.path.join(base_dir, "strat", "strategies.json")
                general_path = os.path.join(base_dir, "strat", "general.json")
                other_path = os.path.join(base_dir, "strat", "other.json") # Legacy support
                youtube_strat_path = os.path.join(base_dir, "strat", "youtube.json")
                discord_strat_path = os.path.join(base_dir, "strat", "discord.json")
                warp_strat_path = os.path.join(base_dir, "strat", "warp.json")
                cloudflare_strat_path = os.path.join(base_dir, "strat", "cloudflare.json")
                whatsapp_strat_path = os.path.join(base_dir, "strat", "whatsapp.json")
                bin_dir = os.path.join(base_dir, "fake")
                state_path = os.path.join(base_dir, "temp", "checker_state.json")
                
                # Глобальный лимит фоновых задач и управление ресурсами (Max 32 total)
                # Strategy restricted to 4 concurrent processes (winws)
                STRATEGY_THREADS = 4 
                PORTS_PER_STRAT = 7
                WARP_PORT = 1370
                WARP_PORT_LEGACY = 1370
                BASE_PORT = 16000 # Range 16000-16500
                
                # Use Global Strategy Ports (Pre-allocated 16000-16400)
                port_pool = strategy_ports_queue
                STEP = STRATEGY_PORT_STEP
                
                domains = []
                if os.path.exists(rkn_path):
                    with open(rkn_path, "r", encoding="utf-8") as f:
                        # Используем splitlines() для более надежного чтения файла
                        lines = f.read().splitlines()
                        domains = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
                
                # Добавляем домены из hard.txt для улучшения поиска стратегий под сложные случаи
                hard_path = os.path.join(base_dir, "temp", "hard.txt")
                if os.path.exists(hard_path):
                    try:
                        with open(hard_path, "r", encoding="utf-8") as f:
                            hard_lines = f.read().splitlines()
                            for l in hard_lines:
                                d = l.split('#')[0].strip()
                                if d and d not in domains:
                                    domains.append(d)
                    except: pass
                
                if not domains:
                    log_func("[Check] rkn.txt пуст или отсутствует. Ожидание...")
                    time.sleep(60)
                    continue
                
                # === НОВОЕ: Фильтрация живых доменов для стабилизации оценки ===

                # === НОВОЕ: IPCacheManager для оптимизации WinDivert фильтров ===
                class IPCacheManager:
                    def __init__(self, cache_file="test_ip_cache.json", ttl_hours=8):
                        self.cache_path = os.path.join(get_base_dir(), "temp", cache_file)
                        self.ttl_seconds = ttl_hours * 3600
                        self.cache = {}
                        self.lock = threading.Lock()
                        self.load()

                    def load(self):
                        try:
                            if os.path.exists(self.cache_path):
                                self.cache = load_json_robust(self.cache_path, {})
                        except: pass

                    def save(self):
                        try:
                            save_json_safe(self.cache_path, self.cache)
                        except: pass

                    def ensure_ips(self, domains):
                        """
                        Возвращает словарь {domain: ip} для списка доменов.
                        Если IP нет в кэше или он устарел - резолвит.
                        """
                        result = {}
                        updates = False
                        now = time.time()
                        
                        # Pre-fill from cache
                        to_resolve = []
                        with self.lock:
                            for d in domains:
                                entry = self.cache.get(d)
                                if entry and (now - entry.get("ts", 0) < self.ttl_seconds) and entry.get("ip"):
                                    result[d] = entry["ip"]
                                else:
                                    to_resolve.append(d)
                        
                        # Resolve missing
                        if to_resolve:
                            # log_func(f"[IPCache] Резолвинг {len(to_resolve)} доменов для фильтра...")
                            for d in to_resolve:
                                # Используем dns_manager быстрый resolve
                                # Важно: resolve возвращает (ip, status)
                                ip, _ = dns_manager.resolve(d, None, check_cache=True) 
                                if ip:
                                    result[d] = ip
                                    with self.lock:
                                        self.cache[d] = {"ip": ip, "ts": int(now)}
                                    updates = True
                        
                        if updates:
                            self.save()
                            
                        return result

                ip_cache_manager = IPCacheManager()

                # === НОВОЕ: Фильтрация живых доменов для стабилизации оценки ===
                def filter_alive_domains(domain_list, max_count=100):
                    # 24h Check Cooldown
                    last_chk = state.get("last_alive_filter_time", 0)
                    if time.time() - last_chk < 86400:
                        return domain_list[:max_count]

                    alive = []
                    dns_limiter = RateLimiter(5) # 5 domains per second limit

                    def check_conn(d):
                        dns_limiter.acquire()
                        # Используем DNSManager для проверки
                        ip, _ = dns_manager.resolve(d, dns_manager.burst_limiter, check_cache=True)
                        if ip:
                            return d
                        return None
                    
                    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                        futures = [executor.submit(check_conn, d) for d in domain_list]
                        for f in concurrent.futures.as_completed(futures):
                            if is_closing: break
                            if f.result(): alive.append(f.result())
                            if len(alive) >= max_count: break
                    
                    state["last_alive_filter_time"] = time.time()
                    save_state()
                    return alive

                def clean_args_for_check(strat_args):
                    # Полностью удаляем старые фильтры, чтобы они не конфликтовали с --wf-raw для изоляции.
                    # Это правильная логика из старой версии.
                    new_args = []
                    for arg in strat_args:
                        # FIX: Sanitize to ignore badly formed args (lists)
                        if not isinstance(arg, str): continue
                        if arg.startswith("--wf-tcp") or arg.startswith("--wf-udp") or arg.startswith("--hostlist") or arg.startswith("--ipset") or arg.startswith("--filter-tcp") or arg.startswith("--filter-udp"):
                            continue
                        else:
                            new_args.append(arg)
                    return new_args

                # Функция ревалидации списков (проверка, работают ли сайты с новой стратегией)
                def revalidate_list(strat_name, strat_args, log_f):
                    l_path = os.path.join(base_dir, "list", f"{strat_name}.txt")
                    if not os.path.exists(l_path): return
                    
                    try:
                        with open(l_path, "r", encoding="utf-8") as f:
                            doms = [l.strip() for l in f if l.strip() and not l.startswith("#")]
                    except: return

                    if not doms: return
                    
                    log_f(f"[Revalidate] Проверка {len(doms)} доменов для {strat_name}...")
                    
                    test_port = port_pool.get()
                    try:
                        # Изоляция трафика
                        p_end = test_port + 3
                        
                        test_args = clean_args_for_check(strat_args)
                        
                        # Определяем протоколы для захвата
                        has_tcp = any("filter-tcp" in a for a in test_args)
                        has_udp = any("filter-udp" in a for a in test_args)
                        if not has_tcp and not has_udp: has_tcp = has_udp = True
                        
                        proto_parts = []
                        if has_tcp: proto_parts.append(f"(tcp and tcp.SrcPort >= {test_port} and tcp.SrcPort <= {p_end})")
                        if has_udp: proto_parts.append(f"(udp and udp.SrcPort >= {test_port} and udp.SrcPort <= {p_end})")
                        
                        isolation_filter = f"outbound and !loopback and ({' or '.join(proto_parts)})"
                        
                        test_args.append(f'--wf-raw={isolation_filter}')
                        
                        exe_path = os.path.join(get_base_dir(), "bin", WINWS_FILENAME)
                        # PRIORITY_BELOW_NORMAL (0x00004000) for background checks to avoid GUI freezes
                        proc = subprocess.Popen([exe_path] + test_args, cwd=get_base_dir(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, 
                                               creationflags=subprocess.CREATE_NO_WINDOW | 0x00004000)
                        time.sleep(3)
                        
                        failed = []
                        for d in doms:
                            if is_closing: break
                            if not check_domain_robust(d, test_port):
                                failed.append(d)
                        
                        try: subprocess.run(["taskkill", "/F", "/PID", str(proc.pid)], creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        except: pass
                        
                        if failed:
                            log_f(f"[Revalidate] {len(failed)} доменов не работают с новой {strat_name}. Перенос в hard.txt.")
                            good = [d for d in doms if d not in failed]
                            with open(l_path, "w", encoding="utf-8") as f: f.write("\n".join(good))
                            for d in failed: add_to_hard_list_safe(d)
                            if root: root.after(0, schedule_smart_restart)
                    except Exception as e:
                        log_f(f"[Revalidate] Ошибка: {e}")
                    finally:
                        port_pool.put(test_port)

                # --- Система защиты доменов от частых запросов ---
                domain_locks = {}
                domain_last_check = {}
                domain_locks_mutex = threading.Lock()

                def get_domain_wait_time(domain):
                    with domain_locks_mutex:
                        last = domain_last_check.get(domain, 0)
                        diff = time.time() - last
                        if diff < 5: return 5 - diff
                        return 0

                def check_domain_safe(domain, port):
                    with domain_locks_mutex:
                        if domain not in domain_locks:
                            domain_locks[domain] = threading.Lock()
                            domain_last_check[domain] = 0
                        lock = domain_locks[domain]
                    
                    with lock:
                        last = domain_last_check.get(domain, 0)
                        now = time.time()
                        if now - last < 5: # Интервал 5 секунд
                            time.sleep(5 - (now - last))
                        
                        res = check_domain_robust(domain, port)
                        domain_last_check[domain] = time.time()
                        return res

                def check_strat(strat_args, port_start, target_domains=None, rate_limiter=None, progress_tracker=None, run_id=None):
                    # Global Stop Check
                    if is_closing or not is_service_active: return None
                    
                    # Zombie Check: If global RunID advanced, we are a zombie task from previous run. Die.
                    if run_id is not None and run_id != SERVICE_RUN_ID:
                        return None
                    # Если запрошен перезапуск или экстренная операция - прерываем
                    if restart_requested_event.is_set(): return None
                    if not urgent_analysis_queue.empty(): return None
                    
                    # Проверяем наличие .bin файлов перед запуском, чтобы избежать падений
                    for arg in strat_args:
                        if '.bin' in arg and '=' in arg:
                            try:
                                val = arg.split('=', 1)[1]
                                # Сначала проверяем прямой путь
                                if os.path.exists(os.path.join(base_dir, val)):
                                    continue
                                # Если нет, проверяем в папке fake (авто-коррекция сработает позже)
                                fname = os.path.basename(val)
                                if os.path.exists(os.path.join(base_dir, "fake", fname)):
                                    continue
                                    
                                # FIX: More informative error message
                                log_func(f"[Check] Пропуск стратегии: отсутствует файл '{fname}' (путь: {val})")
                                return None
                            except:
                                pass

                    
                    if target_domains is None:
                        target_domains = domains

                    # Перемешиваем порядок проверки доменов, чтобы снизить конкуренцию за локи
                    # при параллельном запуске стратегий одного сервиса
                    domains_to_check = sorted(list(target_domains))

                    proc = None
                    try:
                        port_count = PORTS_PER_STRAT
                        
                        # Изоляция трафика: ограничиваем захват только портами этого теста
                        # Это предотвращает перехват пакетов основного Warp/VPN соединения
                        p_end = port_start + port_count + 2
                        
                        # Очищаем стратегию от параметров драйвера и адаптируем фильтры
                        test_args = clean_args_for_check(strat_args)
                        
                        # Преобразуем пути к bin-файлам в абсолютные для логов и надежности запуска из любого места
                        for i in range(len(test_args)):
                            arg = test_args[i]
                            if "=" in arg and ".bin" in arg:
                                k, v = arg.split("=", 1)
                                fname = os.path.basename(v)
                                # Всегда ищем в fake и используем абсолютный путь
                                if os.path.exists(os.path.join(bin_dir, fname)):
                                    test_args[i] = f"{k}={os.path.join(get_base_dir(), 'fake', fname)}"
                        
                        # === FIX: Strict IP Filtering to prevent Twitch Lag ===
                        # 1. Get IPs for target domains
                        target_ips_map = ip_cache_manager.ensure_ips(target_domains)
                        unique_ips = sorted(list(set(target_ips_map.values())))
                        
                        ip_filter_part = ""
                        if unique_ips:
                            # Construct IP filter: (ip.DstAddr == X or ip.DstAddr == Y)
                            # WinDivert optimization: check IP first!
                            ip_parts = [f"ip.DstAddr == {ip}" for ip in unique_ips]
                            combined_ips = " or ".join(ip_parts)
                            
                            # Safety check for command line length (max ~32k total, reserve 2k for other args)
                            if len(combined_ips) < 28000:
                                ip_filter_part = f" and ({combined_ips})"
                            else:
                                # Fallback: filter only first N IPs that fit
                                safe_ips = []
                                current_len = 0
                                for p in ip_parts:
                                    if current_len + len(p) + 4 < 28000:
                                        safe_ips.append(p)
                                        current_len += len(p) + 4
                                    else:
                                        break
                                if safe_ips:
                                    ip_filter_part = f" and ({' or '.join(safe_ips)})"
                        
                        # Определяем протоколы для захвата
                        has_tcp = any("filter-tcp" in a for a in test_args)
                        has_udp = any("filter-udp" in a for a in test_args)
                        if not has_tcp and not has_udp: has_tcp = has_udp = True
                        
                        proto_parts = []
                        if has_tcp: proto_parts.append(f"(tcp and tcp.SrcPort >= {port_start} and tcp.SrcPort <= {p_end})")
                        if has_udp: proto_parts.append(f"(udp and udp.SrcPort >= {port_start} and udp.SrcPort <= {p_end})")
                        
                        # FINAL STRICT FILTER (Outbound + IP + Ports)
                        isolation_filter = f"outbound and !loopback{ip_filter_part} and ({' or '.join(proto_parts)})"
                        
                        exe_name = WINWS_FILENAME
                        test_exe_name = "winws_test.exe"
                        exe_path = os.path.join(get_base_dir(), "bin", exe_name)
                        test_exe_path = os.path.join(get_base_dir(), "bin", test_exe_name)
                        
                        # STRICT: Always use test exe. If missing, try to restore.
                        if not os.path.exists(test_exe_path):
                            try: shutil.copy2(exe_path, test_exe_path)
                            except: pass
                        
                        if not os.path.exists(test_exe_path):
                            # Fail safely instead of using main exe
                            log_func(f"[Check] Ошибка: winws_test.exe не найден. Пропуск.")
                            return None
                            
                        final_exe = test_exe_path
                        
                        final_args = [final_exe]
                        final_args.extend(test_args)
                        final_args.append(f'--wf-raw={isolation_filter}')
                        
                        # Попытка запуска с ретраем для надежности (исправляет падения с кодом 1)
                        for attempt in range(2):
                            # PRIORITY_BELOW_NORMAL (0x00004000) for background checks to avoid GUI freezes
                            proc = subprocess.Popen(final_args, cwd=get_base_dir(), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, 
                                                   text=True, encoding='utf-8', errors='replace', 
                                                   creationflags=subprocess.CREATE_NO_WINDOW | 0x00004000)
                            
                            time.sleep(2.0)
                            if proc.poll() is None:
                                break # Успешный запуск
                            
                            # Если программа остановлена, падение ожидаемо - молча выходим
                            if is_closing or not is_service_active: return None
                            
                            start_time = time.time()
                            try:
                                _, stderr_out = proc.communicate(timeout=1003) # Hard cap 1000s + buffer
                            except subprocess.TimeoutExpired:
                                log_func(f"[Check] WinWS завис ( > 1000сек). Принудительное завершение.")
                                try: subprocess.run(["taskkill", "/F", "/PID", str(proc.pid)], creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                except: pass
                                return None

                            elapsed = time.time() - start_time
                            if elapsed > 1000:
                                log_func(f"[Check] ВНИМАНИЕ: Стратегия проверялась {elapsed:.1f} сек!")
                            
                            # Логируем только если это не штатная остановка
                            if proc.returncode != 0:
                                log_func(f"[Check] WinWS упал (код {proc.returncode}). Порт: {port_start}. Попытка {attempt+1}/2")
                                
                                err_msg = stderr_out.strip() if stderr_out else ""
                                if err_msg: log_func(f"[Check] Ошибка WinWS: {err_msg}")
                                
                                # FIX: Auto-repair driver if service is disabled (Code 34 / 0x422) or missing (Code 177)
                                if proc.returncode in (34, 177) or \
                                   ("service cannot be started" in err_msg and "disabled" in err_msg) or \
                                   ("device which does not exist" in err_msg):
                                    
                                    # Ограничиваем количество попыток ремонта
                                    repair_attempts = getattr(self, '_repair_attempts', 0)
                                    if repair_attempts < 3:
                                        log_func(f"[Check] Обнаружена проблема с драйвером (Code {proc.returncode}). Запуск восстановления...")
                                        try: 
                                            repair_windivert_driver(log_func)
                                            self._repair_attempts = repair_attempts + 1
                                        except: pass
                                    else:
                                        log_func(f"[Error] Не удалось восстановить драйвер WinDivert после 3 попыток. Проверьте 'Изоляцию ядра' в Windows.")
                                        # Больше не пытаемся чинить в этой сессии
                                        time.sleep(60) 
                                    
                                    time.sleep(1.0)
                                    continue # Retry immediately
                                
                                if attempt == 1:
                                    log_func(f"[Check] Стратегия вызывает сбой процесса. Пропускаем.")
                                    return 0 # Возвращаем 0 (blocked), чтобы не ломать воркер возвратом None
                            time.sleep(2) # Delay before retry
                        
                        time.sleep(3.0) # Увеличиваем время на инициализацию winws для надежности
                        
                        # Параллельная проверка доменов внутри стратегии (8 потоков на стратегию)
                        score = 0
                        local_ports = queue.Queue()
                        for i in range(port_count):
                            local_ports.put(port_start + i)
                        
                        def check_task(d):
                            # Zombie Check inside loop (The most effective kill switch)
                            if run_id is not None and run_id != SERVICE_RUN_ID: return None

                            # Notify Start
                            if progress_tracker: progress_tracker(event="start")

                            if rate_limiter: rate_limiter.acquire()
                            p = local_ports.get()
                            try:
                                res = check_domain_safe(d, p)
                                # Notify Finish
                                if progress_tracker: progress_tracker(event="finish", success=res)
                                return res
                            finally:
                                local_ports.put(p)

                        executor = concurrent.futures.ThreadPoolExecutor(max_workers=port_count)
                        try:
                            futures = {executor.submit(check_task, d): d for d in domains_to_check}
                            checks_done = 0
                            for f in concurrent.futures.as_completed(futures):
                                if is_closing or not is_service_active: 
                                    executor.shutdown(wait=False, cancel_futures=True)
                                    return None # FIX: Return None on detailed abort to prevent saving partial score
                                try:
                                    if f.result(): score += 1
                                    checks_done += 1
                                    # Legacy callback moved to check_task observer
                                except: pass
                        finally:
                            # Гарантированное завершение без ожидания зависших задач
                            executor.shutdown(wait=False, cancel_futures=True)
                        
                        if is_closing or not is_service_active: return None
                        return score
                    except Exception as e:
                        log_func(f"[Check] Ошибка теста: {e}")
                        return None
                    finally:
                        if proc:
                            try: subprocess.run(["taskkill", "/F", "/PID", str(proc.pid)], creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            except: pass
                        time.sleep(0.3) # Пауза для гарантированного освобождения фильтра драйвером

                def check_strat_threaded(strat_args, target_domains=None, progress_tracker=None, run_id=None):
                    if is_closing or not is_service_active: return None
                    
                    # Zombie Check
                    if run_id is not None and run_id != SERVICE_RUN_ID: return None

                    # FIX: Sanitize arguments to prevent 'list' object has no attribute 'startswith' crash
                    if strat_args:
                        strat_args = [a for a in strat_args if isinstance(a, str)]
                    
                    # Priority Yield: If Audit is running, pause submission/execution
                    # We check here to prevent starting new heavy tasks if Audit is active
                    # But tasks are submitted in batch. The loop below handles submission pause.
                    # Here we adhere to the Semaphore limit.
                    
                    p_start = port_pool.get()
                    try:
                        with BACKGROUND_SEM:
                            return check_strat(strat_args, p_start, target_domains, rate_limiter=BACKGROUND_RATE_LIMITER, progress_tracker=progress_tracker, run_id=run_id)
                    finally:
                        port_pool.put(p_start)

                # === Path Portability Helper ===
                def sanitize_fake_path(path_str):
                    """Convert any fake binary path to portable format: fake/filename.bin"""
                    if not path_str:
                        return path_str
                    basename = os.path.basename(path_str)
                    return f"fake/{basename}"

                # === DOMAIN DIVERSIFICATION ===
                # Счётчик для назначения offset'ов задачам
                _domain_offset_counter = {"value": 0}
                _domain_offset_lock = threading.Lock()
                
                def get_offset_domains(domains, task_idx=None):
                    """
                    Возвращает сдвинутый список доменов для диверсификации проверок.
                    Каждая задача получает уникальный offset, чтобы параллельные потоки
                    не "долбили" одни и те же домены одновременно.
                    
                    Пример: 4 потока, 100 доменов
                    - Поток 1: [dom1, dom2, ..., dom100]
                    - Поток 2: [dom26, dom27, ..., dom100, dom1, ..., dom25]
                    - Поток 3: [dom51, dom52, ..., dom100, dom1, ..., dom50]
                    - Поток 4: [dom76, dom77, ..., dom100, dom1, ..., dom75]
                    """
                    if not domains or len(domains) < 4:
                        return list(domains)
                    
                    n = len(domains)
                    
                    # Получаем уникальный offset для этой задачи
                    if task_idx is None:
                        with _domain_offset_lock:
                            task_idx = _domain_offset_counter["value"]
                            _domain_offset_counter["value"] += 1
                    
                    # Вычисляем offset на основе индекса задачи
                    # Используем STRATEGY_THREADS для равномерного распределения
                    chunk_size = n // STRATEGY_THREADS
                    if chunk_size < 1: chunk_size = 1
                    
                    offset = (task_idx * chunk_size) % n
                    
                    # Создаём сдвинутый список (циклический сдвиг)
                    return domains[offset:] + domains[:offset]
                
                def reset_domain_offset_counter():
                    """Сбрасывает счётчик offset'ов (вызывать перед каждым этапом)"""
                    with _domain_offset_lock:
                        _domain_offset_counter["value"] = 0

                # === РАСШИРЕННАЯ ФУНКЦИЯ МУТАЦИИ СТРАТЕГИЙ (с обучением) ===
                def mutate_strategy(args, bin_files, count=None, learning_data=None):
                    """
                    Генерирует мутации стратегии с учётом статистики обучения.
                    50% проверенных успешных мутаций + 50% экспериментальных.
                    
                    Ограничения:
                    - Не изменять wssize
                    - TTL <= 11
                    - Не менять порты
                    - Не изменять UDP-сегменты
                    - Не более 2 bin-файлов на стратегию
                    """
                    if not args: return []
                    # FIX: Sanitize args
                    args = [a for a in args if isinstance(a, str)]
                    
                    if learning_data is None:
                        learning_data = load_learning_data()
                    
                    generated_hashes = set()
                    mutations = []
                    
                    # Split args into segments by '--new'
                    def split_segments(arg_list):
                        segments = []
                        current_seg = []
                        for a in arg_list:
                            if a == "--new":
                                if current_seg:
                                    segments.append(current_seg)
                                    current_seg = []
                                continue
                            current_seg.append(a)
                        if current_seg: segments.append(current_seg)
                        return segments
                    
                    def join_segments(segs):
                        full = []
                        for i, s in enumerate(segs):
                            if i > 0: full.append("--new")
                            full.extend(s)
                        return full
                    
                    def is_tcp_segment(seg):
                        return any(a.startswith("--wf-tcp") or a.startswith("--filter-tcp") for a in seg)
                    
                    def is_udp_segment(seg):
                        return any(a.startswith("--wf-udp") or a.startswith("--filter-udp") for a in seg)
                    
                    def count_bin_files(arg_list):
                        return sum(1 for a in arg_list if ".bin" in a)
                    
                    def validate_mutation(new_args):
                        """Проверяет ограничения мутации и очищает от мусора."""
                        # FIX: Remove any None or non-string elements (extra safety)
                        if any(not isinstance(a, str) for a in new_args if a is not None):
                            return False
                        
                        clean_args = []
                        for a in new_args:
                            if not a: continue
                            # FIX: Prevent malformed arguments like ^! or random binary garbage
                            # winws can fail on specific special characters if not escaped
                            if "^!" in a or "\x00" in a or "\\x" in a:
                                return False
                                
                            # Запрет wssize
                            if "--wssize" in a or "--wsize" in a:
                                return False
                            # TTL <= 11
                            if "--dpi-desync-ttl=" in a:
                                try:
                                    v = int(a.split("=")[1])
                                    if v > 11: return False
                                except: pass
                            clean_args.append(a)
                            
                        # Не более 2 bin файлов
                        if count_bin_files(new_args) > 2:
                            return False
                        return True
                    
                    def should_auto_scroll():
                        try:
                            # Получаем глобальные координаты мыши
                            ptr_x, ptr_y = log_text_widget.winfo_pointerxy()
                            # Получаем координаты виджета
                            wid_x = log_text_widget.winfo_rootx()
                            wid_y = log_text_widget.winfo_rooty()
                            wid_w = log_text_widget.winfo_width()
                            wid_h = log_text_widget.winfo_height()
                            
                            # Если мышь внутри виджета - НЕ скроллим
                            if (wid_x <= ptr_x <= wid_x + wid_w) and (wid_y <= ptr_y <= wid_y + wid_h):
                                return False
                                
                            # Проверяем позицию скролла (если пользователь открутил вверх)
                            # yview()[1] возвращает позицию нижней границы видимой области (0.0 - 1.0)
                            if log_text_widget.yview()[1] < 0.99:
                                return False
                                
                            return True
                        except:
                            return True

                    def get_hash(arg_list):
                        return hashlib.md5(str(arg_list).encode()).hexdigest()
                    
                    def add_mutation(new_args):
                        if not validate_mutation(new_args):
                            return False
                        h = get_hash(new_args)
                        if h in generated_hashes:
                            return False
                        generated_hashes.add(h)
                        mutations.append(new_args)
                        return True
                    
                    segments = split_segments(args)
                    
                    # === ДОСТУПНЫЕ МУТАЦИИ (на основе документации zapret) ===
                    
                    # Desync режимы
                    DESYNC_MODES = ["fake", "split", "split2", "disorder", "multisplit", 
                                   "multidisorder", "fakedsplit", "fakeddisorder", "hostfakesplit", "syndata"]
                    
                    # Fooling методы
                    FOOLING_METHODS = ["ts", "md5sig", "badseq", "badsum", "datanoack"]
                    
                    # Split позиции
                    SPLIT_POSITIONS = ["1", "2", "3", "midsld", "midsld+1", "midsld-1", 
                                      "host", "host+1", "host+2", "sld+1", "sniext", "sniext+1"]
                    
                    # Repeats значения
                    REPEATS_VALUES = [2, 3, 4, 5, 6, 8, 10, 11]
                    
                    # TTL значения
                    TTL_VALUES = [1, 2, 3, 4, 5, 11]
                    
                    # AutoTTL значения
                    AUTOTTL_VALUES = ["1", "2", "5", "2:3-64"]
                    
                    # SeqOvl значения  
                    SEQOVL_VALUES = ["1", "2"]
                    
                    # Fake TLS mod опции
                    FAKE_TLS_MODS = ["none", "rnd", "dupsid", "rndsni", "padencap", "rnd,dupsid", "rnd,rndsni,padencap"]
                    
                    # Host mod опции
                    HOST_MODS = ["host=ya.ru", "host=www.google.com", "host=ozon.ru", "host=ya.ru,altorder=1"]
                    
                    # FakedSplit altorder
                    ALTORDER_VALUES = ["0", "1", "2", "3"]
                    
                    # === ГЕНЕРАЦИЯ МУТАЦИЙ ===
                    
                    def get_success_weight(arg_key):
                        """Получает вес успешности аргумента из статистики"""
                        return get_argument_success_rate(arg_key, learning_data)
                    
                    def select_by_weight(options, get_key_fn=None):
                        """Выбирает опцию с учётом 50/50 баланса"""
                        if not options: return None
                        
                        # 50% шанс выбрать на основе статистики
                        if random.random() < 0.5 and learning_data.get("argument_stats"):
                            # Weighted selection
                            weights = []
                            for opt in options:
                                key = get_key_fn(opt) if get_key_fn else str(opt)
                                w = get_success_weight(key)
                                weights.append(max(0.1, w))  # Минимальный вес
                            
                            # LOG: Prove usage
                            try:
                                if IS_DEBUG_MODE:
                                     # Log only occasionally to avoid spam, or always if specific flag?
                                     # Let's log unique events or just simple confirmation
                                     log_func(f"[Evo-Weight] Using stats for selection. Options: {len(options)}, MaxWeight: {max(weights):.2f}")
                            except: pass

                            total = sum(weights)
                            if total > 0:
                                r = random.random() * total
                                cumulative = 0
                                for opt, w in zip(options, weights):
                                    cumulative += w
                                    if r <= cumulative:
                                        return opt
                        
                        # 50% шанс случайный выбор (эксперимент)
                        return random.choice(options)
                    
                    # --- 1. Мутация desync режима ---
                    for seg_idx, seg in enumerate(segments):
                        if not is_tcp_segment(seg) or is_udp_segment(seg):
                            continue
                        
                        for i, arg in enumerate(seg):
                            if arg.startswith("--dpi-desync="):
                                current_mode = arg.split("=")[1]
                                # Выбираем новый режим
                                new_mode = select_by_weight(
                                    [m for m in DESYNC_MODES if m != current_mode],
                                    lambda m: f"--dpi-desync={m}"
                                )
                                if new_mode:
                                    new_segs = [list(s) for s in segments]
                                    new_segs[seg_idx][i] = f"--dpi-desync={new_mode}"
                                    add_mutation(join_segments(new_segs))
                    
                    # --- 2. Мутация fooling ---
                    for seg_idx, seg in enumerate(segments):
                        if not is_tcp_segment(seg) or is_udp_segment(seg):
                            continue
                        
                        has_fooling = any("--dpi-desync-fooling=" in a for a in seg)
                        
                        if has_fooling:
                            # Изменить существующий
                            for i, arg in enumerate(seg):
                                if arg.startswith("--dpi-desync-fooling="):
                                    new_fool = select_by_weight(FOOLING_METHODS, lambda f: f"--dpi-desync-fooling={f}")
                                    if new_fool:
                                        new_segs = [list(s) for s in segments]
                                        new_segs[seg_idx][i] = f"--dpi-desync-fooling={new_fool}"
                                        add_mutation(join_segments(new_segs))
                                    # Комбинация
                                    combo = select_by_weight([f"{f1},{f2}" for f1 in FOOLING_METHODS[:3] for f2 in FOOLING_METHODS[:3] if f1 != f2])
                                    if combo:
                                        new_segs = [list(s) for s in segments]
                                        new_segs[seg_idx][i] = f"--dpi-desync-fooling={combo}"
                                        add_mutation(join_segments(new_segs))
                        else:
                            # Добавить новый
                            new_fool = select_by_weight(FOOLING_METHODS, lambda f: f"--dpi-desync-fooling={f}")
                            if new_fool:
                                new_segs = [list(s) for s in segments]
                                new_segs[seg_idx].append(f"--dpi-desync-fooling={new_fool}")
                                add_mutation(join_segments(new_segs))
                    
                    # --- 3. Мутация split-pos ---
                    for seg_idx, seg in enumerate(segments):
                        if not is_tcp_segment(seg) or is_udp_segment(seg):
                            continue
                        
                        for i, arg in enumerate(seg):
                            if arg.startswith("--dpi-desync-split-pos="):
                                curr_val = arg.split("=")[1]
                                new_val = select_by_weight(
                                    [p for p in SPLIT_POSITIONS if p != curr_val],
                                    lambda p: f"--dpi-desync-split-pos={p}"
                                )
                                if new_val:
                                    new_segs = [list(s) for s in segments]
                                    new_segs[seg_idx][i] = f"--dpi-desync-split-pos={new_val}"
                                    add_mutation(join_segments(new_segs))
                    
                    # --- 4. Мутация repeats ---
                    for seg_idx, seg in enumerate(segments):
                        if not is_tcp_segment(seg) or is_udp_segment(seg):
                            continue
                        
                        for i, arg in enumerate(seg):
                            if arg.startswith("--dpi-desync-repeats="):
                                try:
                                    curr_val = int(arg.split("=")[1])
                                    new_val = select_by_weight(
                                        [r for r in REPEATS_VALUES if r != curr_val],
                                        lambda r: f"--dpi-desync-repeats={r}"
                                    )
                                    if new_val:
                                        new_segs = [list(s) for s in segments]
                                        new_segs[seg_idx][i] = f"--dpi-desync-repeats={new_val}"
                                        add_mutation(join_segments(new_segs))
                                except: pass
                    
                    # --- 5. Мутация TTL (макс 11) ---
                    for seg_idx, seg in enumerate(segments):
                        if not is_tcp_segment(seg) or is_udp_segment(seg):
                            continue
                        
                        has_ttl = any("--dpi-desync-ttl=" in a for a in seg)
                        if has_ttl:
                            for i, arg in enumerate(seg):
                                if arg.startswith("--dpi-desync-ttl="):
                                    new_val = select_by_weight(TTL_VALUES, lambda t: f"--dpi-desync-ttl={t}")
                                    if new_val:
                                        new_segs = [list(s) for s in segments]
                                        new_segs[seg_idx][i] = f"--dpi-desync-ttl={new_val}"
                                        add_mutation(join_segments(new_segs))
                        else:
                            # Добавить TTL
                            new_val = select_by_weight(TTL_VALUES, lambda t: f"--dpi-desync-ttl={t}")
                            if new_val:
                                new_segs = [list(s) for s in segments]
                                new_segs[seg_idx].append(f"--dpi-desync-ttl={new_val}")
                                add_mutation(join_segments(new_segs))
                    
                    # --- 6. Мутация autottl ---
                    for seg_idx, seg in enumerate(segments):
                        if not is_tcp_segment(seg) or is_udp_segment(seg):
                            continue
                        
                        has_autottl = any("--dpi-desync-autottl" in a for a in seg)
                        if not has_autottl:
                            new_val = select_by_weight(AUTOTTL_VALUES, lambda a: f"--dpi-desync-autottl={a}")
                            if new_val:
                                new_segs = [list(s) for s in segments]
                                new_segs[seg_idx].append(f"--dpi-desync-autottl={new_val}")
                                add_mutation(join_segments(new_segs))
                    
                    # --- 7. Мутация seqovl ---
                    for seg_idx, seg in enumerate(segments):
                        if not is_tcp_segment(seg) or is_udp_segment(seg):
                            continue
                        
                        has_seqovl = any("--dpi-desync-split-seqovl=" in a for a in seg)
                        if not has_seqovl:
                            new_val = select_by_weight(SEQOVL_VALUES, lambda s: f"--dpi-desync-split-seqovl={s}")
                            if new_val:
                                new_segs = [list(s) for s in segments]
                                new_segs[seg_idx].append(f"--dpi-desync-split-seqovl={new_val}")
                                add_mutation(join_segments(new_segs))
                    
                    # --- 8. Мутация fake-tls-mod ---
                    for seg_idx, seg in enumerate(segments):
                        if not is_tcp_segment(seg) or is_udp_segment(seg):
                            continue
                        
                        for i, arg in enumerate(seg):
                            if arg.startswith("--dpi-desync-fake-tls-mod="):
                                new_mod = select_by_weight(FAKE_TLS_MODS, lambda m: f"--dpi-desync-fake-tls-mod={m}")
                                if new_mod:
                                    new_segs = [list(s) for s in segments]
                                    new_segs[seg_idx][i] = f"--dpi-desync-fake-tls-mod={new_mod}"
                                    add_mutation(join_segments(new_segs))
                    
                    # --- 9. Мутация hostfakesplit-mod ---
                    for seg_idx, seg in enumerate(segments):
                        if not is_tcp_segment(seg) or is_udp_segment(seg):
                            continue
                        
                        has_hostmod = any("--dpi-desync-hostfakesplit-mod=" in a for a in seg)
                        # Только если есть hostfakesplit в desync
                        has_hostfakesplit = any("hostfakesplit" in a for a in seg)
                        
                        if has_hostfakesplit:
                            if has_hostmod:
                                for i, arg in enumerate(seg):
                                    if arg.startswith("--dpi-desync-hostfakesplit-mod="):
                                        new_mod = select_by_weight(HOST_MODS)
                                        if new_mod:
                                            new_segs = [list(s) for s in segments]
                                            new_segs[seg_idx][i] = f"--dpi-desync-hostfakesplit-mod={new_mod}"
                                            add_mutation(join_segments(new_segs))
                            else:
                                new_mod = select_by_weight(HOST_MODS)
                                if new_mod:
                                    new_segs = [list(s) for s in segments]
                                    new_segs[seg_idx].append(f"--dpi-desync-hostfakesplit-mod={new_mod}")
                                    add_mutation(join_segments(new_segs))
                    
                    # --- 10. Мутация fake-tls bin файла ---
                    if bin_files and count_bin_files(args) < 2:
                        for seg_idx, seg in enumerate(segments):
                            if not is_tcp_segment(seg) or is_udp_segment(seg):
                                continue
                            
                            has_fake_tls = any("--dpi-desync-fake-tls=" in a for a in seg)
                            
                            # Выбор bin на основе статистики
                            # FIX: Validate that files actually exist before using them
                            tls_bins = []
                            for b in bin_files:
                                if "tls" in b.lower() or "clienthello" in b.lower():
                                    # Verify file exists
                                    fname = os.path.basename(b)
                                    full_path = os.path.join(get_base_dir(), "fake", fname)
                                    if os.path.exists(full_path):
                                        tls_bins.append(b)
                            
                            if tls_bins:
                                selected_bin = select_by_weight(
                                    tls_bins,
                                    lambda b: os.path.basename(b)
                                )
                                if selected_bin:
                                    new_segs = [list(s) for s in segments]
                                    if has_fake_tls:
                                        # Заменить
                                        for i, arg in enumerate(new_segs[seg_idx]):
                                            if arg.startswith("--dpi-desync-fake-tls="):
                                                new_segs[seg_idx][i] = f"--dpi-desync-fake-tls={sanitize_fake_path(selected_bin)}"
                                                break
                                    else:
                                        # Добавить
                                        new_segs[seg_idx].append(f"--dpi-desync-fake-tls={sanitize_fake_path(selected_bin)}")
                                    add_mutation(join_segments(new_segs))
                    
                    # --- Ограничение количества если указано ---
                    if count and len(mutations) > count:
                        # Перемешиваем для разнообразия и берём первые count
                        random.shuffle(mutations)
                        mutations = mutations[:count]
                    
                    return mutations

                bin_files = glob.glob(os.path.join(bin_dir, "*.bin"))
                bin_files = [os.path.relpath(p, base_dir).replace("\\", "/") for p in bin_files]

                
                # Оставляем только надежные бинарники для ускорения и эффективности
                priority_keywords = ["google", "microsoft", "facebook", "discord", "rutracker", "instagram", "twitter", "youtube"]
                reliable_bins = [b for b in bin_files if any(k in b.lower() for k in priority_keywords)]
                if not reliable_bins and bin_files: 
                    reliable_bins = [b for b in bin_files if "google" in b.lower()] or [bin_files[0]]

                # Структура state["current_wave_strategies"] теперь будет хранить словари {"name": "...", "args": [...]}
                state = {
                    "wave": 1,
                    "idx": 0,
                    "current_wave_strategies": [],
                    "best_strategies": [],
                    "bin_performance": {b: 0 for b in bin_files},
                    "general_score": -1,
                    "completed": False,
                    "hard_checked": False,
                    "youtube_checked": False,
                    "discord_checked": False,
                    "cloudflare_checked": False,
                    "whatsapp_checked": False,
                    "last_wave_count": 0,
                    "evolution_stage": 0,
                    "app_version": CURRENT_VERSION # FIX: Default to current version to prevent false reset on fresh start
                }

                state_lock = threading.Lock()
                s_display = "" # Prevent UnboundLocalError
                skip_main_check = False # FIX: Prevent UnboundLocalError during resume logic checks
                # FIX: Retry loading state to avoid race conditions or transient IO errors
                for _ in range(5):
                    loaded_s = load_json_robust(state_path, {})
                    if loaded_s and loaded_s.get("app_version"):
                        state.update(loaded_s)
                        break
                    time.sleep(0.1)
                else:
                    # Final attempt if loop failed
                    state.update(load_json_robust(state_path, {}))
                
                # DEBUG (CLI only): print loaded-state snapshot only when it changes.
                if IS_DEBUG_CLI:
                    state_sig = (
                        state.get("app_version"),
                        CURRENT_VERSION,
                        state.get("last_checked_ip"),
                        bool(state.get("completed")),
                        state.get("evolution_stage"),
                    )
                    if state_sig != advanced_strategy_checker_worker.last_loaded_state_sig:
                        advanced_strategy_checker_worker.last_loaded_state_sig = state_sig
                        log_func(
                            f"[Check-Debug] Loaded State: Ver={state.get('app_version')} "
                            f"CurVer={CURRENT_VERSION} IP={mask_ip(state.get('last_checked_ip'))} "
                            f"Comp={state.get('completed')} Evo={state.get('evolution_stage')}"
                        )

                # last_standby_log_wrapper removed - using state instead
                # FIX: Если версия изменилась или было обновление -> Сбрасываем флаг завершения
                # чтобы гарантировать проверку стратегий на новой версии
                try:
                    is_updated = ARGS_PARSED.get('updated', False)
                except (NameError, AttributeError):
                    is_updated = '--updated' in sys.argv
                
                if state.get("app_version") != CURRENT_VERSION or is_updated:
                    log_func(f"[Check] Версия изменилась или флаг updated (StateVer={state.get('app_version')}, CurVer={CURRENT_VERSION}, Upd={is_updated}). Сброс статуса проверки.")
                    state["completed"] = False
                    state["hard_checked"] = False
                    state["youtube_checked"] = False
                    state["discord_checked"] = False
                    state["cloudflare_checked"] = False
                    state["whatsapp_checked"] = False
                    state["app_version"] = CURRENT_VERSION
                    # Не сбрасываем bin_performance, чтобы не терять статистику
                    try:
                        with open(state_path, "w", encoding="utf-8") as f:
                            json.dump(state, f, indent=2)
                    except: pass
                
                # FIX: Force Evolution Mode Reset at Loader Level
                if IS_EVO_MODE:
                    # If we are in EVO mode, we MUST ensure we start from stage 0
                    # This overrides any saved state
                    
                    if state.get("evolution_stage", 0) > 0 or state.get("completed", False):
                        log_func("[Check] Режим --evo: Глобальный сброс состояния (Start from Stage 0)")
                        state["evolution_stage"] = 0
                        state["completed"] = False
                        try:
                            with open(state_path, "w", encoding="utf-8") as f:
                                json.dump(state, f, indent=2)
                        except: pass

                def save_state():
                    try:
                        with open(state_path, "w", encoding="utf-8") as f:
                            json.dump(state, f, indent=2)
                    except Exception as e:
                        if IS_DEBUG_MODE: log_func(f"[Check-Error] Failed to save state: {e}")

                # --- Логика проверки IP и необходимости запуска ---
                # Повторная проверка VPN непосредственно перед получением IP, чтобы избежать гонки состояний при запуске.

                if is_vpn_active_func():
                    log_print("[Check] Обнаружен VPN, проверка IP отложена.")
                    time.sleep(5)
                    continue

                current_ip = None
                try:
                    current_ip = get_public_ip_isolated()
                except Exception as e:
                    log_func(f"[Check] Не удалось определить IP: {e}. Повтор через 60 сек.")
                    time.sleep(60)
                    continue

                # Еще одна проверка после получения IP, чтобы гарантировать, что это не IP от VPN
                if is_vpn_active_func():
                    time.sleep(5)
                    continue
                
                # === FIX: Если IP None (ошибка сети), не продолжаем, чтобы не сбросить прогресс ===
                if not current_ip:
                    log_func("[Check] IP не определен (None). Пропускаем цикл.")
                    time.sleep(10)
                    continue

                need_check = False
                # === НОВОЕ: Записываем IP и проверяем нужна ли переверификация ===
                # FIX: Debounce IP changes to prevent constant restarts on unstable connections
                # We trust record_ip_change but verify the "need_recheck" flag carefully
                
                try:
                    needs_ip_recheck = record_ip_change(current_ip, log_func)
                except NameError:
                    # Generic fallback if function missing (shouldn't happen but safety first)
                    needs_ip_recheck = False
                    if state.get("last_checked_ip") != current_ip:
                         needs_ip_recheck = True

                # FIX: Chech loaded_ip and completion status BEFORE using them in debounce logic
                loaded_completed = state.get("completed", False) or state.get("checks_completed", False)
                loaded_ip = state.get("last_checked_ip", None)
                same_ip_and_completed = loaded_completed and (loaded_ip == current_ip or loaded_ip is None)

                # Extra Debounce: If IP just changed, wait a bit and re-verify before nuking state
                if needs_ip_recheck and loaded_ip != current_ip:
                     if IS_DEBUG_MODE: log_func(f"[Check] IP changed ({mask_ip(loaded_ip)} -> {mask_ip(current_ip)}). Debouncing...")
                     time.sleep(10)
                     try:
                         check_ip = get_public_ip_isolated()
                         if check_ip != current_ip:
                             log_func(f"[Check] IP change was transient ({mask_ip(current_ip)} -> {mask_ip(check_ip)}). Ignoring.")
                             needs_ip_recheck = False
                             current_ip = check_ip # Adopt the latest one but don't reset
                     except: pass
                
                # Check 7-day timeout
                last_full_ts = state.get("last_full_check_time", 0)
                days_passed = 0
                if last_full_ts > 0:
                     days_passed = (time.time() - last_full_ts) / 86400
                
                is_timeout = days_passed > 7
                
                # FIX: Smart Resume Logic
                # Только если таймаут ИЛИ (IP требует перепроверки И он отличается от сохраненного)
                # Это предотвращает сброс Evo стадий при ложных срабатываниях смены IP
                should_full_reset = is_timeout or (needs_ip_recheck and loaded_ip != current_ip)

                if should_full_reset:
                    need_check = True
                    # FIX: Correct message for default timestamp
                    if last_full_ts == 0:
                        reason = f"смена IP ({mask_ip(current_ip)})" if (needs_ip_recheck and loaded_ip != current_ip) else "первая проверка стратегий"
                    else:
                        reason = f"смена IP ({mask_ip(current_ip)})" if (needs_ip_recheck and loaded_ip != current_ip) else f"плановая ревалидация ({int(days_passed)} дн.)"
                    
                    log_func(f"[Check] Обнаружена {reason}. Запуск полной проверки стратегий. (IP_Recheck={needs_ip_recheck}, Timeout={is_timeout})")
                    
                    # FIX: Use clear+update to preserve dictionary reference for closures/nonlocals
                    state.clear()
                    state.update({
                        "wave": 1, "idx": 0, "current_wave_strategies": [],
                        "best_strategies": [], "bin_performance": {b: 0 for b in bin_files},
                        "general_score": -1, "completed": False,
                        "hard_checked": False,
                        "youtube_checked": False,
                        "discord_checked": False,
                        "cloudflare_checked": False,
                        "whatsapp_checked": False,
                        "last_wave_count": 0,
                        "evolution_stage": 0,
                        "checks_completed": False,
                        "last_checked_ip": current_ip,
                        "app_version": CURRENT_VERSION
                    })
                    save_state()
                
                elif not same_ip_and_completed:
                    # FIX: RESUME LOGIC (IP same, but NOT completed)
                    # We do NOT wipe state, just flag to continue
                    if not state.get("completed", False):
                         # Just log the resume
                         if not skip_main_check: 
                             log_func(f"[Check] Возобновление проверки (IP прежний: {mask_ip(current_ip)}, Completed=False)")
                             # FIX: Explicitly ensure we are NOT in completed state if we are resuming check
                             state["checks_completed"] = False 
                             save_state()

                         need_check = True

                # FIX: In Evo mode, we want to proceed even if IP didn't change (to run evolution on existing base)
                # Also check if Evolution stage > 0 (dynamic evolution in progress)
                # FIX: Check 'completed' (Total) instead of 'evolution_stage' (Partial).
                # If checks_completed=True but completed=False, we MUST proceed to Evolution.
                if not need_check and not IS_EVO_MODE and state.get("completed", False):
                    # Robust spam protection: Log only once per hour
                    # Use GLOBAL dict to bypass any local scope reset issues
                    tid = threading.get_ident()
                    # tid = threading.get_ident() # Removed as per instruction
                    last_log = STANDBY_LOG_TIMERS.get(0, 0) # Using 0 as a global key
                    now_ts = time.time()
                    
                    if now_ts - last_log > 86400:
                         STANDBY_LOG_TIMERS[0] = now_ts # Using 0 as a global key
                         
                         diff = now_ts - last_log
                         log_func(f"[Check] Проверка не требуется (все стратегии актуальны). Ожидание смены IP или истечения срока давности (7 дней).")
                         
                    # Standby Mode: Responsive Sleep Loop
                    # FIX: Check every 5 seconds instead of sleeping 24 hours
                    for _ in range(12): # 1 minute wait
                        if is_closing or not is_service_active: break
                        time.sleep(5)
                    continue

                # === STATE INITIALIZATION (Pre-Check) ===
                # Moved outside 'if all_tasks' to ensure Evolution has access to them even if Main Check is skipped
                blocked_services = set()
                consecutive_zeros = {}
                proven_working_services = set()
                service_baselines = {}
                service_totals = {}
                active_scores_runtime = {}
                perfect_services = set()
                
                # FIX: If resuming, trust saved scores to prevent 'consecutive_zeros' from blocking services during Evolution
                if state.get("general_score", 0) > 0: proven_working_services.add("general")
                if state.get("youtube_score", 0) > 0: proven_working_services.add("youtube")
                if state.get("discord_score", 0) > 0: proven_working_services.add("discord")
                if state.get("whatsapp_score", 0) > 0: proven_working_services.add("whatsapp")
                if state.get("telegram_score", 0) > 0: proven_working_services.add("telegram")

                # Restore Blocked Services (Checked but Score <= 0)
                for svc in ["general", "youtube", "discord", "whatsapp", "telegram", "cloudflare"]:
                    if state.get(f"{svc}_checked", False) and state.get(f"{svc}_score", 0) <= 0:
                        blocked_services.add(svc)

                # --- Подготовка задач для всех сервисов ---
                all_tasks = [] # (service_key, strategy_entry, domains, json_path)
                is_scanning = True # FIX: Ensure flag set here
                last_strategy_check_time = time.time()  # Update check timestamp
                check_phase_scores = {}  # FIX: Словарь для накопления {(service, name): (score, total)}
                
                # FIX: Restore scores from previous run to prevent "Score 0" replacement issue
                try:
                    s_path = os.path.join(get_base_dir(), "temp", "strategy_scores.json")
                    if os.path.exists(s_path):
                        saved_scores = load_json_robust(s_path, {})
                        if saved_scores:
                            for svc, items_dict in saved_scores.items():
                                if not isinstance(items_dict, dict): continue
                                for name, details in items_dict.items():
                                    if isinstance(details, dict) and "score" in details:
                                         # Restore as (score, total) tuple
                                         check_phase_scores[(svc, name)] = (details["score"], details.get("total", 0))
                            log_func(f"[Init] Восстановлено {len(check_phase_scores)} результатов стратегий для сравнения.")
                except Exception as e:
                    if IS_DEBUG_MODE: log_func(f"[Init-Err] Failed to load scores: {e}")

                def prepare_service_tasks(service_key, json_path, test_domains, state_key):
                    # FIX: Strict Block Check - if service is blocked runtime, do not generate tasks
                    if service_key in blocked_services: return []
                    
                    if state.get(state_key, False): return []
                    
                    service_strategies = []
                    
                    # Ensure json exists
                    if not os.path.exists(json_path):
                        defaults = {}
                        try:
                            with open(strat_path, "r", encoding="utf-8") as f:
                                main_data = json.load(f)
                                if service_key in main_data:
                                    defaults[f"Current {service_key}"] = main_data[service_key]
                        except: pass
                        try:
                            with open(json_path, "w", encoding="utf-8") as f:
                                json.dump(defaults, f, indent=4)
                        except: pass

                    # 1. Load "Current" from strategies.json
                    try:
                        with open(strat_path, "r", encoding="utf-8") as f:
                            main_data = json.load(f)
                            
                            # FIX: If service is not in strategies.json, consider it disabled/inactive
                            if service_key not in main_data:
                                return []
                            
                            if service_key in main_data:
                                args = main_data[service_key]
                                # FIX: Respect DISABLED/OFF status (including null/false)
                                if args is None or (isinstance(args, bool) and not args) or \
                                   (isinstance(args, str) and args.strip().upper() in ["DISABLED", "OFF", "FALSE", "NONE"]):
                                     blocked_services.add(service_key)
                                     return []
                                     
                                # Mark as "Current" for UI clarity, but it might duplicate a file strategy.
                                # StrategyChecker will check it.
                                service_strategies.append({"name": f"Current {service_key}", "args": args})
                    except: pass

                    # 2. Load File Strategies
                    try:
                        with open(json_path, "r", encoding="utf-8") as f:
                            raw_data = json.load(f)
                            file_strats = []
                            if isinstance(raw_data, dict) and "strategies" in raw_data:
                                file_strats = raw_data["strategies"]
                            elif isinstance(raw_data, list):
                                file_strats = raw_data
                            elif isinstance(raw_data, dict): # Legacy dict of lists
                                for k, v in raw_data.items():
                                    if k != "version": file_strats.append({"name": k, "args": v})
                            
                            # Add them if not exact arg duplicate of "Current"
                            current_args_str = str(service_strategies[0]["args"]) if service_strategies else ""
                            
                            for s in file_strats:
                                # Start with type check
                                if not isinstance(s, dict): continue

                                # We want to check ALL strategies. 
                                # But if "Current" is identical to "youtube_5", we don't need to check "youtube_5" twice?
                                # Actually, checking twice is waste.
                                # Let's skip if args match exactly.
                                if str(s.get("args")) != current_args_str:
                                    service_strategies.append(s)
                                else:
                                    # If it matches current, we might want to know WHICH strategy matches current.
                                    # But for checking purposes, "Current" covers it.
                                    pass
                    except: pass
                    
                    tasks = []
                    for s in service_strategies:
                        if isinstance(s, dict) and "name" in s:
                             tasks.append((service_key, s, test_domains, strat_path))
                    return tasks

                def read_domains_from_file(filepath):
                    domains = []
                    if os.path.exists(filepath):
                        try:
                            with open(filepath, "r", encoding="utf-8") as f:
                                lines = f.read().splitlines()
                                domains = [l.strip().split('#')[0].strip() for l in lines if l.strip() and not l.startswith("#")]
                        except: pass
                    return domains

                # --- Запуск фонового прогрева DNS (сразу) ---
                warmup_file = os.path.join(base_dir, "temp", "dns_warmup.txt")
                threading.Thread(target=resolve_domains_to_ips, args=(domains, warmup_file), daemon=True).start()

                # === НОВОЕ: Проверка - нужно ли пропустить основную проверку и перейти к эволюции ===
                skip_main_check = (
                    state.get("checks_completed", False) or 
                    state.get("evolution_stage", 0) > 0 or
                    (
                        state.get("hard_checked", False) and
                        state.get("youtube_checked", False) and
                        state.get("discord_checked", False) and
                        state.get("cloudflare_checked", False) and
                        state.get("whatsapp_checked", False) and
                        not state.get("completed", False)
                    )
                )
                

                
                if not skip_main_check:
                    # --- 0. Cloudflare Strategy Check ---
                    cloudflare_list_path = os.path.join(base_dir, "list", "cloudflare.txt")
                    cf_domains = read_domains_from_file(cloudflare_list_path)
                    if not cf_domains:
                        cf_domains = ["www.cloudflare.com", "cloudflare.com"]
                    all_tasks.extend(prepare_service_tasks("cloudflare", cloudflare_strat_path, cf_domains, "cloudflare_checked"))

                    # --- 1. YouTube Strategy Check ---
                    youtube_list_path = os.path.join(base_dir, "list", "youtube.txt")
                    yt_domains = read_domains_from_file(youtube_list_path)
                    if not yt_domains:
                        yt_domains = ["www.youtube.com", "i.ytimg.com", "yt3.ggpht.com", "redirector.googlevideo.com"]
                    all_tasks.extend(prepare_service_tasks("youtube", youtube_strat_path, yt_domains, "youtube_checked"))

                    # --- 2. Discord Strategy Check ---
                    discord_list_path = os.path.join(base_dir, "list", "discord.txt")
                    dc_domains = read_domains_from_file(discord_list_path)
                    if not dc_domains:
                        dc_domains = ["discord.com", "gateway.discord.gg", "cdn.discordapp.com"]
                    all_tasks.extend(prepare_service_tasks("discord", discord_strat_path, dc_domains, "discord_checked"))
                    # discord_list_path = os.path.join(base_dir, "list", "discord.txt")
                    # ds_domains = read_domains_from_file(discord_list_path)
                    # if not ds_domains:
                    #     ds_domains = ["discord.com", "gateway.discord.gg", "cdn.discordapp.com", "discordapp.com"]
                    # all_tasks.extend(prepare_service_tasks("discord", discord_strat_path, ds_domains, "discord_checked"))
                    
                    # --- 3. WhatsApp Strategy Check ---
                    # whatsapp_list_path = os.path.join(base_dir, "list", "whatsapp.txt")
                    # wa_domains = read_domains_from_file(whatsapp_list_path)
                    # if not wa_domains:
                    #     wa_domains = ["whatsapp.com", "whatsapp.net"]
                    # all_tasks.extend(prepare_service_tasks("whatsapp", whatsapp_strat_path, wa_domains, "whatsapp_checked"))
                
                # --- General / Hard Strategy Check ---
                # === НОВОЕ: Правильный выбор доменов для General (всегда 100 доменов) ===
                
                # 1. Читаем домены из специфических списков (для других сервисов)
                # Исключаем: youtube, discord, cloudflare, whatsapp и любые начинающиеся с "_" (будущие стратегии)
                service_domains = set()
                service_lists = [
                    os.path.join(base_dir, "list", "youtube.txt"),
                    os.path.join(base_dir, "list", "discord.txt"),
                    os.path.join(base_dir, "list", "cloudflare.txt"),
                    os.path.join(base_dir, "list", "whatsapp.txt"),
                    os.path.join(base_dir, "list", "telegram.txt"),  # Добавляем telegram если существует
                ]
                for list_file in service_lists:
                    if os.path.exists(list_file):
                        try:
                            with open(list_file, "r", encoding="utf-8") as f:
                                for line in f:
                                    d = line.split('#')[0].strip().lower()
                                    if d:
                                        service_domains.add(d)
                        except: pass
                
                # Также исключаем домены из стратегий начинающихся с "_"
                try:
                    with open(strat_path, "r", encoding="utf-8") as f:
                        strat_data = json.load(f)
                        for strat_name in strat_data.keys():
                            if strat_name.startswith("_"):  # Стратегии-заполнители (будущие)
                                # Получаем домены для такой стратегии если есть
                                future_list = os.path.join(base_dir, "list", f"{strat_name[1:]}.txt")  # Убираем "_"
                                if os.path.exists(future_list):
                                    try:
                                        with open(future_list, "r", encoding="utf-8") as f2:
                                            for line in f2:
                                                d = line.split('#')[0].strip().lower()
                                                if d:
                                                    service_domains.add(d)
                                    except: pass
                except: pass
                
                # Helper: проверка на принадлежность к сервисам (включая поддомены)
                def is_service_domain(d):
                    if d in service_domains: return True
                    parts = d.split('.')
                    for i in range(1, len(parts)):
                        if ".".join(parts[i:]) in service_domains: return True
                    return False


                
                # === ПОДГОТОВКА ДОМЕНОВ (Всегда, т.к. нужны для Эволюции) ===
                # 2. Получаем HOT домены (0-50 шт)
                all_hot = get_hot_domains(max_count=100)
                clean_hot_domains = []
                seen_roots = set() # Для дедупликации по корневому домену
                for d in all_hot:
                    if len(clean_hot_domains) >= 50: break
                    if not is_service_domain(d):
                        root_d = get_registered_domain(d)
                        if root_d not in seen_roots:
                            clean_hot_domains.append(d)
                            seen_roots.add(root_d)
                
                # log_func(f"[Check] Проверка {len(clean_hot_domains)} посещаемых доменов...")
                alive_hot = filter_alive_domains(clean_hot_domains, 50)

                # === НОВОЕ: Проверка прямой доступности для HOT доменов ===
                truly_blocked_hot = []
                for d in alive_hot:
                    if is_closing: break
                    port = 0
                    try: port = audit_ports_queue.get(timeout=1)
                    except: pass
                    try:
                        status, _ = detect_throttled_load(d, port)
                        if status == "ok":
                            pass # Доступен напрямую, пропускаем
                        else:
                            truly_blocked_hot.append(d)
                    finally:
                        if port > 0: audit_ports_queue.put(port)
                
                alive_hot = truly_blocked_hot
                
                # 3. Добираем из RKN до 100
                needed = 100 - len(alive_hot)
                alive_cold = []
                
                if needed > 0:
                    excluded_for_cold = service_domains.union(set(alive_hot))
                    # Берем с запасом (3x), чтобы найти живые
                    cold_candidates = get_cold_domains(rkn_path, excluded_for_cold, max_count=needed*3)
                    
                    if cold_candidates:
                        # log_func(f"[Check] Добираем {needed} доменов из RKN (проверка {len(cold_candidates)} кандидатов)...")
                        alive_cold = filter_alive_domains(cold_candidates, needed)
                
                domains_for_general = alive_hot + alive_cold
                
                if not skip_main_check:
                     log_func(f"[Check] Тестирование на {len(alive_hot)} заблокированных доменах из истории посещений и {len(alive_cold)} доменов из списка rkn")
                elif state.get("evolution_stage", 0) > 0 and not state.get("completed", False):
                     # Log ONLY if we are actually resuming an incomplete session
                     log_func(f"[Check] Основная проверка уже завершена. Переход к эволюции (Domains: {len(domains_for_general)})...")
                
                current_strategies_data = {}
                try:
                    with open(strat_path, "r", encoding="utf-8") as f:
                        current_strategies_data = json.load(f)
                except: pass
                old_hard_strategies = {k: v for k, v in current_strategies_data.items() if k.startswith("hard_")}

                # Добавляем в общий пул, если нужна проверка и мы НЕ пропускаем основную проверку
                # FIX: Always add general tasks if check is running. 
                # Resume logic (filtering against completed_tasks) will handle what's already done.
                # Do NOT block based on 'general_score > 0' because that stops testing after finding just one.
                if not skip_main_check:
                    general_args = []
                    try:
                        with open(strat_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            general_args = data.get("general", [])
                            if general_args:
                                all_tasks.append(("general", {"name": "Current General", "args": general_args}, domains_for_general, strat_path))
                    except: pass
                    
                    for h_name, h_args in old_hard_strategies.items():
                        all_tasks.append(("general", {"name": h_name, "args": h_args}, domains_for_general, strat_path))

                    # === FIX: Добавить стратегии из general.json ===
                    # Проверяем не только hard_1-12, но и эволюционировавшие стратегии из пула
                    try:
                        gen_pool_path = os.path.join(base_dir, "strat", "general.json")
                        if os.path.exists(gen_pool_path):
                            gen_data = load_json_robust(gen_pool_path, {})
                            gen_list = []
                            if isinstance(gen_data, dict) and "strategies" in gen_data:
                                gen_list = gen_data["strategies"]
                            elif isinstance(gen_data, list):
                                gen_list = gen_data
                            
                            added_count = 0
                            for s in gen_list[:36]:  # Top 36 проверенных
                                if isinstance(s, dict) and "args" in s and "name" in s:
                                    all_tasks.append(("general", s, domains_for_general, strat_path))
                                    added_count += 1
                            
                            if added_count > 0:
                                log_func(f"[Check-Init] Добавлено {added_count} стратегий из general.json")
                    except Exception as e:
                        log_func(f"[Check-Init] Ошибка загрузки general.json: {e}")



                # Инициализация списка результатов
                all_strategy_results = []
                

                
                # HELPER: Update Active Config Immediate
                def update_active_config_immediate(succ_svc, succ_args, reason_msg):
                    try:
                        s_path = os.path.join(base_dir, "strat", "strategies.json")
                        c_data = load_json_robust(s_path, {})
                        
                        updated = False
                        if succ_svc == "general":
                            c_data["general"] = succ_args
                            updated = True
                        else:
                            # Update specific service key
                            c_data[succ_svc] = succ_args
                            updated = True
                        
                        if updated:
                            save_json_safe(s_path, c_data)
                            if root: root.after(0, lambda: log_print(f"{reason_msg}. Ядро перезапущено."))
                            else: print(f"{reason_msg}. Ядро перезапущено.")
                            
                            if root: root.after(0, perform_hot_restart_backend)
                            return True
                    except Exception as ex:
                        log_func(f"[HotSwap] Ошибка обновления конфига: {ex}")
                    return False

                # --- Запуск параллельной проверки ВСЕХ стратегий ---
                task_queue = [] # FIX: Initialize to prevent UnboundLocalError
                aborted_by_service = False
                active_futures = {}
                

                if all_tasks:
                    if "standby_log_ts" in state:
                        del state["standby_log_ts"] # Cleanup old key just in case
                    tid = threading.get_ident()
                    if tid in STANDBY_LOG_TIMERS:
                        del STANDBY_LOG_TIMERS[tid] # Reset timer on activity
                    log_func(f"[Check] Задачи: {len(all_tasks)}. Потоков: {STRATEGY_THREADS}")
                    
                    # Unified Task Queue for Phase 1
                    # FIX: Prioritize "Current" tasks, then Interleave others by service for strict mixing
                    current_tasks = []
                    other_tasks = []
                    
                    for t in all_tasks:
                        name = t[1]["name"]
                        if name.startswith("Current ") or name.startswith("Текущая "):
                            current_tasks.append(t)
                        else:
                            other_tasks.append(t)

                    # Group others by service
                    service_groups = {}
                    for t in other_tasks:
                        svc = t[0]
                        if svc not in service_groups: service_groups[svc] = []
                        service_groups[svc].append(t)
                    
                    # Round-robin mix
                    mixed_others = []
                    services = sorted(list(service_groups.keys())) # Fixed order for predictability
                    if service_groups:
                        max_len = max(len(g) for g in service_groups.values())
                        for i in range(max_len):
                            for svc in services:
                                if i < len(service_groups[svc]):
                                    mixed_others.append(service_groups[svc][i])
                    
                    task_queue = current_tasks + mixed_others
                    
                    # === RESUME LOGIC (IP Bound, 7-Day TTL) ===
                    PROGRESS_FILE = os.path.join(get_base_dir(), "temp", "checker_progress.json")
                    completed_tasks = set()
                    
                    # Load previous progress
                    if os.path.exists(PROGRESS_FILE):
                        try:
                            p_data = load_json_robust(PROGRESS_FILE)
                            
                            # 1. Check IP Binding
                            is_same_ip = p_data.get("ip") == current_ip
                            
                            # 2. Check 7-Day TTL (604800 seconds)
                            is_fresh = time.time() - p_data.get("timestamp", 0) < 604800
                            
                            if is_same_ip and is_fresh:
                                completed_tasks = set(p_data.get("completed", []))
                                
                                # FIX: Only re-check "Current" strategies if we lack a valid baseline score!
                                # If we have a score in state, we trust it and skip re-check.
                                tasks_to_remove = set()
                                for t in completed_tasks:
                                    if t.startswith("Current ") or t.startswith("Текущая "):
                                        # Extract service name: "Current youtube" -> "youtube"
                                        try:
                                            svc_name = t.split(' ')[1]
                                            # Check if we have a valid score for this service
                                            # special handling for "Current General" -> "general"
                                            if svc_name.lower() == "general": svc_key = "general_score"
                                            else: svc_key = f"{svc_name}_score"
                                            
                                            if state.get(svc_key, -1) < 0:
                                                tasks_to_remove.add(t)
                                        except:
                                            tasks_to_remove.add(t)
                                
                                completed_tasks -= tasks_to_remove
                                
                                if completed_tasks:
                                    log_func(f"[Init] Восстановлен прогресс для IP {mask_ip(current_ip)}: {len(completed_tasks)} стратегий уже проверено.")
                            else:
                                # IP changed or Too Old - ignore previous progress (start fresh)
                                pass
                        except: pass
                    
                    # Filter queue
                    initial_len = len(task_queue)
                    task_queue = [t for t in task_queue if t[1]["name"] not in completed_tasks]
                    skipped_count = initial_len - len(task_queue)
                    
                    if skipped_count > 0:
                         log_func(f"[Check] Пропущено {skipped_count} стратегий (уже проверены). Осталось: {len(task_queue)}")
                         
                    # FIX: Force EVO Mode - Skip standard queue
                    if IS_EVO_MODE:
                        log_func("[Check] Режим --evo: Пропуск стандартной очереди (оставляем только Current)...")
                        # Keep only "Current" strategies to establish baseline
                        task_queue = [t for t in task_queue if t[1]["name"].startswith("Current ") or t[1]["name"].startswith("Текущая ")]
                        
                        # Also force reset 'completed' state later to ensure Evolution runs

                    
                    priority_tasks = set() # Init empty set to prevent NameError
                    restart_needed = False
                    
                    # Blockage Tracking
                    blocked_services = set()
                    consecutive_zeros = {}
                    proven_working_services = set() # Services that had at least one success
                    
                    # Internet Outage Detection
                    recent_results = []  # Track last N results (True/False)
                    OUTAGE_WINDOW = 10   # Check last 10 results
                    OUTAGE_THRESHOLD = 0.8  # 80% failures = likely outage

                    # Reset Baselines for this session OR restore from state if resuming on same IP
                    # Previous session scores are irrelevant if network changed.
                    service_baselines = {}
                    service_totals = {}
                    
                    # FIX: Restore baselines from state if IP matches (resume after stop)
                    try:
                        saved_ip = state.get("last_checked_ip", "")
                        if saved_ip == current_ip:
                            # Restore saved scores as baselines
                            service_baselines = {
                                "general": state.get("general_score", 0),
                                "youtube": state.get("youtube_score", 0),
                                "discord": state.get("discord_score", 0),
                                "whatsapp": state.get("whatsapp_score", 0),
                                "telegram": state.get("telegram_score", 0),
                            }
                            # Restore totals to enable percentage comparison
                            service_totals = {
                                "general": state.get("general_total", 100),
                                "youtube": state.get("youtube_total", 16),
                                "discord": state.get("discord_total", 16),
                                "whatsapp": state.get("whatsapp_total", 16),
                                "telegram": state.get("telegram_total", 16),
                            }
                            # Filter out zeros
                            service_baselines = {k: v for k, v in service_baselines.items() if v > 0}
                            if service_baselines:
                                log_func(f"[Check] Восстановлены результаты прошлой сессии: {service_baselines} (Totals: {service_totals})")
                    except Exception as e:
                        if IS_DEBUG_MODE: log_func(f"[Check] Ошибка восстановления baselines: {e}")

                    # FIX: Restore check_phase_scores from disk if resuming (to populate Evolution/Sorting later)
                    if saved_ip == current_ip:
                         try:
                             scores_path = os.path.join(base_dir, "temp", "strategy_scores.json")
                             if os.path.exists(scores_path):
                                 saved_scores_data = load_json_robust(scores_path, {})
                                 count_restored = 0
                                 for svc_key, svc_data in saved_scores_data.items():
                                     for s_name, s_info in svc_data.items():
                                         if isinstance(s_info, dict) and "score" in s_info:
                                              check_phase_scores[(svc_key, s_name)] = (s_info["score"], s_info.get("total", 0))
                                              count_restored += 1
                                 if count_restored > 0:
                                      log_func(f"[Init] Восстановлено {count_restored} индивидуальных результатов тестов.")
                         except Exception as ex:
                               if IS_DEBUG_MODE: log_func(f"[Init] Ошибка восстановления scores: {ex}")
                    
                    active_scores_runtime = {}  # FIX: Cached scores for sorting phase 
                    
                    # FIX: Populate runtime scores from restored check_phase_scores (critical for Evo mode skip)
                    if check_phase_scores:
                        for (c_svc, c_name), c_val in check_phase_scores.items():
                            c_score, c_total = c_val if isinstance(c_val, tuple) else (c_val, 0)
                            
                            if c_svc not in active_scores_runtime: active_scores_runtime[c_svc] = {}
                            active_scores_runtime[c_svc][c_name] = c_score
                            
                            # Also ensure baseline is correct (state might be outdated)
                            # Use ratio-based comparison for robustness
                            curr_b_score = service_baselines.get(c_svc, 0)
                            curr_b_total = service_totals.get(c_svc, 0)
                            
                            b_ratio = curr_b_score / curr_b_total if curr_b_total > 0 else -1
                            c_ratio = c_score / c_total if c_total > 0 else 0
                            
                            if c_ratio > b_ratio:
                                service_baselines[c_svc] = c_score
                                service_totals[c_svc] = c_total

                    # DEBUG LOG: Verify Baselines
                    if IS_DEBUG_MODE or IS_EVO_MODE:
                        log_func(f"[Evo-Debug] Baselines after restore: {service_baselines}")
                        if "youtube" in service_baselines:
                            log_func(f"[Evo-Debug] Youtube Baseline: {service_baselines['youtube']}")
                        else:
                            log_func(f"[Evo-Debug] Youtube NOT in baselines! check_phase_scores sample: {list(check_phase_scores.keys())[:5] if check_phase_scores else 'Empty'}")

                    perfect_services = set()
                   
                    log_func(f"[Check] Проверка текущих стратегий ({len(task_queue)} шт.)")
                    
                    # Manual Executor for all phases to enable non-blocking shutdown
                    executor = concurrent.futures.ThreadPoolExecutor(max_workers=STRATEGY_THREADS)
                    aborted_by_service = False

                    try:
                        active_futures = {}
                        pending_hotswap = []  # Стратегии, ожидающие Hot Swap (если baseline ещё не установлен)
                        
                        while (task_queue or active_futures) and is_service_active and not is_closing:
                            # 1. Fill slots (Заполнение потоков)
                            while len(active_futures) < STRATEGY_THREADS and task_queue and is_service_active and not is_closing:
                                task = task_queue.pop(0)
                                if not is_service_active or is_closing:
                                    task_queue.insert(0, task)
                                    break
                                
                                svc, strat, doms, path = task
                                line_id = id(task)
                                
                                # Progress Tracker Logic
                                def make_progress_tracker(lid, s_name, s_svc, total):
                                    state_tr = {'score': 0, 'active': 0, 'checked': 0, 'created': False}
                                    lock = threading.Lock()
                                    
                                    def tracker(event, **kwargs):
                                        nonlocal state_tr
                                        with lock:
                                            if not is_service_active and not is_closing: return

                                            if event == 'start':
                                                if not state_tr['created']:
                                                    bar = get_progress_bar(0, 0, total, width=20)
                                                    imsg = f"[Check] {s_name} ({s_svc}) {bar} 0/0"
                                                    progress_manager.create_line(lid, imsg)
                                                    state_tr['created'] = True
                                                state_tr['active'] += 1
                                            elif event == 'finish':
                                                if state_tr['active'] > 0: state_tr['active'] -= 1
                                                state_tr['checked'] += 1
                                                if kwargs.get('success'): state_tr['score'] += 1
                                        
                                        if state_tr['created']:
                                            gray_count = state_tr['checked'] + state_tr['active'] - state_tr['score']
                                            bar = get_progress_bar(state_tr['score'], gray_count, total, width=20)
                                            msg = f"[Check] {s_name} ({s_svc}) {bar} {state_tr['score']}/{state_tr['checked']}"
                                            progress_manager.update_line(lid, msg, is_final=False)
                                    return tracker
                                    
                                tracker_func = make_progress_tracker(line_id, strat['name'], svc, len(doms))

                                fut = executor.submit(check_strat_threaded, strat["args"], doms, progress_tracker=tracker_func, run_id=current_run_id)
                                active_futures[fut] = (task, line_id)

                            # 2. Wait / Abort logic
                            if not is_service_active:
                                aborted_by_service = True
                                break

                            if not active_futures: break
                            
                            while audit_running_event.is_set():
                                 time.sleep(1)
                                 
                            done, _ = concurrent.futures.wait(active_futures.keys(), timeout=1, return_when=concurrent.futures.FIRST_COMPLETED)
                            
                            if aborted_by_service or is_closing:
                                for f in active_futures.keys(): f.cancel()
                                break
                            
                            # 3. Process Results
                            for fut in done:
                                task_info = active_futures.pop(fut)
                                task, line_id = task_info
                                svc, strat, doms, path = task
                                try:
                                    sc = fut.result()
                                    
                                    # Perfect Score Check Phase 2
                                    if sc is not None and sc >= len(doms) and len(doms) > 0:
                                        if svc not in perfect_services:
                                            log_func(f"Для стратегии {strat['name']} ({svc}) результат 100% ({sc}/{len(doms)}). Дальнейшие улучшения не требуются.")
                                            perfect_services.add(svc)

                                    if sc is None: 
                                        if not (is_closing or not is_service_active):
                                             progress_manager.update_line(line_id, f"[Check] {strat['name']} ({svc}): Ошибка", is_final=True)
                                        continue
                                    
                                    # Update UI Line
                                    gray_count = len(doms) - sc
                                    if gray_count < 0: gray_count = 0 
                                    bar = get_progress_bar(sc, gray_count, len(doms), width=20)
                                    final_msg = f"[Check] {strat['name']} ({svc}) {bar} {sc}/{len(doms)} ✓"
                                    progress_manager.update_line(line_id, final_msg, is_final=True)

                                    if svc in blocked_services:
                                        continue
                                    
                                    s_name = strat["name"]
                                    
                                    # FIX: Сохраняем score и total для последующего использования в Evolution
                                    check_phase_scores[(svc, s_name)] = (sc, len(doms))
                                    all_strategy_results.append((sc, strat, svc, len(doms)))

                                    # === [LEARNING] Update Stats for Check Phase ===
                                    try:
                                        bin_used = []
                                        if "bin" in strat and strat["bin"]:
                                            bin_used.append(strat["bin"])
                                        
                                        # FORCE LOG to prove we are here
                                        if IS_DEBUG_MODE:
                                            log_func(f"[DEBUG-Check] Saving stats for {strat['name']} (Score={sc})")

                                        update_learning_stats(
                                            strat["args"], 
                                            sc, 
                                            len(doms), 
                                            service=svc, 
                                            bin_files_used=bin_used, 
                                            logger=log_func
                                        )
                                    except Exception as e:
                                        log_func(f"[Learning] Error updating stats: {e}")

                                    
                                    is_current = s_name.startswith("Current ") or s_name.startswith("Текущая ")

                                    # Обновляем базовый счетчик, если это текущая стратегия
                                    if is_current:
                                        service_baselines[svc] = sc
                                        service_totals[svc] = len(doms)
                                        
                                        if svc == "general": 
                                            state["general_score"] = sc
                                            state["general_total"] = len(doms)
                                        else: 
                                            state[f"{svc}_score"] = sc
                                            state[f"{svc}_total"] = len(doms)
                                        save_state()
                                        
                                        # CRITICAL: Проверяем pending_hotswap для этого сервиса
                                        # (стратегии, которые были проверены ДО Current)
                                        for p_sc, p_strat, p_svc, p_total in pending_hotswap:
                                            if p_svc == svc:
                                                p_ratio = p_sc / p_total if p_total > 0 else 0
                                                c_ratio = sc / len(doms) if len(doms) > 0 else 0
                                                
                                                if p_ratio > c_ratio:
                                                    msg_t = f"   >>> Найдена более сильная стратегия для {svc} ({p_sc}/{p_total} > {sc}/{len(doms)}) [из очереди]"
                                                    if root: root.after(0, lambda m=msg_t: log_print(m))
                                                    
                                                    service_baselines[svc] = p_sc
                                                    service_totals[svc] = p_total
                                                    if svc == "general": 
                                                        state["general_score"] = p_sc
                                                        state["general_total"] = p_total
                                                    else: 
                                                        state[f"{svc}_score"] = p_sc
                                                        state[f"{svc}_total"] = p_total
                                                    save_state()
                                                    
                                                    update_active_config_immediate(p_svc, p_strat["args"], "   Применена новая стратегия (Pending)")
                                                    break  # Применили лучшую - выходим

                                    # Логика замены (Hot Swap)
                                    # Берем текущий базовый счет и общее кол-во
                                    bl_score = service_baselines.get(svc, -1)
                                    bl_total = service_totals.get(svc, 0)
                                    
                                    # Рассчитываем коэффициенты для сравнения (проценты успеха)
                                    bl_ratio = bl_score / bl_total if bl_total > 0 else -1
                                    curr_ratio = sc / len(doms) if len(doms) > 0 else 0
                                    
                                    # baseline_ready = (bl >= 0)
                                    baseline_ready = (bl_ratio >= 0)
                                    
                                    # Если baseline не готов - откладываем Hot Swap проверку
                                    if not baseline_ready and not is_current:
                                        pending_hotswap.append((sc, strat, svc, len(doms)))


                                    if baseline_ready and not is_current and curr_ratio > bl_ratio:
                                         # Thread-safe логирование в GUI
                                         msg_t = f"   >>> Найдена более сильная стратегия для {svc} ({sc}/{len(doms)} > {bl_score}/{bl_total})"
                                         if root: root.after(0, lambda m=msg_t: log_print(m))
                                         
                                         # Обновляем baseline сразу
                                         service_baselines[svc] = sc
                                         service_totals[svc] = len(doms)
                                         
                                         if svc == "general": 
                                             state["general_score"] = sc
                                             state["general_total"] = len(doms)
                                         else: 
                                             state[f"{svc}_score"] = sc
                                             state[f"{svc}_total"] = len(doms)
                                         save_state()

                                         update_active_config_immediate(svc, strat["args"], "   Применена новая стратегия")


                                    # Track results for outage detection
                                    recent_results.append(sc > 0)
                                    if len(recent_results) > OUTAGE_WINDOW:
                                        recent_results.pop(0)
                                    
                                    # Blockage Logic with Smart Internet Outage Detection
                                    if sc == 0:
                                        consecutive_zeros[svc] = consecutive_zeros.get(svc, 0) + 1
                                        
                                        # Check if multiple services are failing (pattern detection)
                                        if len(recent_results) >= 5:  # Need at least 5 results
                                            failure_rate = 1.0 - (sum(recent_results) / len(recent_results))
                                            
                                            # If 80%+ failures in recent results → likely internet outage
                                            if failure_rate >= OUTAGE_THRESHOLD:
                                                # Verify with Google connectivity check (single call)
                                                if not check_internet_connectivity():
                                                    # Internet is down!
                                                    log_func("[Пауза] Обнаружен обрыв интернета (множественные отказы). Ожидание восстановления...")
                                                    
                                                    # Wait for internet with 1-second polling
                                                    while not is_closing and is_service_active:
                                                        time.sleep(1)
                                                        if check_internet_connectivity():
                                                            log_func("[Пауза] Интернет восстановлен. Продолжение проверки...")
                                                            break
                                                    
                                                    if is_closing or not is_service_active:
                                                        break
                                                    
                                                    # Reset tracking
                                                    recent_results.clear()
                                                    for k in list(consecutive_zeros.keys()):
                                                        consecutive_zeros[k] = 0
                                                    # Continue checking from current position
                                                    continue
                                        
                                        
                                        # Normal blockage logic (service-specific)
                                        # FIX: Don't block services with a proven baseline (persists across restarts)
                                        has_saved_baseline = False
                                        if svc == "general":
                                            has_saved_baseline = state.get("general_score", 0) > 0
                                        else:
                                            has_saved_baseline = state.get(f"{svc}_score", 0) > 0
                                        
                                        if consecutive_zeros[svc] > 2 and svc not in blocked_services and svc not in proven_working_services and not has_saved_baseline:
                                            blocked_services.add(svc)
                                            log_func(f"[Warning] {svc} не отвечает (3 раза по 0). Пропуск остальных.")
                                            state[f"{svc}_checked"] = True
                                            state[f"{svc}_score"] = 0 # Explicitly zero to persist block
                                            save_state()
                                            task_queue = [t for t in task_queue if t[0] != svc]
                                            for f, t in active_futures.items():
                                                if t[0] == svc: f.cancel()
                                    else:
                                        # Success - reset counter and mark as working
                                        consecutive_zeros[svc] = 0
                                        if sc > 0:
                                            proven_working_services.add(svc)
                                    
                                    # Save progress
                                    completed_tasks.add(s_name)
                                    if len(completed_tasks) % 5 == 0:
                                         save_json_safe(PROGRESS_FILE, {
                                            "completed": list(completed_tasks), 
                                            "timestamp": time.time(), "ip": current_ip 
                                         })
                                         
                                         # FIX: Also save scores incrementally to avoid total loss if interrupted
                                         try:
                                             scores_temp_path = os.path.join(base_dir, "temp", "strategy_scores.json")
                                             partial_scores = {}
                                             # Reconstruct full structure from flat dict
                                             for (svc_k, name_k), val_pair in check_phase_scores.items():
                                                 val_s, val_t = val_pair if isinstance(val_pair, tuple) else (val_pair, 0)
                                                 if svc_k not in partial_scores: partial_scores[svc_k] = {}
                                                 partial_scores[svc_k][name_k] = {
                                                     "score": val_s, 
                                                     "total": val_t,
                                                     "timestamp": int(time.time())
                                                 }
                                             
                                             # Merge with existing file to handle restarts
                                             # (If run 1 saved A, B, and run 2 saves C, we want A, B, C)
                                             existing_partials = load_json_robust(scores_temp_path, {})
                                             for k_svc, v_dict in partial_scores.items():
                                                 if k_svc not in existing_partials: existing_partials[k_svc] = {}
                                                 existing_partials[k_svc].update(v_dict)
                                                 
                                             save_json_safe(scores_temp_path, existing_partials)
                                         except: pass

                                except Exception as e:
                                    log_func(f"[Check] Error processing result: {e}")

                    finally:
                        executor.shutdown(wait=not aborted_by_service, cancel_futures=True)

                # === BREAK CONDITIONS ===
                # 1. Service Stop
                if not is_service_active or is_closing:
                    # Emergency: User Disabled. Cancel all futures and purge queue
                    for fut in active_futures.copy():
                        fut.cancel()
                    active_futures.clear()
                    
                    task_queue = []
                    
                    # FIX: Do NOT reset is_scanning here - it should stay True until Evolution completes
                    # is_scanning = False  # REMOVED: This was too early, Evolution phase still needs it
                    
                    # Only log if we were actually doing something
                    if task_queue or active_futures:
                         log_func("[Check] Процесс остановлен пользователем.")
                    
                    # Clear everything to prevent re-entry in this cycle
                    all_tasks = []
                    task_queue = []
                    
                    time.sleep(2) # Give UI time to breathe
                    time.sleep(2) # Give UI time to breathe
                    
                    # FIX: Do not continue if we just finished normally! 
                    # Only continue if actually ABORTED.
                    if aborted_by_service:
                        continue 
                    # If simply empty queue (finished Check), FALL TROUGH to Evo logic! 

                # === FIX: Mark Checks Completed Immediately After Loop ===
                # If we exited the loop normally (not aborted, service active), it means queue is empty (all checks done)
                # FIX: Must check 'not is_closing' to avoid marking as done if user just hit Stop
                if not aborted_by_service and is_service_active and not is_closing:
                     if not state.get("checks_completed", False):
                         log_func("[Check] Основная проверка завершена. Фиксация состояния.")
                         state["checks_completed"] = True
                         save_state() 
                         
                         # === СОХРАНЕНИЕ SCORES ПОСЛЕ CHECK PHASE ===
                         try:
                             log_func("[Score-Save] Сохранение результатов тестирования...")
                             scores_path = os.path.join(base_dir, "temp", "strategy_scores.json")
                             strategy_scores_data = {}
                             
                             for (svc, name), score_val in check_phase_scores.items():
                                 score, total_count = score_val if isinstance(score_val, (list, tuple)) else (score_val, 0)
                                 if svc not in strategy_scores_data:
                                     strategy_scores_data[svc] = {}
                                 strategy_scores_data[svc][name] = {
                                     "score": score,
                                     "total": total_count,
                                     "timestamp": int(time.time())
                                 }
                             
                             save_json_safe(scores_path, strategy_scores_data)
                             total = sum(len(v) for v in strategy_scores_data.values())
                             log_func(f"[Score-Save] Сохранено {total} scores")
                         except Exception as e:
                             log_func(f"[Score-Save] Ошибка: {e}")

                def sort_and_distribute_results(results_list, score_cache=None, log_func=log_func):
                    # Sort by Ratio DESC (Success Percentage)
                    # We use a custom key to handle different domain counts
                    def get_ratio(x):
                        # x = (score, strat, svc, total) OR (score, strat, svc)
                        sc = x[0]
                        tot = x[3] if len(x) > 3 else 100 # Default to 100 if total missing
                        return sc / tot if tot > 0 else 0

                    results_list.sort(key=get_ratio, reverse=True)
                    
                    if score_cache is None: score_cache = {}

                    # Split by Service
                    grouped = {}
                    for item in results_list:
                        sc = item[0]
                        st = item[1]
                        svc = item[2]
                        tot = item[3] if len(item) > 3 else 100
                        
                        if svc not in grouped: grouped[svc] = []
                        grouped[svc].append((sc, st, tot))
                        
                    for svc, items in grouped.items():
                        # Get current baseline for this service (score and total)
                        bl_score = service_baselines.get(svc, -1)
                        bl_total = service_totals.get(svc, 100)
                        bl_ratio = bl_score / bl_total if bl_total > 0 else -1
                        
                        top_item = items[0] # (score, strat_obj, total)
                        top_score = top_item[0]
                        top_total = top_item[2]
                        top_ratio = top_score / top_total if top_total > 0 else 0
                        
                        # Only log if exciting improvement or Current
                        if top_ratio > bl_ratio:
                             log_func(f"[Sorter] {svc}: Новая лучшая -> {top_item[1].get('name', 'Unknown')} ({top_score}/{top_total})")

                        # Save SORTED lists back to files
                        if svc == "discord": target_limit = 99
                        else: target_limit = 200 if svc == "general" else 12  # FIX: Increased limit
                        start_path = os.path.join(base_dir, "strat", f"{svc}.json")
                        
                        try:
                            # 1. Load existing strategies from file (Pool)
                            existing_data = load_json_robust(start_path, {})
                            existing_list = []
                            if isinstance(existing_data, dict) and "strategies" in existing_data:
                                existing_list = existing_data["strategies"]
                            elif isinstance(existing_data, list):
                                existing_list = existing_data
                            
                            # 2. Partition: Checked vs Unchecked
                            # Checked = In 'items' (New Results) OR In 'score_cache' (Old results we know)
                            
                            checked_names_current = set()
                            for sc, st, tot in items:
                                raw_name = st.get('name', '')
                                # Normalize (Strip "Current ", lowercase start)
                                if raw_name.startswith('Current '):
                                    clean = raw_name[8:]
                                    if clean and clean[0].isupper(): clean = clean[0].lower() + clean[1:]
                                    checked_names_current.add(clean)
                                else:
                                    checked_names_current.add(raw_name)
                                checked_names_current.add(raw_name) # Add raw too just in case
                            
                            unchecked_strategies = []
                            cached_strategies_to_add = []
                            
                            for s in existing_list:
                                s_name = s['name']
                                if s_name in checked_names_current:
                                    pass # Already in 'items' (new result overrides cache)
                                elif svc in score_cache and s_name in score_cache[svc]:
                                    # Found in Cache! Treat as Checked/Verified baseline.
                                    # Add to pool with Cached Score to complete in Tournament.
                                    cached_score = score_cache[svc][s_name]
                                    # FIX: If it's a tuple (score, total) in cache, handle it.
                                    # But score_cache (active_scores_runtime) usually only has raw score.
                                    # We'll assume a default total for cached ones if missing.
                                    c_s = cached_score[0] if isinstance(cached_score, (list, tuple)) else cached_score
                                    cached_strategies_to_add.append({"score": c_s, "strat": s})
                                else:
                                    unchecked_strategies.append(s)
                            
                            # 3. Create Pool of "Active Candidates"
                            # 'items' contains ALL results from this run. 
                            
                            active_candidates = [] # list of dict(score, strat, total)
                            
                            for sc, st, tot in items:
                                # FIX: Strip "Current " prefix before saving
                                clean_strat = st.copy()
                                name = clean_strat.get('name', '')
                                if name.startswith('Current '):
                                    clean_name = name[8:]  # len('Current ') = 8
                                    if clean_name and clean_name[0].isupper():
                                        clean_name = clean_name[0].lower() + clean_name[1:]
                                    clean_strat['name'] = clean_name
                                active_candidates.append({"score": sc, "strat": clean_strat, "total": tot})
                            
                            # Add Cached (Old Verified)
                            for c_item in cached_strategies_to_add:
                                # We don't know the total for cached ones easily, assume 100 or use existing if any
                                active_candidates.append({"score": c_item["score"], "strat": c_item["strat"], "total": 100})
                            
                            # Sort Active Candidates by Ratio DESC
                            active_candidates.sort(key=lambda x: x["score"] / x["total"] if x.get("total", 0) > 0 else 0, reverse=True)
                            
                            # --- UPDATE strategies.json (Global Active Config) ---
                            # FIX: Update for ALL services if we found a better one (Top 1)
                            if active_candidates:
                                try:
                                    strat_main_path = os.path.join(base_dir, "strat", "strategies.json")
                                    main_data = load_json_robust(strat_main_path, {})
                                    
                                    best_cand = active_candidates[0]
                                    best_strat = best_cand["strat"]
                                    updated_active = False
                                    
                                    if svc == "general":
                                        if best_strat and "args" in best_strat:
                                            main_data["general"] = best_strat["args"]
                                            updated_active = True
                                        for i in range(12):
                                            key = f"hard_{i+1}"
                                            if i < len(active_candidates):
                                                s_cand = active_candidates[i]["strat"]
                                                if "args" in s_cand:
                                                    main_data[key] = s_cand["args"]
                                                    updated_active = True
                                    else:
                                        if best_strat and "args" in best_strat:
                                            main_data[svc] = best_strat["args"]
                                            updated_active = True
                                    
                                    if updated_active:
                                        save_json_safe(strat_main_path, main_data)
                                except Exception as e:
                                    log_func(f"[Sorter] strategies.json update error: {e}")
                                    log_func(f"[Sorter] Ошибка обновления strategies.json для {svc}: {e}")
                                    pass

                            # 4. Prune Active Candidates to fit allowed space in Pool file
                            # Rule: "Delete only after Full Check" => strict limit only if Unchecked is empty.

                            space_for_active = target_limit - len(unchecked_strategies)
                            
                            final_active = []
                            
                            if len(unchecked_strategies) == 0:
                                # Full Check achieved (or file was empty). Enforce strict limit.
                                if space_for_active < 1: space_for_active = 1 # Keep at least 1
                                final_active = [x["strat"] for x in active_candidates[:space_for_active]]
                            else:
                                # Partial Check. 
                                # We MUST keep all Unchecked. 
                                # We also want to keep Verified ones, but maybe not junk?
                                # Let's keep Top N Verified where N is reasonable (e.g. Limit).
                                # Effectively, we allow file to grow to (Limit + Unchecked).
                                # But we prune Verified junk (score 0 or just check limit).
                                # Pruning Verified to 'target_limit' ensures we don't explode with mutations if we run evo many times without finishing.
                                
                                # Logic: Keep Top 60 verified. And Keep All Unchecked.
                                # This ensures mutations don't pile up infinitely.
                                
                                # Logic: Keep Top 36 verified. And Keep All Unchecked.
                                # This ensures mutations don't pile up infinitely.
                                
                                limit_verified = target_limit
                                # FIX: Strict constraint to ensure we don't float above limit
                                if len(active_candidates) > limit_verified:
                                    active_candidates = active_candidates[:limit_verified]
                                
                                final_active = [x["strat"] for x in active_candidates]
                                
                            # LOGGING
                            if IS_DEBUG_MODE:
                                 top_names = [x.get('name', 'Unknown') for x in final_active[:5]]
                                 
                                 # Comparison
                                 old_top = existing_list[0].get('name', 'Unknown') if existing_list else "None"
                                 new_top = final_active[0].get('name', 'Unknown') if final_active else "None"
                                 diff = "CHANGED" if old_top != new_top else "SAME"
                                 
                                 log_func(f"[Sorter-Merge] {svc}: Top={diff} ({old_top} -> {new_top}). Saved: {len(final_active) + len(unchecked_strategies)}. Top-5: {top_names}")
                                 
                                 # Diff
                                 old_names = set(s.get('name', '') for s in existing_list)
                                 new_names = set(s.get('name', '') for s in final_active)
                                 added = new_names - old_names
                                 removed = old_names - new_names
                                 
                                 if added and IS_DEBUG_MODE: log_func(f"[Sorter-Diff] {svc}: +ADDED: {list(added)}")
                                 if removed and IS_DEBUG_MODE: log_func(f"[Sorter-Diff] {svc}: -REMOVED: {list(removed)}")
                            
                            # 5. Combine and Save
                            final_list = final_active + unchecked_strategies
                            
                            # Save
                            new_data = {"version": CURRENT_VERSION, "strategies": final_list}
                            save_json_safe(start_path, new_data)
                            
                            # === СОХРАНЕНИЕ SCORES В temp/strategy_scores.json ===
                            # FIX: Отдельное хранилище для результатов (не распространяется, удаляется при --fresh)
                            if IS_DEBUG_MODE: log_func(f"[DEBUG-SAVE] Попытка сохранения scores для {svc}...")
                            try:
                                scores_path = os.path.join(base_dir, "temp", "strategy_scores.json")
                                existing_scores = load_json_robust(scores_path, {})
                                
                                if IS_DEBUG_MODE: log_func(f"[Sorter-Scores-Debug] Сохранение scores для {svc}. Кандидатов: {len(active_candidates)}")
                                
                                # Обновляем scores для текущего сервиса
                                if svc not in existing_scores:
                                    existing_scores[svc] = {}
                                
                                import time
                                current_time = int(time.time())
                                
                                saved_count = 0
                                for candidate in active_candidates:
                                    strat_name = candidate["strat"].get("name", "")
                                    if strat_name:
                                        existing_scores[svc][strat_name] = {
                                            "score": candidate["score"],
                                            "total": candidate.get("total", 0),
                                            "timestamp": current_time
                                        }
                                        saved_count += 1
                                
                                save_json_safe(scores_path, existing_scores)
                                if IS_DEBUG_MODE: log_func(f"[Sorter-Scores] {svc}: Сохранено {saved_count} scores в {scores_path}")
                            except Exception as e:
                                if True: log_func(f"[Sorter-Scores] Ошибка сохранения scores для {svc}: {e}")
                            
                            if IS_DEBUG_MODE: log_func(f"[Sorter] {svc}: Оптимизация. Проверено: {len(active_candidates)}, Оставлено: {len(final_active)}, Не тронуто: {len(unchecked_strategies)}. Всего: {len(final_list)}")
                            
                        except Exception as e:
                            log_func(f"[Sorter] Ошибка сохранения {svc}: {e}")
                            pass





                # === CALL SORTER for Phase 1 Results ===
                # This prunes the files to the strict limits (Tournament Phase 1)
                # FIX: Run this OUTSIDE 'if all_tasks' so that even if we skipped checks, we can sort/evo
                pass
                
                if all_strategy_results:
                     # === INLINED SCORE SAVING ===
                     try:
                         scores_path = os.path.join(base_dir, "temp", "strategy_scores.json")
                         existing_scores = load_json_robust(scores_path, {})
                         
                         log_func(f"[Score-Saver-Direct] Saving {len(all_strategy_results)} results to {scores_path}")
                         
                         import time
                         current_time = int(time.time())
                         
                         for item in all_strategy_results:
                             score = item[0]
                             strat = item[1]
                             svc = item[2]
                             
                             if svc not in existing_scores: existing_scores[svc] = {}
                             s_name = strat.get("name", "")
                             if s_name:
                                 existing_scores[svc][s_name] = {
                                     "score": score,
                                     "timestamp": current_time
                                 }
                         
                         save_json_safe(scores_path, existing_scores)
                         log_func("[Score-Saver-Direct] Success.")
                     except Exception as e:
                         log_func(f"[Score-Saver-Direct] Error: {e}")

                     sort_and_distribute_results(all_strategy_results, score_cache=active_scores_runtime)

                if IS_DEBUG_MODE: log_func("[StrategyChecker-Debug] Фаза завершена. Сохранение состояния...")
                # === НОВОЕ: Пропускаем сохранение флагов если они уже были установлены (продолжение после перезапуска) ===
                if not skip_main_check:
                    # FIX: Only mark services as checked if they were actually fully processed/skipped due to completion
                    # If we aborted or didn't finish, do not mark as checked!
                    
                    if not aborted_by_service and not is_closing:
                        # Logic: If task_queue is empty, we finished everything we intended to check.
                        # EXCEPT if we were interrupted before this block?
                        # This block is reached if loop finished.
                        
                        # We can assume if we are here and not aborted, we finished the queue.
                        state["cloudflare_checked"] = True
                        state["youtube_checked"] = True
                        state["discord_checked"] = True
                        state["whatsapp_checked"] = True
                        state["hard_checked"] = True
                        state["checks_completed"] = True # Sync with flag
                        save_state()
                        if IS_DEBUG_MODE: log_func("[StrategyChecker-Debug] Состояние сохранено (Все проверки завершены).")
                else:
                    if IS_DEBUG_MODE: log_func("[StrategyChecker-Debug] Пропуск сохранения флагов (уже установлены).")
                
                # --- Загрузка кандидатов из general.json ---
                
                if not is_service_active or is_closing:
                    log_func("[Check] Проверка остановлена перед этапом Эволюции.")
                    is_scanning = False
                    break

                # --- PHASE 3: EVOLUTION (3 STAGES) ---

                # FIX: Fallback - ensure we have baselines even if Check Phase was skipped
                if not active_scores_runtime and check_phase_scores:
                    log_func(f"[Evo-PreCheck] Restoring {len(check_phase_scores)} scores for Evolution baseline...")
                    for (c_svc, c_name), c_val in check_phase_scores.items():
                        c_score, c_total = c_val if isinstance(c_val, (list, tuple)) else (c_val, 0)
                        
                        if c_svc not in active_scores_runtime: active_scores_runtime[c_svc] = {}
                        active_scores_runtime[c_svc][c_name] = c_score
                        
                        # Populate baseline using ratio comparison
                        curr_b_score = service_baselines.get(c_svc, 0)
                        curr_b_total = service_totals.get(c_svc, 0)
                        
                        b_ratio = curr_b_score / curr_b_total if curr_b_total > 0 else -1
                        c_ratio = c_score / c_total if c_total > 0 else 0
                        
                        if c_ratio > b_ratio:
                            service_baselines[c_svc] = c_score
                            service_totals[c_svc] = c_total
                    
                    if IS_DEBUG_MODE: log_func(f"[Evo-Debug] Forced Baselines: {service_baselines}")

                # FIX: Explicit Pruning BEFORE Evolution
                
                # FIX: Explicit Pruning BEFORE Evolution
                # Ensure we strictly respect the limits (60 for General, 12 for others) before starting Evolution.
                # This clears out any "overflow" from previous runs or merges.
                if not is_closing and is_service_active:

                     try:
                         log_func("[Check] Принудительная очистка слабых стратегий перед Эволюцией...")
                         services_to_prune = ["general", "youtube", "discord"] # Removed whatsapp, telegram
                         
                         for svc_p in services_to_prune:
                             if svc_p == "discord": lim = 99
                             else: lim = 36 if svc_p == "general" else 12  # FIX: Reduced from 60
                             p_path = os.path.join(base_dir, "strat", f"{svc_p}.json")
                             
                             if os.path.exists(p_path):
                                 p_data = load_json_robust(p_path, {})
                                 p_list = []
                                 if isinstance(p_data, dict) and "strategies" in p_data:
                                     p_list = p_data["strategies"]
                                 elif isinstance(p_data, list): 
                                     p_list = p_data
                                 
                                 if len(p_list) > lim:
                                     # Sort by score if available in runtime cache, otherwise trust file order (usually sorted)
                                     # BUT: File might be unsorted if manually edited.
                                     # Let's try to sort using known scores first.
                                     
                                     scored_prune = []
                                     for s in p_list:
                                         s_name = s.get("name", "")
                                         # Try specific service score first, then generic
                                         sc = active_scores_runtime.get((svc_p, s_name), 0)
                                         if sc == 0 and svc_p == "general": sc = state.get("general_score", 0) # Fallback? No, that's global.
                                         
                                         # If we have NO score, we must assume it's valid/unchecked/or just trust file order?
                                         # If we prune strictly, we might kill unchecked ones.
                                         # RULE: "Delete only after Full Check". 
                                         # But user said: "Strategies remaining > 60 ALTHOUGH Check passed".
                                         # So we assume Check Phase populated scores or at least ordered them.
                                         scored_prune.append((sc, s))
                                     
                                     # Sort DESC
                                     # Stable sort to preserve file order for ties
                                     scored_prune.sort(key=lambda x: x[0], reverse=True)
                                     
                                     # Keep Top N
                                     kept_strategies = [x[1] for x in scored_prune[:lim]]
                                     
                                     # Save back
                                     save_json_safe(p_path, {"version": CURRENT_VERSION, "strategies": kept_strategies})
                                     log_func(f"[Pruner] {svc_p}: Оставлено {len(kept_strategies)} лучших стратегий (было {len(p_list)}).")
                                     
                     except Exception as e:
                         log_func(f"[Pruner] Ошибка очистки: {e}")

                # Re-open executor for Phase 3 (using if True to match indent level 28 not needed anymore)
                with concurrent.futures.ThreadPoolExecutor(max_workers=STRATEGY_THREADS) as executor:
                    # --- PHASE 3: EVOLUTION (3 STAGES) ---
                    # Reduced percentages: 60% -> 40% -> 20%
                    stages = [0.6, 0.4, 0.2]
                
                    
                    # DEBUG: POPUP REMOVED
                    start_stage = state.get("evolution_stage", 0)
                    if IS_EVO_MODE:
                         # Always force restart evolution sequence in --evo mode
                         # This fixes issue where --fresh might fail to delete state file or user wants to re-run
                         if state.get("completed", False) or start_stage > 0:
                             log_func("[Check] Режим --evo: Принудительный сброс этапа эволюции на 0.")
                             start_stage = 0
                             state["completed"] = False
                             state["evolution_stage"] = 0 # Force save to state immediately?
                             save_state()

                    
                    # Если все этапы уже завершены, пропускаем блок эволюции
                    # If all stages already completed, skip evolution block
                    # FIX: Also skip if completed=True (evolution_stage was reset to 0 on completion)
                    if start_stage >= len(stages) or state.get("completed", False):
                        if IS_DEBUG_MODE: log_func(f"[StrategyChecker-Debug] Все этапы эволюции завершены, пропуск блока.")
                    else:
                        if start_stage > 0:
                            log_func(f"[Check] Восстановление эволюции с этапа {start_stage+1}/3...")
                        
                        
                        for stage_idx, percentage in enumerate(stages):
                            prefix = f"[Evo-{stage_idx+1}]"
                            if stage_idx < start_stage: 
                                if IS_DEBUG_CLI: log_func(f"[Check-Debug] Пропуск этапа {stage_idx} (Target: {start_stage})")
                                continue
                            if not is_service_active or is_closing: break
                            
                            # DEBUG TRACE

                            
                            # Сохраняем текущий этап в начале
                            state["evolution_stage"] = stage_idx
                            save_state()
                            
                            # 1. Gather Strategies from Files (Freshly Sorted)
                            strategies_to_evolve = []
                            
                            # === КОНСТАНТЫ ФИЛЬТРАЦИИ ===
                            # Минимальный порог качества: 20% от общего количества доменов
                            THRESHOLD_PERCENT = 0.20
                            
                            # Динамический подсчет доменов из list/*.txt файлов
                            def count_domains_in_file(filename):
                                """Считает количество непустых строк в файле"""
                                try:
                                    path = os.path.join(base_dir, "list", filename)
                                    if os.path.exists(path):
                                        with open(path, "r", encoding="utf-8") as f:
                                            return len([line for line in f if line.strip() and not line.strip().startswith("#")])
                                except:
                                    pass
                                return 0
            
                            DOMAIN_COUNTS = {
                                "general": count_domains_in_file("rkn.txt") or 100,  # fallback to 100
                                "youtube": count_domains_in_file("youtube.txt") or 16,
                                "discord": count_domains_in_file("discord.txt") or 23,
                                "whatsapp": count_domains_in_file("whatsapp.txt") or 3,
                                "telegram": count_domains_in_file("telegram.txt") or 10
                            }
                            
                            if True:  # Debug
                                thresholds = {k: int(v * THRESHOLD_PERCENT) for k, v in DOMAIN_COUNTS.items()}
                                # log_func(f"[Evo-Init] Пороги качества (20%): {thresholds}")
                            
                            try:
                                # === VALIDATION: --evo требует результаты Checker ===
                                if IS_EVO_MODE and not state.get("checks_completed", False):
                                    log_func("======================================================")
                                    log_func("[Evo-Error] Режим --evo требует результаты Checker!")
                                    log_func("[Evo-Error] Запустите Nova БЕЗ флага --evo для получения")
                                    log_func("[Evo-Error] результатов из Checker.")
                                    log_func("======================================================")
                                    is_scanning = False
                                    break
                                
                                # === UNIFIED LOGIC: Одна логика для всех режимов ===
                                # Этап 1: 60%, Этап 2: 40%, Этап 3: 20% (от лимита)
                                percentage = stages[stage_idx] if stage_idx < len(stages) else 0.2
                                
                                # Загружаем strategies.json для доступа к Current
                                d = load_json_robust(strat_path, {})
                                if not isinstance(d, dict): d = {}
                                
                                # === ЗАГРУЗКА SCORES ИЗ temp/strategy_scores.json ===
                                strategy_scores = {}  # {(service, name): score}
                                try:
                                    scores_path = os.path.join(base_dir, "temp", "strategy_scores.json")
                                    # log_func(f"[Evo-Scores-Debug] Проверка файла: {scores_path}")
                                    # log_func(f"[Evo-Scores-Debug] Файл существует: {os.path.exists(scores_path)}")
                                    
                                    if os.path.exists(scores_path):
                                        scores_data = load_json_robust(scores_path, {})
                                        # log_func(f"[Evo-Scores-Debug] Загружено из файла: {type(scores_data)}, keys: {list(scores_data.keys()) if isinstance(scores_data, dict) else 'N/A'}")
                                        
                                        for svc_name, strategies in scores_data.items():
                                            for strat_name, info in strategies.items():
                                                if isinstance(info, dict) and "score" in info:
                                                     strategy_scores[(svc_name, strat_name)] = info["score"]
                                        # if True: log_func(f"[Evo-Scores] Загружено {len(strategy_scores)} результатов из strategy_scores.json")
                                        
                                        # Debug: Show what was loaded per service
                                        # Debug: Show what was loaded per service
                                        # if True:
                                        #    for svc_debug in ["general", "youtube", "discord", "whatsapp"]:
                                        #        pass
                                    else:
                                        log_func(f"[Evo-Scores-Warning] Файл {scores_path} не найден! Scores не загружены.")
                                except Exception as e:
                                    log_func(f"[Evo-Scores] Ошибка загрузки scores: {e}")
                                
                                
                                # 1. General: Текущая + из general.json
                                if "general" in d and isinstance(d["general"], list):
                                     strategies_to_evolve.append(({
                                         "name": "Current General",
                                         "args": d["general"]
                                     }, "general"))
                                     
                                gen_path = os.path.join(base_dir, "strat", "general.json")
                                if os.path.exists(gen_path):
                                    gen_data = load_json_robust(gen_path, {})
                                    gen_list = []
                                    if isinstance(gen_data, dict) and "strategies" in gen_data:
                                        gen_list = gen_data["strategies"]
                                    elif isinstance(gen_data, list):
                                        gen_list = gen_data
                                    
                                    # FIX: Файл уже отсортирован после Checker (TOP->WORST). Берем TOP N.
                                    # Фильтруем по last_score (минимум 20/100 для General)
                                    max_general = 36
                                    count = int(max_general * percentage)
                                    if count < 1: count = 1
                                    
                                    # FIX: Фильтруем по score из strategy_scores.json
                                    min_score_general = int(DOMAIN_COUNTS["general"] * THRESHOLD_PERCENT)
                                    filtered_general = 0  # Debug counter
                                    for s in gen_list:
                                        if isinstance(s, dict) and "args" in s:
                                            name = s.get("name", "")
                                            score = strategy_scores.get(("general", name), 0)
                                            
                                            # Debug: Log filtering decisions
                                            if score == 0 and name:
                                                if filtered_general < 3: pass

                                                filtered_general += 1
                                            elif score < min_score_general:
                                                if filtered_general < 3: pass

                                                filtered_general += 1
                                            else:
                                                # Passed filter
                                                strategies_to_evolve.append((s, "general"))
                                                if len([x for x in strategies_to_evolve if x[1] == "general"]) >= count:
                                                    break
                                    
                                    if filtered_general > 0 and False: # Silence
                                        taken = len([x for x in strategies_to_evolve if x[1] == "general"])

                                    
                                    # 2. YouTube: из youtube.json
                                    max_special = 12
                                    special_count = int(max_special * percentage)
                                    if special_count < 1: special_count = 1
                                    
                                    for svc in ["youtube"]:
                                        # FIX: Inject Current Strategy first
                                        if svc in d and isinstance(d[svc], list):
                                             strategies_to_evolve.append(({
                                                 "name": f"Current {svc}",
                                                 "args": d[svc]
                                             }, svc))
                                        
                                        sp = os.path.join(base_dir, "strat", f"{svc}.json")
                                        if os.path.exists(sp):
                                            s_spec_data = load_json_robust(sp, {})
                                            s_spec_list = []
                                            
                                            if isinstance(s_spec_data, dict) and "strategies" in s_spec_data:
                                                s_spec_list = s_spec_data["strategies"]
                                            elif isinstance(s_spec_data, list):
                                                s_spec_list = s_spec_data
                                            
                                            # FIX: Файл уже отсортирован после Checker. Берем TOP N.
                                            # Фильтруем по score из strategy_scores.json
                                            min_score = int(DOMAIN_COUNTS.get(svc, 10) * THRESHOLD_PERCENT)
                                            
                                            # Unique filter с фильтрацией по score
                                            unique_spec = []
                                            seen_args = set()
                                            filtered_count = 0  # Debug counter
                                            for s in s_spec_list:
                                                if isinstance(s, dict) and "args" in s:
                                                    name = s.get("name", "")
                                                    score = strategy_scores.get((svc, name), 0)
                                                    
                                                    # Debug: Log filtering decisions
                                                    if score == 0 and name:
                                                        if filtered_count < 3: pass # Limit spam

                                                        filtered_count += 1
                                                    
                                                    if score < min_score:
                                                        if score > 0 and filtered_count < 3:
                                                            pass

                                                        filtered_count += 1
                                                        continue  # Пропускаем слабые
                                                    
                                                    a = s.get("args", "")
                                                    if a:
                                                        a_key = str(a)
                                                        if a_key not in seen_args:
                                                            seen_args.add(a_key)
                                                            unique_spec.append(s)
                                                            
                                                    if len(unique_spec) >= special_count:
                                                        break
                                            
                                            if filtered_count > 0:
                                                pass

                                            
                                            for s in unique_spec[:special_count]:
                                                strategies_to_evolve.append((s, svc))
                                            
                                            # \u0421\u0442\u0430\u0442\u0438\u0441\u0442\u0438\u043a\u0430 \u0444\u0438\u043b\u044c\u0442\u0440\u0430\u0446\u0438\u0438
                                            filtered_out = len(s_spec_list) - len(unique_spec)
                                            if filtered_out > 0:
                                                pass

                                
                            except Exception as e:
                                log_func(f"[StrategyChecker-Debug] Ошибка подготовки эволюции: {e}")
                                pass

                            # 2. Mutate (дозаполнение перенесено ниже)
                            # === ДОЗАПОЛНЕНИЕ: Гарантируем минимальное количество стратегий ===
                            # Вынесено ПОСЛЕ обоих блоков (EVO и Normal) чтобы работало всегда
                            try:
                                # Загружаем strategies.json для доступа к Current
                                d_fill = load_json_robust(strat_path, {})
                                if not isinstance(d_fill, dict): d_fill = {}
                                
                                # Загружаем learning_data для мутаций
                                learning_data_prefill = load_learning_data()
                                
                                # Определяем целевые количества для текущего этапа
                                targets = {
                                    "general": int(36 * percentage),  # FIX: Снижено с 60 до 36
                                    "youtube": int(12 * percentage)
                                }
                                
                                # Подсчитываем текущее количество для каждого сервиса
                                current_counts = {}
                                for _, svc in strategies_to_evolve:
                                    current_counts[svc] = current_counts.get(svc, 0) + 1
                                
                                # if True: log_func(f"[Evo-Fill] Текущие: {current_counts}. Целевые: {targets}")
                                
                                # Дозаполняем
                                for svc, target in targets.items():
                                    current = current_counts.get(svc, 0)
                                    deficit = target - current
                                    
                                    if deficit > 0 and svc in d_fill and isinstance(d_fill[svc], list):
                                        # Генерируем мутации Current стратегии
                                        current_args = d_fill[svc]
                                        # log_func(f"[Evo-Fill] {svc}: {current}/{target}. Генерирую {deficit} мутаций Current.")
                                        
                                        for i in range(deficit):
                                            mutations = mutate_strategy(current_args, bin_files, count=1, learning_data=learning_data_prefill)
                                            if mutations:
                                                m_args = mutations[0]
                                                # Generate unique name
                                                h_obj = hashlib.md5(str(m_args).encode())
                                                h_str = h_obj.hexdigest()[:3].upper()
                                                # FIX: Standard naming without 'Fill_' prefix
                                                # Use service name + hash, similar to other mutations
                                                new_name = f"{svc}_M{h_str}" 
                                                strategies_to_evolve.append(({"name": new_name, "args": m_args}, svc))
                            except Exception as e:
                                log_func(f"[Evo-Fill] Ошибка дозаполнения: {e}")
                                pass
                            
                            # Итоговая статистика
                            final_counts = {}
                            for _, svc in strategies_to_evolve:
                                final_counts[svc] = final_counts.get(svc, 0) + 1
                            # log_func(f"[Evo] Собрано стратегий: {final_counts}")
                            log_func(f"[Evo] Подготовка к эволюции... собрано {len(strategies_to_evolve)} стратегий.")
                            
                            # if True: log_func(f"[Trace] Gathering done (after fill). Strategies found: {len(strategies_to_evolve)}")
                            evo_tasks = []
                            learning_data = load_learning_data()  # Загружаем статистику один раз
                            
                            # Filter out strategies for perfect services (100% success)
                            strategies_to_evolve = [x for x in strategies_to_evolve if x[1] not in perfect_services]

                            reset_domain_offset_counter()  # Сбрасываем счётчик offset для диверсификации
                            
                            for strat, svc in strategies_to_evolve:
                                # Skip blocked services
                                if svc in blocked_services:
                                     # FIX: Allow blocked services ONE chance in Evo if it's the first stage?
                                     # Or just log it.

                                     continue
                                
                                # Select domains
                                target_doms = domains_for_general
                                if svc != "general":
                                    # Load list
                                    l_path = os.path.join(base_dir, "list", f"{svc}.txt")
                                    t_doms = []
                                    if os.path.exists(l_path):
                                         try:
                                             # FIX: Filter comments
                                             with open(l_path, "r") as f: 
                                                 t_doms = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
                                         except: pass
                                    if t_doms: target_doms = t_doms
                                
                                # Генерируем мутации с учётом статистики обучения
                                # FIX: Строго по 1 мутации на стратегию, чтобы не раздувать очередь (10 стратегий -> 10 задач)
                                mutations = mutate_strategy(strat['args'], bin_files, count=1, learning_data=learning_data)
                                
                                for i, m_args in enumerate(mutations):
                                    base_name = strat['name'].split('_M')[0] # Reset suffix
                                    # Generate distinct 3-char suffix from args hash
                                    h_obj = hashlib.md5(str(m_args).encode())
                                    h_str = h_obj.hexdigest()[:3].upper()
                                    new_name = f"{base_name}_M{h_str}"
                                    
                                    # Применяем диверсификацию доменов
                                    diversified_doms = get_offset_domains(target_doms)
                                    
                                    evo_tasks.append((svc, {"name": new_name, "args": m_args}, diversified_doms, ""))

                            log_func(f"{prefix} Сгенерировано {len(evo_tasks)} задач.")

                            if True: pass # Force log


                            if not strategies_to_evolve:
                                if IS_DEBUG_MODE or True: log_func(f"[Evo-{stage_idx+1}] Нет стратегий для эволюции. Пропуск этапа.")
                                continue # Continue to next stage instead of breaking!
                            
                            # === Evolution Stage Message ===
                            stage_msg = f"[Evo] Эволюция стратегий. Этап {stage_idx+1}."
                            progress_manager.log_message(stage_msg)
                        
                            # 3. Check Loop (REWRITTEN FOR INDENTATION SAFETY)
                            evo_results = []
                            active_evo = {}

                            
                            # === Interleave Tasks Logic ===
                            # Group by service first
                            tasks_by_svc = {}
                            for t in evo_tasks:
                                s_key = t[0]
                                if s_key not in tasks_by_svc: tasks_by_svc[s_key] = []
                                tasks_by_svc[s_key].append(t)
                            
                            # Round-robin mix
                            q_evo = []
                            max_len = 0
                            for k in tasks_by_svc:
                                if len(tasks_by_svc[k]) > max_len: max_len = len(tasks_by_svc[k])
                                
                            for i in range(max_len):
                                for k in tasks_by_svc:
                                    if i < len(tasks_by_svc[k]):
                                        q_evo.append(tasks_by_svc[k][i])
                            
                            better_found = False

                            while (q_evo or active_evo) and is_service_active and not is_closing:
                                while len(active_evo) < STRATEGY_THREADS and q_evo and is_service_active and not is_closing:
                                    t = q_evo.pop(0)
                                    
                                    # Double-check service status before creating UI line (race condition protection)
                                    if not is_service_active or is_closing:
                                        q_evo.insert(0, t)  # Put task back
                                        break
                                    
                                    svc, strat, doms, _ = t
                                    line_id = id(t)
                                    
                                    # Factory for ProgressTracker (Evolution Phase)
                                    def make_evo_tracker(lid, s_name, s_svc, total, pfx=prefix):
                                        state = {'score': 0, 'active': 0, 'checked': 0, 'created': False}
                                        lock = threading.Lock()
                                        def tracker(event, **kwargs):
                                            nonlocal state
                                            update_needed = False
                                            with lock:
                                                # STOP CHECK: Prevent updates after service stop
                                                if not is_service_active and not is_closing:
                                                    return
                                                if event == 'start': 
                                                    # Lazy Creation
                                                    if not state['created']:
                                                        bar = get_progress_bar(0, 0, total, width=20)
                                                        imsg = f"{pfx} {s_name} ({s_svc}) {bar} 0/0"
                                                        progress_manager.create_line(lid, imsg)
                                                        state['created'] = True

                                                    state['active'] += 1
                                                    update_needed = True
                                                elif event == 'finish':
                                                    if state['active'] > 0: state['active'] -= 1
                                                    state['checked'] += 1
                                                    if kwargs.get('success'): state['score'] += 1
                                                    update_needed = True
                                            if update_needed and state['created']:
                                                gray_count = state['checked'] + state['active'] - state['score']
                                                bar = get_progress_bar(state['score'], gray_count, total, width=20)
                                                
                                                # FIX: Checkmark inside tracker to guarantee visibility
                                                suffix = ""
                                                if state['checked'] == total: suffix = " ✓"
                                                
                                                msg = f"{pfx} {s_name} ({s_svc}) {bar} {state['score']}/{state['checked']}{suffix}"
                                                progress_manager.update_line(lid, msg, is_final=False)
                                        return tracker

                                    tracker_func = make_evo_tracker(line_id, strat['name'], svc, len(doms))
                                    
                                    fut = executor.submit(check_strat_threaded, strat["args"], doms, progress_tracker=tracker_func, run_id=SERVICE_RUN_ID)
                                    active_evo[fut] = (t, line_id)
                                
                                if not active_evo: break
                                done, _ = concurrent.futures.wait(active_evo.keys(), return_when=concurrent.futures.FIRST_COMPLETED)
                                
                                for f in done:
                                    task_info = active_evo.pop(f)
                                    t, line_id = task_info
                                    svc_t, strat_t, doms_t, _ = t  # Extract from task tuple
                                    try:
                                        sc = f.result()
                                        
                                        # Perfect Score Check Phase 3
                                        if sc is not None and sc >= len(doms_t) and len(doms_t) > 0:
                                            if svc_t not in perfect_services:
                                                log_func(f"{prefix} Найдена лучшая стратегия для {svc_t} (100%).")
                                                perfect_services.add(svc_t)

                                        if sc is None:
                                            # Если остановка - молчим, иначе - ошибка
                                            if not (is_closing or not is_service_active):
                                                progress_manager.update_line(line_id, f"{prefix} {strat_t['name']} ({svc_t}): Ошибка", is_final=True)
                                            continue
                                        
                                        # CACHE SCORE
                                        # CACHE SCORE (Inlined)
                                        if svc_t not in active_scores_runtime: active_scores_runtime[svc_t] = {}
                                        active_scores_runtime[svc_t][strat_t['name']] = sc
                                        
                                        # === UPDATE LEARNING STATS ===
                                        try:
                                            # Извлекаем bin-файлы из аргументов
                                            bin_files_used = [a.split("=")[1] for a in strat_t.get("args", []) 
                                                             if isinstance(a, str) and ".bin" in a]
                                            update_learning_stats(
                                                strat_t.get("args", []), 
                                                sc, 
                                                len(doms_t), 
                                                service=svc_t,
                                                bin_files_used=bin_files_used
                                            )
                                        except: pass
                                        
                                        # Add result to list
                                        evo_results.append((sc, strat_t, svc_t, len(doms_t)))
                                        
                                        # UI Update
                                        total_cnt = len(doms_t)
                                        gray_count = total_cnt - sc
                                        bar = get_progress_bar(sc, gray_count, total_cnt, width=20)
                                        final_msg = f"{prefix} {strat_t['name']} ({svc_t}) {bar} {sc}/{total_cnt} ✓"
                                        progress_manager.update_line(line_id, final_msg, is_final=True)
                                        
                                        bl_score = service_baselines.get(svc_t, 0)
                                        bl_total = service_totals.get(svc_t, 1)
                                        bl_ratio = bl_score / bl_total if bl_total > 0 else -1
                                        curr_ratio = sc / total_cnt if total_cnt > 0 else 0
                                        
                                        if curr_ratio > bl_ratio:
                                             log_func(f"{prefix} >>> Улучшение для {svc_t}: {sc}/{total_cnt} (было {bl_score}/{bl_total}) -> {strat_t['name']}")
                                             service_baselines[svc_t] = sc
                                             service_totals[svc_t] = total_cnt
                                             better_found = True
                                             
                                             # FIX: Persist score to state for resume after stop
                                             if svc_t == "general":
                                                 state["general_score"] = sc
                                                 state["general_total"] = total_cnt
                                             else:
                                                 state[f"{svc_t}_score"] = sc
                                                 state[f"{svc_t}_total"] = total_cnt
                                             save_state()
                                             
                                             # HOT SWAP: Only apply if this is REALLY better than current winws strategy
                                             # Load current strategy from strategies.json to compare
                                             try:
                                                 strat_main_path = os.path.join(base_dir, "strat", "strategies.json")
                                                 current_config = load_json_robust(strat_main_path, {})
                                                 current_args = current_config.get(svc_t if svc_t != "general" else "general", [])
                                                 
                                                 # Only trigger Hot Swap if args are actually different
                                                 if strat_t["args"] != current_args:
                                                     update_active_config_immediate(svc_t, strat_t["args"], f"{prefix} Применена лучшая стратегия {strat_t['name']}")
                                             except Exception as hs_err:
                                                 if IS_DEBUG_MODE: log_func(f"[Evo-HotSwap] Error: {hs_err}")
                                        
                                    except Exception as e:
                                        log_func(f"[Evo-Error] Loop Error: {e}")

                            # Cancel futures and log stop message
                            
                            # 4. Sort Phase (Save results even if stopping - preservation of knowledge)
                            if evo_results:
                                 sort_and_distribute_results(evo_results, score_cache=active_scores_runtime)
                                 if not is_service_active or is_closing:
                                     log_func(f"[Check] Частичные результаты этапа сохранены.")
                            
                            # Save Progress (Only advance stage if NOT closing)
                            if is_service_active and not is_closing:
                                state["evolution_stage"] = stage_idx + 1
                                save_state()
                            
                            # Exit for loop if stopping
                            if not is_service_active or is_closing:
                                break
                            
                            

                            # 5. End of stage log (Hot Swap already called inside loop if needed)
                            if better_found and is_service_active and not is_closing:
                                log_func(f"[Check] Эволюция нашла улучшения на этапе {stage_idx + 1}.")


                    # --- FINAL COMPLETION CHECK ---
                    # Logic moved OUTSIDE the "stages" loop but inside "if is_service_active"
                    # Check if we are truly done (either skipped all because finished, or finished just now)
                    
                    # Reload stage to be sure
                    current_stage_check = state.get("evolution_stage", 0)
                    
                    if is_service_active and not is_closing and current_stage_check >= len(stages):
                        # FINISH
                        log_func("[Check] Подбор полностью завершен.")
                        
                        # Sync keys to match reading logic
                        state["last_check_time"] = time.time()
                        state["last_full_check_time"] = time.time() 
                        state["completed"] = True
                        state["evolution_stage"] = 0
                        state["last_checked_ip"] = current_ip  # NEW: Save IP for restart detection
                        state["app_version"] = CURRENT_VERSION # FIX: Ensure version persists
                        save_state()
                        
                        # Update check timestamp for DomainCleaner cooldown
                        last_strategy_check_time = time.time()
                        
                        # === FINAL PRUNING: Enforce strict limits after Evolution ===
                        try:
                            log_func("[Check] Финальная очистка стратегий...")
                            for svc_final in ["general", "youtube"]: # Removed whatsapp, telegram
                                lim_final = 36 if svc_final == "general" else 12
                                p_final = os.path.join(base_dir, "strat", f"{svc_final}.json")
                                
                                if os.path.exists(p_final):
                                    data_final = load_json_robust(p_final, {})
                                    list_final = []
                                    if isinstance(data_final, dict) and "strategies" in data_final:
                                        list_final = data_final["strategies"]
                                    elif isinstance(data_final, list):
                                        list_final = data_final
                                    
                                    if len(list_final) > lim_final:
                                        # Sort by score from runtime cache
                                        scored_final = []
                                        for s_f in list_final:
                                            s_n = s_f.get("name", "")
                                            sc_f = active_scores_runtime.get((svc_final, s_n), 0)
                                            scored_final.append((sc_f, s_f))
                                        
                                        scored_final.sort(key=lambda x: x[0], reverse=True)
                                        kept_final = [x[1] for x in scored_final[:lim_final]]
                                        
                                        save_json_safe(p_final, {"version": CURRENT_VERSION, "strategies": kept_final})
                                        log_func(f"[Pruner-Final] {svc_final}: {len(kept_final)} (было {len(list_final)})")
                        except Exception as prune_err:
                            log_func(f"[Pruner-Final] Ошибка: {prune_err}")
                        
                        log_func("[Check] Очистка завершена.")
                        
                        # CRITICAL FIX: Stop the outer "while is_scanning" loop
                        # This 'break' leaves the ThreadPoolExecutor context
                        # We also need to flag the outer variable
                        is_scanning = False 
                        all_tasks = [] # Ensure no re-entry from outer loop check?
                        break


                # End of block
                # FIX: Do NOT reset is_scanning here - Evolution phase may not be started yet!
                # is_scanning = False  # REMOVED: Too early, Evolution still needs this flag
                
                # FIX: Clear progress on successful full completion
                # But only if we actually did something?
                if IS_DEBUG_CLI and (task_queue or active_futures):
                    log_func("[Check-Debug] Removed progress file (finished round one).")
                # For now, let's keep the progress file - it serves as "Temporary knowledge" 
                # that expires in 4 hours. No explicit delete needed, handled by timestamp check.
                
                log_func("[Check] Цикл проверки завершен.")
                
                # Prevent Busy-Loop in Idle: Sleep before next checking cycle
                # If urgent checks appear, they wake via matcher_wakeup_event or queue in next loop start
                time.sleep(30)

            except BaseException as e:
                try:
                     import traceback
                     with open(os.path.join(get_base_dir(), "temp", "debug_worker.log"), "a", encoding="utf-8") as f:
                         f.write(f"{time.strftime('%H:%M:%S')} CRASH: {e}\n{traceback.format_exc()}\n")
                except: pass
                
                if "aborted_by_service" in str(e) or "Остановка сервиса" in str(e) or not is_service_active:
                     pass
                else:
                     log_func(f"[Check] Ошибка рабочего цикла: {e}")
                
                time.sleep(5)
                    


    def log_previous_session_results(log_func):
        """Выводит результаты предыдущей сессии проверки стратегий."""
        try:
            state_path = os.path.join(get_base_dir(), "temp", "checker_state.json")
            state = load_json_robust(state_path)
            
            if state:
                gen_score = state.get("general_score", -1)
                best = state.get("best_strategies", [])
                
                msg = []
                if gen_score > 0: msg.append(f"General Score: {gen_score}")
                if best: msg.append(f"Найдено стратегий: {len(best)}")
                
                if msg:
                    log_func(f"[Init] Результаты прошлой сессии: {', '.join(msg)}")
        except: pass

    def periodic_exclude_checker_worker(log_func):
        global is_closing, is_vpn_active, is_scanning, restart_requested_event
        EXCLUDE_CHECK_STATE_FILE = os.path.join(get_base_dir(), "temp", "exclude_check_state.json")
        time.sleep(60) 
        
        while True:
            try:
                if is_closing or is_vpn_active or not is_service_active:
                    time.sleep(5)
                    continue

                # ... (rest of the IP change and time check logic remains the same)
                last_run = 0
                if os.path.exists(EXCLUDE_CHECK_STATE_FILE):
                    with open(EXCLUDE_CHECK_STATE_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        last_run = data.get("last_run", 0)
                
                if time.time() - last_run < 86400: # Check once a day
                    time.sleep(60)
                    continue

                log_func("[Audit] Запуск периодической проверки доменов из exclude_auto...")
                is_scanning = True
                audit_running_event.set() # Signal Priority
                
                path = os.path.join(get_base_dir(), "temp", "exclude_auto.txt")
                if not os.path.exists(path):
                    is_scanning = False
                    continue
                    
                with open(path, "r", encoding="utf-8") as f:
                    domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                
                domains_to_remove = []
                
                def audit_task(domain):
                    # Priority Task: Uses Semaphore & Rate Limiter
                    BACKGROUND_RATE_LIMITER.acquire()
                    port = audit_ports_queue.get()
                    try:
                        with BACKGROUND_SEM:
                             status, _ = detect_throttled_load(domain, port)
                             return domain, status != "ok"
                    finally:
                        audit_ports_queue.put(port)

                futures = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                    for d in domains:
                        if is_closing: break
                        futures.append(executor.submit(audit_task, d))
                    
                    for future in concurrent.futures.as_completed(futures):
                        d, has_problem = future.result()
                        if has_problem:
                             log_func(f"[Audit] {d} перестал быть доступен напрямую. Будет удален из исключений.")
                             domains_to_remove.append(d)

                is_scanning = False

                if domains_to_remove:
                    with exclude_file_lock:
                        new_content = [d for d in domains if d not in domains_to_remove]
                        with open(path, "w", encoding="utf-8") as f:
                            f.write("\n".join(new_content))
                    
                    for d in domains_to_remove:
                        auto_excluded_domains.discard(d)
                        record_domain_visit(d)
                    
                    log_func(f"[Audit] Удалено {len(domains_to_remove)} недоступных доменов из exclude_auto.")
                    smart_update_general(domains_to_remove)
                    log_func(f"[Audit] Добавлено {len(domains_to_remove)} доменов в general.txt для перепроверки.")
                else:
                    log_func("[Audit] Проверка завершена. Изменений нет.")
                
                save_json_safe(EXCLUDE_CHECK_STATE_FILE, {"last_run": time.time()})
                    
            except Exception as e:
                log_func(f"[Audit] Ошибка: {e}")
                is_scanning = False
            finally:
                audit_running_event.clear() # Release Priority
            
            time.sleep(60)

    # ================= УПРАВЛЕНИЕ HARD_X СТРАТЕГИЯМИ В LIST/ =================

    def load_hard_strategy_domains(hard_name, log_func=None):
        """Загружает список доменов для hard_X стратегии из list/hard_X.txt."""
        domains = set()
        base_dir = get_base_dir()
        hard_file = os.path.join(base_dir, "list", f"{hard_name}.txt")
        
        if os.path.exists(hard_file):
            try:
                with open(hard_file, "r", encoding="utf-8") as f:
                    for line in f:
                        d = line.split('#')[0].strip().lower()
                        if d:
                            domains.add(d)
            except Exception as e:
                if log_func:
                    log_func(f"[HardList] Ошибка чтения {hard_file}: {e}")
        
        return domains

    def save_hard_strategy_domains(hard_name, domains, log_func=None):
        """Сохраняет список доменов для hard_X стратегии в list/hard_X.txt."""
        base_dir = get_base_dir()
        hard_file = os.path.join(base_dir, "list", f"{hard_name}.txt")
        
        try:
            os.makedirs(os.path.dirname(hard_file), exist_ok=True)
            with open(hard_file, "w", encoding="utf-8") as f:
                for d in sorted(domains):
                    if d:
                        f.write(f"{d}\n")
            if log_func:
                log_func(f"[HardList] {hard_name}.txt сохранен ({len(domains)} доменов).")
        except Exception as e:
            if log_func:
                log_func(f"[HardList] Ошибка при сохранении {hard_file}: {e}")

    def load_all_hard_domains():
        """Загружает все домены из всех hard_X.txt файлов."""
        all_domains = {}
        for i in range(1, 13):
            hard_name = f"hard_{i}"
            domains = load_hard_strategy_domains(hard_name)
            if domains:
                all_domains[hard_name] = domains
        return all_domains

    def migrate_hard_domains(old_hard_name, new_hard_name, log_func=None):
        """Мигрирует домены из одной hard_X стратегии в другую.
        Например, если hard_5 переименована в hard_7."""
        base_dir = get_base_dir()
        
        # Загружаем домены старой стратегии
        domains = load_hard_strategy_domains(old_hard_name)
        
        if not domains:
            return
        
        # Загружаем существующие домены новой стратегии (если есть)
        new_domains = load_hard_strategy_domains(new_hard_name)
        new_domains.update(domains)
        
        # Сохраняем в новое место
        save_hard_strategy_domains(new_hard_name, new_domains, log_func)
        
        # Удаляем старый файл
        old_file = os.path.join(base_dir, "list", f"{old_hard_name}.txt")
        try:
            if os.path.exists(old_file):
                os.remove(old_file)
                if log_func:
                    log_func(f"[HardList] Домены из {old_hard_name} перемещены в {new_hard_name}.")
        except Exception as e:
            if log_func:
                log_func(f"[HardList] Ошибка при удалении {old_file}: {e}")

    def cleanup_hard_lists(log_func=None):
        """Удаляет пустые hard_X.txt файлы."""
        base_dir = get_base_dir()
        list_dir = os.path.join(base_dir, "list")
        
        removed_count = 0
        for i in range(1, 13):
            hard_file = os.path.join(list_dir, f"hard_{i}.txt")
            if os.path.exists(hard_file):
                try:
                    with open(hard_file, "r", encoding="utf-8") as f:
                        content = f.read()
                        domains = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith("#")]
                    
                    if not domains:
                        os.remove(hard_file)
                        removed_count += 1
                except: pass
        
        if log_func and removed_count > 0:
            log_func(f"[HardList] Удалено {removed_count} пустых файлов hard_X.txt.")

    # === НОВОЕ: Функции для работы с реестром замедленных доменов ===
    
    def load_throttled_registry():
        """Загружает реестр замедленных доменов из файла."""
        try:
            base_dir = get_base_dir()
            registry_path = os.path.join(base_dir, "temp", "throttled_registry.json")
            
            if os.path.exists(registry_path):
                with open(registry_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except: pass
        return {}

    def save_throttled_registry():
        """Сохраняет реестр замедленных доменов в файл."""
        try:
            base_dir = get_base_dir()
            registry_path = os.path.join(base_dir, "temp", "throttled_registry.json")
            
            with throttled_registry_lock:
                with open(registry_path, "w", encoding="utf-8") as f:
                    json.dump(throttled_domains_registry, f, indent=4)
        except: pass

    def mark_domain_as_throttled_registry(domain, throttle_type="unknown"):
        """Отмечает домен в реестре как замедленный с типом блокировки."""
        domain = domain.lower()
        with throttled_registry_lock:
            throttled_domains_registry[domain] = {
                "throttle_type": throttle_type,
                "timestamp": time.time(),
                "boost_strategy": None
            }
            save_throttled_registry()

    def mark_boost_strategy_for_domain(domain, boost_strategy):
        """Сохраняет найденную boost стратегию для домена."""
        domain = domain.lower()
        with throttled_registry_lock:
            if domain in throttled_domains_registry:
                throttled_domains_registry[domain]["boost_strategy"] = boost_strategy
                throttled_domains_registry[domain]["timestamp"] = time.time()
                save_throttled_registry()

    def get_boost_strategy_for_domain(domain):
        """Получает сохраненную boost стратегию для замедленного домена."""
        domain = domain.lower()
        with throttled_registry_lock:
            if domain in throttled_domains_registry:
                return throttled_domains_registry[domain].get("boost_strategy")
        return None

    def get_throttle_type_for_domain(domain):
        """Получает тип замедления для домена из реестра."""
        domain = domain.lower()
        with throttled_registry_lock:
            if domain in throttled_domains_registry:
                return throttled_domains_registry[domain].get("throttle_type", "unknown")
        return None

    def is_domain_in_throttled_registry(domain):
        """Проверяет, есть ли домен в реестре замедленных."""
        domain = domain.lower()
        with throttled_registry_lock:
            return domain in throttled_domains_registry



    def add_domain_to_hard_strategy(domain, hard_name, log_func=None):
        """Добавляет домен в определенную hard_X стратегию."""
        domain = domain.lower()
        domains = load_hard_strategy_domains(hard_name)
        
        if domain not in domains:
            domains.add(domain)
            save_hard_strategy_domains(hard_name, domains, log_func)
            return True
        return False

    def remove_domain_from_hard_strategy(domain, hard_name, log_func=None):
        """Удаляет домен из hard_X стратегии."""
        domain = domain.lower()
        domains = load_hard_strategy_domains(hard_name)
        
        if domain in domains:
            domains.discard(domain)
            save_hard_strategy_domains(hard_name, domains, log_func)
            return True
        return False

    def find_hard_strategy_for_domain(domain):
        """Находит, в какой hard_X стратегии находится домен."""
        domain = domain.lower()
        for i in range(1, 13):
            hard_name = f"hard_{i}"
            domains = load_hard_strategy_domains(hard_name)
            if domain in domains:
                return hard_name
        return None

    def add_to_auto_exclude(domain):
        domain = domain.lower()
        if is_garbage_domain(domain): return False
        if is_domain_excluded(domain): return False
        base_dir = get_base_dir()
        list_dir = os.path.join(base_dir, "list")
        auto_excluded_domains.add(domain)
        added_new = False
        try:
            path = os.path.join(base_dir, "temp", "exclude_auto.txt")
            with exclude_file_lock:
                if not os.path.exists(path):
                    with open(path, "w", encoding="utf-8") as f: pass
                with open(path, "r+", encoding="utf-8") as f:
                    content = f.read()
                    if domain not in {line.strip() for line in content.splitlines()}:
                        f.write(f"\n{domain}")
                        added_new = True
        except: pass

        try:
            if os.path.exists(list_dir):
                for filename in os.listdir(list_dir):
                    if not filename.endswith(".txt"): continue
                    if filename.lower().startswith("exclude"): continue 
                    file_path = os.path.join(list_dir, filename)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            lines = f.readlines()
                        new_lines = []
                        modified = False
                        for line in lines:
                            clean_line = line.split('#')[0].strip()
                            if clean_line == domain:
                                modified = True
                            else:
                                new_lines.append(line)
                        if modified:
                            with open(file_path, "w", encoding="utf-8") as f:
                                f.writelines(new_lines)
                            log_print(f"[Cleaner] {domain} удален из {filename}, т.к. доступен напрямую.")
                    except: pass
        except: pass
        return added_new

    # ================= НОВЫЕ ФУНКЦИИ (Hard Checker & Robust Check) =================

    # Состояние для отслеживания замедленных доменов
    throttled_domains = {}  # domain -> {"first_check": timestamp, "count": int}
    throttled_domains_lock = threading.Lock()
    THROTTLE_DETECTION_THRESHOLD = 3  # Количество проверок для подтверждения замедления
    THROTTLE_RECOVERY_TIME = 3600  # 1 час, после которого забываем о замедлении
    
    # === НОВОЕ: Реестр замедленных доменов для boost стратегий ===
    throttled_domains_registry = {}  # domain -> {"boost_strategy": name, "throttle_type": type, "timestamp": time}
    throttled_registry_lock = threading.RLock()
    
    # === НОВОЕ: Очередь экстренного анализа ===
    urgent_analysis_queue = queue.Queue()
    matcher_wakeup_event = threading.Event()
    
    class RobustHTTPSConnection(http.client.HTTPSConnection):
        """HTTPSConnection с поддержкой SO_REUSEADDR для быстрого повторного использования портов."""
        def connect(self):
            err = None
            # Пытаемся подключиться по всем адресам (IPv4/IPv6)
            for res in socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM):
                af, socktype, proto, canonname, sa = res
                sock = None
                try:
                    sock = socket.socket(af, socktype, proto)
                    # Включаем SO_REUSEADDR
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    
                    if self.source_address:
                        sock.bind(self.source_address)
                        
                    if self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                        sock.settimeout(self.timeout)
                        
                    sock.connect(sa)
                    self.sock = sock
                    break
                except Exception as _:
                    err = _
                    if sock is not None:
                        sock.close()
            
            if self.sock is None:
                raise err if err else socket.error("getaddrinfo returns an empty list")

            if self._tunnel_host:
                self._tunnel()
            
            self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)

    def detect_throttled_load(domain, port=0, priority=False):
        """
        Обнаруживает блокировку и возвращает точный статус.
        Возвращает (status, diagnostics), где status:
        - "ok":      Сайт доступен, проблем нет.
        - "blocked": Обнаружена блокировка/замедление DPI.
        - "error":   Сайт доступен, но вернул ошибку (HTTP 4xx/5xx, отказ в соединении).
        - "no_dns":  Домен не резолвится.
        """
        global last_strategy_check_time
        last_strategy_check_time = time.time()  # Update timestamp for DNS cleaner isolation
        
        try:
            # Используем DNSManager для разрешения домена.
            # check_cache=False заставляет выполнить свежую проверку, но результат все равно обновит кэш.
            # Используем burst_limiter, так как это активная проверка, а не фоновая очистка.
            ip, status = dns_manager.resolve(domain, dns_manager.burst_limiter, check_cache=True)
            if ip is None:
                return "no_dns", f"dns_manager_{status}"

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            try:
                context.set_alpn_protocols(['http/1.1'])
            except: pass
            
            source_addr = ("0.0.0.0", port) if port > 0 else None
            
            conn = RobustHTTPSConnection(
                domain, 443, timeout=5, context=context,
                source_address=source_addr
            )
            
            # Если приоритет высокий (экстренная разблокировка), игнорируем семафор
            if priority:
                conn.request("GET", "/", headers=BROWSER_HEADERS)
                resp = conn.getresponse()
            else:
                with background_connection_semaphore:
                    conn.request("GET", "/", headers=BROWSER_HEADERS)
                    resp = conn.getresponse()
            
            # Проверка HTTP статуса
            if resp.status >= 400:
                # Считываем часть тела для определения WAF/DDoS заглушек (Cloudflare, Qrator и т.д.)
                try:
                    chunk = resp.read(8192)
                    body_sample = chunk.decode('utf-8', errors='ignore').lower()
                except:
                    body_sample = ""
                
                conn.close()
                
                waf_sigs = ["cloudflare", "ddos-guard", "qrator", "just a moment", "checking your browser", "security check", "challenge-platform"]
                if any(s in body_sample for s in waf_sigs):
                    return "ok", f"waf_protection_{resp.status}"
                
                return "error", f"http_{resp.status}"
            
            accumulated = b''
            start_time = time.time()
            last_chunk_time = start_time
            MIN_SPEED = 512

            while True:
                try:
                    chunk = resp.read(4096)
                    
                    if not chunk:
                        conn.close()
                        return "ok", "ok"
                    
                    accumulated += chunk
                    current_time = time.time()
                    time_delta = current_time - last_chunk_time
                    
                    if time_delta > 0.01:
                        read_speed = len(chunk) / time_delta
                        if read_speed < MIN_SPEED and len(accumulated) > 1000:
                            conn.close()
                            return "blocked", f"slow_speed_{read_speed:.0f}"
                    
                    last_chunk_time = current_time
                    
                    if 16000 < len(accumulated) < 20000:
                        try:
                            next_chunk = resp.read(1)
                            if not next_chunk:
                                conn.close()
                                return "blocked", f"connection_closed_at_{len(accumulated)//1024}kb"
                            accumulated += next_chunk
                        except socket.timeout:
                            conn.close()
                            return "blocked", f"timeout_at_{len(accumulated)//1024}kb"
                        except Exception:
                            conn.close()
                            return "blocked", f"error_at_{len(accumulated)//1024}kb"
                    
                    if len(accumulated) > 500000:
                        conn.close()
                        return "ok", "ok"
                    
                    if len(accumulated) > 10485760:
                        conn.close()
                        return "ok", "ok"
                
                except socket.timeout:
                    bytes_kb = len(accumulated) // 1024
                    conn.close()
                    return "blocked", f"timeout_at_{bytes_kb}kb"
                
                except ConnectionResetError:
                    bytes_kb = len(accumulated) // 1024
                    conn.close()
                    return "blocked", f"tcp_reset_at_{bytes_kb}kb"
                
                except BrokenPipeError:
                    bytes_kb = len(accumulated) // 1024
                    conn.close()
                    return "blocked", f"broken_pipe_at_{bytes_kb}kb"
            
        except socket.timeout:
            return "error", "timeout_connection"
        except ConnectionRefusedError:
            return "error", "connection_refused"
        except Exception as e:
            error_type = type(e).__name__
            return "error", f"error_{error_type}"

    def is_domain_throttled(domain):
        """Проверяет, был ли домен помечен как замедленный."""
        with throttled_domains_lock:
            if domain not in throttled_domains:
                return False
            
            entry = throttled_domains[domain]
            # Проверяем, не прошло ли время восстановления
            if time.time() - entry["first_check"] > THROTTLE_RECOVERY_TIME:
                del throttled_domains[domain]
                return False
            
            return entry["count"] >= THROTTLE_DETECTION_THRESHOLD

    def classify_throttle_type(diag_info):
        """Классифицирует тип замедления на основе диагностики и возвращает тип для boost стратегии."""
        if not diag_info:
            return "unknown"
        
        diag_lower = diag_info.lower()
        
        # Классификация по диагностической информации
        if "slow_speed" in diag_lower:
            return "Slow_DPI"
        elif "connection_closed_at_16kb" in diag_lower or "connection_closed_at_17kb" in diag_lower or "connection_closed_at_18kb" in diag_lower or "connection_closed_at_19kb" in diag_lower:
            return "DPI_16KB"
        elif "tcp_reset" in diag_lower:
            return "TCP_RST"
        elif "timeout_at_16kb" in diag_lower or "timeout_at_17kb" in diag_lower or "timeout_at_18kb" in diag_lower or "timeout_at_19kb" in diag_lower:
            return "DPI_16KB"  # Похоже на DPI 16KB, но с таймаутом
        elif "timeout_at" in diag_lower:
            return "Early_Timeout"
        elif "slow_speed" in diag_lower:
            return "Slow_DPI"
        else:
            return "unknown"

    def mark_domain_as_throttled(domain):
        """Отмечает домен как замедленный (для подтверждения нужно несколько проверок)."""
        with throttled_domains_lock:
            if domain not in throttled_domains:
                throttled_domains[domain] = {"first_check": time.time(), "count": 1}
            else:
                throttled_domains[domain]["count"] += 1
                throttled_domains[domain]["first_check"] = time.time()  # Сбрасываем таймер при каждой проверке

    def unmark_domain_throttled(domain):
        """Удаляет домен из списка замедленных (т.е. он снова работает нормально)."""
        with throttled_domains_lock:
            if domain in throttled_domains:
                del throttled_domains[domain]

    def check_domain_robust(domain, port=0, priority=False):
        """
        Проверяет доступность домена и отслеживает замедления.
        Возвращает True, если статус "ok" ИЛИ "error" с кодом HTTP (старая логика).
        """
        for attempt in range(2):
            status, diag = detect_throttled_load(domain, port, priority)
            
            # Логика старой версии: если дошли до ответа сервера (даже с ошибкой 4xx/5xx) - это успех.
            is_http_error_success = (status == "error" and diag.startswith("http_"))
            
            if status == "ok" or is_http_error_success:
                unmark_domain_throttled(domain)
                return True
            
            # Если это последняя попытка и статус 'blocked' - фиксируем замедление
            if attempt == 1 and status == "blocked":
                mark_domain_as_throttled(domain)

            # Для всех остальных случаев (no_dns, connection_refused, etc.) или после неудачной первой попытки - просто продолжаем
            if attempt == 0:
                time.sleep(0.3)
        
        return False # Если после всех попыток не было успеха

    def add_to_hard_list_safe(domain):
        """Безопасно добавляет домен в temp/hard.txt для подбора стратегии."""
        try:
            hard_path = os.path.join(get_base_dir(), "temp", "hard.txt")
            lock = globals().get('hard_list_lock', threading.Lock())
            
            with lock:
                lines = []
                if os.path.exists(hard_path):
                    with open(hard_path, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                
                new_lines = []
                found = False
                timestamp = time.strftime("%d.%m.%Y в %H:%M")
                new_entry = f"{domain} # Не удалось разблокировать (Auto-Detect {timestamp})\n"
                domain_lower = domain.lower().strip()
                
                for line in lines:
                    parts = line.strip().split('#')[0].strip().lower()
                    if parts == domain_lower:
                        new_lines.append(new_entry)
                        found = True
                    else:
                        new_lines.append(line)
                
                if not found:
                    new_lines.append(new_entry)
                    
                with open(hard_path, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)

        except Exception as e:
            print(f"Error updating hard.txt: {e}")

    def remove_from_hard_list_safe(domain):
        """Безопасно удаляет домен из temp/hard.txt."""
        try:
            hard_path = os.path.join(get_base_dir(), "temp", "hard.txt")
            if not os.path.exists(hard_path): return

            # Используем блокировку если она доступна, иначе просто читаем/пишем (риск гонки, но лучше чем ничего)
            # В этом контексте hard_list_lock должен быть доступен
            lock = globals().get('hard_list_lock', threading.Lock()) 
            
            with lock:
                with open(hard_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                
                new_lines = []
                domain_lower = domain.lower().strip()
                
                for line in lines:
                    if line.strip().split('#')[0].strip().lower() != domain_lower:
                        new_lines.append(line)
                
                with open(hard_path, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                    
        except Exception as e:
            print(f"Error removing from hard.txt: {e}")

    def add_to_blocked_list_safe(domain):
        """Безопасно добавляет домен в list/ru.txt (кладбище)."""
        try:
            base_dir = get_base_dir()
            blocked_path = os.path.join(base_dir, BLOCKED_LIST_FILENAME)
            
            # Создаем директорию list если нет (хотя должна быть)
            os.makedirs(os.path.dirname(blocked_path), exist_ok=True)
            
            # Используем отдельный лок для blocked списка или общий hard_list_lock
            lock = globals().get('hard_list_lock', threading.Lock())
            
            with lock:
                # Читаем существующие чтобы не дублировать
                existing = set()
                if os.path.exists(blocked_path):
                     with open(blocked_path, "r", encoding="utf-8") as f:
                        for l in f:
                            existing.add(l.strip().split('#')[0].strip().lower())
                
                domain_lower = domain.lower().strip()
                if domain_lower in existing: return

                with open(blocked_path, "a", encoding="utf-8") as f:
                    ts = time.strftime('%d.%m.%Y')
                    f.write(f"{domain_lower} # Blocked (No Strategy Found) {ts}\n")
                    
        except Exception as e:
            print(f"Error updating ru.txt: {e}")

    def load_exclude_auto_checked():
        global exclude_auto_checked_domains
        path = os.path.join(get_base_dir(), EXCLUDE_AUTO_CHECKED_FILE)
        data = load_json_robust(path, {})
        with exclude_auto_checked_lock:
            exclude_auto_checked_domains = {}
            for ip, domains in data.items():
                exclude_auto_checked_domains[ip] = set(domains)

    def save_exclude_auto_checked():
        path = os.path.join(get_base_dir(), EXCLUDE_AUTO_CHECKED_FILE)
        with exclude_auto_checked_lock:
            data = {ip: list(doms) for ip, doms in exclude_auto_checked_domains.items()}
        save_json_safe(path, data)

    def exclude_auto_monitor_worker(log_func):
        """Проверяет домены в exclude_auto.txt на замедление/блокировку.
        Каждый домен проверяется ОДИН РАЗ для текущего IP в щадящем режиме."""
        global exclude_auto_checked_domains
        
        check_delay = 3
        last_logged_ip = None
        
        while not is_closing:
            try:
                if not is_service_active or is_vpn_active:
                    time.sleep(5)
                    continue
                
                try:
                    current_ip = get_public_ip_isolated()
                    if not current_ip: continue
                except: continue
                
                with exclude_auto_checked_lock:
                    if current_ip not in exclude_auto_checked_domains:
                        exclude_auto_checked_domains[current_ip] = set()
                        # log_func(f"[ExcludeMonitor] Новый IP {current_ip}, начинаем проверку доменов")
                    checked_for_this_ip = exclude_auto_checked_domains[current_ip]
                
                exclude_auto_path = os.path.join(get_base_dir(), "temp", "exclude_auto.txt")
                if not os.path.exists(exclude_auto_path):
                    time.sleep(10)
                    continue
                
                with open(exclude_auto_path, "r", encoding="utf-8") as f:
                    exclude_auto_domains = {line.split('#')[0].strip().lower() for line in f if line.strip() and not line.startswith('#')}
                
                unchecked_domains = list(exclude_auto_domains - checked_for_this_ip)
                if not unchecked_domains:
                    time.sleep(30)
                    continue
                
                domain = unchecked_domains[0]
                
                try:
                    port = audit_ports_queue.get(timeout=2)
                    try:
                        status, diag = detect_throttled_load(domain, port)
                    finally:
                        audit_ports_queue.put(port)
                    
                    if status == "blocked":
                        log_func(f"[ExcludeMonitor] {domain} - замедление/блокировка [{diag}], удаляется из исключений.")
                        # Удаляем из exclude_auto.txt и добавляем в hard.txt для анализа
                        if domain in auto_excluded_domains: auto_excluded_domains.discard(domain)
                        record_domain_visit(domain) # Попадет в hard.txt через background_checker
                        
                        try:
                            with open(exclude_auto_path, "w", encoding="utf-8") as f:
                                for d in exclude_auto_domains:
                                    if d != domain: f.write(f"{d}\n")
                            log_func(f"[ExcludeMonitor] Домен удалён из exclude_auto.txt")
                        except Exception as e:
                            log_func(f"[ExcludeMonitor] Ошибка удаления: {e}")
                    
                    elif status == "ok":
                         log_func(f"[ExcludeMonitor] {domain} доступен")
                    # Игнорируем статусы "error" и "no_dns"
                    
                    with exclude_auto_checked_lock:
                        checked_for_this_ip.add(domain)
                        if len(checked_for_this_ip) % 5 == 0:
                            save_exclude_auto_checked()
                
                except Exception as e:
                    log_func(f"[ExcludeMonitor] Ошибка проверки {domain}: {e}")
                    with exclude_auto_checked_lock:
                        checked_for_this_ip.add(domain)
                
                time.sleep(check_delay)
            
            except Exception as e:
                log_func(f"[ExcludeMonitor] Критическая ошибка: {e}")
                time.sleep(10)

    # === НОВОЕ: Функции адаптивной системы подбора стратегий ===
    
    def load_visited_domains():
        """Загружает статистику посещённых заблокированных доменов."""
        global visited_domains_stats
        try:
            base_dir = get_base_dir()
            path = os.path.join(base_dir, VISITED_DOMAINS_FILE)
            if os.path.exists(path):
                visited_domains_stats = load_json_robust(path)
                if visited_domains_stats:
                    return len(visited_domains_stats)
        except Exception as e:
            print(f"[AdaptiveSystem] Ошибка загрузки visited_domains_stats: {e}")
        return 0

    def save_visited_domains():
        """Сохраняет статистику посещённых доменов."""
        global visited_domains_stats
        try:
            base_dir = get_base_dir()
            path = os.path.join(base_dir, VISITED_DOMAINS_FILE)
            with visited_domains_lock:
                save_json_safe(path, visited_domains_stats)
        except Exception as e:
            print(f"[AdaptiveSystem] Ошибка сохранения visited_domains: {e}")

    # Кэши для оптимизации проверки доменов
    strategy_domains_cache = set()
    rkn_domains_cache = set()
    last_domains_cache_update = 0

    def update_domain_lists_cache():
        """Обновляет кэш доменов из стратегий и RKN."""
        global strategy_domains_cache, rkn_domains_cache, last_domains_cache_update
        
        if time.time() - last_domains_cache_update < 60: return

        try:
            base_dir = get_base_dir()
            
            # 1. RKN cache
            new_rkn = set()
            rkn_path = os.path.join(base_dir, "rkn.txt")
            if os.path.exists(rkn_path):
                with open(rkn_path, "r", encoding="utf-8") as f:
                    new_rkn = {l.strip().split('#')[0].strip().lower() for l in f if l.strip() and not l.startswith("#")}
            rkn_domains_cache = new_rkn

            # 2. Strategy lists cache (General, Hard, Boost)
            new_strat_domains = set()
            
            # General
            gen_path = os.path.join(base_dir, "list", "general.txt")
            if os.path.exists(gen_path):
                with open(gen_path, "r", encoding="utf-8") as f:
                    new_strat_domains.update(l.strip().split('#')[0].strip().lower() for l in f if l.strip() and not l.startswith("#"))
            
            # Hard & Boost (scan directory)
            list_dir = os.path.join(base_dir, "list")
            if os.path.exists(list_dir):
                for fname in os.listdir(list_dir):
                    if (fname.startswith("hard_") or fname.startswith("boost_")) and fname.endswith(".txt"):
                        try:
                            with open(os.path.join(list_dir, fname), "r", encoding="utf-8") as f:
                                new_strat_domains.update(l.strip().split('#')[0].strip().lower() for l in f if l.strip() and not l.startswith("#"))
                        except: pass
            
            strategy_domains_cache = new_strat_domains
            last_domains_cache_update = time.time()
            
        except Exception as e:
            print(f"[Cache] Ошибка обновления кэша доменов: {e}")

    def is_domain_in_set_robust(domain, domain_set):
        """Проверяет наличие домена или его родителя в множестве."""
        if domain in domain_set: return True
        parts = domain.split('.')
        # Проверяем поддомены (например, если google.com в списке, то mail.google.com подходит)
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in domain_set: return True
        return False

    def record_domain_visit(domain):
        """Записывает посещение заблокированного домена (Строгий режим: Только Стратегии + !RKN)."""
        global visited_domains_stats
        if not domain: return
        domain = domain.lower()
        if is_domain_excluded(domain): return
        
        # Обновляем кэши (lazy load)
        update_domain_lists_cache()
        
        # ПРАВИЛО 1: Домен должен быть в списках стратегий (General/Hard/Boost)
        if not is_domain_in_set_robust(domain, strategy_domains_cache):
            return

        # ПРАВИЛО 2: Домен НЕ должен быть в RKN (избегаем дубликатов при тесте)
        if is_domain_in_set_robust(domain, rkn_domains_cache):
            return

        # Исключаем сервисные (уже было)
        if is_service_domain_only(domain): return
        
        now = time.time()
        with visited_domains_lock:
            if domain not in visited_domains_stats:
                visited_domains_stats[domain] = {
                    "visits_per_week": 1,
                    "last_visit": now,
                    "total_visits": 1,
                    "priority": 1,
                    "first_visit": now
                }
            else:
                stats = visited_domains_stats[domain]
                stats["total_visits"] += 1
                stats["last_visit"] = now
                
                days_active = (now - stats["first_visit"]) / (24 * 3600)
                if days_active > 0:
                    visits_per_day = stats["total_visits"] / days_active
                    stats["visits_per_week"] = max(1, int(visits_per_day * 7))
                
                stats["priority"] = min(10, max(1, stats["visits_per_week"] // 5 + 1))
        
        if visited_domains_stats[domain]["total_visits"] == 1 or visited_domains_stats[domain]["total_visits"] % 5 == 0:
            save_visited_domains()

    def load_strategies_evolution():
        """Загружает историю эволюции стратегий."""
        global strategies_evolution
        try:
            base_dir = get_base_dir()
            path = os.path.join(base_dir, STRATEGIES_EVOLUTION_FILE)
            if os.path.exists(path):
                strategies_evolution = load_json_robust(path)
                
                # FIX: Versioned Migration (Reset if older than 0.997)
                ver = strategies_evolution.get("_version", "0.0")
                if ver < "0.997":
                   strategies_evolution = {}
                
                if strategies_evolution:
                    return len(strategies_evolution)
        except Exception as e:
            print(f"[AdaptiveSystem] Ошибка загрузки strategies_evolution: {e}")
        return 0

    def save_strategies_evolution():
        """Сохраняет историю эволюции стратегий."""
        global strategies_evolution
        try:
            base_dir = get_base_dir()
            path = os.path.join(base_dir, STRATEGIES_EVOLUTION_FILE)
            with strategies_evolution_lock:
                # FIX: Save current version to protect against future wipes
                strategies_evolution["_version"] = CURRENT_VERSION
                save_json_safe(path, strategies_evolution)
        except Exception as e:
            print(f"[AdaptiveSystem] Ошибка сохранения strategies_evolution: {e}")

    def update_strategy_success_rate(strategy_name, success_rate, log_func=None):
        """Обновляет метрику успеха для стратегии и отслеживает деградацию."""
        global strategies_evolution
        with strategies_evolution_lock:
            if strategy_name not in strategies_evolution:
                strategies_evolution[strategy_name] = {
                    "original_params": None,
                    "current_success_rate": success_rate,
                    "previous_success_rate": success_rate,
                    "modifications_tried": 0,
                    "last_checked": time.time(),
                    "status": "active"  # active, degraded, pending_review
                }
            else:
                evo = strategies_evolution[strategy_name]
                evo["previous_success_rate"] = evo.get("current_success_rate", success_rate)
                evo["current_success_rate"] = success_rate
                evo["last_checked"] = time.time()
                
                # Если деградация > 20%
                if evo["previous_success_rate"] > 0:
                    degradation = ((evo["previous_success_rate"] - success_rate) / evo["previous_success_rate"]) * 100
                    if degradation > 20:
                        # Если статус уже был degraded, не спамим логами, но обновляем данные
                        if evo["status"] != "degraded" and log_func:
                            log_func(f"[AdaptiveSystem] {strategy_name} деградировала на {degradation:.1f}% (было {evo['previous_success_rate']:.0f}%, стало {success_rate:.0f}%)")
                        evo["status"] = "degraded"
                    else:
                        evo["status"] = "active"
                    return degradation > 20
        
        save_strategies_evolution()
        return False

    def load_ip_history():
        """Загружает историю IP адресов."""
        global ip_history, last_recheck_ip, last_full_recheck_date
        try:
            base_dir = get_base_dir()
            path = os.path.join(base_dir, IP_HISTORY_FILE)
            if os.path.exists(path):
                ip_history = load_json_robust(path, [])
                if ip_history:
                    if ip_history:
                        last_entry = ip_history[-1]
                        last_recheck_ip = last_entry.get("ip")
                        last_full_recheck_date = last_entry.get("timestamp")
                    return len(ip_history)
        except Exception as e:
            print(f"[AdaptiveSystem] Ошибка загрузки ip_history: {e}")
        return 0

    def save_ip_history():
        """Сохраняет историю IP адресов."""
        global ip_history
        try:
            base_dir = get_base_dir()
            path = os.path.join(base_dir, IP_HISTORY_FILE)
            with ip_history_lock:
                save_json_safe(path, ip_history)
        except Exception as e:
            print(f"[AdaptiveSystem] Ошибка сохранения ip_history: {e}")

    # ================= МОДУЛЬ: LOG_FILTER =================
    def should_ignore(line):
        text_lower = line.lower().strip()
        
        if not text_lower: return True

        # 1. ВАЖНОЕ (Белый список)
        critical_markers = [
            "panic", "fatal", "could not read", "error", "fail", "must specify", "unknown option",
            "не удается", "не найдено", "ошибка"
        ]
        
        if any(m in text_lower for m in critical_markers):
            if "decryption failed" in text_lower or "crypto failed" in text_lower:
                return True
            return False

        # 2. ФИЛЬТРЫ (Черный список)
        starts_with_filters = (
            "github version", "read", "adding low-priority", "we have", "profile",
            "loading", "loaded", "lists summary", "hostlist file", "ipset file",
            "splits summary", "windivert", "!impostor", "initializing",
            "(", ")", "outbound", "inbound", "and", "or",
            "packet: id=", "ip4:", "ip6:", "tcp: len=", "udp: len=",
            "using cached desync", "desync profile", "* ipset check", "* hostlist check",
            "hostlist check", "reassemble", "starting reassemble", "delay desync",
            "discovering", "sending delayed", "replaying", "replay ip4", "replay ip6",
            "dpi desync src=", "multisplit pos", "normalized multisplit", "seqovl",
            "sending multisplit", "sending original", "dropping", "not applying tampering",
            "desync profile changed", "tls", "quic initial", "packet contains",
            "incoming ttl", "forced wssize", "req retrans", 
            "auto hostlist", 
            "sending fake[1]", "changing ip_id", "[d:", "discovered l7",
            "hostname:", "discovered hostname", "all multisplit pos", "sending",
            "applying tampering", "resending original",
            '"outbound and !loopback'
        )
        
        if text_lower.startswith(starts_with_filters):
            return True
        
        if text_lower.startswith("outbound and !loopback"):
            return True

        contains_filters = [
            "exclude hostlist", "include hostlist", "exclude ipset",
            "desync_any_proto is not set", "initial defrag crypto failed",
            "delayed packets", "fail counter", "threshold reached",
            "--wf-raw", "fake[1] applied",
            "session id length mismatch"
        ]
        
        if any(f in text_lower for f in contains_filters):
            return True

        return False

    def get_line_tag(line):
        text_lower = line.lower()

        if line.startswith("!!! [AUTO]"): return "normal"
        if "[StrategyBuilder]" in line: return "info"
        if "[DomainCleaner]" in line:
            return "info"
        if any(x in line for x in ["[Check]", "[Check-Init]", "[Evo]", "[Evo-Init]", "[Evo-PreCheck]", "[Evo-1]", "[Init]"]): 
            return "info"
        if ("[RU]" in line and "статус:" in text_lower and "connecting" in text_lower) or ("happy eyeballs" in text_lower):
            return "warning"
        
        # Специальное выделение проблем для [RU], [EU], [SingBox]
        if any(cat in line for cat in ["[RU]", "[EU]", "[SingBox]"]):
            if any(x in text_lower for x in ["ошибка", "error", "fail", "не удается", "не найден", "не удалось", "exception", "warning", "warn", "остановка", "падение"]):
                return "error"

        if any(x in text_lower for x in ["err:", "error", "dead", "crash", "could not read", "fatal", "panic", "must specify", "unknown option", "не удается", "не найдено", "repair", "ремонт"]):
            return "error"
        # Detect WinDivert-related codes only as standalone diagnostics (avoid false matches in IP:port like :3478).
        if re.search(r'(?<!\d)(177|34)(?!\d)', text_lower) and any(k in text_lower for k in ["код", "code", "exit", "windivert", "driver"]):
            return "error"
        
        if "fail" in text_lower:
            return "fail"
        
        if "ok (" in text_lower:
            return "normal"
        
        if any(x in text_lower for x in ["успешное подключение", "успешно инициализирован", "ядро активно"]):
            return "normal"
        
        if any(x in text_lower for x in ["пропуск", "удаление", "отмена", "инфо", "успешно"]):
            return "info"
            
        return "normal"

    # ================= МОДУЛЬ: NOVA_AUTOTUNE (необходимые функции) =================
    def get_public_ip_isolated():
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.poolmanager import PoolManager
        
        class SourcePortAdapter(HTTPAdapter):
            def __init__(self, port, *args, **kwargs):
                self._source_port = port
                super().__init__(*args, **kwargs)
            def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
                options = [(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)]
                try:
                    from urllib3.connection import HTTPConnection
                    options = HTTPConnection.default_socket_options + options
                except: pass
                
                self.poolmanager = PoolManager(
                    num_pools=connections, maxsize=maxsize,
                    block=block, source_address=('0.0.0.0', self._source_port), socket_options=options, **pool_kwargs)

        services = ['https://api.ipify.org', 'https://ifconfig.me', 'https://icanhazip.com', 'https://ipinfo.io/ip']
        local_port = random.randint(16000, 16009)
        session = requests.Session()
        session.trust_env = False # FIX: Ignore system proxy to get real ISP IP
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        session.mount('https://', SourcePortAdapter(local_port))
        
        def is_valid_ip(text):
            if not text or len(text) > 45 or '<' in text or '>' in text or 'html' in text.lower():
                return False
            return True

        try:
            for url in services:
                try:
                    ip = session.get(url, timeout=5).text.strip()
                    if is_valid_ip(ip): return ip
                except: continue
        finally:
            session.close()
            
        # Fallback: Standard request (if isolated failed)
        try:
            # Try one more time with standard requests (no source port binding)
            for url in services:
                 try:
                     # FIX: Explicitly disable proxies for fallback
                     ip = requests.get(url, headers=session.headers, timeout=5, proxies={"http": None, "https": None}).text.strip()
                     if is_valid_ip(ip): return ip
                 except: continue
        except: pass
        
        return None

    def _resolve_worker(domain):
        ips = []
        try:
            addr_infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
            for info in addr_infos:
                ips.append(info[4][0])
        except: pass
        return ips

    def resolve_domains_to_ips(domains, output_file):
        unique_ips = set()
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_domain = {executor.submit(_resolve_worker, d): d for d in domains}
            for i, future in enumerate(as_completed(future_to_domain), 1):
                if is_closing: 
                    executor.shutdown(wait=False)
                    return False
                ips = future.result()
                unique_ips.update(ips)
                
        if not unique_ips: return False
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                for ip in sorted(unique_ips):
                    f.write(f"{ip}\n")
            return True
        except: return False

    # ================= МОДУЛЬ: AI LEARNING SYSTEM =================
    class StrategyLearner:
        def __init__(self):
            self.filepath = LEARNING_DATA_FILE
            self.data = {
                "weights": {},  # {feature: score}
                "bins": {},     # {bin_name: score}
                "services": {}  # {service_name: {feature: score}}
            }
            self.lock = threading.Lock()
            self.load()

        def load(self):
            if os.path.exists(self.filepath):
                loaded = load_json_robust(self.filepath)
                if isinstance(loaded, dict) and loaded:
                    # FIX: Versioned Migration for Learning Data
                    ver = loaded.get("_version", "0.0")
                    if ver < "0.997":
                        self.data = {}
                    else:
                        self.data = loaded
            
            # Ensure structure integrity
            if "weights" not in self.data: self.data["weights"] = {}
            if "bins" not in self.data: self.data["bins"] = {}
            if "services" not in self.data: self.data["services"] = {}

        def save(self):
            try:
                with self.lock:
                    self.data["_version"] = CURRENT_VERSION
                    save_json_safe(self.filepath, self.data)
            except: pass

        def _extract_features(self, args):
            features = []
            for arg in args:
                if "=" in arg:
                    key, val = arg.split("=", 1)
                    if key in ["--dpi-desync", "--dpi-desync-fooling", "--dpi-desync-mode"]:
                        features.extend([f"{key}={v}" for v in val.split(",")])
                    elif key in ["--dpi-desync-ttl", "--dpi-desync-repeats", "--dpi-desync-split-pos"]:
                        features.append(arg) # Keep value for these
                    elif "fake" in key and ".bin" in val:
                        pass # Bins handled separately
                    else:
                        features.append(key) # Just existence of flag
                else:
                    features.append(arg)
            return features

        def _extract_bin(self, args):
            for arg in args:
                if ".bin" in arg and "=" in arg:
                    return os.path.basename(arg.split("=", 1)[1])
            return None

        def train(self, service, args, success_rate):
            """Обновляет веса на основе успеха стратегии (0-100)."""
            with self.lock:
                # Нормализация: >50 - успех, <50 - неудача
                delta = (success_rate - 50) / 10.0 
                
                features = self._extract_features(args)
                bin_file = self._extract_bin(args)

                # Обновляем глобальные веса
                for f in features:
                    self.data["weights"][f] = self.data["weights"].get(f, 0) + delta
                
                if bin_file:
                    self.data["bins"][bin_file] = self.data["bins"].get(bin_file, 0) + delta

                # Обновляем веса сервиса
                if service not in self.data["services"]:
                    self.data["services"][service] = {}
                
                for f in features:
                    self.data["services"][service][f] = self.data["services"][service].get(f, 0) + delta * 1.5 # Сервис-специфичные веса важнее

        def generate_strategy(self, service, base_args=None):
            """Генерирует стратегию на основе обученных весов."""
            with self.lock:
                # Базовые компоненты
                core_modes = ["--dpi-desync=fake", "--dpi-desync=split2", "--dpi-desync=disorder2", "--dpi-desync=multisplit"]
                fooling_modes = ["badseq", "badsum", "md5sig", "ts"]
                
                # Выбор режима на основе весов
                mode = self._weighted_choice(core_modes, service)
                
                new_args = [mode]
                
                # Добавляем fooling
                if random.random() > 0.3:
                    f = self._weighted_choice([f"--dpi-desync-fooling={x}" for x in fooling_modes], service)
                    new_args.append(f)
                
                # Добавляем TTL
                ttl = random.randint(1, 11)
                new_args.append(f"--dpi-desync-ttl={ttl}")
                
                # Добавляем Bin (если fake)
                if "fake" in mode:
                    best_bins = sorted(self.data["bins"].items(), key=lambda x: x[1], reverse=True)
                    if best_bins and random.random() > 0.2:
                        bin_name = best_bins[0][0] # Top bin
                    else:
                        # Fallback or exploration
                        bin_name = "tls_clienthello_www_google_com.bin" 
                    
                    # Определяем тип fake
                    if "quic" in bin_name:
                        new_args.append(f"--dpi-desync-fake-quic=fake/{bin_name}")
                    else:
                        new_args.append(f"--dpi-desync-fake-tls=fake/{bin_name}")

                return new_args

        def _weighted_choice(self, options, service):
            # Простой эпсилон-жадный выбор
            if random.random() < 0.2: # 20% exploration
                return random.choice(options)
            
            # Exploitation
            srv_weights = self.data["services"].get(service, {})
            glob_weights = self.data["weights"]
            
            scored = []
            for opt in options:
                # Извлекаем ключевую часть для поиска веса
                key = opt.split("=")[1] if "=" in opt else opt
                # Ищем точное совпадение ключа или частичное
                w = srv_weights.get(opt, 0) * 2 + glob_weights.get(opt, 0)
                scored.append((w, opt))
            
            scored.sort(key=lambda x: x[0], reverse=True)
            return scored[0][1]



    def record_ip_change(new_ip, log_func=None):
        """Записывает смену IP адреса (кроме VPN) и возвращает True если переверификация нужна."""
        global last_recheck_ip, last_full_recheck_date, ip_history
        
        if is_vpn_active:
            if log_func:
                log_func(f"[AdaptiveSystem] VPN активен, пропускаем запись IP смены")
            return False
        
        needs_recheck = False
        
        with ip_history_lock:
            if last_recheck_ip != new_ip:
                # IP сменился
                last_recheck_ip = new_ip
                ip_history.append({
                    "ip": new_ip,
                    "timestamp": time.time(),
                    "strategies_working_count": 0
                })
                # Очищаем историю если она стала слишком большой
                if len(ip_history) > 100:
                    ip_history = ip_history[-100:]
                
                needs_recheck = True
            else:
                # IP не менялся, проверяем 7-дневный лимит
                now = time.time()
                if last_full_recheck_date is None or (now - last_full_recheck_date) > (7 * 24 * 3600):
                    last_full_recheck_date = now
                    needs_recheck = True
        
        save_ip_history()
        return needs_recheck

    def get_hot_domains(max_count=20):
        """Возвращает HOT домены (посещённые) отсортированные по приоритету."""
        global visited_domains_stats
        with visited_domains_lock:
            # Filter out metadata like "version" which are not dicts
            valid_items = [
                x for x in visited_domains_stats.items() 
                if isinstance(x[1], dict) and "priority" in x[1] and "last_visit" in x[1]
            ]
            sorted_domains = sorted(
                valid_items,
                key=lambda x: (-x[1]["priority"], -x[1]["last_visit"])
            )
            return [d[0] for d in sorted_domains[:max_count]]

    def get_cold_domains(rkn_path, excluded_set, max_count=20):
        """Возвращает COLD домены (из rkn.txt но не посещённые)."""
        try:
            with open(rkn_path, "r", encoding="utf-8") as f:
                all_rkn = set([l.strip().lower() for l in f if l.strip() and not l.startswith("#")])
        except:
            return []
        cold = list(all_rkn - excluded_set)
        random.shuffle(cold)
        return cold[:max_count]

    def generate_light_boost_strategies():
        """Генерирует список легких стратегий-кандидатов для boost."""
        strategies = []
        
        # 1. Fake (самые легкие)
        for ttl in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
            strategies.append(["--dpi-desync=fake", f"--dpi-desync-ttl={ttl}"])
            strategies.append(["--dpi-desync=fake", f"--dpi-desync-ttl={ttl}", "--dpi-desync-fooling=badseq"])
            strategies.append(["--dpi-desync=fake", f"--dpi-desync-ttl={ttl}", "--dpi-desync-fooling=md5sig"])

        # 2. Split2 (легкая фрагментация)
        for pos in ["1", "2", "3", "host", "method"]:
            strategies.append(["--dpi-desync=split2", f"--dpi-desync-split-pos={pos}"])
            strategies.append(["--dpi-desync=split2", f"--dpi-desync-split-pos={pos}", "--dpi-desync-split-seqovl"])

        # 3. Disorder2 (легкий disorder)
        for pos in ["1", "2", "3", "host", "method"]:
            strategies.append(["--dpi-desync=disorder2", f"--dpi-desync-split-pos={pos}"])
            strategies.append(["--dpi-desync=disorder2", f"--dpi-desync-split-pos={pos}", "--dpi-desync-split-seqovl"])
            
        # 4. Mod_http (для HTTP замедлений)
        strategies.append(["--dpi-desync=mod_http", "--dpi-desync-mod-http=hostcase"])
        strategies.append(["--dpi-desync=mod_http", "--dpi-desync-mod-http=methodspace"])

        return strategies

    def boost_evolution_worker(log_func):
        """Фоновый процесс эволюции boost стратегий.
        Ищет новые эффективные стратегии для замедленных доменов и обновляет boost_x слоты."""
        
        while not is_closing:
            try:
                if is_vpn_active or not is_service_active:
                    time.sleep(10)
                    continue
                
                # 1. Ищем кандидатов на улучшение (домены в hard.txt, которые были замедлены)
                target_domains = []
                with throttled_registry_lock:
                    for d, info in throttled_domains_registry.items():
                        # Если домен замедлен, но не имеет boost стратегии (значит он скорее всего в hard.txt или general не подошел)
                        if not info.get("boost_strategy"):
                            target_domains.append(d)
                
                if not target_domains:
                    time.sleep(60)
                    continue
                
                # Берем случайный домен для тестов
                test_domain = random.choice(target_domains)

                # Проверяем, доступен ли он вообще (если нет IP, нет смысла тестить)
                try:
                    socket.gethostbyname(test_domain)
                except:
                    time.sleep(10)
                    continue

                log_func(f"[BoostEvo] Поиск лучшей boost стратегии для {test_domain}...")
                
                # Генерируем кандидатов
                candidates = generate_light_boost_strategies()
                random.shuffle(candidates)
                
                # Загружаем сохраненных кандидатов
                base_dir = get_base_dir()
                boost_cand_path = os.path.join(base_dir, "strat", "boost.json")
                saved_candidates = []
                try :
                    if os.path.exists(boost_cand_path):
                        with open(boost_cand_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            for k, v in data.items():
                                saved_candidates.append(v)
                except: pass
                
                # Объединяем: сначала сохраненные, потом новые
                test_pool = saved_candidates + candidates[:20] # Берем 20 случайных новых
                
                best_strat = None
                
                # Тестируем
                # Используем check_strat из advanced_strategy_checker_worker? Нет, он локальный.
                # Реализуем упрощенный тест здесь
                
                for strat_args in test_pool:
                    if is_closing: break
                    
                    # Запуск полноценного теста с изоляцией
                    test_port = None
                    try:
                        # Используем свободный порт из очереди аудита
                        test_port = audit_ports_queue.get(timeout=5)
                        if test_boost_strategy_isolated(strat_args, test_domain, test_port, base_dir, log_func):
                            best_strat = strat_args
                            log_func(f"[BoostEvo] Найдена работающая стратегия для {test_domain}: {' '.join(strat_args)}")
                            break
                    except queue.Empty:
                        log_func("[BoostEvo] Нет свободных портов для тестирования")
                        break
                    except Exception as e:
                        if IS_DEBUG_MODE: log_func(f"[BoostEvo] Ошибка при тесте стратегии: {e}")
                    finally:
                        if test_port:
                            audit_ports_queue.put(test_port)
                
                # Сохраняем найденную стратегию, если она действительно новая
                if best_strat and best_strat not in saved_candidates:
                    try:
                        # Загружаем текущие стратегии из boost.json
                        data = {}
                        if os.path.exists(boost_cand_path):
                            data = load_json_robust(boost_cand_path, {})
                        
                        # Ищем свободный слот или перезаписываем boost_12 (как в matcher)
                        slot = "boost_12"
                        for i in range(1, 13):
                            if f"boost_{i}" not in data:
                                slot = f"boost_{i}"
                                break
                        
                        data[slot] = best_strat
                        save_json_safe(boost_cand_path, data)
                        log_func(f"[BoostEvo] Новая эффективная стратегия сохранена в слот {slot}")
                    except Exception as e:
                        log_func(f"[BoostEvo] Ошибка при сохранении стратегии: {e}")
                
                time.sleep(300)

            except Exception as e:
                time.sleep(60)

    def update_boost_strategy(slot_name, new_args, log_func):
        """Обновляет boost_x стратегию и перепроверяет привязанные домены."""
        base_dir = get_base_dir()
        strat_path = os.path.join(base_dir, "strat", "strategies.json")
        
        try:
            with open(strat_path, "r", encoding="utf-8") as f:
                strategies = json.load(f)
            
            old_args = strategies.get(slot_name, [])
            strategies[slot_name] = new_args
            
            with open(strat_path, "w", encoding="utf-8") as f:
                json.dump(strategies, f, indent=4)
            
            log_func(f"[BoostEvo] Стратегия {slot_name} обновлена.")
            
            # Проверяем домены, привязанные к этому слоту
            domains = load_hard_strategy_domains(slot_name)
            if domains:
                log_func(f"[BoostEvo] Перепроверка {len(domains)} доменов для {slot_name}...")
                # Логика перепроверки будет в hard_strategy_matcher (он увидит, что домены не работают и перенесет их)
                
        except Exception as e:
            log_func(f"[BoostEvo] Ошибка обновления: {e}")

    def test_boost_strategy_isolated(strat_args, domain, port, base_dir, log_func):
        """Тестирует стратегию на отдельном порту."""
        proc = None
        try:
            test_args = []
            for arg in strat_args:
                if arg.startswith(("--wf-tcp", "--wf-udp", "--hostlist", "--ipset")):
                    continue
                if arg.startswith("--filter-tcp"): test_args.append("--filter-tcp=1-65535")
                elif arg.startswith("--filter-udp"): test_args.append("--filter-udp=1-65535")
                else: test_args.append(arg)
            
            for i in range(len(test_args)):
                arg = test_args[i]
                if "=" in arg and ".bin" in arg:
                    k, v = arg.split("=", 1)
                    fname = os.path.basename(v)
                    if os.path.exists(os.path.join(base_dir, "fake", fname)):
                        test_args[i] = f"{k}={os.path.join(base_dir, 'fake', fname)}"

            p_end = port + 1
            has_tcp = any("filter-tcp" in a for a in test_args)
            has_udp = any("filter-udp" in a for a in test_args)
            if not has_tcp and not has_udp: has_tcp = has_udp = True
            
            proto_parts = []
            if has_tcp: proto_parts.append(f"(tcp and tcp.SrcPort >= {port} and tcp.SrcPort <= {p_end})")
            if has_udp: proto_parts.append(f"(udp and udp.SrcPort >= {port} and udp.SrcPort <= {p_end})")
            
            isolation_filter = f"outbound and !loopback and ({' or '.join(proto_parts)})"
            
            exe_name = WINWS_FILENAME
            # Use Test Process for checks if available
            test_exe = os.path.join(base_dir, "bin", "winws_test.exe")
            if os.path.exists(test_exe):
                exe_name = "winws_test.exe"

            exe_path = os.path.join(base_dir, "bin", exe_name)
            final_args = [exe_path] + test_args + [f'--wf-raw={isolation_filter}']
            
            # PRIORITY_BELOW_NORMAL (0x00004000) for background checks to avoid GUI freezes
            proc = subprocess.Popen(final_args, cwd=base_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, 
                                   creationflags=subprocess.CREATE_NO_WINDOW | 0x00004000)
            time.sleep(1.5)
            
            status, _ = detect_throttled_load(domain, port)
            return status == "ok"
            
        except Exception:
            return False
        finally:
            if proc:
                try: subprocess.run(["taskkill", "/F", "/PID", str(proc.pid)], creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except: pass

    def boost_strategy_matcher_worker(log_func):
        """Подбирает boost стратегии для замедленных доменов.
        Пробует стратегии для преодоления конкретного типа замедления."""
        
        while not is_closing:
            try:
                if is_vpn_active:
                    time.sleep(5)
                    continue

                if not is_service_active:
                    time.sleep(5)
                    continue
                
                base_dir = get_base_dir()
                strat_boost_path = os.path.join(base_dir, "strat", "boost.json")
                
                # Загружаем strategies (boost.json)
                strategies = {}
                try:
                    strategies = load_json_robust(strat_boost_path, {})
                except: strategies = {}

                # Если пусто, генерируем дефолтные и сохраняем
                if not strategies:
                    defaults = generate_light_boost_strategies()
                    for i in range(1, 13):
                        if i <= len(defaults):
                            strategies[f"boost_{i}"] = defaults[i-1]
                    save_json_safe(strat_boost_path, strategies)
                    time.sleep(1) # Даем время на запись
                
                # Получаем список всех boost стратегий (именованных и нумерованных)
                available_boost = [k for k in strategies.keys() if k.startswith("boost_")]
                
                # FIX: Support modern "strategies" list format (do not regenerate legacy keys if new format exists)
                has_modern_format = False
                if "strategies" in strategies and isinstance(strategies["strategies"], list):
                    for s in strategies["strategies"]:
                        if isinstance(s, dict) and "name" in s and "args" in s:
                            s_name = s["name"]
                            # Inject into memory map for usage (but NOT saving)
                            strategies[s_name] = s["args"]
                            available_boost.append(s_name)
                            has_modern_format = True

                # Если нет нумерованных boost_x и нет современного формата -> создаем дефолтные
                has_numbered = any(re.match(r"boost_\d+$", k) for k in available_boost)
                
                if not has_numbered and not has_modern_format:
                    defaults = generate_light_boost_strategies()
                    for i in range(1, 13):
                        if i <= len(defaults):
                            name = f"boost_{i}"
                            strategies[name] = defaults[i-1]
                            available_boost.append(name)
                    save_json_safe(strat_boost_path, strategies)
                
                if not available_boost:
                    log_func("[BoostMatcher] Нет доступных boost стратегий для подбора")
                    time.sleep(60)
                    continue
                
                # Берем домены из реестра замедленных которые еще не имеют boost стратегии
                throttled_to_process = []
                with throttled_registry_lock:
                    for domain, info in list(throttled_domains_registry.items()):
                        if info.get("boost_strategy") is None:
                            throttled_to_process.append((domain, info.get("throttle_type", "unknown")))
                
                if not throttled_to_process:
                    time.sleep(60)
                    continue
                
                log_func(f"[BoostMatcher] Подбор boost стратегий для {len(throttled_to_process)} замедленных доменов...")
                
                # Обрабатываем по 3 домена за итерацию
                for domain, throttle_type in throttled_to_process[:3]:
                    if is_closing: break
                    
                    # 1. Формируем список для проверки (приоритет по типу)
                    priority_list = []
                    others = []
                    
                    type_map = {
                        "Slow_DPI": "boost_Slow_DPI",
                        "DPI_16KB": "boost_DPI_16KB",
                        "TCP_RST": "boost_TCP_RST",
                        "Early_Timeout": "boost_Early_Timeout"
                    }
                    target_name = type_map.get(throttle_type)
                    
                    for b in available_boost:
                        if b == target_name: priority_list.append(b)
                        elif b == "boost_Combined_Aggressive": priority_list.append(b)
                        else: others.append(b)
                    
                    # Сортируем others: сначала именованные, потом нумерованные
                    others.sort(key=lambda x: (not x.startswith("boost_Slow"), x))
                    
                    test_order = priority_list + others
                    
                    log_func(f"[BoostMatcher] {domain} (тип: {throttle_type}) - тестируем {len(test_order)} стратегий...")
                    
                    found_strat = None
                    
                    # Используем порт из audit_ports_queue для теста
                    try:
                        test_port = audit_ports_queue.get(timeout=5)
                    except:
                        test_port = 16010 # Fallback
                    
                    try:
                        # А. Проверка существующих стратегий
                        for i, boost_name in enumerate(test_order):
                            if is_closing: break
                            args = strategies.get(boost_name)
                            if not args: continue
                            
                            # FIX: Granular progress log (User Request)
                            # log_func(f"[BoostMatcher] {domain}: ({i+1}/{len(test_order)}) {boost_name}...")
                            
                            if test_boost_strategy_isolated(args, domain, test_port, base_dir, None): # Log func None to reduce spam inside checker
                                log_func(f"[BoostMatcher] {domain} работает с {boost_name}!")
                                found_strat = boost_name
                                break
                        
                        # Б. Если не найдено - ищем в boost.json (кандидаты)
                        if not found_strat:
                            boost_cand_path = os.path.join(base_dir, "strat", "boost.json")
                            candidates = {}
                            if os.path.exists(boost_cand_path):
                                try:
                                    with open(boost_cand_path, "r", encoding="utf-8") as f:
                                        candidates = json.load(f)
                                except: pass
                            
                            if candidates:
                                log_func(f"[BoostMatcher] Проверка кандидатов из boost.json для {domain}...")
                                for c_name, c_args in candidates.items():
                                    if is_closing: break
                                    if test_boost_strategy_isolated(c_args, domain, test_port, base_dir, None):
                                        log_func(f"[BoostMatcher] Кандидат {c_name} подошел!")
                                        # Сохраняем как новую boost_x стратегию
                                        # Ищем свободный слот или перезаписываем boost_12
                                        slot = "boost_12"
                                        for i in range(1, 13):
                                            if f"boost_{i}" not in strategies:
                                                slot = f"boost_{i}"
                                                break
                                        update_boost_strategy(slot, c_args, log_func)
                                        found_strat = slot
                                        break
                    finally:
                        audit_ports_queue.put(test_port)
                    
                    if found_strat:
                        # Сохраняем найденную boost стратегию
                        mark_boost_strategy_for_domain(domain, found_strat)
                        # Добавляем домен в список стратегии (аналогично hard_x)
                        add_domain_to_hard_strategy(domain, found_strat, log_func)
                        log_func(f"[BoostMatcher] Сохранено: {domain} -> {found_strat}")
                    else:
                        # Если boost стратегии не помогли - переносим в hard.txt для подбора hard_x
                        log_func(f"[BoostMatcher] {domain} не подходит для boost стратегий. Переносим в hard.txt для подбора hard_x")
                        add_to_hard_list_safe(domain)
                        
                        # FIX: Mark as failed in registry to prevent infinite loop
                        with throttled_registry_lock:
                            if domain in throttled_domains_registry:
                                throttled_domains_registry[domain]["boost_strategy"] = "failed"
                
                time.sleep(120)  # Проверяем каждые 2 минуты
                
            except Exception as e:
                log_func(f"[BoostMatcher] Ошибка: {e}")
                time.sleep(60)

    def hard_strategy_matcher_worker(log_func):
        """Проверяет домены из list/hard_X.txt если их стратегия была удалена из strategies.json.
        Переносит домены в General стратегию или в temp/hard.txt для подбора новой стратегии."""
        global matcher_wakeup_event
        last_known_hard_strats = {}  # {hard_name: set(domains)}
        
        while not is_closing:
            try:
                if is_vpn_active or not is_service_active:
                    time.sleep(5)
                    continue
                
                # 1. Обработка экстренной очереди (высокий приоритет)
                urgent_domains = []
                while not urgent_analysis_queue.empty():
                    try: urgent_domains.append(urgent_analysis_queue.get_nowait())
                    except: break
                
                if urgent_domains:
                    urgent_domains = list(set(urgent_domains))
                    log_func(f"[HardMatcher] ЭКСТРЕННЫЙ ПОДБОР для {len(urgent_domains)} сайтов: {', '.join(urgent_domains)}")
                    
                    base_dir = get_base_dir()
                    strat_path = os.path.join(base_dir, "strat", "strategies.json")
                    strategies = load_json_robust(strat_path, {})

                    for domain in urgent_domains:
                        if is_closing: break
                        
                        port = audit_ports_queue.get()
                        try:
                            status, diag = detect_throttled_load(domain, port, priority=True)
                        finally:
                            audit_ports_queue.put(port)
                        
                        if status == "no_dns":
                            log_func(f"[HardMatcher] {domain} - ошибка DNS. Пропуск.")
                            continue

                        if status == "ok":
                            log_func(f"[HardMatcher] {domain} разблокирован (General). Добавляем в general.txt")
                            smart_update_general([domain])
                            remove_from_hard_list_safe(domain)
                            continue
                        
                        found_strategy = None
                        is_throttled = "slow_speed" in diag or "timeout_at" in diag
                        
                        if is_throttled:
                            log_func(f"[HardMatcher] {domain} замедлен [{diag}]. Пробуем Boost стратегии...")
                            boost_keys = sorted([k for k in strategies if k.startswith("boost_")], key=lambda x: (not x.startswith("boost_Slow"), x))
                            
                            for b_name in boost_keys:
                                if is_closing: break
                                if test_boost_strategy_isolated(strategies[b_name], domain, 16015, base_dir, log_func):
                                    log_func(f"[HardMatcher] Найден Boost: {b_name}")
                                    mark_boost_strategy_for_domain(domain, b_name)
                                    add_domain_to_hard_strategy(domain, b_name, log_func)
                                    remove_from_hard_list_safe(domain)
                                    found_strategy = b_name
                                    break
                        
                        if not found_strategy:
                            log_func(f"[HardMatcher] {domain} заблокирован. Пробуем Hard стратегии...")
                            for i in range(1, 13):
                                if is_closing: break
                                h_name = f"hard_{i}"
                                if h_name in strategies:
                                    if test_boost_strategy_isolated(strategies[h_name], domain, 16016, base_dir, log_func):
                                        log_func(f"[HardMatcher] Найдена Hard стратегия: {h_name}")
                                        add_domain_to_hard_strategy(domain, h_name, log_func)
                                        remove_from_hard_list_safe(domain)
                                        found_strategy = h_name
                                        break
                        
                        if found_strategy:
                            if root: root.after(0, perform_hot_restart)
                        else:
                            log_func(f"[HardMatcher] Быстрый подбор не удался для {domain}. Переносим в BLOCKED.")
                            add_to_blocked_list_safe(domain)
                            remove_from_hard_list_safe(domain)
                            if is_throttled:
                                t_type = classify_throttle_type(diag)
                                mark_domain_as_throttled_registry(domain, t_type)

                # 2. Стандартная проверка удаленных стратегий
                base_dir = get_base_dir()
                strat_path = os.path.join(base_dir, "strat", "strategies.json")
                strategies = load_json_robust(strat_path, {})
                
                current_hard_strats = {k: v for k, v in strategies.items() if k.startswith("hard_")}
                deleted_hards = set(last_known_hard_strats.keys()) - set(current_hard_strats.keys())
                
                if deleted_hards:
                     # CRITICAL FIX: Не реагируем на удаление при выходе
                    if is_closing: break
                    
                    log_func(f"[HardMatcher] Обнаружено удаление стратегий: {', '.join(deleted_hards)}")
                    
                    for hard_name in deleted_hards:
                        domains_to_migrate = load_hard_strategy_domains(hard_name)
                        if not domains_to_migrate: continue

                        log_func(f"[HardMatcher] Миграция {len(domains_to_migrate)} доменов из {hard_name}...")
                        for domain in domains_to_migrate:
                            if check_domain_robust(domain, 0):
                                log_func(f"[HardMatcher] {domain} работает с General. Добавляем в list/general.txt")
                                smart_update_general([domain])
                            else:
                                log_func(f"[HardMatcher] {domain} не работает с General. Переносим в temp/hard.txt")
                                add_to_hard_list_safe(domain)
                        
                        hard_file = os.path.join(base_dir, "list", f"{hard_name}.txt")
                        try:
                            if os.path.exists(hard_file): os.remove(hard_file)
                        except: pass
                        if root: root.after(0, perform_hot_restart)
                
                last_known_hard_strats = {k: load_hard_strategy_domains(k) for k in current_hard_strats.keys()}
                
                matcher_wakeup_event.wait(60)
                matcher_wakeup_event.clear()
                
            except Exception as e:
                log_func(f"[HardMatcher] Ошибка: {e}")
                time.sleep(60)

    # ================= УПРАВЛЕНИЕ ПРОЦЕССОМ =================
    
    def parse_ports_from_args(arg_list):
        tcp_ports = set()
        udp_ports = set()
        
        # FIX: Ensure we have a list to iterate
        if isinstance(arg_list, dict):
            arg_list = arg_list.get("args", [])
        if not isinstance(arg_list, list):
            return tcp_ports, udp_ports

        for arg in arg_list:
            if not isinstance(arg, str): continue
            arg_clean = arg.strip()
            
            if "=" not in arg_clean: continue
            
            if arg_clean.startswith("--wf-tcp=") or arg_clean.startswith("--filter-tcp="):
                ports = arg_clean.split("=", 1)[1]
                for part in ports.split(","):
                    part = part.strip()
                    if not part: continue
                    if "-" in part:
                         try:
                             start, end = part.split('-')
                             tcp_ports.add(f"(tcp.DstPort >= {start} and tcp.DstPort <= {end})")
                         except: pass
                    else:
                         tcp_ports.add(f"tcp.DstPort == {part}")
            
            if arg_clean.startswith("--wf-udp=") or arg_clean.startswith("--filter-udp="):
                ports = arg_clean.split("=", 1)[1]
                for part in ports.split(","):
                    part = part.strip()
                    if not part: continue
                    if "-" in part:
                         try:
                             start, end = part.split('-')
                             udp_ports.add(f"(udp.DstPort >= {start} and udp.DstPort <= {end})")
                         except: pass
                    else:
                         udp_ports.add(f"udp.DstPort == {part}")
        return tcp_ports, udp_ports

    def repair_windivert_driver(log_func=None):
        """
        Attempts to repair broken WinDivert driver installation.
        Fixes Code 177, 577, and 0x422 (Disabled).
        """
        try:
            if log_func: log_func("[Repair] Запуск процедуры восстановления драйвера WinDivert...")
        except: pass
        
        # 1. Stop and Delete Service (Full reset)
        try:
            # Force enable first in case it was disabled (Fix for Code 34)
            subprocess.run(["sc", "config", "windivert", "start=", "demand"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            
            # Direct Registry Fix for Code 34
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WinDivert", 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 3) # 3 = Manual
                winreg.CloseKey(key)
            except: pass

            subprocess.run(["sc", "stop", "windivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(["sc", "delete", "windivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        except: pass
        
        # 1.1 Deeper Registry Cleanup (Fix for persistent 177 / zombie services)
        try:
            import winreg
            reg_path = r"SYSTEM\CurrentControlSet\Services\WinDivert"
            try:
                # Need to open with all access to delete
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_ALL_ACCESS)
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                winreg.CloseKey(key)
                if IS_DEBUG_MODE: log_func("[Repair] Запись службы в реестре удалена.")
            except: pass
        except: pass

        # 2. Kill any WinWS remnants that might be holding the driver
        try:
            subprocess.run(["taskkill", "/F", "/IM", "winws.exe"], creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["taskkill", "/F", "/IM", "winws_test.exe"], creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except: pass

        # 3. Clean system remnants (Drivers often stuck in system32/drivers)
        try:
            sys_driver = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers', 'WinDivert64.sys')
            if os.path.exists(sys_driver):
                subprocess.run(["del", "/F", "/Q", sys_driver], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except: pass

        # 4. Restore driver files from internal resources
        try:
            base_dir = get_base_dir()
            bin_path = os.path.join(base_dir, "bin")
            
            required_files = ["WinDivert.dll", "WinDivert64.sys"]
            missing = [f for f in required_files if not os.path.exists(os.path.join(bin_path, f))]
            
            if missing and getattr(sys, 'frozen', False):
                internal = get_internal_path("bin")
                for f in required_files:
                    src = os.path.join(internal, f)
                    dst = os.path.join(bin_path, f)
                    if os.path.exists(src):
                        try: shutil.copy2(src, dst)
                        except: pass
                if log_func: log_func("[Repair] Файлы драйвера восстановлены из ресурсов.")
        except Exception as e:
            if log_func: log_func(f"[Repair] Ошибка при восстановлении файлов: {e}")

        # 5. Diagnostic Advice
        if log_func:
            log_func("[Repair] Совет: Если ошибка 177 повторяется, проверьте 'Изоляцию ядра' (Целостность памяти) в Защитнике Windows.")

        time.sleep(1.5)
        if log_func: log_func("[Repair] Процедура завершена. Ожидание запуска...")

    def start_nova_service(silent=False, restart_mode=False):
        threading.Thread(target=_start_nova_service_impl, args=(silent, restart_mode), daemon=True).start()

    def sync_hard_domains_to_strategies(log_func=None):
        """Очищает strategies.json от ошибочных --hostlist-exclude для hard_X стратегий."""
        try:
            base_dir = get_base_dir()
            strat_path = os.path.join(base_dir, "strat", "strategies.json")
            
            strategies = {}
            try:
                with open(strat_path, "r", encoding="utf-8") as f:
                    strategies = json.load(f)
            except: pass
            
            modified = False
            for i in range(1, 13):
                hard_name = f"hard_{i}"
                if hard_name in strategies:
                    strat_args = strategies[hard_name]
                    new_args = []
                    changed = False
                    for arg in strat_args:
                        # Удаляем --hostlist-exclude, указывающие на этот же hard список (это была ошибка)
                        if "--hostlist-exclude" in arg and f"{hard_name}.txt" in arg:
                            changed = True
                            continue
                        new_args.append(arg)
                    
                    if changed:
                        strategies[hard_name] = new_args
                        modified = True
                        if log_func:
                            log_func(f"[HardSync] Исправлена стратегия {hard_name} (удален ошибочный exclude).")
            
            if modified:
                try:
                    with open(strat_path, "w", encoding="utf-8") as f:
                        json.dump(strategies, f, indent=4)
                    if log_func:
                        log_func(f"[HardSync] strategies.json очищен от ошибок.")
                except Exception as e:
                    if log_func:
                        log_func(f"[HardSync] Ошибка при сохранении: {e}")
        except Exception as e:
            if log_func:
                log_func(f"[HardSync] Ошибка: {e}")

    def check_hard_list_on_startup(log_func=None):
        """Проверяет домены из temp/hard.txt при запуске. Если стратегии не подобраны и new hard_X списки не сформированы, оставляет домены в hard.txt."""
        try:
            base_dir = get_base_dir()
            hard_path = os.path.join(base_dir, "temp", "hard.txt")
            
            if not os.path.exists(hard_path):
                return
            
            # Читаем домены из hard.txt
            with open(hard_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            domains = [l.split('#')[0].strip().lower() for l in lines if l.strip() and not l.startswith("#")]
            
            if not domains:
                return
            
            if log_func:
                log_func(f"[HardCheck] При запуске найдено {len(domains)} доменов в temp/hard.txt, проверяем стратегии...")
            
            # Загружаем текущие hard_X стратегии
            strat_path = os.path.join(base_dir, "strat", "strategies.json")
            strategies = {}
            try:
                with open(strat_path, "r", encoding="utf-8") as f:
                    strategies = json.load(f)
            except: pass
            
            current_hard_strats = {k: v for k, v in strategies.items() if k.startswith("hard_")}
            
            # Для каждого домена - проверяем был ли он уже подобран ранее
            domains_found = []
            domains_not_found = []
            
            for domain in domains:
                found = False
                for hard_name in current_hard_strats.keys():
                    hard_domains = load_hard_strategy_domains(hard_name)
                    if domain in hard_domains:
                        domains_found.append(domain)
                        found = True
                        break
                
                if not found:
                    domains_not_found.append(domain)
            
            # Если нашли - убираем из hard.txt
            if domains_found:
                if log_func:
                    log_func(f"[HardCheck] {len(domains_found)} доменов уже имеют стратегии. Удаляем из hard.txt")
                
                with open(hard_path, "w", encoding="utf-8") as f:
                    for domain in domains_not_found:
                        f.write(f"{domain}\n")
                
                domains = domains_not_found
            
            # Если остались домены без стратегий - ждем пока сформируются новые hard_X списки
            if domains:
                if log_func:
                    log_func(f"[HardCheck] {len(domains)} доменов ждут подбора стратегии. Оставляем в hard.txt для background worker.")
                if log_func:
                    log_func(f"[HardCheck] Background worker проверит их когда будут сформированы новые hard_X стратегии.")
                    
        except Exception as e:
            if log_func:
                log_func(f"[HardCheck] Ошибка: {e}")

    # ================= МОДУЛЬ: AUTO-UPDATE =================
    def compare_versions(v1, v2):
        """Сравнивает версии формата x.y.z без внешних библиотек."""
        try:
            p1 = [int(x) for x in v1.split('.')]
            p2 = [int(x) for x in v2.split('.')]
            # Normalize length (1.0 == 1.0.0)
            len_diff = len(p1) - len(p2)
            if len_diff > 0: p2.extend([0] * len_diff)
            elif len_diff < 0: p1.extend([0] * (-len_diff))
            return p1 > p2
        except: return False

    def calculate_file_hash(file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def pac_updater_worker(log_func):
        """
        Monitors list/*.txt and ip/*.txt for changes.
        - Updates PAC file.
        - Optimizes general.txt (removes VPN domains).
        - Triggers Hot Reload for WinWS if strategies/lists change.
        """
        base = get_base_dir()
        
        # Files to monitor
        # PAC relevant
        monitor_vpn = [
            os.path.join(base, "list", "ru.txt"),
            os.path.join(base, "list", "eu.txt"),
            os.path.join(base, "ip", "ru.txt"),
            os.path.join(base, "ip", "eu.txt")
        ]
        
        # General list (for Hot Reload)
        file_general = os.path.join(base, "list", "general.txt")
        file_exclude = os.path.join(base, "list", "exclude.txt")
        
        all_monitor_files = monitor_vpn + [file_general, file_exclude]
        
        def get_file_stats(p):
            """Returns hash for robust change detection"""
            try:
                if os.path.exists(p):
                    with open(p, "rb") as f:
                        content = f.read()
                        return hashlib.md5(content).hexdigest()
            except: pass
            return ""

        def read_general_unique_domains():
            """Reads normalized unique domain entries from general.txt (comments/empty ignored)."""
            result = set()
            try:
                if not os.path.exists(file_general):
                    return result
                with open(file_general, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        raw = line.split("#")[0].strip().lower()
                        if not raw:
                            continue
                        result.add(raw)
            except:
                pass
            return result

        def read_unique_entries(path):
            """Reads normalized unique entries from list/ip text file (comments/empty ignored)."""
            result = set()
            try:
                if not os.path.exists(path):
                    return result
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        raw = line.split("#")[0].strip().lower()
                        if not raw:
                            continue
                        result.add(raw)
            except:
                pass
            return result

        # Helper: Deduplicate List File
        def deduplicate_list_file(f_path):
            """Removes duplicates and empty lines while preserving # version header."""
            try:
                if not os.path.exists(f_path): return False
                
                with open(f_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                
                header = ""
                data = set()
                original_content = "".join(lines)
                
                for line in lines:
                    stripped = line.strip()
                    if not stripped: continue
                    if stripped.startswith("# version:"):
                        header = stripped + "\n"
                        continue
                    if stripped.startswith("#"):
                        # Keep other comments? Or discard? 
                        # Usually user wants to keep comments, but de-duplicate data.
                        # For simplicity, let's keep comments as unique entries if they are not headers.
                        data.add(stripped)
                        continue
                    
                    data.add(stripped.lower())
                
                # Sort data: comments first (but there's only one header usually), then domains
                sorted_data = sorted(list(data))
                new_content = header
                for item in sorted_data:
                    new_content += f"{item}\n"
                
                if new_content != original_content:
                    with open(f_path, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    return True
            except Exception as e:
                safe_trace(f"[Deduplicator] Error processing {os.path.basename(f_path)}: {e}")
            return False

        # Helper: Optimize General List (Remove VPN domains)
        def optimize_general_list():
            """Removes domains from general.txt that are already in VPN lists (ru.txt, eu.txt)"""
            try:
                if not os.path.exists(file_general): return False
                
                # 0. Cross-deduplicate ru.txt and eu.txt (Priority: eu.txt)
                ru_path = os.path.join(base, "list", "ru.txt")
                eu_path = os.path.join(base, "list", "eu.txt")
                
                eu_domains = set()
                if os.path.exists(eu_path):
                    with open(eu_path, "r", encoding="utf-8") as f:
                        for line in f:
                            d = line.split("#")[0].strip().lower()
                            if d and not line.strip().startswith("#"):
                                eu_domains.add(d)
                
                ru_changed = False
                ru_domains_clean = set()
                if os.path.exists(ru_path):
                    with open(ru_path, "r", encoding="utf-8") as f:
                        ru_lines = f.readlines()
                    
                    new_ru_lines = []
                    for line in ru_lines:
                        stripped = line.strip()
                        if not stripped:
                            new_ru_lines.append(line)
                            continue
                        if stripped.startswith("#"):
                            new_ru_lines.append(line)
                            continue
                        
                        d = stripped.split("#")[0].strip().lower()
                        if d in eu_domains:
                            ru_changed = True
                            continue # Keep only in eu.txt
                        
                        new_ru_lines.append(line)
                        ru_domains_clean.add(d)
                    
                    if ru_changed:
                        with open(ru_path, "w", encoding="utf-8") as f:
                            f.writelines(new_ru_lines)
                        log_func("[List] Удалены дубликаты: домены из ru.txt теперь только в eu.txt")

                # 1. Load combined VPN domains for general.txt optimization
                # vpn_domains = eu_domains.union(ru_domains_clean)
                
                # 2. Process General - DISABLED BY USER REQUEST (Feb 2026)
                # We no longer remove domains from general even if they are in VPN lists,
                # because winws strategies might need to be applied even if VPN is active.
                cleaned_count = 0 
                
                if ru_changed:
                    return True # File(s) changed

                    
            except Exception as e:
                safe_trace(f"[Optimizer] Error: {e}")
            return False
        
        # Init state
        # Initial cleanup: Deduplicate everything first
        for f in monitor_vpn:
            deduplicate_list_file(f)
            
        file_hashes = {f: get_file_stats(f) for f in all_monitor_files}
        general_domains_snapshot = read_general_unique_domains()
        entries_snapshot = {f: read_unique_entries(f) for f in (monitor_vpn + [file_exclude])}
        
        # Capture current run ID
        my_run_id = SERVICE_RUN_ID
        
        log_func("[PAC] Мониторинг списков запущен")
        
        while not is_closing:
            if SERVICE_RUN_ID != my_run_id: break
            
            time.sleep(2)
            try:
                # When Nova core is stopped, do not re-apply PAC or trigger restarts.
                # Keep snapshots in sync to avoid false "new entries" after next start.
                if not is_service_active:
                    for f in all_monitor_files:
                        file_hashes[f] = get_file_stats(f)
                    general_domains_snapshot = read_general_unique_domains()
                    for f in (monitor_vpn + [file_exclude]):
                        entries_snapshot[f] = read_unique_entries(f)
                    continue

                vpn_changed = False
                general_changed = False
                exclude_changed = False
                general_new_unique_domains = set()
                vpn_new_unique_count = 0
                exclude_new_unique_count = 0
                
                # Check VPN files
                for f_path in monitor_vpn:
                    current_hash = get_file_stats(f_path)
                    if current_hash != file_hashes[f_path]:
                        prev_entries = entries_snapshot.get(f_path, set())
                        # Deduplicate immediately if changed
                        if deduplicate_list_file(f_path):
                            # Update hash to the cleaned version
                            current_hash = get_file_stats(f_path)
                        cur_entries = read_unique_entries(f_path)
                        entries_snapshot[f_path] = cur_entries
                        vpn_new_unique_count += max(0, len(cur_entries - prev_entries))

                        file_hashes[f_path] = current_hash
                        vpn_changed = True

                # Check General file
                gen_hash = get_file_stats(file_general)
                if gen_hash != file_hashes[file_general]:
                    current_general_domains = read_general_unique_domains()
                    general_new_unique_domains = current_general_domains - general_domains_snapshot
                    general_domains_snapshot = current_general_domains
                    file_hashes[file_general] = gen_hash
                    general_changed = True

                # Check Exclude file
                exc_hash = get_file_stats(file_exclude)
                if exc_hash != file_hashes[file_exclude]:
                    prev_entries = entries_snapshot.get(file_exclude, set())
                    cur_entries = read_unique_entries(file_exclude)
                    entries_snapshot[file_exclude] = cur_entries
                    exclude_new_unique_count = max(0, len(cur_entries - prev_entries))
                    file_hashes[file_exclude] = exc_hash
                    exclude_changed = True
                
                # Logic Flow
                if vpn_changed:
                    # 1. Update PAC
                    if pac_manager:
                        pac_manager.generate_pac()
                        pac_manager.refresh_system_options()
                        log_func("[PAC] Списки VPN обновлены")

                    # 2. Optimize General (might trigger general_changed next loop, or now)
                    if optimize_general_list():
                        # Sync hash/snapshot only (no auto-restart for optimizer side effects).
                        file_hashes[file_general] = get_file_stats(file_general)
                        general_domains_snapshot = read_general_unique_domains()
                        
                restart_reasons = []
                if general_new_unique_domains:
                    restart_reasons.append(f"general +{len(general_new_unique_domains)}")
                if exclude_new_unique_count > 0:
                    restart_reasons.append(f"exclude +{exclude_new_unique_count}")

                if restart_reasons:
                    log_func(f"[Auto] Добавлены новые записи ({', '.join(restart_reasons)}) -> Ядро перезапущено")
                    perform_hot_restart_backend()
                else:
                    if general_changed and IS_DEBUG_MODE:
                        log_func("[Auto] Изменен general.txt без новых доменов (без автоперезапуска).")
                    if exclude_changed and IS_DEBUG_MODE:
                        log_func("[Auto] Изменен exclude.txt без новых записей (без автоперезапуска).")
                    if vpn_changed:
                        if vpn_new_unique_count > 0 and IS_DEBUG_MODE:
                            log_func(f"[Auto] Добавлены новые записи в ru/eu/ip (+{vpn_new_unique_count}) -> обновлен только PAC (без автоперезапуска).")
                        elif IS_DEBUG_MODE:
                            log_func("[Auto] Изменены ru/eu/ip без новых записей (обновлен только PAC, без автоперезапуска).")
                        
            except Exception as e:
                safe_trace(f"[PAC Worker] Error: {e}")
                time.sleep(5)

    def update_ip_cache_worker(paths, log_func):
        """Checks external IP. If changed, clears domain check cache."""
        import requests
        
        # Wait a bit for network to stabilize
        time.sleep(2)
        
        try:
            current_ip = None
            try:
                # Use a reliable IP echo service with timeout
                r = requests.get("https://api.ipify.org", timeout=5)
                if r.status_code == 200:
                    current_ip = r.text.strip()
            except: pass
            
            if not current_ip:
                 safe_trace("[IP Worker] Failed to get external IP")
                 return

            ip_cache_file = os.path.join(get_base_dir(), "temp", "ip_last.txt")
            last_ip = ""
            if os.path.exists(ip_cache_file):
                with open(ip_cache_file, "r") as f:
                    last_ip = f.read().strip()
                    
            if current_ip == last_ip:
                pass # Silent success (User request: reduce log spam)

            else:
                log_func(f"[Init] IP изменился ({mask_ip(last_ip)} -> {mask_ip(current_ip)}). Сброс кэша проверок.")
                try:
                    with check_cache_lock:
                        check_cache.clear()
                        save_json_safe(CHECK_CACHE_FILE, check_cache)
                except: pass
                
                try:
                    with open(ip_cache_file, "w") as f:
                        f.write(current_ip)
                except: pass
                    
        except Exception as e:
            safe_trace(f"[IP Worker] Error: {e}")

    def proxy_watchdog_worker(log_func):
        """Monitors WARP and Opera Proxy, restarts if crashed."""
        def is_local_port_open(port):
            try:
                import socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.6)
                    return s.connect_ex(("127.0.0.1", int(port))) == 0
            except:
                return False

        def is_local_http_proxy_alive(port, timeout=1.5):
            return is_local_http_proxy_responsive(port=port, timeout=timeout)

        my_run_id = SERVICE_RUN_ID
        retry_timestamps = []  # Track retry times
        MAX_RETRIES = 6
        RETRY_WINDOW = 60  # seconds
        RETRY_PAUSE = 3
        CHECK_INTERVAL = 5
        last_opera_port_state = None
        last_opera_issue_state = None
        last_pac_server_state = None
        pac_fail_streak = 0
        opera_bad_proxy_streak = 0
        opera_last_good_ts = 0.0
        opera_next_restart_ts = 0.0
        singbox_next_restart_ts = 0.0
        
        # Keep first PAC/1371 refresh close to startup to minimize DIRECT window for EU domains.
        time.sleep(2)
        
        while not is_closing:
            if SERVICE_RUN_ID != my_run_id: break
            time.sleep(CHECK_INTERVAL)
            
            try:
                # Manual STOP: watchdog must be inert and must not revive EU/SingBox/WARP.
                if not is_service_active:
                    last_opera_port_state = None
                    continue

                now = time.time()
                # Clean old timestamps
                retry_timestamps[:] = [t for t in retry_timestamps if now - t < RETRY_WINDOW]
                
                if len(retry_timestamps) >= MAX_RETRIES:
                    continue  # Rate limit reached, skip
                
                # Check WARP (only if it was ever connected successfully)
                if warp_manager:
                    if getattr(warp_manager, 'is_connected', False):
                        status = warp_manager.get_status()
                        if status and "Disconnected" in status:
                            log_func("[RU] Обнаружено отключение. Переподключение...")
                            retry_timestamps.append(now)
                            time.sleep(RETRY_PAUSE)
                            warp_manager.run_warp_cli("connect")
                            time.sleep(5)
                            new_status = warp_manager.get_status()
                            if new_status and "Connected" in new_status:
                                log_func("[RU] Соединение восстановлено.")
                            else:
                                log_func(f"[RU] Не удалось восстановить: {new_status}")
                
                # Check Opera Proxy availability (process can be None on failed start).
                if opera_proxy_manager:
                    opera_port = int(getattr(opera_proxy_manager, "port", 1371))
                    opera_proc = getattr(opera_proxy_manager, "process", None)
                    opera_proc_dead = bool(opera_proc and opera_proc.poll() is not None)
                    opera_port_alive = is_local_port_open(opera_port)
                    opera_proxy_alive = is_local_http_proxy_alive(opera_port) if opera_port_alive else False
                    opera_owned = bool(getattr(opera_proxy_manager, "owns_process", False))
                    opera_external = bool(getattr(opera_proxy_manager, "using_external", False))
                    if opera_port_alive and opera_proxy_alive:
                        opera_bad_proxy_streak = 0
                        opera_last_good_ts = now
                    elif opera_port_alive and not opera_proxy_alive:
                        opera_bad_proxy_streak += 1
                    else:
                        opera_bad_proxy_streak = 0

                    # Debounce short health-check glitches on 1371 to prevent flapping.
                    opera_usable = bool(opera_port_alive and opera_proxy_alive)
                    if (not opera_usable) and opera_port_alive:
                        if (now - opera_last_good_ts) < 20 and opera_bad_proxy_streak < 3:
                            opera_usable = True

                    need_restart = False
                    if opera_proc_dead:
                        exit_code = opera_proc.returncode
                        if last_opera_issue_state != "proc_dead":
                            log_func(f"[EU] Процесс завершился (код: {exit_code}). Перезапуск...")
                        last_opera_issue_state = "proc_dead"
                        # Read log for details
                        try:
                            if hasattr(opera_proxy_manager, 'log_file') and os.path.exists(opera_proxy_manager.log_file):
                                with open(opera_proxy_manager.log_file, "r", encoding="utf-8", errors="ignore") as f:
                                    lines = f.readlines()
                                    if lines:
                                        log_func("[EU] Лог падения:")
                                        for l in lines[-5:]:
                                            log_func(f" > {l.strip()}")
                        except:
                            pass
                        need_restart = True
                    elif not opera_port_alive:
                        if last_opera_issue_state != "port_down":
                            log_func(f"[EU] Порт {opera_port} недоступен. Запуск/восстановление...")
                        last_opera_issue_state = "port_down"
                        need_restart = True
                    elif not opera_proxy_alive:
                        startup_grace_deadline = float(getattr(opera_proxy_manager, "_startup_grace_deadline", 0.0) or 0.0)
                        in_startup_grace = bool(opera_owned and opera_proc and opera_proc.poll() is None and now < startup_grace_deadline)
                        recent_activity = False
                        try:
                            recent_activity = bool(getattr(opera_proxy_manager, "_has_recent_log_activity", lambda **_: False)(max_age_sec=60))
                        except:
                            recent_activity = False

                        # In grace mode (fresh managed start) or during short transient glitches, avoid restarts.
                        if in_startup_grace or opera_usable or (opera_owned and opera_proc and recent_activity):
                            if in_startup_grace and last_opera_issue_state != "proxy_warmup" and IS_DEBUG_MODE:
                                log_func(f"[EU] Инициализация прокси {opera_port} продолжается (grace).")
                            if in_startup_grace or (opera_owned and opera_proc and recent_activity):
                                last_opera_issue_state = "proxy_warmup"
                            else:
                                last_opera_issue_state = None
                            need_restart = False
                        # For adopted external proxy never force restart/takeover from watchdog.
                        elif opera_external and not opera_owned:
                            if last_opera_issue_state != "proxy_bad_external":
                                log_func(f"[EU] Порт {opera_port} открыт, но внешний прокси не отвечает корректно.")
                            last_opera_issue_state = "proxy_bad_external"
                            need_restart = False
                        # Managed proxy: do not hard-restart on proxy-health probe failures.
                        # Registration/discovery may be slow and aggressive restarts create endless loops.
                        elif opera_bad_proxy_streak >= 3:
                            if last_opera_issue_state != "proxy_bad":
                                log_func(f"[EU] Порт {opera_port} открыт, но прокси не отвечает корректно.")
                            last_opera_issue_state = "proxy_bad"
                            need_restart = False
                        else:
                            need_restart = False
                    elif opera_proc is None:
                        # For adopted external proxy, never force local start/takeover from watchdog.
                        # Otherwise we can get PAC flapping and endless restart attempts.
                        if not opera_external:
                            try:
                                opera_proxy_manager.start()
                                opera_port_alive = is_local_port_open(opera_port)
                                opera_proxy_alive = is_local_http_proxy_alive(opera_port) if opera_port_alive else False
                                opera_usable = bool(opera_port_alive and opera_proxy_alive)
                                opera_owned = bool(getattr(opera_proxy_manager, "owns_process", False))
                                opera_external = bool(getattr(opera_proxy_manager, "using_external", False))
                                if opera_usable:
                                    opera_bad_proxy_streak = 0
                                    opera_last_good_ts = now
                            except:
                                pass
                        last_opera_issue_state = None
                    else:
                        last_opera_issue_state = None

                    if need_restart:
                        if now < opera_next_restart_ts:
                            need_restart = False
                        else:
                            retry_timestamps.append(now)
                            time.sleep(RETRY_PAUSE)
                            opera_proxy_manager.start()
                            opera_port_alive = is_local_port_open(opera_port)
                            opera_proxy_alive = is_local_http_proxy_alive(opera_port) if opera_port_alive else False
                            opera_usable = bool(opera_port_alive and opera_proxy_alive)
                            if opera_usable:
                                opera_bad_proxy_streak = 0
                                opera_last_good_ts = now
                                opera_next_restart_ts = 0.0
                                log_func(f"[EU] Порт {opera_port} восстановлен.")
                                last_opera_issue_state = None
                            else:
                                # Backoff to avoid rapid restart loops when upstream registration is failing.
                                opera_next_restart_ts = now + 30.0
                                if last_opera_issue_state != "recover_failed":
                                    log_func(f"[EU] Не удалось восстановить порт {opera_port}.")
                                last_opera_issue_state = "recover_failed"

                    # Rebuild PAC when 1371 availability changes, so EU routing is always fresh.
                    if last_opera_port_state is None:
                        last_opera_port_state = opera_usable
                        try:
                            if pac_manager:
                                pac_manager.generate_pac()
                                pac_manager.refresh_system_options()
                                state_text = "доступен" if opera_usable else "недоступен"
                                log_func(f"[PAC] Обновлен: порт {opera_port} {state_text}.")
                        except Exception as e:
                            safe_trace(f"[PAC Watchdog] refresh error: {e}")
                    elif opera_usable != last_opera_port_state:
                        last_opera_port_state = opera_usable
                        try:
                            if pac_manager:
                                pac_manager.generate_pac()
                                pac_manager.refresh_system_options()
                                state_text = "доступен" if opera_usable else "недоступен"
                                log_func(f"[PAC] Обновлен: порт {opera_port} {state_text}.")
                        except Exception as e:
                            safe_trace(f"[PAC Watchdog] refresh error: {e}")

                # Keep PAC HTTP server resilient: if it dies, browsers silently go DIRECT.
                if pac_manager:
                    pac_ok = False
                    try:
                        pac_ok = pac_manager._is_pac_server_alive()
                    except:
                        pac_ok = False
                    if last_pac_server_state is None:
                        last_pac_server_state = pac_ok
                    if pac_ok:
                        pac_fail_streak = 0
                    else:
                        pac_fail_streak += 1
                    if not pac_ok and pac_fail_streak >= 3:
                        if last_pac_server_state is not False or pac_fail_streak == 3:
                            log_func("[PAC] Сервер недоступен. Перезапуск...")
                        try:
                            pac_manager.stop_server()
                        except:
                            pass
                        try:
                            pac_manager.start_server()
                            pac_manager.set_system_proxy()
                            pac_ok = pac_manager._is_pac_server_alive()
                        except:
                            pac_ok = False
                        if pac_ok:
                            log_func("[PAC] Сервер восстановлен.")
                            pac_fail_streak = 0
                        else:
                            if last_pac_server_state is not False:
                                log_func("[PAC] Не удалось восстановить сервер PAC.")
                    last_pac_server_state = pac_ok

                # Check SingBox voice tunnel; recover if it died after startup.
                if sing_box_manager and warp_manager and getattr(warp_manager, 'is_connected', False):
                    sb_starting = False
                    try:
                        sb_starting = bool(sing_box_manager.is_startup_in_progress())
                    except:
                        sb_starting = False
                    sb_proc = getattr(sing_box_manager, "process", None)
                    sb_exit_code = None
                    if sb_proc:
                        try:
                            sb_exit_code = sb_proc.poll()
                        except:
                            sb_exit_code = None
                    sb_alive = bool(sb_proc and sb_exit_code is None)
                    if sb_alive:
                        singbox_next_restart_ts = 0.0
                    elif sb_starting:
                        # Prevent race: startup in progress means watchdog must wait.
                        pass
                    elif now < singbox_next_restart_ts:
                        pass
                    else:
                        if sb_proc and sb_exit_code is not None:
                            try:
                                sing_box_manager._handle_runtime_exit(exit_code=sb_exit_code, context="watchdog")
                            except:
                                pass
                        log_func("[SingBox] Процесс неактивен. Перезапуск голосового туннеля...")
                        retry_timestamps.append(now)
                        singbox_next_restart_ts = now + 8.0
                        time.sleep(1.0)
                        try:
                            sing_box_manager.start()
                        except Exception as e:
                            log_func(f"[SingBox] Ошибка автозапуска: {e}")
            except: pass

    def check_and_update_worker(log_func):
        """Фоновая проверка обновлений."""
        # Обновление работает только в скомпилированном виде (.exe)
        # FIX: Debug log to verify start
        
        if "--no-update" in sys.argv:
            log_func("[Update] Автообновление отключено пользователем (--no-update).")
            return

        log_func("[Update] Запуск потока обновлений...") 
        
        # FIX: Robust frozen check for Nuitka onefile
        is_frozen = getattr(sys, 'frozen', False) or sys.argv[0].lower().endswith(".exe")
        
        if not is_frozen:
            log_func(f"[Update] Не скомпилировано (frozen={getattr(sys, 'frozen', False)}). Режим отладки: только проверка версии.")
            # return  <-- FIX: Don't return, allow checking

        try:
            # FIX: Import requests here to ensure it's available in this thread
            import requests
        except ImportError as e:
            log_func(f"[Update] CRITICAL: Ошибка импорта requests: {e}")
            return

        # Capture Run ID to die if Service restarts
        my_run_id = SERVICE_RUN_ID
        
        first_run = True

        while not is_closing:
            # Zombie Killer
            if SERVICE_RUN_ID != my_run_id:
                break
            
            try:
                # 1. Проверка версии
                latest_version = None
                download_url = None
                expected_hash = None
                
                try:
                    session = requests.Session()
                    session.trust_env = False
                    # FIX: Add browser-like headers to prevent throttling and improve stability
                    session.headers.update({
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                        'Accept': '*/*',
                        'Accept-Encoding': 'identity',  # Prevent unintended compression for already compressed binaries
                    })
                    r = session.get(UPDATE_URL, timeout=10)
                    
                    if r.status_code == 200:
                        data = r.json()
                        latest_version = data.get("version")
                        download_url = data.get("url")
                        # Поддержка разных ключей для хеша
                        expected_hash = data.get("sha256") or data.get("hash") or data.get("checksum")
                        # Если формат ключа "algo:hash", убираем префикс
                        if expected_hash and ":" in expected_hash:
                            expected_hash = expected_hash.split(":", 1)[1]
                    else:
                        # Сервер ответил ошибкой (404 и т.д.)
                        if first_run: log_func("[Update] Новая версия программы готовится (Status != 200)")
                        
                except Exception as e:
                    # Ошибка сети/парсинга -> считаем что обновления нет/готовится
                    # FIX: Show error for debug
                    if first_run:
                        log_func(f"[Update] Ошибка получения данных: {e}") 
                        log_func("[Update] Новая версия программы готовится")
                    # Пауза 8 часов
                    first_run = False
                    for _ in range(28800):
                        if is_closing: return
                        time.sleep(1)
                    continue

                if not latest_version or not download_url:
                     # JSON некорректен или нет URL
                    if first_run: log_func("[Update] Новая версия программы готовится (No Data)")
                    first_run = False
                    for _ in range(28800):
                        if is_closing: return
                        time.sleep(1)
                    continue

                # Debug version comparison
                should_update = compare_versions(latest_version, CURRENT_VERSION)
                if first_run and IS_DEBUG_MODE:
                    log_func(f"[Update-Debug] Server: {latest_version}, Local: {CURRENT_VERSION}, Update: {should_update}, Frozen: {is_frozen}")

                if should_update:
                    
                    # FIX: Check frozen status BEFORE downloading
                    if not is_frozen and not sys.argv[0].lower().endswith(".exe"):
                         if first_run: log_func(f"[Update] Найдено обновление: {latest_version}. (Скачивание пропущено: запуск из исходника)")
                         first_run = False
                         for _ in range(28800):
                            if is_closing: return
                            time.sleep(1)
                         continue

                    log_func(f"[Update] Происходит обновление программы до v{latest_version}. Ожидайте.")
                    
                    # 2. Скачивание
                    # FIX: In Nuitka OneFile, sys.executable is the temp python.exe
                    # sys.argv[0] is the actual path to the launched .exe
                    current_exe = sys.argv[0]
                    # На всякий случай нормализуем путь
                    current_exe = os.path.abspath(current_exe)
                    
                    new_exe = current_exe + ".new"
                    
                    log_func(f"[Update] Начало загрузки файла: {download_url}")
                    try:
                        with session.get(download_url, stream=True, timeout=120) as r:
                            r.raise_for_status()
                            total_size = int(r.headers.get('content-length', 0))
                            downloaded = 0
                            last_log_time = 0
                            
                            with open(new_exe, 'wb') as f:
                                # FIX: Increased chunk_size from 8KB to 128KB for significantly better download performance
                                for chunk in r.iter_content(chunk_size=131072):
                                    f.write(chunk)
                                    downloaded += len(chunk)
                                    
                                    # Логируем прогресс каждые 2 секунды или каждые 10MB
                                    cur_time = time.time()
                                    if cur_time - last_log_time > 2 and total_size > 0:
                                        percent = (downloaded / total_size) * 100
                                        log_func(f"[Update] Скачано {downloaded/1024/1024:.1f} MB / {total_size/1024/1024:.1f} MB ({percent:.0f}%)")
                                        last_log_time = cur_time

                    except Exception as e:
                        log_func(f"[Update] FAIL: Не удалось скачать файл обновления: {e}")
                        # Пауза 8 часов
                        first_run = False
                        for _ in range(28800):
                            if is_closing: return
                            time.sleep(1)
                        continue

                    log_func("[Update] Загрузка завершена. Проверка целостности...")

                    # 3. Проверка хеша (если есть)
                    if expected_hash:
                        downloaded_hash = calculate_file_hash(new_exe)
                        if not downloaded_hash or downloaded_hash.lower() != expected_hash.lower():
                            log_func(f"[Update] ОШИБКА: Несовпадение контрольной суммы!")
                            log_func(f"[Update] Ожидалось: {expected_hash}")
                            log_func(f"[Update] Получено:  {downloaded_hash}")
                            try: os.remove(new_exe)
                            except: pass
                            # Пауза перед следующей попыткой
                            for _ in range(3600):
                                if is_closing: return
                                time.sleep(1)
                            continue
                        else:
                            log_func("[Update] Контрольная сумма совпала.")

                    # 4. Установка
                    log_func("[Update] Остановка служб перед обновлением...")
                    
                    # Остановка процессов
                    stop_nova_service(silent=True)
                    # time.sleep(3) # Removed artificial delay for seamless update
                    log_func("[Update] Службы остановлены. Замена файлов...")
                    
                    # Подмена файлов
                    old_exe = current_exe + ".old"
                    try:
                        if os.path.exists(old_exe): os.remove(old_exe)
                        os.rename(current_exe, old_exe)
                        os.rename(new_exe, current_exe)
                        
                        # FIX: Using VBScript for reliable DELAYED restart without console windows
                        # This allows the main process to exit completely before the new one starts
                        
                        vbs_script = os.path.join(os.path.dirname(current_exe), "restart_helper.vbs")
                        
                        # Arguments for the new process
                        # escaping quotes for VBScript can be tricky, so we keep it simple
                        updated_args_str = " ".join([f'"{a}"' for a in sys.argv[1:] if a != "--updated"])
                        if updated_args_str: updated_args_str = " " + updated_args_str
                        
                        # VBScript content
                        # WScript.Sleep 3000 (3 seconds)
                        # Shell.Run path, 1 (SW_SHOWNORMAL), False (Don't wait)
                        # We pass --updated and --cleanup-old-exe
                        
                        vbs_content = f'''
                        WScript.Sleep 3000
                        Set objShell = CreateObject("WScript.Shell")
                        strCmd = """{current_exe}"" --updated --cleanup-old-exe ""{old_exe}""{updated_args_str}"
                        objShell.Run strCmd, 1, False
                        Set objFSO = CreateObject("Scripting.FileSystemObject")
                        ' Self-delete the script after a short delay (best effort)
                        ' objFSO.DeleteFile WScript.ScriptFullName
                        '''
                        
                        try:
                            with open(vbs_script, "w", encoding="utf-8") as f:
                                f.write(vbs_content)
                                
                            # Execute VBScript detached
                            ctypes.windll.shell32.ShellExecuteW(
                                None, 
                                "open", 
                                "wscript.exe", 
                                f'"{vbs_script}"', 
                                None, 
                                0 # SW_HIDE (for wscript, but the app it launches will be normal)
                            )
                        except Exception as e:
                            log_func(f"[Update] VBScript launch failed: {e}. Fallback to direct.")
                             # Last resort fallback
                            subprocess.Popen([current_exe, "--updated", "--cleanup-old-exe", old_exe] + [a for a in sys.argv[1:] if a != "--updated"])
                        
                        os._exit(0)
                        
                    except Exception as e:
                        log_func(f"[Update] Критическая ошибка при замене файла: {e}")
                        # Откат
                        if os.path.exists(old_exe) and not os.path.exists(current_exe):
                            try: os.rename(old_exe, current_exe)
                            except: pass
                        
                        log_func("Обновление программы невозможно автоматически. Перезапустите Nova для установки обновления вручную")
                else:
                    if first_run: log_func("Версия программы актуальна")

            except Exception as e:
                log_func(f"[Update] Ошибка: {e}")
            
            # Пауза 8 часов перед следующей проверкой
            first_run = False
            for _ in range(28800):
                if is_closing: return
                time.sleep(1)
    def learning_data_flush_worker():
        """Периодически сбрасывает кэш обучения на диск."""
        while not is_closing:
            time.sleep(60)
            flush_learning_data()

    # ================= DEPENDENCY DOWNLOADER =================
    def download_dependencies(log_func, status_callback=None):
        """Downloads required binaries if missing."""
        # Allow download in script mode too (for debugging/first run)
        # if not getattr(sys, 'frozen', False): return

        base = get_base_dir()
        bin_dir = os.path.join(base, "bin")
        temp_dir = os.path.join(base, "temp")
        if not os.path.exists(bin_dir):
            os.makedirs(bin_dir)
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)

        # Base URL (Direct GitHub with browser headers - User Request)
        BASE_URL = "https://github.com/confeden/nova_updates/raw/main/bin/"
        
        # Files to check/download
        files = [
            "winws.exe",
            "WinDivert.dll",
            "WinDivert64.sys",
            "cygwin1.dll",
            "warp-cli.exe",
            "warp-svc.exe",
            "opera-proxy.windows-amd64.exe",
            "aws_lc_fips_0_13_7_crypto.dll",
            "aws_lc_fips_0_13_7_rust_wrapper.dll",
            "warp_ipc.dll",
            "wintun.dll",
            "libcronet.dll",
            "sing-box.exe",
            "winws_test.exe"
        ]

        BIN_CHECK_FILE = os.path.join(temp_dir, "bin_check.json")
        
        def _load_bin_check():
            try:
                with open(BIN_CHECK_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except:
                return {}
        
        def _save_bin_check(data):
            try:
                with open(BIN_CHECK_FILE, "w", encoding="utf-8") as f:
                    json.dump(data, f)
            except:
                pass
        
        bin_check = _load_bin_check()
        already_verified = (
            bin_check.get("version") == CURRENT_VERSION
            and isinstance(bin_check.get("ok"), list)
            and set(bin_check["ok"]) >= set(files)
        )

        missing_files = []
        for f in files:
            path = os.path.join(bin_dir, f)
            if not os.path.exists(path) or os.path.getsize(path) == 0:
                missing_files.append(f)

        if not missing_files and not already_verified:
            # Все файлы есть локально, но ещё не проверяли размеры для этой версии.
            # Делаем однократный HEAD-запрос к GitHub и кешируем результат.
            log_func("[Init] Проверка актуальности компонентов (однократно для v{})...".format(CURRENT_VERSION))
            size_mismatch = []
            try:
                import requests
                sess = requests.Session()
                sess.trust_env = False
                for f in files:
                    url = "https://raw.githubusercontent.com/confeden/nova_updates/main/bin/{}".format(f)
                    try:
                        r = sess.head(url, timeout=4)
                        if r.status_code == 200:
                            remote_size = int(r.headers.get("content-length", 0))
                            local_size = os.path.getsize(os.path.join(bin_dir, f))
                            if remote_size > 0 and local_size != remote_size:
                                log_func(f"[Init] Размер файла {f} ({local_size}) ≠ GitHub ({remote_size}). Удаляем.")
                                try: os.remove(os.path.join(bin_dir, f))
                                except: pass
                                size_mismatch.append(f)
                    except:
                        pass
            except:
                pass
            
            if size_mismatch:
                missing_files.extend(size_mismatch)
            else:
                # Все совпало → записываем в кеш, чтобы не проверять повторно
                _save_bin_check({"version": CURRENT_VERSION, "ok": files})
                log_func("[Init] Все компоненты актуальны. Проверка сохранена в кеш.")
        
        if not missing_files:
            return True

        # Сбрасываем кеш — что-то надо скачать
        _save_bin_check({})


        # FIX: Force cleanup processes before attempting to update files (WinError 32 fix)
        try:
            log_func("[Init] Остановка процессов перед обновлением компонентов...")
            subprocess.run(["taskkill", "/F", "/IM", "sing-box.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(["taskkill", "/F", "/IM", "winws.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(["taskkill", "/F", "/IM", "warp-cli.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(["taskkill", "/F", "/IM", "opera-proxy.windows-amd64.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            
            # Force stop driver service
            subprocess.run(["sc", "stop", "windivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW, timeout=5)
            time.sleep(1.0) # Wait for release
        except: pass

        # ZIP Strategy (User Request: Single connection, faster)
        ZIP_URL = "https://github.com/confeden/nova_updates/archive/refs/heads/main.zip"
        zip_path = os.path.join(temp_dir, "update_temp.zip")

        estimated_total_size = 30 * 1024 * 1024

        def _status_progress(percent):
            try:
                pct = int(percent)
            except:
                pct = 0
            if pct < 0:
                pct = 0
            if pct > 100:
                pct = 100
            if status_callback:
                status_callback(f"Загрузка с GitHub {pct}% . . .")

        def _detect_total_size():
            try:
                import requests as _requests
                head_resp = _requests.head(
                    ZIP_URL,
                    allow_redirects=True,
                    timeout=10,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                if head_resp and getattr(head_resp, "ok", False):
                    return int(head_resp.headers.get("content-length", 0) or 0)
            except:
                pass
            return 0

        def _percent_from_file_size(size_bytes, max_cap=99):
            total_ref = known_total_size if known_total_size > 0 else estimated_total_size
            if size_bytes <= 0:
                return 1
            try:
                pct = int((size_bytes / total_ref) * 100)
            except:
                pct = 1
            if pct < 1:
                pct = 1
            if pct > max_cap:
                pct = max_cap
            return pct

        def _monitor_download_process(proc):
            last_pct = -1
            while proc.poll() is None:
                try:
                    current_size = os.path.getsize(zip_path) if os.path.exists(zip_path) else 0
                except:
                    current_size = 0
                pct = _percent_from_file_size(current_size, max_cap=99)
                if pct > last_pct:
                    _status_progress(pct)
                    last_pct = pct
                time.sleep(0.2)

            # Final size probe after process exit.
            try:
                current_size = os.path.getsize(zip_path) if os.path.exists(zip_path) else 0
            except:
                current_size = 0
            pct = _percent_from_file_size(current_size, max_cap=99)
            if pct > last_pct:
                _status_progress(pct)
                last_pct = pct
            return last_pct

        known_total_size = _detect_total_size()
        _status_progress(1)
        log_func(f"[Init] Обнаружено отсутствие {len(missing_files)} компонентов. Скачивание ZIP-архива...")
        
        import requests
        from requests.adapters import HTTPAdapter
        import zipfile
        import shutil

        # Optimize connection
        session = requests.Session()
        retries = HTTPAdapter(max_retries=3, pool_connections=1, pool_maxsize=1)
        session.mount('https://', retries)
        
        # PowerShell Masking
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.22621; en-US) PowerShell/7.4.0",
        })

        download_success = False

        # --- METHOD 1: System Curl (HTTP/2, Faster) ---
        if not download_success:
            curl_path = shutil.which("curl")
            if curl_path:
                log_func(f"[Download] Использование System Curl (HTTP/2) для скорости...")
                try:
                    startupinfo = subprocess.STARTUPINFO()
                    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    
                    process = subprocess.Popen(
                        [curl_path, "-L", "-o", zip_path, ZIP_URL],
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL,
                        startupinfo=startupinfo,
                    )
                    _monitor_download_process(process)
                    if process.returncode == 0 and os.path.exists(zip_path) and os.path.getsize(zip_path) > 0:
                         log_func("[Download] Curl успешно скачал файл.")
                         _status_progress(100)
                         download_success = True
                    else:
                        log_func(f"[Download] Curl завершился с кодом {process.returncode}")
                except Exception as e:
                    log_func(f"[Download] Curl Error: {e}. Пробуем следующий метод...")

        # --- METHOD 2: PowerShell (Native Windows) ---
        if not download_success and shutil.which("powershell"):
            log_func("[Download] Использование PowerShell (Invoke-WebRequest)...")
            try:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                
                # Use Invoke-WebRequest
                ps_cmd = f"Invoke-WebRequest -Uri '{ZIP_URL}' -OutFile '{zip_path}' -UseBasicParsing"

                process = subprocess.Popen(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    startupinfo=startupinfo
                )
                _monitor_download_process(process)
                
                if process.returncode == 0 and os.path.exists(zip_path) and os.path.getsize(zip_path) > 0:
                    log_func("[Download] PowerShell успешно скачал файл.")
                    _status_progress(100)
                    download_success = True
                else:
                    log_func("[Download] PowerShell Error.")
            except Exception as e:
                 log_func(f"[Download] PowerShell Exception: {e}")

        # --- METHOD 3: CertUtil (Native Windows Legacy) ---
        if not download_success and shutil.which("certutil"):
            log_func("[Download] Использование CertUtil...")
            try:
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

                # -urlcache -split -f "url" "file"
                process = subprocess.Popen(
                    ["certutil", "-urlcache", "-split", "-f", ZIP_URL, zip_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    startupinfo=startupinfo
                )
                _monitor_download_process(process)
                
                if process.returncode == 0 and os.path.exists(zip_path) and os.path.getsize(zip_path) > 0:
                    log_func("[Download] CertUtil успешно скачал файл.")
                    _status_progress(100)
                    download_success = True
                else:
                    log_func(f"[Download] CertUtil Error.")
            except Exception as e:
                 log_func(f"[Download] CertUtil Exception: {e}")

        # --- METHOD 4: Python Requests (Fallback) ---
        if not download_success:
                # FALLBACK: Requests
                log_func("[Download] Использование Requests (HTTP/1.1)...")
                with session.get(ZIP_URL, stream=True, timeout=(10, 300)) as r:
                    r.raise_for_status()
                    total_size = int(r.headers.get('content-length', 0))
                    if total_size > 0:
                        known_total_size = total_size
                    downloaded = 0
                    
                    with open(zip_path, 'wb') as f:
                        last_percent = -1
                        for chunk in r.iter_content(chunk_size=256*1024):
                            if chunk:
                                f.write(chunk)
                                downloaded += len(chunk)
                                percent = _percent_from_file_size(downloaded, max_cap=99)
                                if percent > last_percent:
                                    _status_progress(percent)
                                    last_percent = percent
                
                download_success = True # If no exception raised
                _status_progress(100)

        if not download_success:
             raise Exception("Все методы загрузки не удались.")
            
        try:
            log_func("[Init] Архивы загружен. Распаковка...")
            if status_callback: status_callback("РАСПАКОВКА . . .")

            # Extract BIN folder
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # GitHub zip structure: nova_updates-main/bin/file.exe
                # We need to find the prefix
                root_folder = zip_ref.namelist()[0].split('/')[0] # usually repo-branch
                
                for member in zip_ref.namelist():
                    if member.startswith(f"{root_folder}/bin/") and not member.endswith("/"):
                        filename = os.path.basename(member)
                        if not filename: continue
                        
                        # Extract to temp first to avoid AV locks/partial writes in bin
                        temp_extract_path = os.path.join(temp_dir, filename)
                        
                        source = zip_ref.open(member)
                        target = open(temp_extract_path, "wb")
                        with source, target:
                            shutil.copyfileobj(source, target)
                            
                        # Move to bin
                        final_path = os.path.join(bin_dir, filename)
                        if os.path.exists(final_path):
                            try: os.remove(final_path)
                            except: pass
                        
                        try:
                            # Retry loop for moving files (robust against antivirus/driver locks)
                            moved = False
                            for attempt in range(3):
                                try:
                                    shutil.move(temp_extract_path, final_path)
                                    moved = True
                                    break
                                except Exception as move_err:
                                    if attempt < 2: 
                                        time.sleep(1.0)
                                        # Emergency kill again
                                        subprocess.run(["taskkill", "/F", "/IM", "winws.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
                                    else:
                                        raise move_err
                            
                            if not moved: raise Exception("Move failed after retries")

                        except Exception as e:
                            log_func(f"[Init] Ошибка перемещения {filename}: {e}")
                            
            log_func("[Init] Распаковка завершена.")
            
            # Verify missing files again
            still_missing = []
            for f in missing_files:
                 if not os.path.exists(os.path.join(bin_dir, f)) or os.path.getsize(os.path.join(bin_dir, f)) == 0:
                     still_missing.append(f)
            
            if still_missing:
                log_func(f"[Init] Ошибка: Не удалось извлечь {len(still_missing)} файлов из архива!")
                if os.path.exists(zip_path): 
                    try: os.remove(zip_path) 
                    except: pass
                return False
                
            if os.path.exists(zip_path): 
                try: os.remove(zip_path) 
                except: pass
                
            log_func("[Init] Все компоненты успешно загружены.")
            # Сохраняем кеш — файлы свежие, следующий запуск не будет делать HEAD-запросы
            _save_bin_check({"version": CURRENT_VERSION, "ok": files})
            
            # Create winws_test.exe for process isolation
            try:
                w_src = os.path.join(bin_dir, "winws.exe")
                w_dst = os.path.join(bin_dir, "winws_test.exe")
                if os.path.exists(w_src):
                    # FIX: Only copy if missing to avoid locking active test process
                    if not os.path.exists(w_dst):
                        shutil.copy2(w_src, w_dst)
            except: pass
            
            return True
        except Exception as e:
            log_func(f"[Init] Ошибка распаковки: {e}")
            if os.path.exists(zip_path): 
                try: os.remove(zip_path) 
                except: pass
            return False




    SERVICES_RUNNING = False

    def start_services_threads(log_func=None):
        """Helper to start all background threads (Global Context)"""
        global SERVICES_RUNNING
        if log_func is None: log_func = print
        
        # FIX: Prevent duplicate service threads during hot restarts
        if SERVICES_RUNNING:
            safe_trace("[Services] Threads already running. Skipping start_services_threads.")
            return

        SERVICES_RUNNING = True
        
        # FIX: Force reset WinDivert service configuration to fix "Service disabled" errors (WinError 34)
        # This happens if the service was left in a bad state or disabled by previous runs
        try:
            subprocess.run(["sc", "config", "windivert", "start=", "demand"], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(["sc", "stop", "windivert"], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        except: pass
        
        # Ensure path structure is ready
        try:
            paths = ensure_structure()
            safe_trace("[Services] Structure ensured. Checking dependencies...")
        except Exception as e:
            safe_trace(f"[Services] Structure ERROR: {e}")
            return
            
        # Download dependencies before starting threads
        try:
             download_dependencies(log_func)
        except Exception as e:
             log_func(f"[Init] Ошибка проверки зависимостей: {e}")

        safe_trace("[Services] Threads launching...")

        # === PRIORITY SERVICES ===
        # PAC & Watchdog first to ensure connectivity and updates work immediately
        threading.Thread(target=pac_updater_worker, args=(log_func,), daemon=True).start()
        threading.Thread(target=proxy_watchdog_worker, args=(log_func,), daemon=True).start()
        threading.Thread(target=update_ip_cache_worker, args=(paths, log_func), daemon=True).start()
        threading.Thread(target=check_and_update_worker, args=(log_func,), daemon=True).start()
        threading.Thread(target=learning_data_flush_worker, daemon=True).start()

        # === CORE CHECKERS ===
        for _ in range(2): 
            threading.Thread(target=background_checker_worker, args=(log_func,), daemon=True).start()

        threading.Thread(target=periodic_exclude_checker_worker, args=(log_func,), daemon=True).start()
        threading.Thread(target=exclude_auto_monitor_worker, args=(log_func,), daemon=True).start()
        
        # === HEAVY / LOWER PRIORITY ===
        threading.Thread(target=advanced_strategy_checker_worker, args=(log_func,), daemon=True).start()
        threading.Thread(target=payload_worker, args=(log_func,), daemon=True).start()
        threading.Thread(target=vpn_monitor_worker, args=(log_func,), daemon=True).start()
        threading.Thread(target=hard_strategy_matcher_worker, args=(log_func,), daemon=True).start()
        threading.Thread(target=boost_evolution_worker, args=(log_func,), daemon=True).start()
        threading.Thread(target=boost_strategy_matcher_worker, args=(log_func,), daemon=True).start()
        threading.Thread(target=batch_exclude_worker, args=(log_func,), daemon=True).start()
        
        threading.Thread(target=domain_cleaner_worker, args=(log_func,), daemon=True).start()


    def _start_nova_service_impl(silent=False, restart_mode=False):
        global warp_manager, pac_manager, opera_proxy_manager, sing_box_manager, SERVICE_RUN_ID, state_lock

        # Initialize SingBoxManager if not already done
        if 'sing_box_manager' not in globals() or sing_box_manager is None:
             sing_box_manager = SingBoxManager(log_func=log_print)

        # Increment run ID
        try:
            with state_lock:
                SERVICE_RUN_ID += 1
        except: pass

        # === SYNC INIT: Dependencies MUST exist before we try to launch anything ===
        logger = globals().get('log_print', safe_trace)

        pass

        def update_loading_status_sync(msg):
            try:
                if 'status_label' in globals() and 'root' in globals() and root:
                    root.after(0, lambda: status_label.config(text=msg))
            except: pass

        if not restart_mode:
            # CRITICAL: Clear stale system proxy BEFORE any HTTP requests.
            # If Nova was killed (crash/taskkill), the PAC proxy stays in Windows,
            # causing download_dependencies and WARP registration to timeout on dead ports.
            try:
                import winreg
                inet_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0, winreg.KEY_SET_VALUE)
                try:
                    winreg.DeleteValue(inet_key, "AutoConfigURL")
                except FileNotFoundError:
                    pass
                winreg.SetValueEx(inet_key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(inet_key)
            except:
                pass

            if not download_dependencies(logger, status_callback=update_loading_status_sync):
                msg = "Не удалось загрузить необходимые компоненты!\nПроверьте интернет и повторите попытку."
                if not silent:
                    root.after(0, lambda: messagebox.showerror("Ошибка", msg))
                return
            
            # Show "STARTING" only after successful download
            update_loading_status_sync("ЗАПУСК . . .")

            # Kill stale WinWS/driver BEFORE WARP bootstrap, otherwise old filters
            # can block daemon API startup and trigger watchdog panic.
            try:
                logger("[Init] Предочистка WinWS/Windivert перед запуском WARP...")
                for p in [WINWS_FILENAME, "winws.exe", "winws_test.exe"]:
                    try:
                        subprocess.run(
                            ["taskkill", "/F", "/IM", p, "/T"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            timeout=2
                        )
                    except:
                        pass
                subprocess.run(
                    ["sc", "stop", "windivert"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=2
                )
            except:
                pass

        # === ASYNC INIT WRAPPER for background services ===
        def start_bg_services():
            try:
                def safe_log(msg):
                    try: 
                        if 'log_print' in globals(): log_print(msg)
                        else: print(msg)
                    except: pass
                
                # Initialize managers
                global warp_manager, pac_manager, opera_proxy_manager, sing_box_manager
                if not warp_manager: warp_manager = WarpManager(log_func=safe_log)
                if not pac_manager: pac_manager = PacManager(log_func=safe_log)
                
                # sing_box_manager can be None here if not initialized in main
                if not sing_box_manager: 
                    sing_box_manager = SingBoxManager(log_func=safe_log)
                
                if not opera_proxy_manager: opera_proxy_manager = OperaProxyManager(log_func=safe_log)

                # Start Opera proxy early, but WARP daemon bootstrap is deferred until kernel is up.
                threading.Thread(target=opera_proxy_manager.start, daemon=True).start()
                threading.Thread(target=lambda: (pac_manager.start_server(), pac_manager.set_system_proxy()), daemon=True).start()
            except Exception as e:
                safe_trace(f"[Init] BG Services Error: {e}")

        # 1. IMMEDIATE ASYNC START
        if not restart_mode:
            start_bg_services()

        # 2. Kernel Start
        try:
            threading.Thread(target=lambda: _start_nova_service_logic(silent, restart_mode), daemon=True).start()
        except: pass

        # 2. Start Background Services (Async)
        pass


    def _start_nova_service_logic(silent=False, restart_mode=False): # Added restart_mode
        global is_service_active, process, is_closing
        
        logger = globals().get('log_print', print)
        
        # TRACE LOGGING
        if restart_mode and not silent:
            if 'log_print' in globals():
                 log_print("[Init] Ядро перезапущено после изменений в list/general.txt")

        # Сбрасываем флаг завершения при перезапуске, чтобы фоновые проверки возобновились
        is_closing = False
        
        if not is_admin(): 
            root.after(0, lambda: messagebox.showerror("Ошибка", "Нужны права Администратора!"))
            return

        
        exe_path = os.path.join(get_base_dir(), "bin", WINWS_FILENAME)
        if not os.path.exists(exe_path): 
            root.after(0, lambda: messagebox.showerror("Ошибка", f"Файл {WINWS_FILENAME} не найден!"))
            return
        
        # EARLY CLEANUP: Stop old driver + kill old processes. All calls have short timeouts.
        # If any call times out, windivert is in a bad state → auto-recover with sc delete.
        _windivert_stuck = False
        
        # sc stop: if driver was actually running, we MUST wait for full unload before winws starts.
        # 0.8s was previously proven insufficient; 1.2s is required for stable re-attach.
        # On a cold start (driver not loaded), sc stop returns non-zero instantly → skip wait.
        _driver_was_running = False
        try:
             if not restart_mode:
                 _sc_result = subprocess.run(["sc", "stop", "windivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW, timeout=2)
                 _driver_was_running = (_sc_result.returncode == 0)
        except subprocess.TimeoutExpired:
            _windivert_stuck = True
            _driver_was_running = True
        except: pass

        sync_hard_domains_to_strategies(log_print if not silent else None)
        # Wait for WinDivert driver to fully unload before winws.exe tries to re-attach.
        # Without this wait, winws may load a partially-released driver instance that
        # corrupts TCP packets (causing WARP proxy connections to silently fail).
        time.sleep(1.2 if _driver_was_running else 0.1)

        # Kill old winws process
        try:
            subprocess.run(["taskkill", "/F", "/IM", WINWS_FILENAME],
                           creationflags=subprocess.CREATE_NO_WINDOW,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except subprocess.TimeoutExpired:
            _windivert_stuck = True
        except: pass
        
        try:
            subprocess.run(["sc", "stop", "windivert"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           creationflags=subprocess.CREATE_NO_WINDOW, timeout=2)
        except subprocess.TimeoutExpired:
            _windivert_stuck = True
        except: pass
        
        # AUTO-RECOVERY: If windivert driver is stuck (commands timed out),
        # force-delete the service registration. The driver will be re-installed
        # automatically when winws.exe starts next time.
        if _windivert_stuck:
            logger("[Init] WinDivert драйвер завис. Автоматическое лечение (sc delete)...")
            try:
                subprocess.run(["sc", "delete", "windivert"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               creationflags=subprocess.CREATE_NO_WINDOW, timeout=3)
            except: pass
            time.sleep(0.5)
            logger("[Init] WinDivert сброшен. Драйвер будет переустановлен при запуске ядра.")
        
        # Load configs
        global throttled_domains_registry
        throttled_domains_registry = load_throttled_registry()
        if throttled_domains_registry and not silent and not restart_mode:
            log_print(f"[Init] Загружено {len(throttled_domains_registry)} замедленных доменов из реестра")
        
        visited_count = load_visited_domains()
        evo_count = load_strategies_evolution()
        ip_count = load_ip_history()
        if not silent and not restart_mode:
            log_print(f"[Init] Адаптивная система: {visited_count} посещённых доменов, {evo_count} стратегий в эволюции, {ip_count} IP в истории")

        is_service_active = True
        try: restart_requested_event.clear()
        except: pass
        root.after(0, lambda: btn_toggle.config(text="ОСТАНОВИТЬ"))
        root.after(0, lambda: status_label.config(text="АКТИВНО : РАБОТАЕТ", fg=COLOR_TEXT_NORMAL))
        
        paths = ensure_structure()
        ensure_warp_control_exclusions(log_print if not silent else None)
        
        # Гарантируем существование файлов исключений перед запуском winws
        for fpath in [IP_CACHE_FILE, paths['list_exclude_auto']]:
            if not os.path.exists(fpath):
                try:
                    with open(fpath, "w", encoding="utf-8") as f: pass
                except: pass

        if not silent: print(f"Инициализация стратегий из {STRATEGIES_FILENAME}...")

        
        strategies = load_strategies_from_file(paths['strat_json'])
        
        # FIX: Normalize strategies to Lists if they were loaded as Dicts (legacy/update artifact)
        # This prevents "No ports found" error in WinWS
        for k, v in list(strategies.items()):
            if isinstance(v, dict):
                strategies[k] = v.get("args", [])
        
        # FAILSAFE: If strategies are still empty (file read error/race condition), load Defaults
        if not strategies:
             if not silent: print("[Init] Внимание: Стратегии не загружены (0). Используем встроенные настройки по умолчанию.")
             strategies = DEFAULT_STRATEGIES.copy()
        
        if not silent: print(f"Загружено стратегий: {len(strategies)}")
        
        args = [exe_path] 
        
        exclusions = []
        # Check exclusion files and only add if they are not empty (to avoid winws crash)
        for arg_tpl in [("--ipset-exclude", paths['ip_exclude']), 
                        ("--ipset-exclude", IP_CACHE_FILE),
                        ("--hostlist-exclude", paths['list_exclude_auto']),
                        ("--hostlist-exclude", paths['list_exclude'])]:
             if os.path.exists(arg_tpl[1]) and os.path.getsize(arg_tpl[1]) > 0:
                 exclusions.append(f"{arg_tpl[0]}={arg_tpl[1]}")

        try:
            # === FIX: Use list/general.txt directly (User Request) ===
            # Removed temp/general_clean.txt generation logic
            pass
        except: pass
        
        # RESTORED: Global filter generation from v0.995
        all_tcp_conditions = set()
        all_udp_conditions = set()
        
        for strat_name, strat_args in strategies.items():
            t, u = parse_ports_from_args(strat_args)
            all_tcp_conditions.update(t)
            all_udp_conditions.update(u)

        if not all_tcp_conditions and not all_udp_conditions:
             msg = f"!!! ВНИМАНИЕ: Не найдены порты (wf-tcp/wf-udp) для WinWS.\n"
             msg += f"Загружено стратегий: {len(strategies)}\n"
             if strategies:
                 msg += f"Ключи: {list(strategies.keys())[:5]}...\n"
                 if 'general' in strategies:
                      s_gen = strategies['general']
                      msg += f"General ({type(s_gen)}): {str(s_gen)[:100]}"
             
             print(msg)
             if not silent: root.after(0, lambda: messagebox.showwarning("Проблема конфигурации", msg))

        tcp_part = "false"
        if all_tcp_conditions:
            tcp_ports_logic = " or ".join(all_tcp_conditions)
            # Exclude internal range 16000-16500 for safety
            tcp_part = f"(tcp and ({tcp_ports_logic}) and (tcp.SrcPort < 16000 or tcp.SrcPort > 16500))"
        
        udp_part = "false"
        if all_udp_conditions:
            udp_ports_logic = " or ".join(all_udp_conditions)
            udp_part = f"(udp and ({udp_ports_logic}) and (udp.SrcPort < 16000 or udp.SrcPort > 16500))"
            
        global_filter = f"outbound and !loopback and ({tcp_part} or {udp_part})"
        
        # FIX: Pass as two separate arguments to avoid quoting issues with huge limits
        args.extend(["--wf-raw", global_filter])
        if not silent: print(f"[Init] Global filter passed via command line ({len(global_filter)} chars)")

        strat_keys = [k for k in strategies.keys() if k != "general"]
        
        # Приоритет для WARP: перемещаем его в начало списка, чтобы широкие фильтры (как voice) не перехватывали его трафик
        if "warp" in strat_keys:
            strat_keys.remove("warp")
            strat_keys.insert(0, "warp")
        
        # === FIX: Load runtime state to filter blocked services ===
        blocked_state = {}
        try:
             state_path = os.path.join(get_base_dir(), "temp", "checker_state.json")
             if os.path.exists(state_path):
                 with open(state_path, "r", encoding="utf-8") as f:
                     blocked_state = json.load(f)
        except: pass

        num_specific_strats_added = 0
        for strat_name in strat_keys:
            if strat_name.startswith("_"): continue
            
            # Check blockage
            # Logic: If checked=True AND score<=0 -> Service is dead, disable strategy in Main WinWS
            # This logic automatically resets on IP change because 'blocked_state' is reset/cleared by Checker
            is_blocked = False
            if blocked_state.get(f"{strat_name}_checked", False):
                 s_score = blocked_state.get(f"{strat_name}_score", 0)
                 if s_score <= 0:
                      is_blocked = True
            
            if is_blocked:
                 if not silent: print(f"[Init] Пропуск стратегии {strat_name} (сервис заблокирован)")
                 continue

            list_file_path = os.path.join(get_base_dir(), "list", f"{strat_name}.txt")
            list_file_rel = os.path.join("list", f"{strat_name}.txt")
            
            if strat_name == "youtube": list_file_path = paths['list_youtube']; list_file_rel = os.path.relpath(paths['list_youtube'], get_base_dir())
            if strat_name == "discord": list_file_path = paths['list_discord']; list_file_rel = os.path.relpath(paths['list_discord'], get_base_dir())
            
            ip_file_path = os.path.join(get_base_dir(), "ip", f"{strat_name}.txt")
            ip_file_rel = os.path.join("ip", f"{strat_name}.txt")
            
            has_list = os.path.exists(list_file_path) and os.path.getsize(list_file_path) > 0
            has_ip = os.path.exists(ip_file_path) and os.path.getsize(ip_file_path) > 0
            if not has_list and not has_ip and strat_name != "voice": continue

            if num_specific_strats_added > 0:
                args.append("--new")
            
            num_specific_strats_added += 1

            # Формируем контекстные аргументы (списки, исключения), которые должны применяться к каждой части стратегии
            context_args = []
            if strat_name not in ["voice", "telegram", "whatsapp", "warp"]:
                context_args.extend(exclusions)

            if strat_name != "voice":
                # Check if user ALREADY defined hostlist/ipset in strategies.json to avoid duplicates
                current_strategy_args = strategies.get(strat_name, [])
                user_defined_hostlist = any("--hostlist=" in a for a in current_strategy_args)
                user_defined_ipset = any("--ipset=" in a for a in current_strategy_args)

                if strat_name != "cloudflare": 
                    if has_list and strat_name != "warp" and not user_defined_hostlist: 
                        context_args.append(f"--hostlist={list_file_path}")
                    if has_ip and not user_defined_ipset:   
                        context_args.append(f"--ipset={ip_file_path}")
                else:
                    # Cloudflare specific logic
                    if has_list and not user_defined_hostlist: 
                        context_args.append(f"--hostlist={list_file_path}")
            
            args.extend(context_args)
            
            current_strategy_args = strategies.get(strat_name, [])
            for arg in current_strategy_args:
                if not isinstance(arg, str): continue # FIX: Prevent corrupted/nested list args from crashing
                if "=" in arg and ".bin" in arg:
                    k, v = arg.split("=", 1)
                    fname = os.path.basename(v)
                    if os.path.exists(os.path.join(get_base_dir(), "fake", fname)):
                        arg = f"{k}={os.path.join(get_base_dir(), 'fake', fname)}"
                
                if arg == "--new":
                    args.append(arg)
                    args.extend(context_args) 
                elif arg.startswith("--wf-tcp"): args.append(arg.replace("--wf-tcp", "--filter-tcp"))
                elif arg.startswith("--wf-udp"): args.append(arg.replace("--wf-udp", "--filter-udp"))
                else: args.append(arg)

        target_gen_list = paths['list_general']
        # Removed "Smart Clean" logic as per user request (restore v0.996 behavior)


        gen_list_exists = os.path.exists(target_gen_list) and os.path.getsize(target_gen_list) > 0
        
        # FIX: Check if General is blocked
        is_gen_blocked = False
        if blocked_state.get("general_checked", False) and blocked_state.get("general_score", 0) <= 0:
             is_gen_blocked = True
        
        if is_gen_blocked:
             if not silent: print("[Init] Пропуск General стратегии (сервис заблокирован)")
        elif gen_list_exists or os.path.exists(paths['ip_general']):
            if num_specific_strats_added > 0:
                args.append("--new")
            
            # Define common args for General strategy reuse
            general_common_args = []
            general_common_args.extend(exclusions)
            if gen_list_exists:
                 general_common_args.append(f"--hostlist={target_gen_list}")
            
            # Add ipset if exists
            if os.path.exists(paths['ip_general']) and os.path.getsize(paths['ip_general']) > 0:
                 general_common_args.append(f"--ipset={paths['ip_general']}")

            args.extend(general_common_args)
            
            # DEBUG: Print final args for general strategy
            # print(f"[Debug] General Args: {general_common_args}")
                
            for arg in strategies.get("general", []):
                # FIX: Harden against corrupted JSON (lists inside lists)
                if not isinstance(arg, str):
                     if IS_DEBUG_MODE: print(f"[Warning] Invalid arg type in general strategy: {type(arg)} - {arg}")
                     continue

                if "=" in arg and ".bin" in arg:
                    k, v = arg.split("=", 1)
                    fname = os.path.basename(v)
                    if os.path.exists(os.path.join(get_base_dir(), "fake", fname)):
                        arg = f"{k}={os.path.join(get_base_dir(), 'fake', fname)}"

                if arg == "--new":
                    args.append(arg)
                    args.extend(general_common_args) 
                elif arg.startswith("--wf-tcp"): args.append(arg.replace("--wf-tcp", "--filter-tcp"))
                elif arg.startswith("--wf-udp"): args.append(arg.replace("--wf-udp", "--filter-udp"))
                else: args.append(arg)
        else:
             if not silent: print("[Init] General список пуст. Общая стратегия не применена.")
        
        full_command_parts = [exe_path]
        for arg in args[1:]:
            if arg == "--debug=1": continue
            if arg.startswith("--wf-raw="):
                val = arg.split("=", 1)[1]
                full_command_parts.append(f'--wf-raw="{val}"')
            elif "=" in arg and ("\\" in arg or "/" in arg or " " in arg):
                # Don't add quotes here, they might be added by shell or confusing in debug
                full_command_parts.append(arg)
            else:
                full_command_parts.append(arg)
                
        # FIX: Absolute paths for copy buffer
        abs_parts = []
        for part in full_command_parts:
            # Check if part looks like a relative path to existing file
            if os.path.exists(part):
                 abs_parts.append(os.path.abspath(part))
            else:
                 abs_parts.append(part)
        
        full_command_abs = " ".join(abs_parts)
        
        def insert_cmd_link():
            if not log_text_widget: return
            tag_name = f"cmd_link_{int(time.time()*1000)}"
            def copy_cmd(e):
                root.clipboard_clear(); root.clipboard_append(full_command_abs); root.update()
                print("[Info] Команда скопирована.")
            # FIX: Removed extra newline
            log_text_widget.insert(tk.END, "Нажмите чтобы скопировать команду запуска winws\n", tag_name)
            log_text_widget.tag_config(tag_name, foreground=COLOR_TEXT_NORMAL, underline=True)
            log_text_widget.tag_bind(tag_name, "<Button-1>", copy_cmd)

        if not silent: root.after(0, insert_cmd_link)

        def run_process():
            global process, is_closing, is_service_active, nova_service_status, is_restarting
            
            
            safe_trace(f"[run_process] Thread started. Active={is_service_active}")
            
            # PREVENT RESTART if stopped (unless explicitly restarting)
            if not is_service_active and not is_closing and not is_restarting:
                safe_trace("[run_process] Aborting: inactive/closing.")
                return

            # --- Smart Startup Retry Loop ---
            max_retries = 3
            retry_delay = 0.5
            
            for attempt in range(max_retries + 1):
                try:
                    # Debug logging (Only if --debug flag is present)
                    if IS_DEBUG_MODE and attempt == 0:
                        try:
                            size = os.path.getsize(exe_path)
                            print(f"[Debug] winws.exe ({size} bytes)")
                        except: print("[Debug] winws.exe missing/error")
                        print(f"[Debug] CMD: {full_command_abs}")

                    if not silent and attempt == 0:
                        log_print("Запуск ядра (subprocess)...")
                        
                        log_print("Ядро активно")
                        if IS_DEBUG_CLI:
                            cmd_str = subprocess.list2cmdline(args)
                            log_print(f"[Debug] CmdLine: {cmd_str}")
                    else:
                        if not silent and attempt > 0: print(f"[Info] Попытка запуска #{attempt+1}...")

                    # Launch via subprocess (LOCAL variable only initially)
                    with winws_startup_lock:
                        proc = subprocess.Popen(args, cwd=get_base_dir(), 
                                                        stdout=subprocess.PIPE, 
                                                        stderr=subprocess.STDOUT,
                                                        stdin=subprocess.DEVNULL, 
                                                        text=True, 
                                                        creationflags=subprocess.CREATE_NO_WINDOW, 
                                                        encoding='utf-8',
                                                        errors='replace', 
                                                        bufsize=1)
                    
                    # NOTE: Do NOT set 'process = proc' yet! 
                    # This prevents StrategyChecker from detecting it as "Active but Crashed" during the 1.0s wait.
                    
                    # --- Smart Startup Check ---
                    time.sleep(0.2) # Wait briefly to verify start (long wait no longer needed due to preventive cleanup)
                    
                    if proc.poll() is not None:
                        # Process died immediately
                        exit_code = proc.poll()
                        if attempt < max_retries:
                            # === FIX: Check for Service Disabled Error (Output-based) ===
                            # WinWS prints: "error opening filter: The service cannot be started..."
                            captured_output = []
                            try:
                                for line in proc.stdout: captured_output.append(line)
                            except: pass
                            combined_output = "".join(captured_output)
        
                            if "cannot be started" in combined_output and "disabled" in combined_output:
                                 if not silent: log_print(f"[Error] Служба WinDivert отключена. Попытка включения...")
                                 repair_windivert_driver(log_print if not silent else None)
                                 time.sleep(1.0)
                                 continue

                             # FIX: Special handling for Code 177 (Driver Missing/Corrupt)
                            if exit_code == 177:
                                if not silent: log_print(f"[Error] Сбой драйвера (Код 177). Попытка лечения #{attempt+1}...")
                                repair_windivert_driver(log_print if not silent else None)
                                # Increase delay for driver to settle
                                time.sleep(1.0)
                                continue

                            # FIX: Handling for Code 34 (Service Disabled)
                            if exit_code == 34:
                                if not silent: log_print(f"[Error] Драйвер отключен (Код 34). Включение...")
                                repair_windivert_driver(log_print if not silent else None)
                                time.sleep(1.0)
                                continue

                            # Downgrade to Info for first attempt (Driver Busy common scenario)
                            msg_type = "Info" if (attempt == 0 and exit_code == 1) else "Warning"
                            msg_text = "Драйвер занят, ожидание..." if (attempt == 0 and exit_code == 1) else f"Ядро упало сразу после запуска (код {exit_code})."
                            
                            if not silent: print(f"[{msg_type}] {msg_text} Повтор через {retry_delay}с...")
                            time.sleep(retry_delay)
                            continue
                        else:
                            # CRITICAL: If we failed 3 times, we MUST show the logs to know WHY.
                            # Capture output from the dead process
                            failed_out = []
                            try:
                                for line in proc.stdout:
                                    failed_out.append(line.strip())
                            except: pass
                            
                            print(f"\n[Error] WinWS не смог запуститься после {max_retries} попыток (код {exit_code}).")
                            print("Лог падения:")
                            for l in failed_out: print(f"  > {l}")
                                
                            raise Exception(f"WinWS failed to start (Exit Code {exit_code})")
                    else:
                         # Process is stable -> NOW we expose it to the system
                         process = proc 
                         nova_service_status = "Running"
                         # Reset Restart Flag
                         is_restarting = False
                         
                         # Update UI Status
                         if not silent and root:
                             root.after(0, lambda: status_label.config(text="АКТИВНО : РАБОТАЕТ", fg=COLOR_TEXT_NORMAL))
                             root.after(0, lambda: btn_toggle.config(text="ОСТАНОВИТЬ"))

                         # Start WARP only AFTER WinWS core is confirmed running.
                         if not restart_mode:
                             try:
                                 wm = globals().get("warp_manager")
                                 if wm:
                                     if not silent:
                                         log_print("[Init] Запуск WARP после старта ядра...")
                                     threading.Thread(target=wm.start, daemon=True).start()
                             except Exception as _e:
                                 if IS_DEBUG_MODE and not silent:
                                     log_print(f"[Init] Ошибка отложенного запуска WARP: {_e}")
                         
                         # === ASYNC START: Strategy Checker ===
                         # Launching checker system ONLY after main core is confirmed stable
                         # and ONLY if this is NOT a Hot-Restart (where it's already running).
                         if not is_restarting:
                             threading.Thread(target=lambda: init_checker_system(log_print), daemon=True).start()
                         break

                except Exception as e:
                     if attempt < max_retries:
                         time.sleep(retry_delay)
                         continue
                     else:
                         if not is_closing: print(f"\nCRASH: {e}\n")
                         return

            # Main Output Loop
            try:
                output_history = collections.deque(maxlen=20)
                
                for line in proc.stdout:
                    # REMOVED: if is_closing: break (Capture all crash logs)
                    
                    line_strip = line.strip()
                    if not line_strip: continue
                    
                    output_history.append(line_strip)
                    
                    # FIX: Always show output in debug mode only
                    if IS_DEBUG_MODE:
                        print(f"[WinWS] {line_strip}")
                    
                    # Expanded keyword list to catch more startup errors
                    if any(x in line_strip for x in ["Host", "fail", "add", "Error", "could not read", "windivert", "filter", "must specify", "unknown option", "parameter"]):
                         if "auto hostlist" not in line_strip.lower():
                             if not IS_DEBUG_MODE: # Avoid double print
                                 print(line_strip.replace(get_base_dir(), "."))

                    # Logic for adaptive system (capture domains)
                    try:
                        host_match = re.search(r"(?:Host|SNI|hostname)[:=]\s*([a-zA-Z0-9.-]+\.[a-z]{2,})", line_strip, re.IGNORECASE)
                        if host_match:
                            d_check = host_match.group(1).lower()
                            if not is_domain_excluded(d_check) and not is_garbage_domain(d_check):
                                current_time = time.time()
                                if d_check not in checked_domains_cache or (current_time - checked_domains_cache[d_check] > 60):
                                    checked_domains_cache[d_check] = current_time
                                    check_queue.put(d_check)
                    except: pass

                # CRITICAL FIX: Smart Conditional Crash Log
                exit_code = proc.poll()
                
                if exit_code is not None and exit_code != 0:
                    # Short message for everyone
                    print(f"\n[Warning] Ядро WinWS завершило работу (код {exit_code}).")
                    
                    # Detailed dump only for DEBUG
                    if IS_DEBUG_MODE:
                        print("Последние сообщения:")
                        for l in output_history:
                            print(f"  > {l}")
                    else:
                        print("Запустите с --debug для получения подробного лога.")
                
                if not is_closing and is_service_active:
                     if exit_code is not None and exit_code != 0: 
                        # Ignore if we are explicitly restarting
                        if is_restarting:
                             if IS_DEBUG_MODE: print("[Debug] Игнорирование 'падения' из-за рестарта.")
                             return

                        # UI Update only if we thought it was active
                        if is_service_active:
                            is_service_active = False
                            if root:
                                root.after(0, lambda: btn_toggle.config(text="ЗАПУСТИТЬ"))
                                root.after(0, lambda: status_label.config(text="ОСТАНОВЛЕНО (СБОЙ)", fg=COLOR_TEXT_FAIL))
            except Exception as e: 
                if not is_closing: print(f"\nCRASH: {e}\n")

        # Start the thread, but verify we are still active!
        # Start the thread, but verify we are still active!
        if is_service_active and not is_closing:
             threading.Thread(target=run_process, daemon=True).start()
             
             # FIX: ONLY show startup message and re-init checkers on COLD START
             # On Hot-Restart (strategy change), background tasks are already running.
             if not restart_mode:
                 log_print("[Service] Запуск фоновых процессов...")
                 global_logger = globals().get('log_print', print)
                 safe_trace("[run_process] Launching start_services_threads...")
                 threading.Thread(target=start_services_threads, args=(global_logger,), daemon=True).start()
             else:
                 if IS_DEBUG_MODE: safe_trace("[run_process] Hot-Restart detected, skipping threads launch.")

    def stop_nova_service(silent=False, wait_for_cleanup=False, restart_mode=False):
        global is_service_active, process, is_closing, nova_service_status, SERVICES_RUNNING, SERVICE_RUN_ID
        managed_opera_owned = False
        
        # === НЕМЕДЛЕННОЕ обновление состояния ===
        if not restart_mode:
            is_service_active = False
            # FIX: Only set is_closing in on_closing() to allow background workers (like VPN monitor)
            # to continue running during a manual stop or VPN pause.
            SERVICES_RUNNING = False
            # Invalidate watchdog/checker threads from the current run to prevent post-stop revivals.
            try:
                SERVICE_RUN_ID += 1
            except:
                pass
        
        if not silent: 
            print("Остановка...")
            nova_service_status = "Stopped"
        if not silent: 
            log_print("[Service] Остановка фоновых процессов и ядра...")
            log_print("Система остановлена")
        
        # === НЕМЕДЛЕННОЕ обновление UI ===
        if root and not restart_mode:
            root.after(0, lambda: btn_toggle.config(text="ЗАПУСТИТЬ"))
            root.after(0, lambda: status_label.config(text="ОСТАНОВЛЕНО", fg=COLOR_TEXT_FAIL))
        
        # === КРИТИЧНО: Восстанавливаем системный прокси при остановке ===
        # Иначе браузер не сможет подключиться к сайтам после остановки Nova
        if not restart_mode:
            try:
                if pac_manager:
                    pac_manager.restore_system_proxy()
                    pac_manager.stop_server()
                if opera_proxy_manager:
                    managed_opera_owned = bool(getattr(opera_proxy_manager, "owns_process", False))
                    opera_proxy_manager.stop()
                if 'sing_box_manager' in globals() and sing_box_manager: sing_box_manager.stop()
                if warp_manager:
                    try:
                        warp_manager._set_service_proxy_environment(enable_proxy=False)
                    except:
                        pass
                    warp_manager.stop()
            except Exception as e:
                print(f"[Cleanup] Ошибка восстановления прокси: {e}")
        
        # === Асинхронное завершение процессов (в отдельном потоке, без блокировки UI) ===
        def cleanup_processes():
            """Завершает процессы в фоновом потоке без блокировки UI"""
            time.sleep(0.05)  # Minimize wait
            
            # Сохраняем статистику перед остановкой (чтобы не терять данные при рестарте)
            try: save_visited_domains()
            except: pass
            
            global process
            if process:
                try:
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], 
                                 creationflags=subprocess.CREATE_NO_WINDOW, 
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except:
                    try: process.kill()
                    except: pass
                finally:
                    process = None
            
            # Убиваем оставшиеся процессы по имени
            time.sleep(0.1)
            try:
                # FIX: Hide debug message unless in debug mode
                if not silent and IS_DEBUG_MODE: print("[Debug] Убиваем дочерние процессы...")
                subprocess.run(["taskkill", "/F", "/IM", WINWS_FILENAME], 
                             creationflags=subprocess.CREATE_NO_WINDOW, 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # Cleanup test instances too (ONLY if not restart_mode)
                if not restart_mode:
                    subprocess.run(["taskkill", "/F", "/IM", "winws_test.exe"],
                                 creationflags=subprocess.CREATE_NO_WINDOW,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(["taskkill", "/F", "/IM", "sing-box.exe"],
                                 creationflags=subprocess.CREATE_NO_WINDOW,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if managed_opera_owned:
                        for _proc_name in [
                            "opera-proxy.windows-amd64.exe",
                            "opera-proxy.windows-amd64",
                            "opera-proxy.exe",
                            "opera-proxy",
                        ]:
                            try:
                                subprocess.run(["taskkill", "/F", "/IM", _proc_name],
                                             creationflags=subprocess.CREATE_NO_WINDOW,
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            except:
                                pass
            except: pass
            
            # FIX: Force Driver Stop to release resources (but do not delete, to avoid startup delay/lock)
            try:
                if not restart_mode:
                    subprocess.run(["sc", "stop", "windivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            except: pass
            
            # Обновляем general после завершения
            try: smart_update_general()
            except: pass
            
            if not silent: 
                log_print("[Service] Все процессы завершены.")
                print("Готово.\n")
        
        if wait_for_cleanup:
             # Run synchronously for exit
             cleanup_processes()
        else:
             # Запускаем очистку в отдельном потоке (daemon, чтобы не блокировал выход)
             threading.Thread(target=cleanup_processes, daemon=True).start()

    def perform_hot_restart():
        """Перезапускает только основное ядро, не прерывая тесты и работу сервиса."""
        if not is_service_active: return
        
        # Log to main window if possible
        try:
             log_print("[Auto-Restart] Перезапуск ядра без прерывания тестов...")
        except: 
             print("[Auto-Restart] Перезапуск ядра без прерывания тестов...")

        # Stop main process only (restart_mode=True)
        # This skips killing tests and skips stopping the driver
        # FIX: Wait for cleanup to prevent race condition (killing new process)
        stop_nova_service(silent=True, restart_mode=True, wait_for_cleanup=True)
        
        # FIX: Delay to release file handles
        time.sleep(1.0)
        
        # Start main process again
        start_nova_service(silent=True, restart_mode=True)
        
        try:
             log_print("[Auto-Restart] Ядро перезапущено.")
        except: pass

    # === SPAM PROTECTION & SEQUENTIAL EXECUTION ===
    toggle_queue = queue.Queue()
    
    def toggle_worker():
        while True:
            try:
                cmd = toggle_queue.get()
                
                # Check current state BEFORE action
                is_running = (process is not None)
                
                if is_running:
                    # Request STOP
                    stop_nova_service()
                    # Wait for process to die (max 10s)
                    for _ in range(50):
                         if process is None: break
                         time.sleep(0.2)
                else:
                    # Request START
                    # Increment Global Run ID to kill any zombie tasks from previous run
                    try:
                        global SERVICE_RUN_ID
                        SERVICE_RUN_ID += 1
                    except: pass

                    if is_vpn_active: # Check VPN again in worker
                         root.after(0, lambda: messagebox.showinfo("VPN активен", "Nova не может быть запущен, пока активно VPN-соединение."))
                    else:
                        start_nova_service()
                        # Wait for process to appear (max 15s)
                        for _ in range(75):
                             if process is not None: break
                             time.sleep(0.2)
                
                toggle_queue.task_done()
                # Small pause to prevent rapid-fire visual glitching
                time.sleep(0.5) 
            except Exception as e:
                print(f"Worker Error: {e}")

    # Launch worker daemon
    threading.Thread(target=toggle_worker, daemon=True).start()

    def toggle_service():
        if is_vpn_active:
            messagebox.showinfo("VPN активен", "Nova не может быть запущен, пока активно VPN-соединение.")
            return
            
        # Anti-Spam: Ignore if queue has > 1 pending items (Current action + 1 pending is Max)
        if toggle_queue.qsize() >= 2:
            return 
            
        toggle_queue.put("toggle")

    def on_closing():
        global is_closing, process
        
        # Захватываем геометрию в главном потоке ДО уничтожения/скрытия окна
        main_geo = None
        log_geo = None
        try:
            main_geo = root.geometry()
            if log_window and tk.Toplevel.winfo_exists(log_window):
                log_geo = log_window.geometry()
        except: pass
        
        # === VISUAL SPEEDUP: Hide windows immediately ===
        try:
            if log_window and tk.Toplevel.winfo_exists(log_window):
                log_window.withdraw()
            root.withdraw()
        except: pass
        
        # Ensure tray icon is removed
        try: cleanup_tray()
        except: pass

        # FIX: Set is_closing FIRST so that background workers know we are exiting
        is_closing = True 
        
        def _heavy_cleanup():
            """All potentially-blocking cleanup. Runs in a thread with hard timeout."""
            try:
                # Restore Proxy first!
                if pac_manager:
                    pac_manager.restore_system_proxy()
                    pac_manager.stop_server()
            except: pass
            
            try:
                if warp_manager:
                    try: warp_manager.run_warp_cli("disconnect", timeout=3)
                    except: pass
                    warp_manager.is_connected = False
            except: pass
            
            try:
                if 'sing_box_manager' in globals() and sing_box_manager:
                    sing_box_manager.stop()
            except: pass
            
            # Save state
            try:
                state_to_save = {}
                if main_geo: state_to_save["main_geometry"] = main_geo
                if log_geo: state_to_save["log_size"] = log_geo
                if state_to_save:
                    save_window_state(**state_to_save)
            except: pass
            
            try:
                if dns_manager: dns_manager.save_cache()
                save_visited_domains()
                save_ip_history()
                save_exclude_auto_checked()
                flush_learning_data()
            except: pass
            
            try:
                queue_list = []
                while not check_queue.empty():
                    try: queue_list.append(check_queue.get_nowait())
                    except: break
                if queue_list:
                    with open(PENDING_CHECKS_FILE, "w", encoding="utf-8") as f:
                        json.dump(queue_list, f)
            except: pass
        
        def _force_kill_all():
            """Kill every child process. Fast, no waits."""
            for proc_name in [WINWS_FILENAME, "winws.exe", "winws_test.exe", "sing-box.exe", "warp-svc.exe", "warp-cli.exe",
                              "opera-proxy.windows-amd64.exe", "opera-proxy.exe"]:
                try:
                    subprocess.run(["taskkill", "/F", "/IM", proc_name],
                                   creationflags=subprocess.CREATE_NO_WINDOW,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
                except: pass
            try:
                subprocess.run(["sc", "stop", "CloudflareWARP"],
                               creationflags=subprocess.CREATE_NO_WINDOW,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            except: pass
            try:
                subprocess.run(["sc", "stop", "windivert"],
                               creationflags=subprocess.CREATE_NO_WINDOW,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            except: pass
            if process:
                try:
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)],
                                   creationflags=subprocess.CREATE_NO_WINDOW,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
                except: pass
        
        # Run heavy cleanup in thread with HARD 5-second timeout
        cleanup_thread = threading.Thread(target=_heavy_cleanup, daemon=True)
        cleanup_thread.start()
        cleanup_thread.join(timeout=5)
        
        # Force-kill all child processes (always, even if cleanup succeeded)
        try: _force_kill_all()
        except: pass

        # Немедленно закрываем окно и выходим
        try: root.destroy()
        except: pass
        os._exit(0)

    # === HOT SWAP COOLDOWN ===
    _hot_swap_last_call = [0]  # Mutable container for closure
    _hot_swap_cooldown = 5  # Seconds between restarts
    
    def perform_hot_restart_backend():
        """
        Мгновенный перезапуск только ядра WinWS (Backend) для применения новых стратегий.
        Не останавливает GUI и потоки проверок.
        """
        global process, is_service_active
        
        # Debouncing: Prevent rapid restarts that overload WinDivert driver (Code 177 fix)
        now = time.time()
        if now - _hot_swap_last_call[0] < _hot_swap_cooldown:
            if IS_DEBUG_MODE: print("[HotSwap] Пропуск (cooldown)")
            return
        _hot_swap_last_call[0] = now
        
        # log_print("[HotSwap] Применение новых параметров (WinWS Reset)...")
        # Optimized log to avoid clutter, maybe just print to console or debug log?
        if IS_DEBUG_MODE: print("[HotSwap] Перезапуск ядра...")
        
        # 1. Kill backend
        if process:
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], 
                             creationflags=subprocess.CREATE_NO_WINDOW, 
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                process = None
            except: pass
        
        # Ensure dead
        try:
             subprocess.run(["taskkill", "/F", "/IM", WINWS_FILENAME], 
                          creationflags=subprocess.CREATE_NO_WINDOW, 
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except: pass

        time.sleep(2.0) # Increased breath for WinDivert to release resources
        
        # 2. Restart via start_nova_service (Global context)
        # Flag restart to prevent old thread from reporting Crash
        global is_restarting
        is_restarting = True
        
        if is_service_active and not is_closing:
             # Call start_nova_service which is Thread-Safe (uses root.after for UI)
             # We use a lambda to pass arguments
             if root:
                 root.after(0, lambda: start_nova_service(silent=True, restart_mode=True))
                 if IS_DEBUG_MODE: print("[HotSwap] Запрошен перезапуск через start_nova_service (Hot-Restart Mode).")
             else:
                 # Fallback
                 threading.Thread(target=start_nova_service, args=(True, True), daemon=True).start()

    def launch_background_tasks():
        """Запуск тяжелых фоновых задач ПОСЛЕ отображения окна — в ФОНОВОМ ПОТОКЕ."""
        def _bg_tasks_worker():
            global dns_manager
            try:
                # 1. Инициализация DNS Manager (тяжелая операция)
                if dns_manager is None:
                     dns_manager = DNSManager(get_base_dir())
                

                # Инициализация систем (перенесено из main)
                clean_hard_list()
                log_previous_session_results(log_print) # Вывод результатов прошлой сессии
                
                # Check if updated flag was passed (set in main's ARGS_PARSED global)
                try:
                    if ARGS_PARSED.get('updated', False):
                        log_print("Установлена последняя версия Nova.")
                        # Сообщаем об очистке, если она была (DISABLED per user request)
                        if OLD_VERSION_CLEANED:
                             if IS_DEBUG_MODE: log_print("Следы прежней версии программы удалены")
                    
                    if ARGS_PARSED.get('fresh', False):
                        log_print("Запуск с флагом --fresh: Временные файлы и состояние стратегий сброшены.")

                except NameError:
                    pass
                    
                # === MIGRATION: Auto-convert Legacy Strategy Files to Modern Format ===
                def migrate_service_strategies_format(log_func):
                    target_files = ["youtube.json", "discord.json", "cloudflare.json", "whatsapp.json", "telegram.json"]
                    migrated_count = 0
                    
                    for fname in target_files:
                        try:
                            fpath = os.path.join(get_base_dir(), "strat", fname)
                            if not os.path.exists(fpath): continue
                            
                            data = load_json_robust(fpath)
                            if not data: continue
                            
                            new_data = None
                            needs_save = False
                            
                            # Case 1: Legacy Dict {"strat_name": [args], ...} (No "strategies" key)
                            if isinstance(data, dict) and "strategies" not in data:
                                new_strats = []
                                for k, v in data.items():
                                    if k == "version": continue
                                    new_strats.append({"name": k, "args": v})
                                new_data = {"version": CURRENT_VERSION, "strategies": new_strats}
                                needs_save = True
                                log_func(f"[Migration] Сконвертирован {fname} (Legacy Dict -> Modern)")
                            
                            # Case 2: List [ {name, args}, ... ] (Intermediate)
                            elif isinstance(data, list):
                                new_data = {"version": CURRENT_VERSION, "strategies": data}
                                needs_save = True
                                log_func(f"[Migration] Сконвертирован {fname} (List -> Modern)")
                                
                            if needs_save and new_data:
                                save_json_safe(fpath, new_data)
                                migrated_count += 1
                                
                        except Exception as e:
                            pass
                    
                    if migrated_count > 0:
                         log_func(f"[Migration] Успешно обновлен формат у {migrated_count} файлов стратегий.")

                migrate_service_strategies_format(log_print)
            except Exception as e:
                try: print(f"[BG Tasks] Error: {e}")
                except: pass
        
        threading.Thread(target=_bg_tasks_worker, daemon=True).start()

    def create_round_rect_img(width, height, radius, color, alpha=255):
        """Генерирует изображение закругленного прямоугольника с поддержкой Alpha-канала"""
        from PIL import Image, ImageDraw, ImageTk, ImageFilter
        width = int(width); height = int(height); radius = int(radius)
        # Создаем пустое изображение с альфа-каналом
        img = Image.new('RGBA', (width, height), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        # Получаем RGB цвет из Tkinter названия/hex
        if root:
            rgb = root.winfo_rgb(color)
            fill_color = (rgb[0]//256, rgb[1]//256, rgb[2]//256, alpha)
        else:
            fill_color = (128, 128, 128, alpha)
            
        draw.rounded_rectangle((0, 0, width, height), radius=radius, fill=fill_color)
        return ImageTk.PhotoImage(img)

    def get_darker_rgb(color, factor=0.6):
        if not root: return (50, 50, 50)
        try:
            rgb = root.winfo_rgb(color)
            return (int(rgb[0]/256 * factor), int(rgb[1]/256 * factor), int(rgb[2]/256 * factor))
        except: return (50, 50, 50)

    def get_rgb(color):
        if not root: return (128, 128, 128)
        try:
            rgb = root.winfo_rgb(color)
            return (int(rgb[0]/256), int(rgb[1]/256), int(rgb[2]/256))
        except: return (128, 128, 128)

    def create_gradient_pill_img(width, height, radius, color_rgb, center_alpha=128):
        blur = 10
        w = int(width) + 2 * blur
        h = int(height) + 2 * blur
        
        from PIL import Image, ImageDraw, ImageTk, ImageFilter
        img = Image.new('RGBA', (w, h), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        
        draw.rounded_rectangle((blur, blur, blur+width, blur+height), radius=radius, fill=color_rgb + (center_alpha,))
        img = img.filter(ImageFilter.GaussianBlur(radius=4))
        return ImageTk.PhotoImage(img)

    class RoundedButton:
        def __init__(self, canvas, x, y, width, height, radius, color, text, command=None, fg="#333333"):
            self.canvas = canvas
            self.command = command
            self.state_val = "normal"
            self.normal_color = color
            self.disabled_color = "#E0E0E0"
            self.width = width
            self.height = height
            self.radius = radius
            self.x = x
            self.y = y
            
            self.bg_image = None # Ссылка для предотвращения GC
            self.bg_id = canvas.create_image(x, y, anchor="center")
            self._update_image(color)
            
            font_spec = ("Segoe UI", 10, "bold")
            
            self.text_id = canvas.create_text(x, y, text=text, fill=fg, font=font_spec, tags="btn_text")
            
            for item in [self.bg_id, self.text_id]:
                canvas.tag_bind(item, "<Button-1>", self._on_click)
                canvas.tag_bind(item, "<Enter>", self._on_enter)
                canvas.tag_bind(item, "<Leave>", self._on_leave)
        
        def _update_image(self, color):
            # Используем градиентную заливку с размытием краев (как у меток)
            # center_alpha=170 (33% прозрачности)
            self.bg_image = create_gradient_pill_img(self.width, self.height, self.radius, get_rgb(color), center_alpha=170)
            self.canvas.itemconfig(self.bg_id, image=self.bg_image)
            
        def _on_click(self, event):
            if self.state_val == "normal" and self.command:
                self.command()
        def _on_enter(self, event):
            if self.state_val == "normal": self.canvas.config(cursor="hand2")
        def _on_leave(self, event):
            self.canvas.config(cursor="")
        def config(self, **kwargs):
            if "text" in kwargs: 
                self.canvas.itemconfig(self.text_id, text=kwargs["text"])
            if "state" in kwargs:
                self.state_val = kwargs["state"]
                color = self.normal_color if self.state_val == "normal" else self.disabled_color
                self._update_image(color)
            if "bg" in kwargs:
                self.normal_color = kwargs["bg"]
                if self.state_val == "normal":
                    self._update_image(self.normal_color)
        def configure(self, **kwargs): self.config(**kwargs)

    class CanvasLabel:
        def __init__(self, canvas, x, y, text, font, fg="black", anchor="center", bg_color=None, spacing=2, outline_color="black", outline_width=1):
            self.canvas = canvas
            self.fg = fg
            self.padding_x = 10
            self.padding_y = 4
            self.spacing = spacing
            self.outline_color = outline_color
            self.outline_width = outline_width
            self.x = x
            self.y = y
            self.anchor = anchor
            self.font_spec = font
            self.text_val = text
            self.bindings = []
            
            # Создаем объект шрифта для измерений
            f_family = font[0]
            f_size = font[1]
            f_weight = "bold" if "bold" in font else "normal"
            self.tk_font = tkfont.Font(family=f_family, size=f_size, weight=f_weight)
            
            self.bg_id = canvas.create_image(x, y, anchor="center") # Placeholder
            self.bg_image = None
            self.text_items = []
            
            self._draw_text()
            self._draw_bg()
            
        def _draw_text(self):
            for i in self.text_items: self.canvas.delete(i)
            self.text_items = []
            
            if not self.text_val: return
            
            char_widths = [self.tk_font.measure(c) for c in self.text_val]
            total_width = sum(char_widths) + self.spacing * (len(self.text_val) - 1)
            
            if self.anchor == "center": cur_x = self.x - total_width / 2
            elif self.anchor in ["e", "se", "ne"]: cur_x = self.x - total_width
            else: cur_x = self.x
            
            for i, char in enumerate(self.text_val):
                w = char_widths[i]
                center_x = cur_x + w / 2
                
                y_off = 0
                if char == ":":
                    y_off = -1
                
                if self.outline_color and self.outline_width > 0:
                    for dx in range(-self.outline_width, self.outline_width + 1):
                        for dy in range(-self.outline_width, self.outline_width + 1):
                            if dx == 0 and dy == 0: continue
                            oid = self.canvas.create_text(center_x + dx, self.y + dy + y_off, text=char, font=self.font_spec, fill=self.outline_color, anchor="center")
                            self.text_items.append(oid)

                tid = self.canvas.create_text(center_x, self.y + y_off, text=char, font=self.font_spec, fill=self.fg, anchor="center")
                self.text_items.append(tid)
                
                cur_x += w + self.spacing
            
            self._apply_bindings()

        def _draw_bg(self):
            if not self.text_items:
                self.canvas.itemconfig(self.bg_id, state="hidden")
                return
            
            x1, y1, x2, y2 = self.canvas.bbox(self.text_items[0])
            for item in self.text_items[1:]:
                bx1, by1, bx2, by2 = self.canvas.bbox(item)
                x1 = min(x1, bx1); y1 = min(y1, by1)
                x2 = max(x2, bx2); y2 = max(y2, by2)
            
            w = (x2 - x1) + self.padding_x * 2
            h = (y2 - y1) + self.padding_y * 2
            r = h / 2
            
            # Генерируем градиентный фон на основе цвета текста
            self.bg_image = create_gradient_pill_img(w, h, r, get_darker_rgb(self.fg), center_alpha=128)
            
            # Центрируем изображение относительно текста
            cx = x1 + (x2 - x1) / 2
            cy = y1 + (y2 - y1) / 2
            
            self.canvas.coords(self.bg_id, cx, cy)
            self.canvas.itemconfig(self.bg_id, image=self.bg_image, state="normal")
            
            # Опускаем фон ниже обводки и текста
            if self.text_items:
                self.canvas.tag_lower(self.bg_id, self.text_items[0])

        def config(self, **kwargs):
            redraw = False
            if "text" in kwargs:
                self.text_val = kwargs["text"]
                redraw = True
            if "fg" in kwargs:
                self.fg = kwargs["fg"]
                redraw = True
            
            if redraw:
                self._draw_text()
                self._draw_bg()

        def bind(self, seq, func):
            self.bindings.append((seq, func))
            self._apply_bindings()

        def _apply_bindings(self):
            for seq, func in self.bindings:
                if self.bg_id: self.canvas.tag_bind(self.bg_id, seq, func)
                for item in self.text_items:
                    self.canvas.tag_bind(item, seq, func)

        def pack(self, **kwargs): pass

    class CanvasButton:
        def __init__(self, canvas, x, y, text, font, command, anchor="se", fg="#555555", bg_color=None):
            self.canvas = canvas
            self.command = command
            self.fg = fg
            self.padding_x = 10
            self.padding_y = 4
            self.text_id = canvas.create_text(x, y, text=text, font=font, fill=fg, anchor=anchor)
            self.bg_id = canvas.create_image(x, y, anchor="center")
            self.bg_image = None
            self._draw_bg()

            self.canvas.tag_bind(self.text_id, "<Button-1>", lambda e: self.command())
            self.canvas.tag_bind(self.text_id, "<Enter>", lambda e: canvas.config(cursor="hand2"))
            self.canvas.tag_bind(self.text_id, "<Leave>", lambda e: canvas.config(cursor=""))
            
        def _draw_bg(self):
            bbox = self.canvas.bbox(self.text_id)
            if not bbox: return
            x1, y1, x2, y2 = bbox
            
            w = (x2 - x1) + self.padding_x * 2
            h = (y2 - y1) + self.padding_y * 2
            r = h / 2
            
            # Генерируем градиентный фон
            self.bg_image = create_gradient_pill_img(w, h, r, get_darker_rgb(self.fg), center_alpha=128)
            
            cx = x1 + (x2 - x1) / 2
            cy = y1 + (y2 - y1) / 2
            
            self.canvas.coords(self.bg_id, cx, cy)
            self.canvas.itemconfig(self.bg_id, image=self.bg_image)
            self.canvas.tag_lower(self.bg_id, self.text_id)
            
            # Привязываем события к фону
            self.canvas.tag_bind(self.bg_id, "<Button-1>", lambda e: self.command())
            self.canvas.tag_bind(self.bg_id, "<Enter>", lambda e: self.canvas.config(cursor="hand2"))
            self.canvas.tag_bind(self.bg_id, "<Leave>", lambda e: self.canvas.config(cursor=""))

        def move_to(self, x, y, anchor):
            self.canvas.coords(self.text_id, x, y)
            self.canvas.itemconfig(self.text_id, anchor=anchor)
            self._draw_bg()

        def config(self, **kwargs):
            if "text" in kwargs:
                self.canvas.itemconfig(self.text_id, text=kwargs["text"])
                self._draw_bg()
            if "fg" in kwargs:
                self.fg = kwargs["fg"]
                self.canvas.itemconfig(self.text_id, fill=self.fg)
                self._draw_bg()
        def place(self, **kwargs): pass

    # === CRITICAL MIGRATION LOGIC ===
    def perform_critical_migrations(log_func=None):
        try:
            base = get_base_dir()
            u_strat = os.path.join(base, "strat", "strategies.json")
            u_discord = os.path.join(base, "strat", "discord.json")
            
            # 1. Check strategies.json
            if os.path.exists(u_strat):
                try:
                    curr = load_json_robust(u_strat)
                    if curr:
                        mod = False
                        
                        d_args = curr.get("discord", [])
                        bad_d = any("--filter-tcp=" in x and "443" in x for x in d_args)
                        
                        w_args = curr.get("warp", [])
                        w_udp = next((x for x in w_args if "--filter-udp=" in x), "")
                        bad_w = "500" not in w_udp or "1701" not in w_udp
                        
                        if bad_d or bad_w:
                            ref = {}
                            if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
                                i_strat = os.path.join(sys._MEIPASS, "strat", "strategies.json")
                                if os.path.exists(i_strat):
                                    ref = load_json_robust(i_strat)
                            
                            if ref:
                                if bad_d and "discord" in ref:
                                    curr["discord"] = ref["discord"]
                                    mod = True
                                    if log_func: log_func("[Init] Discord стратегия обновлена из пакета (v1.12).")
                                if bad_w and "warp" in ref:
                                    curr["warp"] = ref["warp"]
                                    mod = True
                                    if log_func: log_func("[Init] WARP стратегия обновлена из пакета (v1.12).")
                            
                            if mod:
                                 curr["version"] = CURRENT_VERSION
                                 save_json_safe(u_strat, curr)
                except: pass

            # 2. Check discord.json
            if os.path.exists(u_discord):
                 try:
                     with open(u_discord, "r", encoding="utf-8", errors="ignore") as f:
                         raw = f.read()
                     if '"--filter-tcp=443,' in raw:
                         if log_func: log_func("[Init] Удален устаревший discord.json для обновления.")
                         f.close()
                         os.remove(u_discord)
                         # Restore immediately to get the new version
                         restore_missing_strategies()
                 except: pass

            # 3. Check list/discord.txt
            u_discord_txt = os.path.join(base, "list", "discord.txt")
            if os.path.exists(u_discord_txt):
                try:
                    with open(u_discord_txt, "r", encoding="utf-8", errors="ignore") as f:
                        raw_txt = f.read()
                    if 'discord.media' not in raw_txt:
                        if log_func: log_func("[Init] Удален устаревший discord.txt для обновления списка доменов.")
                        f.close()
                        os.remove(u_discord_txt)
                        # Восстанавливаем из ресурсов (чтобы сразу появился правильный список)
                        restore_missing_strategies()
                except: pass
        except: pass



    # ================= STARTUP =================
    if __name__ == "__main__":
        safe_trace("[Main] Entry point reached.")
        # === ARGUMENT PARSING: Order-independent, but execution in correct sequence ===
        # Parse all arguments first
        ARGS_PARSED = {
            'fresh': '--fresh' in sys.argv,
            'debug': '--debug' in sys.argv or '-debug' in sys.argv,
            'updated': '--updated' in sys.argv,
            'show_log': '--show-log' in sys.argv,
            'minimized': '--minimized' in sys.argv
        }
        
        # Execute in correct order: 1. Fresh (cleanup), 2. Debug (logging)
        if ARGS_PARSED['fresh']:
            try:
                t_dir = os.path.join(get_base_dir(), "temp")
                if os.path.exists(t_dir):
                     for item in os.listdir(t_dir):
                         if item.lower() == "window_state.json": continue
                         # FIX: Do not delete runtime folders if located in temp (Anti-Self-Destruct)
                         if item.startswith("_MEI") or "nuitka" in item.lower(): continue
                         try:
                             p = os.path.join(t_dir, item)
                             if os.path.isfile(p): os.remove(p)
                             else: shutil.rmtree(p, ignore_errors=True)
                         except: pass
                print("[Info] Флаг --fresh: временные файлы очищены.")
            except: pass

        # === SELF-RELOCATION LOGIC (Check only if Frozen) ===
        if is_compiled:
            base_dir = get_base_dir()
            exe_name = os.path.basename(sys.executable)
            
            # RULE 1: Infrastructure exists -> Clean
            # "в папке где запускается Nova.exe есть любая из папок (bin ip list strat fake list)"
            core_folders = ["bin", "ip", "list", "strat", "fake"]
            has_infrastructure = any(os.path.isdir(os.path.join(base_dir, f)) for f in core_folders)
            
            if not has_infrastructure:
                # RULE 2 & 3: Check for Alien Files
                # "Если папок из белого списка нет... но есть другие папки или файлы"
                is_cluttered = False
                found_alien = "None"
                try:
                    items = os.listdir(base_dir)
                    for item in items:
                        # Allowed: only Nova.exe and Nova.exe.old
                        if item.lower() == exe_name.lower(): continue
                        # FIX: Explicitly ignore common names to prevent self-detection issues
                        if item.lower() in ["nova.exe", "nova_v1.exe", "update.exe"]: continue
                        if item.lower() == (exe_name + ".old").lower(): continue
                        if item.lower() == "temp": continue # Ignore temp folder
                        if item.lower() in ["desktop.ini", "thumbs.db", ".ds_store"]: continue # Ignore system files
                        
                        # Found alien item (e.g. "Nova.spec", "Photo.jpg")
                        is_cluttered = True
                        found_alien = item
                        break
                except:
                    is_cluttered = True # Fail safe
                
                # Prompt user if cluttered
                if is_cluttered:
                    # MessageBox with Yes/No/Cancel
                    # 3 = MB_YESNOCANCEL, 48 = MB_ICONEXCLAMATION, 0x40000 = MB_TOPMOST
                    msg = (
                        "Программа запущена в папке с другими файлами.\n"
                        f"Обнаружен посторонний файл/папка: '{found_alien}'\n"
                        "Рекомендуется создать отдельную папку для программы.\n\n"
                        "Создать папку 'Nova' и запустить программу оттуда?"
                    )
                    ret = ctypes.windll.user32.MessageBoxW(0, msg, "Nova - Первый запуск", 3 | 48 | 0x40000)
                    
                    if ret == 6: # IDYES - Relocate
                        target_dir = os.path.join(base_dir, "Nova")
                        try:
                            # 1. Create Directory
                            os.makedirs(target_dir, exist_ok=True)
                            
                            # 2. Define Paths
                            # FIX: Use argv[0] to get the REAL executable path in Nuitka OneFile mode
                            # sys.executable points to the temp python.exe in the extraction folder
                            # Explicitly force "Nova.exe" as target name to prevent renaming to "python.exe"
                            current_exe = os.path.abspath(sys.argv[0]) if is_compiled else os.path.abspath(sys.executable)
                            target_exe = os.path.abspath(os.path.join(target_dir, "Nova.exe"))
                            
                            # 3. Validation
                            if not os.path.exists(current_exe):
                                raise FileNotFoundError(f"Source file not found: {current_exe}")
                                
                            # 4. Copy File
                            # Retry loop for stability
                            for _ in range(3):
                                try:
                                    shutil.copy2(current_exe, target_exe)
                                    break
                                except:
                                    time.sleep(0.5)
                            
                            # 5. Flush & Verify
                            time.sleep(0.5) # Give file system a moment
                            if not os.path.exists(target_exe):
                                raise FileNotFoundError(f"Target file creation failed: {target_exe}")
                            
                            # 6. Launch new process
                            # Use abspath for cwd to be safe
                            # We pass --cleanup-old-exe to the new process to delete the old one.
                            # This avoids the use of shell commands and prevents command injection.
                            subprocess.Popen([target_exe, "--cleanup-old-exe", current_exe] + sys.argv[1:], cwd=os.path.abspath(target_dir))
                            
                            sys.exit()
                        except Exception as e:
                            # Detailed error message
                            import traceback
                            err_details = f"Error: {e}\nSrc: {sys.executable}\nDst: {target_dir}"
                            ctypes.windll.user32.MessageBoxW(0, f"Ошибка при перемещении:\n{err_details}", "Ошибка Nova", 0x10)
                            sys.exit() 

                    elif ret == 7: # IDNO - Run Here
                         pass # Continue in current folder

                    else: # IDCANCEL (2) or Close - Exit
                        sys.exit()

        # === DEFERRED INIT PLACEHOLDER ===

        # === DEFERRED INIT PLACEHOLDER ===
        # dns_manager инициализируется в launch_background_tasks

        # === INFRASTRUCTURE DEPLOY ===
        # Теперь безопасно распаковываем файлы (мы либо в чистой папке, либо переехали)
        
        # Check First Run Condition BEFORE deploy (if strat folder missing, it's a fresh install)
        is_first_run_condition = not os.path.exists(os.path.join(get_base_dir(), "strat"))
        
        try:
            dep_logs = deploy_infrastructure()
        except Exception as e:
            print(f"Deploy failed: {e}")
            dep_logs = []
        
        # Исправляем стратегии синхронно перед запуском GUI, чтобы избежать гонок
        try:
            rest_logs = restore_missing_strategies()
        except Exception as e:
            print(f"Restore failed: {e}")
            rest_logs = []
        
        # Show Update Report
        total_logs = (dep_logs or []) + (rest_logs or [])
        
        # FIX: Check if this is a fresh install (folders created)
        # If so, suppress "Restored/Updated" spam
        is_fresh_install = is_first_run_condition or any("Создана папка" in l for l in total_logs)
        
        if is_fresh_install:
             # Filter out "Restored" messages, keep only Errors
             total_logs = [l for l in total_logs if "Err" in l or "Crit" in l]
        
        # Filter logs: Show Message Box ONLY if there are REAL updates/fixes.
        # Ignore "Created folder", "Created file" (Fresh Install events).
        important_keywords = ["обновлен", "пересоздан", "сброс", "восстановлен", "update", "reset", "restore"]
        
        display_logs = [log for log in total_logs if any(k in log.lower() for k in important_keywords)]

        # Update Report Popup removed by user request (Silent Mode)
        if display_logs and IS_DEBUG_MODE:
             # Only print to stdout in debug mode
             print(f"[Init] Update Report ({len(display_logs)} items):")
             for l in display_logs: print(f" - {l}")

        import struct # Импорт struct для работы с IP
        
        try:
            # FIX: Use absolute path to ensure we find the correct file
            base_exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            old_exe_chk = os.path.abspath(sys.argv[0]) + ".old" 
            
            # Cleanup .old exe
            if os.path.exists(old_exe_chk):
                 for _ in range(3):
                     try: 
                         os.remove(old_exe_chk)
                         OLD_VERSION_CLEANED = True
                         break
                     except: 
                         time.sleep(0.5)
            
            # Cleanup .vbs scripts from update/restart (now in temp)
            temp_dir = os.path.join(get_base_dir(), "temp")
            for script_name in ["restart_helper.vbs", "updater.vbs"]:
                s_path = os.path.join(temp_dir, script_name)
                if os.path.exists(s_path):
                    try: os.remove(s_path)
                    except: pass

        except: pass

        app_mutex = check_single_instance()

        try: ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Nova.App.Main.1")
        except: pass

        root = tk.Tk()
        root.withdraw()
        root.title(f"Nova v{CURRENT_VERSION}")
        try:
            # FIX: Load icon from internal resources
            icon_path = get_internal_path("icon.ico")
            if os.path.exists(icon_path):
                root.iconbitmap(icon_path)
        except: pass
        root.resizable(False, False)
        root.configure(bg=COLOR_BG)
        
        # Применяем тему Windows к заголовку окна
        try:
            use_dark = 1 if SYSTEM_THEME == "dark" else 0
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(use_dark)), 4)
        except: pass

        def start_move(event):
            root._drag_start_x = event.x
            root._drag_start_y = event.y
            # Monitor bounds are queried dynamically in do_move to handle multi-monitor transitions correctly
            
            # === НОВОЕ: При клике на главное окно поднимаем лог на передний план (если открыт) ===
            try:
                if log_window and log_window.state() == "normal":
                    log_window.lift()
            except: pass


        def do_move(event):
            # Calculate new main positions
            x = root.winfo_x() + (event.x - root._drag_start_x)
            y = root.winfo_y() + (event.y - root._drag_start_y)
            
            # 1. Update Main Window immediately
            root.geometry(f"+{x}+{y}")
            
            # 2. Update Log Window immediately (Synchronous Sync)
            # This makes the log window feel "glued" to the main window
            if log_window and log_window.state() == "normal":
                align_log_window_to_main(forced_main_geom=(x, y, root.winfo_width(), root.winfo_height()))

        root.bind("<Button-1>", start_move)
        root.bind("<B1-Motion>", do_move)

        state = load_window_state()
        geom = state.get("main_geometry")
        w, h = 360, 270
        if geom:
            geom_applied = False
            try:
                m = re.match(r"^(\d+)x(\d+)\+(-?\d+)\+(-?\d+)$", str(geom).strip())
                if m:
                    w_try, h_try = int(m.group(1)), int(m.group(2))
                    x_try, y_try = int(m.group(3)), int(m.group(4))
                    probe_x = x_try + max(20, w_try // 2)
                    probe_y = y_try + 20
                    if is_monitor_available(probe_x, probe_y):
                        root.geometry(f"{w_try}x{h_try}+{x_try}+{y_try}")
                        w, h = w_try, h_try
                        geom_applied = True
                    else:
                        if IS_DEBUG_MODE:
                            print(f"[UI] Геометрия вне экрана, сброс: {geom}")
                else:
                    # Legacy format fallback (size only)
                    root.geometry(geom)
                    m2 = re.match(r"(\d+)x(\d+)", str(geom))
                    if m2:
                        w, h = int(m2.group(1)), int(m2.group(2))
                    geom_applied = True
            except:
                geom_applied = False

            if not geom_applied:
                sw = root.winfo_screenwidth()
                sh = root.winfo_screenheight()
                x = int((sw/2) - (w/2))
                y = int((sh/2) - (h/2))
                root.geometry(f"{w}x{h}+{x}+{y}")
        else:
            sw = root.winfo_screenwidth()
            sh = root.winfo_screenheight()
            x = int((sw/2) - (w/2))
            y = int((sh/2) - (h/2))
            root.geometry(f"{w}x{h}+{x}+{y}")
            
        # FIX: Force window to show if this is a restart/update
        # This prevents the app from starting minimized or hidden
        if "--updated" in sys.argv or "--restart" in sys.argv:
            root.deiconify()
            root.lift()
            root.attributes("-topmost", True)
            root.update()
            root.attributes("-topmost", False)

        main_canvas = tk.Canvas(root, width=w, height=h, highlightthickness=0, bg=COLOR_BG)
        main_canvas.pack(fill="both", expand=True)
        main_canvas.bind("<Button-1>", start_move)
        main_canvas.bind("<B1-Motion>", do_move)

        # Beta Mode Flag
        is_beta_mode = False
        try:
            img_path = get_internal_path(os.path.join("img", "background.png"))
            # Проверка на частую ошибку с JPG
            if os.path.exists(os.path.join(get_base_dir(), "img", "background.jpg")):
                print("[UI] Внимание: найден background.jpg, но программа поддерживает только PNG!")

            if os.path.exists(img_path):
                bg_image = tk.PhotoImage(file=img_path, master=root)
                main_canvas.bg_image = bg_image # Сохраняем ссылку, чтобы сборщик мусора не удалил картинку
                main_canvas.create_image(0, 0, image=bg_image, anchor="nw")
                # print(f"[UI] Фон успешно загружен: {img_path}")
            else:
                # Fallback: Gradient Background (Sapphire -> Yogurt)
                # Only if running as script (.pyw)
                if not getattr(sys, 'frozen', False):
                    is_beta_mode = True # Set flag
                    # Draw Gradient Rectangle
                    # Sapphire (#0F52BA) to Yogurt (#FFB6C1)
                    # We can simulate this with lines or a pill image stretched
                    w_c = main_canvas.winfo_reqwidth()
                    h_c = main_canvas.winfo_reqheight()
                    if w_c < 10: w_c, h_c = w, h
                    
                    # Create gradient image manually
                    try:
                        from PIL import Image, ImageTk, ImageDraw
                        grad = Image.new('RGB', (w_c, h_c), "#0F52BA")
                        draw = ImageDraw.Draw(grad)
                        
                        r1, g1, b1 = 15, 82, 186   # Sapphire
                        r2, g2, b2 = 255, 182, 193 # Yogurt
                        
                        for i in range(h_c):
                            r = int(r1 + (r2 - r1) * i / h_c)
                            g = int(g1 + (g2 - g1) * i / h_c)
                            b = int(b1 + (b2 - b1) * i / h_c)
                            draw.line([(0, i), (w_c, i)], fill=(r, g, b))
                            
                        grad_tk = ImageTk.PhotoImage(grad)
                        main_canvas.bg_image = grad_tk
                        main_canvas.create_image(0, 0, image=grad_tk, anchor="nw")
                        
                        # Add Beta Tester Label
                        # Position: Below the toggle button (h/2 + 10 + 40 + gap)
                        # Center: w/2
                        main_canvas.create_text(w/2, h/2 + 65, text="версия для бета-тестеров", 
                                              font=("Segoe UI", 8), fill="#FFFFFF")

                    except ImportError:
                        pass # PIL not found, fallback to default bg color
                        
        except Exception as e:
            print(f"[UI] Ошибка загрузки фона: {e}")

        status_label = CanvasLabel(main_canvas, w/2, h/2 - 45, "Запуск...", ("Segoe UI Semibold", 10), "grey", bg_color="#E0E0E0", outline_color="#DFF07E", outline_width=2)
        status_label.bind("<Button-1>", start_move)
        status_label.bind("<B1-Motion>", do_move)
        
        btn_toggle = RoundedButton(main_canvas, w/2, h/2 + 10, 160, 40, 20, COLOR_BLUEBERRY_YOGURT, "ЗАПУСТИТЬ", toggle_service)
        
        # Style for Log Button
        log_fg = "#777777"
        log_bg = "#E0E0E0"
        if is_beta_mode:
             log_fg = "#FFFFFF"     # White Text
             log_bg = "#0F52BA"     # Sapphire Background
             
        btn_logs = CanvasButton(main_canvas, w-10, h-10, "Показать лог", ("Segoe UI", 9, "bold"), toggle_log_window, fg=log_fg, bg_color=log_bg)

        # === Autostart Context Menu (Main Window) ===
        main_context_menu = tk.Menu(root, tearoff=0)
        autostart_var = tk.BooleanVar()
        
        def toggle_autostart_main():
            # Work in background
            logger = globals().get('log_print', print)
            threading.Thread(target=toggle_startup, args=(logger,), daemon=True).start()
            
        def update_main_autostart_label():
            # Recreate completely to ensure state is fresh
            try:
                # Safer cleanup of menu items
                last_idx = main_context_menu.index('end')
                if last_idx is not None:
                    for i in range(last_idx, -1, -1):
                        main_context_menu.delete(i)
            except: pass
            
            is_auto = get_autostart_cmd() is not None
            autostart_var.set(is_auto)
            main_context_menu.add_checkbutton(label="Автозапуск Nova", variable=autostart_var, command=toggle_autostart_main)
            main_context_menu.add_separator()
            main_context_menu.add_command(label="Перезапустить Nova", command=restart_nova)

        def show_main_context_menu(event):
            try: 
                # Update label by recreating item
                update_main_autostart_label()
                # Using post with return "break" prevents double-triggering from event bubbling
                main_context_menu.post(event.x_root, event.y_root)
            except: pass
            return "break"
            
        # Bind to Main Window and Canvas
        root.bind("<Button-3>", show_main_context_menu)
        main_canvas.bind("<Button-3>", show_main_context_menu)
        try: status_label.bind("<Button-3>", show_main_context_menu)
        except: pass


        root.update()
        ensure_log_window_created()
        
        # Auto-open log window if --show-log argument is present (restart)
        if ARGS_PARSED.get('show_log', False):
            show_log_window()
        else:
            hide_log_window()
        
        # Показываем окно НЕМЕДЛЕННО (устранение ощущения задержки)
        if ARGS_PARSED.get('minimized', False):
            root.withdraw()
            if IS_DEBUG_MODE: log_print("[Init] Запуск в свернутом режиме (--minimized). Проверьте трей.")
        else:
            root.deiconify()
            root.lift()
            root.focus_force()
            root.update() # Принудительная отрисовка GUI
            # Дополнительный форсированный подъем окна
            root.attributes("-topmost", True)
            root.after(200, lambda: root.attributes("-topmost", False))
        
        # Gentle Focus (уже после того как окно показано)
        if not ARGS_PARSED.get('minimized', False):
            try:
                root.deiconify()
                root.attributes('-topmost', True)
                root.after(50, lambda: root.attributes('-topmost', False))
            except: pass
        
        # Миграция конфигурации перед запуском сервисов
        # Миграция конфигурации перед запуском сервисов
        root.after(50, lambda: perform_critical_migrations(lambda m: logging.info(m) if 'logging' in globals() else None))

        # Запуск основного ядра С НЕБОЛЬШОЙ ЗАДЕРЖКОЙ (дает UI продышаться)
        root.after(100, lambda: start_nova_service())
        
        # Запуск фоновых задач
        root.after(500, lambda: launch_background_tasks())
        
        check_scan_status_loop() 
        
        # FIX: Bind minimize event here, where root is defined
        root.bind("<Unmap>", lambda e: minimize_to_tray(e) if root.state() == 'iconic' else None)
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()

except Exception as e:
    try:
        err_root = tk.Tk()
        err_root.withdraw()
    except: pass
    messagebox.showerror("Критическая ошибка", traceback.format_exc())
    sys.exit(1)
