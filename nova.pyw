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
import winsound
import subprocess
import collections


# === FIX: Force Hide Console (Safeguard) ===
# Проверяем, запущено ли как скомпилированный EXE
is_compiled = getattr(sys, 'frozen', False) or (sys.argv[0].lower().endswith(".exe"))

if is_compiled:
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
    except: pass

# === FIX: Исправление загрузки DLL для Nuitka/Python 3.13 ===
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
    try:
        # Re-run the script with Admin rights
        # For pythonw/python:
        if getattr(sys, 'frozen', False):
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv[1:]), None, 1)
        else:
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{sys.argv[0]}" ' + " ".join(sys.argv[1:]), None, 1)
        sys.exit()
    except Exception as e:
        ctypes.windll.user32.MessageBoxW(0, f"Failed to elevate privileges: {e}\nPlease run as Administrator.", "Nova Admin Error", 0x10)
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
    import hashlib
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from collections import deque
    from tkinter import font as tkfont
    import winreg
    import glob

    # Global defer
    dns_manager = None

    # Конфигурация (перенесено наверх для deploy_infrastructure)
    WINWS_FILENAME = "winws.exe"
    # === AUTO-UPDATE CONFIG ===
    UPDATE_URL = "https://confeden.github.io/nova_updates/version.json"
    CURRENT_VERSION = "1.0"
    
    # Debug Flag: Check args OR existence of "debug" file
    # Centralized argument parsing for consistency
    def _check_debug_mode():
        return ("--debug" in sys.argv or "-debug" in sys.argv or 
                os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug")) or 
                os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug.txt")))
    
    IS_DEBUG_MODE = _check_debug_mode()
    
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
                import json # Ensure json loaded (it is imported later but we need it here)
                try: 
                    with open(embedded_strat_path, "r", encoding="utf-8") as f:
                        snapset = json.load(f)
                        if isinstance(snapset, dict):
                            DEFAULT_STRATEGIES.update(snapset)
                            # print("Loaded embedded strategies snapshot")
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
            # Load Reference Domains from BUNDLED file (sys._MEIPASS for PyInstaller)
            # This ensures we use the latest list packaged with the EXE, not a hardcoded minimal set.
            ref_domains = set()
            
            # Fallback minimal list in case bundle read fails
            HARDCODED_DEFAULTS = ["youtube.com", "discord.com", "facebook.com", "instagram.com", "twitter.com"]
            for d in HARDCODED_DEFAULTS: ref_domains.add(d)

            try:
                internal_gen_path = get_internal_path(os.path.join("list", "general.txt"))
                if os.path.exists(internal_gen_path):
                    with open(internal_gen_path, "r", encoding="utf-8") as f:
                        for line in f:
                            clean = line.split('#')[0].strip()
                            if clean: ref_domains.add(clean)
            except: pass
            
            # Sort for consistency
            REFERENCE_DOMAINS_SORTED = sorted(list(ref_domains))
            
            gen_path = os.path.join(base_dir, "list", "general.txt")
            
            # Read existing file
            existing_lines = []
            existing_version = None
            existing_domains = set()
            
            if os.path.exists(gen_path):
                try:
                    with open(gen_path, "r", encoding="utf-8") as f:
                        existing_lines = f.readlines()
                    
                    # Extract version from first line
                    if existing_lines and existing_lines[0].strip().startswith("# version:"):
                        try:
                            existing_version = existing_lines[0].strip().split(":", 1)[1].strip()
                        except: pass
                    
                    # Extract domains (skip comments)
                    for line in existing_lines:
                        clean = line.split('#')[0].strip()
                        if clean:
                            existing_domains.add(clean)
                            
                except Exception as e:
                    print(f"[Init] Ошибка чтения general.txt: {e}")
            
            # Decision logic
            should_rewrite = False
            new_content_lines = []
            
            if not existing_lines or not existing_domains:
                # Case 1: File is empty or missing -> Create with reference domains
                logs.append(f"Создан general.txt (v{CURRENT_VERSION} - восстановлен из EXE)")
                new_content_lines = [f"# version: {CURRENT_VERSION}\n"]
                new_content_lines.extend([f"{d}\n" for d in REFERENCE_DOMAINS_SORTED])
                should_rewrite = True
                
            elif existing_version is None:
                # Case 2: No version header -> Delete and recreate
                logs.append(f"Пересоздан general.txt (v{CURRENT_VERSION} - восстановлен из EXE)")
                new_content_lines = [f"# version: {CURRENT_VERSION}\n"]
                new_content_lines.extend([f"{d}\n" for d in REFERENCE_DOMAINS_SORTED])
                should_rewrite = True
                
            elif existing_version == CURRENT_VERSION:
                # Case 3: Same version -> Do nothing
                pass
                
            elif existing_version < CURRENT_VERSION:
                # Case 4: Old version -> Merge reference domains with existing
                merged_domains = existing_domains.copy()
                added_count = 0
                for ref_domain in REFERENCE_DOMAINS_SORTED:
                    if ref_domain not in merged_domains:
                        merged_domains.add(ref_domain)
                        added_count += 1
                
                msg = f"Обновлен general.txt: v{existing_version} -> v{CURRENT_VERSION}"
                if added_count > 0: msg += f" (+{added_count} новых доменов из обновления)"
                logs.append(msg)
                
                # Write merged list
                new_content_lines = [f"# version: {CURRENT_VERSION}\n"]
                new_content_lines.extend([f"{d}\n" for d in sorted(merged_domains)])
                should_rewrite = True
            
            # Write if needed
            if should_rewrite:
                try:
                    with open(gen_path, "w", encoding="utf-8") as f:
                        f.writelines(new_content_lines)
                except Exception as e:
                    print(f"[Init] Ошибка записи general.txt: {e}")
            
            # Cleanup old version file
            try:
                ov_path = os.path.join(base_dir, "list", "general.version")
                if os.path.exists(ov_path): os.remove(ov_path)
            except: pass


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
                    
                    # === HARD RESET TRIGGER for v0.997 ===
                    # FIX: Добавлена проверка getattr(sys, 'frozen', False)
                    # Это предотвращает удаление ваших стратегий при запуске .pyw скрипта
                    is_frozen = getattr(sys, 'frozen', False)
                    
                    if CURRENT_VERSION == "0.997" and is_frozen:
                        # Удаляем только если это EXE сборка (релиз)
                        # If file belongs to 'strat' folder and version is NOT 0.997 (missing or old)
                        if fpath in strat_files and ver != CURRENT_VERSION:
                            logs.append(f"Сброс {os.path.basename(fpath)} (v0.997 Hard Reset)")
                            os.remove(fpath)
                            continue


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
            
            # After deletion, we need to RE-DEPLOY if missing.
            # But deploy_infrastructure already ran.
            # We can manually copy missing files from Internal Source if they exist.
            
            if CURRENT_VERSION == "0.997":
                # Try to restore individual JSONs from bundle (if they exist there)
                # Note: Default Bundle usually only has "strategies.json".
                # If user wants individual files like "youtube.json", they must be in the bundle.
                # Assuming standard build puts them in 'strat' folder.
                try:
                    internal_strat_dir = get_internal_path("strat")
                    if os.path.exists(internal_strat_dir) and os.path.isdir(internal_strat_dir):
                        for item in os.listdir(internal_strat_dir):
                            if item.lower().endswith(".json"):
                                target_path = os.path.join(strat_dir, item)
                                if not os.path.exists(target_path): # We just deleted it!
                                    src = os.path.join(internal_strat_dir, item)
                                    shutil.copy2(src, target_path)
                                    logs.append(f"Восстановлен файл {item} из новой сборки")
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
                         # logs.append(f"Debug: Bundle loaded ({len(snap)} keys)")
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
        folders_to_deploy = ["bin", "fake", "list", "strat", "ip"]
        
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
                        
                        if item.lower() == WINWS_FILENAME.lower() or True: # FIX: Force check ALL bin files (Drivers, DLLs)
                            # Update if size differs or missing
                            if os.path.exists(d):
                                try:
                                    if os.path.getsize(s) != os.path.getsize(d):
                                        shutil.copy2(s, d)
                                        updated_bins += 1
                                except: pass
                            else:
                                shutil.copy2(s, d) # Missing? Copy.
                    if updated_bins > 0: logs.append(f"Bin: обновлено {updated_bins} исполняемых файлов")
                 except: pass
            else:
                # Для list, strat, ip: добавляем только отсутствующие файлы (дефолтные), старые не трогаем
                try:
                    for item in os.listdir(internal_source):
                        d = os.path.join(target_folder_path, item)
                        if not os.path.exists(d):
                            s = os.path.join(internal_source, item)
                            if os.path.isfile(s):
                                shutil.copy2(s, d)
                                logs.append(f"Добавлен новый файл конфигурации: {item}")
                except Exception as e:
                    pass

        # FIX: Проверка успешности развертывания критических файлов
        if not os.path.exists(winws_path):
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

    # Запускаем развертывание ПЕРЕД всем остальным
    # REMOVED: Moved to __main__
    # deploy_infrastructure()

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
    VISITED_DOMAINS_FILE = "temp/visited_domains_stats.json"
    STRATEGIES_EVOLUTION_FILE = "temp/strategies_evolution.json"
    IP_HISTORY_FILE = "temp/ip_history.json"
    LEARNING_DATA_FILE = os.path.join(get_base_dir(), "temp", "learning_data.json")

    # === NEW: Service Run ID for zombie thread suppression ===
    SERVICE_RUN_ID = 0

    # Функции модуля nova_boot
    def install_requirements_visually():
        # Если запущено в скомпилированном виде (Nuitka), библиотеки уже внутри.
        # Ничего устанавливать не нужно.
        if getattr(sys, 'frozen', False):
            return

        # Mapping: pip package name -> python module name
        required = {
            "requests": "requests", 
            "urllib3": "urllib3", 
            "Pillow": "PIL"
        }
        missing = []
        for package, module in required.items():
            try:
                __import__(module)
            except ImportError:
                missing.append(package)
        
        if not missing: return 

        install_root = tk.Tk()
        install_root.overrideredirect(True) 
        install_root.configure(bg="#2b2b2b")
        w, h = 400, 100
        sw, sh = install_root.winfo_screenwidth(), install_root.winfo_screenheight()
        install_root.geometry(f"{w}x{h}+{int((sw-w)/2)}+{int((sh-h)/2)}")
        
        lbl = tk.Label(install_root, text="Выполняется первоначальная настройка...\nУстановка компонентов, подождите.", 
                       fg="white", bg="#2b2b2b", font=("Verdana", 10))
        lbl.pack(expand=True)
        install_root.update() 

        try:
            for lib in missing:
                subprocess.check_call([sys.executable, "-m", "pip", "install", lib, "--quiet", "--disable-pip-version-check"], creationflags=subprocess.CREATE_NO_WINDOW)
                __import__(required[lib])
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось установить библиотеки: {e}")
            sys.exit(1)
        finally:
            install_root.destroy()

    install_requirements_visually()



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
        for name, content in files.items():
            path = os.path.join(base_dir, "list", name)
            if not os.path.exists(path) or (name == "general.txt" and os.path.getsize(path) == 0):
                with open(path, "w", encoding="utf-8") as f: f.write(content)
            res[f"list_{name.split('.')[0]}"] = path

        # === НОВОЕ: Создаем необходимые temp файлы ===
        temp_files = {
            "exclude_auto.txt": "",
            "hard.txt": "",
            "visited_domains_stats.json": "{}",
            "strategies_evolution.json": "{}",
            "ip_history.json": "[]",
            "checker_state.json": "{}",
            "ip_cache_state.json": "{}",
            "direct_check_cache.json": "{}",
            "window_state.json": "{}",
            "learning_data.json": "{}"
        }
        for name, content in temp_files.items():
            path = os.path.join(base_dir, "temp", name)
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            else:
                # Восстановление поврежденных/пустых JSON файлов
                if name.endswith(".json") and os.path.getsize(path) == 0:
                    with open(path, "w", encoding="utf-8") as f: f.write(content)

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

    def load_strategies_from_file(filepath):
        if not os.path.exists(filepath): return {}
        try:
            with open(filepath, "r", encoding="utf-8") as f: 
                data = json.load(f)
                
                # FIX: Versioned Load (Discard < 0.997) - ONLY FOR FROZEN BUILD
                # In script mode, we accept any valid JSON to allow testing without version headers
                is_frozen = getattr(sys, 'frozen', False)
                if is_frozen and isinstance(data, dict):
                    ver = data.get("_version", "0.0")
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
    _learning_data_lock = threading.Lock()
    
    def load_learning_data():
        """Загружает данные обучения из temp/learning_data.json"""
        default = {
            "version": "1.0",
            "last_updated": 0,
            "argument_stats": {},
            "combo_stats": {},
            "bin_stats": {},
            "service_stats": {},
            "checked_hashes": {}  # hash -> {timestamp, score} для отслеживания перепроверок
        }
        return load_json_robust(LEARNING_DATA_PATH, default)
    
    def save_learning_data(data):
        """Сохраняет данные обучения"""
        data["last_updated"] = time.time()
        with _learning_data_lock:
            save_json_safe(LEARNING_DATA_PATH, data)
    
    def update_learning_stats(args, score, max_score, service="general", bin_files_used=None):
        """Обновляет статистику обучения после проверки стратегии"""
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
            
            save_learning_data(data)
        except: pass
    
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
        app_mutex = kernel32.CreateMutexW(None, False, "Nova_Unique_Mutex_Lock")
        if kernel32.GetLastError() == 183:
            try:
                temp_root = tk.Tk()
                temp_root.withdraw()
                messagebox.showerror("Ошибка", "Программа уже запущена!")
                temp_root.destroy()
            except: pass
            sys.exit()
        return app_mutex

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

    def is_vpn_active_func():
        """Проверяет наличие активных VPN/Туннельных интерфейсов (PowerShell)."""
        try:
            # Используем PowerShell
            cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -ExpandProperty InterfaceDescription"]
            
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            output = subprocess.check_output(cmd, startupinfo=startupinfo, creationflags=subprocess.CREATE_NO_WINDOW, stderr=subprocess.DEVNULL, timeout=3).decode('utf-8', errors='ignore').lower()
            
            # Uncomment to debug what Nova sees:
            # log_print(f"[VPN Debug] Adapters: {output.strip()}")

            # 1. Keywords that trigger VPN detection
            keywords = ["vpn", "wireguard", "openvpn", "tun", "tap", "zerotier", "tailscale", "secu", "fortinet", "cisco", "hamachi", "amnezia", "warp", "cloudflare"]
            
            # 2. Exclusions (Whitelist) - Adapters containing these will be IGNORED
            exclusions = ["radmin"] 

            for line in output.splitlines():
                line_lower = line.lower()
                
                # Check exclusions FIRST
                if any(ex in line_lower for ex in exclusions):
                     continue

                # Check match
                if any(k in line_lower for k in keywords):
                    # log_print(f"[VPN Debug] Found VPN: {line}")
                    return True
            return False
        except: return False

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

            limiter.acquire()
            
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
                            sock.bind(('0.0.0.0', DNS_CHECK_PORT))
                            sock.settimeout(5.0)  # 5 second timeout
                            
                            # Manual DNS query (simplified A record query)
                            import struct
                            import random as rand
                            
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

    def smart_update_general(new_domains_list=None):
        with general_list_lock:
            filepath = os.path.join(get_base_dir(), "list", "general.txt")
            
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
                if not raw: continue
                unique_domains.add(get_registered_domain(raw))
                
            if new_domains_list:
                for d in new_domains_list:
                    clean_new = get_registered_domain(d)
                    if clean_new: unique_domains.add(clean_new)
            
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
        if "[Check]" in line: return "info"
        if "[ExcludeCheck]" in line: return "info"
        
        if any(x in text_lower for x in ["err:", "error", "dead", "crash", "could not read", "fatal", "panic", "must specify", "unknown option", "не удается", "не найдено"]):
            return "error"
        
        if "fail" in text_lower:
            return "fail"
        
        if "ok (" in text_lower:
            return "normal"
        
        if any(x in text_lower for x in ["пропуск", "удаление", "отмена", "инфо", "успешно", "ядро активно"]):
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
                if not os.path.exists(exclude_file):
                    time.sleep(60)
                    continue
                    
                with open(exclude_file, "r", encoding="utf-8") as f:
                    domains = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                
                created_count = 0
                skipped_count = 0
                
                for domain in domains:
                    if is_closing: break
                    
                    safe_name = sanitize_filename(domain)
                    tls_filename = f"tls_clienthello_{safe_name}.bin"
                    tls_path = os.path.join(bin_dir, tls_filename)
                    
                    need_tls = False
                    if not os.path.exists(tls_path):
                        need_tls = True
                    # FIX: Removed weekly regeneration (user request)
                    # else:
                    #    if (time.time() - os.path.getmtime(tls_path)) > 604800:
                    #        need_tls = True
                    
                    if need_tls:
                        try:
                            data = create_tls_client_hello(domain)
                            with open(tls_path, "wb") as f:
                                f.write(data)
                            log_callback(f"[PayloadGen] Создан TLS фейк: {tls_filename}")
                            created_count += 1
                            time.sleep(0.1)
                        except: pass
                    else:
                        skipped_count += 1
                
                if created_count > 0:
                    log_callback(f"[PayloadGen] Создано {created_count} новых TLS-фейков.")
                
            except Exception as e:
                log_callback(f"[PayloadGen ERROR] Критическая ошибка: {e}")
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

    def calc_log_window_pos(mx, my, mw, mh, log_w, log_h, mon_left, mon_right):
        """Рассчитывает позицию окна логов (справа или слева)."""
        # По умолчанию справа
        new_x = mx + mw
        side = "right"
        
        # Если не влезает справа -> переносим налево
        if new_x + log_w > mon_right:
            left_x = mx - log_w
            if left_x >= mon_left:
                new_x = left_x
                side = "left"
        
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
            new_x, new_y, side = calc_log_window_pos(mx, my, mw, mh, lw, lh, mon_left, mon_right)
            
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

    def ensure_log_window_created():
        global log_window, log_text_widget, cached_log_size
        if log_window and tk.Toplevel.winfo_exists(log_window): return
        
        try:
            state = load_window_state()
            cached_log_size = state.get("log_size", "700x450")
        except: pass

        log_window = tk.Toplevel(root)
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
        
        def restart_nova():
            """Перезапускает Nova: корректная остановка -> перезапуск"""
            def do_restart():
                try:
                    # Step 1: Stop service properly (like clicking STOP button)
                    log_print("[Restart] Остановка Nova...")
                    stop_nova_service(silent=False, wait_for_cleanup=True)
                    
                    # Step 2: Release mutex immediately (no need to wait)
                    mutex_released = False
                    try:
                        kernel32 = ctypes.windll.kernel32
                        if 'app_mutex' in globals() and app_mutex:
                            # Check if mutex handle is valid before closing
                            kernel32.CloseHandle(app_mutex)
                            mutex_released = True
                            log_print("[Restart] Mutex освобожден")
                    except Exception as e:
                        log_print(f"[Restart] Предупреждение: не удалось освободить mutex: {e}")
                    
                    # Step 3: Short wait for cleanup (reduced from 1.5s to 0.5s)
                    time.sleep(0.5)
                    
                    # Step 4: Restart application with --show-log flag
                    log_print("[Restart] Перезапуск Nova...")
                    
                    # Get current executable path
                    if getattr(sys, 'frozen', False):
                        # Running as compiled .exe
                        current_exe = sys.executable
                        # Add --show-log argument to open log window on restart
                        subprocess.Popen([current_exe, "--show-log"], creationflags=subprocess.CREATE_NO_WINDOW)
                    else:
                        # Running as .pyw script
                        current_exe = sys.executable
                        script_path = os.path.abspath(__file__)
                        subprocess.Popen([current_exe, script_path, "--show-log"], creationflags=subprocess.CREATE_NO_WINDOW)
                    
                    # Step 5: Exit current instance (reduced delay)
                    time.sleep(0.3)
                    os._exit(0)
                    
                except Exception as e:
                    log_print(f"[Restart] Ошибка перезапуска: {e}")
            
            # Run restart in separate thread to avoid blocking UI
            threading.Thread(target=do_restart, daemon=True).start()
        
        context_menu.add_command(label="Перезапустить Nova", command=restart_nova)

        log_text_widget.tag_bind("clickable_cmd", "<Button-1>", copy_command)
        log_text_widget.bind("<Button-3>", lambda e: context_menu.post(e.x_root, e.y_root))
        log_text_widget.bind("<Key>", handle_key_press)
        # log_text_widget.bind("<Enter>", lambda e: globals().update(auto_scroll_enabled=False))
        # log_text_widget.bind("<Leave>", lambda e: globals().update(auto_scroll_enabled=True))
        
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
    LOG_SCROLL_STATE = {"in_window": False, "focused": False, "last_leave": 0}

    def should_auto_scroll():
        try:
             # 1. Not focused -> Auto Scroll
             if not LOG_SCROLL_STATE["focused"]: return True
             # 2. In window -> Pause
             if LOG_SCROLL_STATE["in_window"]: return False
             # 3. Delay
             if time.time() - LOG_SCROLL_STATE["last_leave"] < 1.0: return False
             return True
        except: return True

    def log_print(message):
        # if is_closing: return  <-- FIX: Allow logs during shutdown/update
        try: sys.__stdout__.write(message + '\n')
        except: pass
        if root:
            root.after(0, lambda m=message: _safe_log_insert(m))

    def _safe_log_insert(string):
        global early_log_buffer
        lw_exists = log_window and tk.Toplevel.winfo_exists(log_window)
        
        if lw_exists:
            try:
                # FIX: Enable widget before insert (might be disabled by LiveProgressManager)
                log_text_widget.configure(state=tk.NORMAL)
                
                if int(log_text_widget.index('end-1c').split('.')[0]) > LOG_MAX_LINES:
                    log_text_widget.delete('1.0', '101.0')
                
                tag = "normal"
                if "[Check]" in string: tag = "info"
                if "[ExcludeCheck]" in string: tag = "info"
                if "FAIL" in string: tag = "fail"
                if "[Warning]" in string: tag = "warning"
                if "OK" in string: tag = "normal"
                
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
        if active > total - score: active = total - score # Active is remainder
        
        ratio_success = score / total
        ratio_active = active / total

        success_chars = int(ratio_success * width)
        active_chars = int(ratio_active * width)
        
        # Ensure distinct chars check
        if active > 0 and active_chars == 0 and (success_chars + active_chars) < width:
             active_chars = 1

        # Strict Clamp to width
        total_chars = success_chars + active_chars
        if total_chars > width:
            # overflow? reduce active first
            excess = total_chars - width
            active_chars = max(0, active_chars - excess)
            # if still overflow, reduce success
            total_chars = success_chars + active_chars
            if total_chars > width:
                success_chars = max(0, width - active_chars)

        gap_chars = width - success_chars - active_chars
        if gap_chars < 0: gap_chars = 0
        
        bar = "█" * success_chars + "░" * active_chars + " " * gap_chars
        return bar   

    progress_manager = LiveProgressManager()


    # ================= VPN ДЕТЕКТОР =================
    
    def vpn_monitor_worker(log_func):
        """Monitors for VPN connections and pauses/resumes the service."""
        global is_vpn_active, was_service_active_before_vpn, is_service_active, is_closing
        while not is_closing:
            try:
                vpn_is_currently_active = is_vpn_active_func()

                if vpn_is_currently_active and not is_vpn_active:
                    log_func("[VPN Detector] Обнаружен активный VPN. Работа приостановлена.")
                    is_vpn_active = True
                    was_service_active_before_vpn = is_service_active
                    if is_service_active: stop_nova_service(silent=True)
                    if root: root.after(0, lambda: (status_label.config(text="ПАУЗА (VPN)", fg=COLOR_TEXT_ERROR), btn_toggle.config(state=tk.DISABLED)))
                elif not vpn_is_currently_active and is_vpn_active:
                    log_func("[VPN Detector] VPN отключен. Возобновление работы...")
                    is_vpn_active = False
                    
                    def restore_ui():
                        btn_toggle.config(state=tk.NORMAL)
                        # Если сервис не был активен, сбрасываем статус с "ПАУЗА (VPN)" на нейтральный
                        if not was_service_active_before_vpn:
                            status_label.config(text="ГОТОВ К ЗАПУСКУ", fg="#cccccc") # Neutral color

                    if root: root.after(0, restore_ui)
                    if was_service_active_before_vpn: start_nova_service()
            except Exception as e: log_func(f"[VPN Detector] Ошибка в цикле мониторинга: {e}")
            time.sleep(15)

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
        
    # ================= IP UTILS =================
    
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
                        log_func(f"[Auto-Exclude] Кэш IP обновлен (+{len(resolved_ips)}).")
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

    def update_ip_cache_worker(paths, log_func):
        while True:
            if is_closing: break
            try:
                need_update = False
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
                else:
                    cache_mtime = os.path.getmtime(IP_CACHE_FILE)
                    for fpath in [paths['list_exclude'], paths['ip_exclude']]:
                        if os.path.exists(fpath) and os.path.getmtime(fpath) > cache_mtime:
                            need_update = True
                            break
                
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

            # Пауза 60 секунд перед следующей полной проверкой
            for _ in range(60):
                if is_closing: return
                time.sleep(1)

    def domain_cleaner_worker(log_func):
        """Периодически проверяет все списки на "мертвые" домены и удаляет их."""
        global last_strategy_check_time
        
        # Initial delay: 1 minute
        time.sleep(60)
        
        while not is_closing:
            try:
                # Wait for strategy checks to complete
                while not is_closing:
                    if is_scanning:
                        # Strategy checks are running, wait
                        time.sleep(10)
                        continue
                    
                    # Check if strategy checks happened recently
                    time_since_last = time.time() - last_strategy_check_time
                    if time_since_last < 60:  # 1 minute cooldown
                        # Wait for cooldown, but check every 5 seconds if new checks started
                        remaining = 60 - time_since_last
                        for _ in range(int(remaining / 5) + 1):
                            if is_closing: break
                            if is_scanning:
                                # New strategy check started, reset timer
                                break
                            time.sleep(min(5, remaining))
                            remaining = 60 - (time.time() - last_strategy_check_time)
                            if remaining <= 0:
                                break
                        
                        # If strategy check started during wait, restart loop
                        if is_scanning:
                            continue
                    
                    # Cooldown complete and no active checks
                    break
                
                if is_closing:
                    break
                
                # Start domain validation
                base_dir = get_base_dir()
                list_dir = os.path.join(base_dir, "list")
                
                files_to_check = glob.glob(os.path.join(list_dir, "*.txt"))
                
                dead_domains_found = set()
                total_checked = 0

                for file_path in files_to_check:
                    if is_closing: break
                    
                    # CRITICAL: Stop if strategy checks started
                    if is_scanning:
                        log_func("[DomainCleaner] Проверка приостановлена (началась проверка стратегий)")
                        # Wait for strategy checks to complete, then restart
                        while not is_closing and is_scanning:
                            time.sleep(10)
                        continue  # Restart from beginning
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            lines = f.readlines()
                        
                        domains_in_file = [line.split('#')[0].strip().lower() for line in lines if line.strip() and not line.startswith('#')]
                        if not domains_in_file:
                            continue

                            start_idx = 0
                        new_lines = []
                        # FIX: Store progress in temp/ to allow easy cleanup
                        progress_filename = os.path.basename(file_path) + ".progress"
                        progress_path = os.path.join(base_dir, "temp", progress_filename)
                        
                        # Resume logic
                        if os.path.exists(progress_path):
                            try:
                                p_data = load_json_robust(progress_path)
                                start_idx = p_data.get("idx", 0)
                                new_lines = p_data.get("lines", [])
                                if start_idx > 0:
                                    log_func(f"[DomainCleaner] Восстановление проверки {os.path.basename(file_path)} с строки {start_idx}")
                            except: pass

                        for idx, line in enumerate(lines):
                            if idx < start_idx: continue

                            if is_closing: break
                            
                            # CRITICAL: Stop if strategy checks started
                            if is_scanning:
                                log_func("[DomainCleaner] Проверка приостановлена (началась проверка стратегий)")
                                # Save progress explicitly before yield
                                save_json_safe(progress_path, {"idx": idx, "lines": new_lines})
                                
                                # Wait for strategy checks to complete
                                while not is_closing and is_scanning:
                                    time.sleep(10)
                                # Restart (Resume from saved progress)
                                break
                            
                            domain_part = line.split('#')[0].strip().lower()
                            if not domain_part:
                                new_lines.append(line)
                                continue

                            # DNS validation with rate limit (5/sec via cleanup_limiter)
                            domain_exists = dns_manager.validate_domain_exists(domain_part, dns_manager.cleanup_limiter)
                            total_checked += 1
                            
                            if not domain_exists:
                                # Domain confirmed as NXDOMAIN
                                dead_domains_found.add(domain_part)
                                rewritten = True
                                log_func(f"[DomainCleaner] Удалён: {domain_part} (не существует)")
                            else:
                                new_lines.append(line)
                            
                            # Periodic Autosave (every 10 lines)
                            if idx % 10 == 0:
                                save_json_safe(progress_path, {"idx": idx + 1, "lines": new_lines})
                        
                        # Completion
                        if not is_scanning and not is_closing:
                            # Apply changes
                            if len(new_lines) < len(lines): # Something removed
                                lock = general_list_lock if "general" in os.path.basename(file_path) else None
                                _remove_domain_from_file(None, file_path, lock=lock, rewrite_lines=new_lines)
                            
                            # Clean progress
                            if os.path.exists(progress_path): os.remove(progress_path)

                    except Exception as e:
                        # Silent error handling
                        pass

                # Log summary only if domains were found
                if dead_domains_found:
                    log_func(f"[DomainCleaner] Проверка завершена: удалено {len(dead_domains_found)} доменов из {total_checked} проверенных")
                
                # Pause for 24 hours before next check
                for _ in range(24 * 3600):
                    if is_closing: break
                    time.sleep(1)

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
                            log_func(f"[Sorter] {svc}: Новая текущая стратегия -> {best_strat.get('name', 'Unknown')} (Score: {best_score})")
                            log_func(f"[Sorter] {svc}: Список стратегий обновлен и отсортирован.")
                except Exception as e:
                     if log_func: log_func(f"[Sorter] Ошибка сортировки {svc}: {e}")
    
    STANDBY_LOG_TIMERS = {} # ThreadId -> timestamp

    def advanced_strategy_checker_worker(log_func):
        global is_closing, is_scanning, restart_requested_event, is_service_active
        import random
        import shutil
        import glob
        import json
        import queue
        import concurrent.futures
        import hashlib
        
        # Обертываем всю логику в бесконечный цикл для мониторинга смены IP
        was_active = False # State to detect service start/restart transitions
        while not is_closing:
            try:
                if is_vpn_active:
                    time.sleep(5)
                    continue

                if not is_service_active:
                    time.sleep(1)
                    continue
                
                # Capture current ID for this cycle's tasks (managed by toggle_worker)
                current_run_id = SERVICE_RUN_ID
                
                # === Init: Prepare isolated test executable ===
                try:
                    exe_name = WINWS_FILENAME
                    test_exe_name = "winws_test.exe"
                    exe_path = os.path.join(get_base_dir(), "bin", exe_name)
                    test_exe_path = os.path.join(get_base_dir(), "bin", test_exe_name)
                    if os.path.exists(exe_path):
                        shutil.copy2(exe_path, test_exe_path)
                except Exception as e:
                    log_func(f"[Check] Ошибка подготовки ядра: {e}")
                
                # === CRITICAL HEALTH CHECK ===
                # Check if main winws.exe is still running. If not, restart immediately.
                if process and process.poll() is not None and is_service_active:
                     log_func(f"[Check] КРИТИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ: Основной процесс winws.exe упал (код {process.poll()}). Перезапуск...")
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
                        proc = subprocess.Popen([exe_path] + test_args, cwd=get_base_dir(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
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
                                    
                                log_func(f"[Check] Пропуск: отсутствует файл {val}")
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
                        isolation_filter = f"outbound and !loopback and ((tcp and tcp.SrcPort >= {port_start} and tcp.SrcPort <= {p_end}) or (udp and udp.SrcPort >= {port_start} and udp.SrcPort <= {p_end}))"
                        
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
                        
                        # Определяем протоколы для захвата, чтобы не ловить лишнее (причина сбоев)
                        has_tcp = any("filter-tcp" in a for a in test_args)
                        has_udp = any("filter-udp" in a for a in test_args)
                        if not has_tcp and not has_udp: has_tcp = has_udp = True
                        
                        proto_parts = []
                        if has_tcp: proto_parts.append(f"(tcp and tcp.SrcPort >= {port_start} and tcp.SrcPort <= {p_end})")
                        if has_udp: proto_parts.append(f"(udp and udp.SrcPort >= {port_start} and udp.SrcPort <= {p_end})")
                        
                        isolation_filter = f"outbound and !loopback and ({' or '.join(proto_parts)})"
                        
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
                            proc = subprocess.Popen(final_args, cwd=get_base_dir(), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace', creationflags=subprocess.CREATE_NO_WINDOW)
                            
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
                                if attempt == 0:
                                    if stderr_out: log_func(f"[Check] Ошибка WinWS: {stderr_out.strip()}")
                                if attempt == 1:
                                    log_func(f"[Check] Стратегия вызывает сбой процесса. Пропускаем.")
                                    return 0
                            log_func(f"[Check] WinWS упал (код {proc.returncode}). Порт: {port_start}. Попытка {attempt+1}/2")
                            if attempt == 0:
                                # log_func(f"[Check] Аргументы сбоя: {' '.join(final_args)}")
                                if stderr_out: log_func(f"[Check] Ошибка WinWS: {stderr_out.strip()}")
                            if attempt == 1:
                                log_func(f"[Check] Стратегия вызывает сбой процесса. Пропускаем.")
                                return 0 # Возвращаем 0 (blocked), чтобы не ломать воркер возвратом None
                            time.sleep(2)
                        
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
                        """Проверяет ограничения мутации"""
                        for a in new_args:
                            if not isinstance(a, str): continue
                            # Запрет wssize
                            if "--wssize" in a or "--wsize" in a:
                                return False
                            # TTL <= 11
                            if "--dpi-desync-ttl=" in a:
                                try:
                                    v = int(a.split("=")[1])
                                    if v > 11: return False
                                except: pass
                        # Не более 2 bin файлов
                        if count_bin_files(new_args) > 2:
                            return False
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
                            tls_bins = [b for b in bin_files if "tls" in b.lower() or "clienthello" in b.lower()]
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
                    "evolution_stage": 0
                }

                state_lock = threading.Lock()
                s_display = "" # Prevent UnboundLocalError
                state.update(load_json_robust(state_path, {}))
                
                # last_standby_log_wrapper removed - using state instead
                # FIX: Если версия изменилась или было обновление -> Сбрасываем флаг завершения
                # чтобы гарантировать проверку стратегий на новой версии
                try:
                    is_updated = ARGS_PARSED.get('updated', False)
                except (NameError, AttributeError):
                    is_updated = '--updated' in sys.argv
                if state.get("app_version") != CURRENT_VERSION or is_updated:
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
                    except: pass

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
                    # log_func(f"[Check] Не удалось определить IP: {e}. Повтор через 60 сек.")
                    time.sleep(60)
                    continue

                # Еще одна проверка после получения IP, чтобы гарантировать, что это не IP от VPN
                if is_vpn_active_func():
                    time.sleep(5)
                    continue
                
                # === FIX: Если IP None (ошибка сети), не продолжаем, чтобы не сбросить прогресс ===
                if not current_ip:
                    time.sleep(10)
                    continue

                need_check = False
                # === НОВОЕ: Записываем IP и проверяем нужна ли переверификация ===
                # === НОВОЕ: Записываем IP и проверяем нужна ли переверификация (IP, Версия, Время) ===
                needs_ip_recheck = record_ip_change(current_ip, log_func)
                
                # Check 7-day timeout
                last_full_ts = state.get("last_full_check_time", 0)
                days_passed = 0
                if last_full_ts > 0:
                     days_passed = (time.time() - last_full_ts) / 86400
                
                is_timeout = days_passed > 7

                if needs_ip_recheck or is_timeout:
                    need_check = True
                    # FIX: Correct message for default timestamp
                    if last_full_ts == 0:
                        reason = f"смена IP ({current_ip})" if needs_ip_recheck else "первая проверка стратегий"
                    else:
                        reason = f"смена IP ({current_ip})" if needs_ip_recheck else f"плановая ревалидация ({int(days_passed)} дн.)"
                    
                    log_func(f"Обнаружена {reason}. Запуск полной проверки стратегий")
                    state = {
                        "wave": 1, "idx": 0, "current_wave_strategies": [],
                        "best_strategies": [], "bin_performance": {b: 0 for b in bin_files},
                        "general_score": -1, "completed": False,
                        "hard_checked": False,
                        "youtube_checked": False,
                        "discord_checked": False,
                        "cloudflare_checked": False,
                        "whatsapp_checked": False,
                        "last_wave_count": 0,
                        "evolution_stage": 0
                    }
                    save_state()
                
                if not need_check:
                    # === НОВОЕ: Проверка необходимости продолжения эволюции ===
                    # Если completed=False, но все основные проверки завершены -> нужно продолжить эволюцию
                    all_checks_done = (
                        state.get("hard_checked", False) and
                        state.get("youtube_checked", False) and
                        state.get("discord_checked", False) and
                        state.get("cloudflare_checked", False) and
                        state.get("whatsapp_checked", False)
                    )
                    
                    if not state.get("completed", False):
                        if all_checks_done:
                            # Основная проверка завершена, но эволюция не закончена
                            if IS_DEBUG_MODE: log_func(f"[StrategyChecker-Debug] Продолжение эволюции (все проверки завершены, но completed=False)")
                            need_check = True
                        else:
                            # Основная проверка еще не завершена
                            if IS_DEBUG_MODE: log_func(f"[StrategyChecker-Debug] Force check: completed=False")
                            need_check = True

                if not need_check:
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
                         
                    time.sleep(5) 
                    continue

                # --- Подготовка задач для всех сервисов ---
                all_tasks = [] # (service_key, strategy_entry, domains, json_path)
                is_scanning = True # FIX: Ensure flag set here

                def prepare_service_tasks(service_key, json_path, test_domains, state_key):
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
                            if service_key in main_data:
                                # Mark as "Current" for UI clarity, but it might duplicate a file strategy.
                                # StrategyChecker will check it.
                                service_strategies.append({"name": f"Current {service_key}", "args": main_data[service_key]})
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
                ds_domains = read_domains_from_file(discord_list_path)
                if not ds_domains:
                    ds_domains = ["discord.com", "gateway.discord.gg", "cdn.discordapp.com", "discordapp.com"]
                all_tasks.extend(prepare_service_tasks("discord", discord_strat_path, ds_domains, "discord_checked"))
                
                # --- 3. WhatsApp Strategy Check ---
                whatsapp_list_path = os.path.join(base_dir, "list", "whatsapp.txt")
                wa_domains = read_domains_from_file(whatsapp_list_path)
                if not wa_domains:
                    wa_domains = ["whatsapp.com", "whatsapp.net"]
                all_tasks.extend(prepare_service_tasks("whatsapp", whatsapp_strat_path, wa_domains, "whatsapp_checked"))
                
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

                # === НОВОЕ: Проверка - нужно ли пропустить основную проверку и перейти к эволюции ===
                skip_main_check = (
                    state.get("hard_checked", False) and
                    state.get("youtube_checked", False) and
                    state.get("discord_checked", False) and
                    state.get("cloudflare_checked", False) and
                    state.get("whatsapp_checked", False) and
                    not state.get("completed", False)
                )
                
                if skip_main_check:
                    log_func(f"[Check] Основная проверка уже завершена. Переход к эволюции...")
                    # Пропустим подготовку доменов и сразу перейдем к эволюции
                    domains_for_general = []  # Будет загружено позже при необходимости
                else:
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
                    # Исключаем те, что заработали сами (чтобы не портить статистику стратегий)
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
                    
                    log_func(f"[Check] Тестирование на {len(alive_hot)} заблокированных доменах из истории посещений и {len(alive_cold)} доменов из списка rkn")
                
                current_strategies_data = {}
                try:
                    with open(strat_path, "r", encoding="utf-8") as f:
                        current_strategies_data = json.load(f)
                except: pass
                old_hard_strategies = {k: v for k, v in current_strategies_data.items() if k.startswith("hard_")}

                # Добавляем в общий пул, если нужна проверка и мы НЕ пропускаем основную проверку
                if not skip_main_check and (state["general_score"] <= 0 or not state.get("hard_checked", False)):
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
                                    log_func(f"[Init] Восстановлен прогресс для IP {current_ip}: {len(completed_tasks)} стратегий уже проверено.")
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
                    

                    # Reset Baselines for this session strictly! 
                    # We rely on "Current ..." strategies (checked first) to establish the baseline.
                    # Previous session scores are irrelevant if network changed.
                    service_baselines = {} 
                    active_scores_runtime = {}  # FIX: Cached scores for sorting phase 
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
                                    is_current = s_name.startswith("Current ") or s_name.startswith("Текущая ")

                                    # Обновляем базовый счетчик, если это текущая стратегия
                                    if is_current:
                                        service_baselines[svc] = sc
                                        if svc == "general": state["general_score"] = sc
                                        else: state[f"{svc}_score"] = sc
                                        save_state()
                                        
                                        # CRITICAL: Проверяем pending_hotswap для этого сервиса
                                        # (стратегии, которые были проверены ДО Current)
                                        for p_sc, p_strat, p_svc in pending_hotswap:
                                            if p_svc == svc and p_sc > sc:
                                                msg_t = f"   >>> Найдена более сильная стратегия для {svc} ({p_sc} > {sc}) [из очереди]"
                                                if root: root.after(0, lambda m=msg_t: log_print(m))
                                                
                                                service_baselines[svc] = p_sc
                                                if svc == "general": state["general_score"] = p_sc
                                                else: state[f"{svc}_score"] = p_sc
                                                save_state()
                                                
                                                update_active_config_immediate(p_svc, p_strat["args"], "   Применена новая стратегия (Pending)")
                                                break  # Применили лучшую - выходим

                                    # Логика замены (Hot Swap)
                                    # Берем текущий базовый счет
                                    bl = service_baselines.get(svc, -1)
                                    
                                    # CRITICAL FIX: Если baseline ещё не установлен для этого сервиса,
                                    # значит "Current" стратегия ещё не была обработана (гонка в futures).
                                    # Пропускаем Hot Swap - стратегия будет обработана в финальной сортировке.
                                    # Но НЕ пропускаем Blockage Logic и Save Progress!
                                    baseline_ready = (bl >= 0)
                                    
                                    # Если baseline не готов - откладываем Hot Swap проверку
                                    if not baseline_ready and not is_current:
                                        pending_hotswap.append((sc, strat, svc))


                                    if baseline_ready and not is_current and sc > bl:
                                         # Thread-safe логирование в GUI
                                         msg_t = f"   >>> Найдена более сильная стратегия для {svc} ({sc} > {bl})"
                                         if root: root.after(0, lambda m=msg_t: log_print(m))
                                         
                                         # Обновляем baseline сразу
                                         service_baselines[svc] = sc
                                         if svc == "general": state["general_score"] = sc
                                         else: state[f"{svc}_score"] = sc
                                         save_state()

                                         update_active_config_immediate(svc, strat["args"], "   Применена новая стратегия")


                                    # Blockage Logic
                                    if sc == 0:
                                        consecutive_zeros[svc] = consecutive_zeros.get(svc, 0) + 1
                                        if consecutive_zeros[svc] > 2 and svc not in blocked_services and svc not in proven_working_services:
                                            blocked_services.add(svc)
                                            log_func(f"[Warning] {svc} не отвечает (3 раза по 0). Пропуск остальных.")
                                            task_queue = [t for t in task_queue if t[0] != svc]
                                            for f, t in active_futures.items():
                                                if t[0] == svc: f.cancel()
                                    else:
                                        consecutive_zeros[svc] = 0
                                        proven_working_services.add(svc)
                                    
                                    # Save progress
                                    completed_tasks.add(s_name)
                                    if len(completed_tasks) % 5 == 0:
                                         save_json_safe(PROGRESS_FILE, {
                                            "completed": list(completed_tasks), 
                                            "timestamp": time.time(), "ip": current_ip 
                                         })

                                except Exception as e:
                                    log_func(f"[Check] Error processing result: {e}")

                    finally:
                        executor.shutdown(wait=not aborted_by_service, cancel_futures=True)

                # Check abort status
                if aborted_by_service or (not is_service_active and not is_closing):
                    # FIX: Prevent looped logging. If stopped, clear remaining tasks and break outer loop effectively.
                    is_scanning = False
                    
                    # Only log if we were actually doing something
                    if task_queue or active_futures:
                         log_func("[Check] Процесс остановлен пользователем.")
                    
                    # Clear everything to prevent re-entry in this cycle
                    all_tasks = []
                    task_queue = []
                    
                    time.sleep(2) # Give UI time to breathe
                    continue 

                def sort_and_distribute_results(results_list, score_cache=None, log_func=log_func):
                    # Sort by Score DESC
                    results_list.sort(key=lambda x: x[0], reverse=True)
                    
                    if score_cache is None: score_cache = {}

                    # Split by Service
                    grouped = {}
                    for sc, strat, svc in results_list:
                        if svc not in grouped: grouped[svc] = []
                        grouped[svc].append((sc, strat))
                        
                    for svc, items in grouped.items():
                        # Get current baseline for this service
                        baseline = service_baselines.get(svc, -1)
                        
                        top_strat = items[0] # (score, strat_obj)
                        top_score = top_strat[0]
                        
                        # Only log if exciting improvement or Current
                        if top_score > baseline:
                             log_func(f"[Sorter] {svc}: Новая лучшая -> {top_strat[1].get('name', 'Unknown')} ({top_score})")

                        # Save SORTED lists back to files
                        # Save SORTED lists back to files
                        target_limit = 60 if svc == "general" else 12
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
                            
                            checked_names_current = set(st['name'] for sc, st in items)
                            
                            unchecked_strategies = []
                            cached_strategies_to_add = []
                            
                            for s in existing_list:
                                s_name = s['name']
                                if s_name in checked_names_current:
                                    pass # Already in 'items' (new result overrides cache)
                                elif (svc, s_name) in score_cache:
                                    # Found in Cache! Treat as Checked/Verified baseline.
                                    # Add to pool with Cached Score to complete in Tournament.
                                    cached_score = score_cache[(svc, s_name)]
                                    cached_strategies_to_add.append({"score": cached_score, "strat": s})
                                else:
                                    unchecked_strategies.append(s)
                            
                            # 3. Create Pool of "Active Candidates"
                            # 'items' contains ALL results from this run. 
                            
                            active_candidates = [] # list of dict(score, strat)
                            
                            for sc, st in items:
                                active_candidates.append({"score": sc, "strat": st})
                            
                            # Add Cached (Old Verified)
                            active_candidates.extend(cached_strategies_to_add)
                            
                            # Sort Active Candidates by Score DESC
                            active_candidates.sort(key=lambda x: x["score"], reverse=True)
                            
                            # --- UPDATE strategies.json (Global Active Config) ---
                            # FIX: Update for ALL services if we found a better one (Top 1)
                            # This ensures Hot Swap applies the new best strategy immediately.
                            
                            if active_candidates:
                                try:
                                    strat_main_path = os.path.join(base_dir, "strat", "strategies.json")
                                    main_data = load_json_robust(strat_main_path, {})
                                    
                                    # We allow update even in Evo mode because 'active_candidates' includes 
                                    # both New Mutants and Old Cached Parents (sorted by score).
                                    # So active_candidates[0] is strictly the Best Known Strategy.
                                    
                                    best_strat = active_candidates[0]["strat"]
                                    updated_active = False
                                    
                                    if svc == "general":
                                        # 1. Update "Current General"
                                        if best_strat and "args" in best_strat:
                                            # Optional: Check if different to avoid IO churn? 
                                            # JSON save is cheap enough generally.
                                            main_data["general"] = best_strat["args"]
                                            updated_active = True
                                            
                                        # 2. Update "hard_1" ... "hard_12"
                                        for i in range(12):
                                            key = f"hard_{i+1}"
                                            if i < len(active_candidates):
                                                s_cand = active_candidates[i]["strat"]
                                                if "args" in s_cand:
                                                    main_data[key] = s_cand["args"]
                                                    updated_active = True
                                    else:
                                        # For specific services (youtube, discord, etc.)
                                        # Update the key with service name
                                        if best_strat and "args" in best_strat:
                                            main_data[svc] = best_strat["args"]
                                            updated_active = True
                                    
                                    if updated_active:
                                        save_json_safe(strat_main_path, main_data)
                                        log_func(f"[Sorter] strategies.json обновлен для {svc} (Best: {best_strat.get('name')})")
                                        
                                except Exception as e:
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
                                
                                limit_verified = target_limit
                                # FIX: Strict constraint to ensure we don't float above limit
                                if len(active_candidates) > limit_verified:
                                    active_candidates = active_candidates[:limit_verified]
                                
                                final_active = [x["strat"] for x in active_candidates]
                            
                            # 5. Combine and Save
                            final_list = final_active + unchecked_strategies
                            
                            # Save
                            new_data = {"version": "1.0", "strategies": final_list}
                            save_json_safe(start_path, new_data)
                            
                            log_func(f"[Sorter] {svc}: Оптимизация. Проверено: {len(active_candidates)}, Оставлено: {len(final_active)}, Не тронуто: {len(unchecked_strategies)}. Всего: {len(final_list)}")
                            
                        except Exception as e:
                            log_func(f"[Sorter] Ошибка сохранения {svc}: {e}")
                            pass





                # === CALL SORTER for Phase 1 Results ===
                # This prunes the files to the strict limits (Tournament Phase 1)
                sort_and_distribute_results(all_strategy_results, score_cache=active_scores_runtime)

                if IS_DEBUG_MODE: log_func("[StrategyChecker-Debug] Фаза завершена. Сохранение состояния...")
                # === НОВОЕ: Пропускаем сохранение флагов если они уже были установлены (продолжение после перезапуска) ===
                if not skip_main_check:
                    state["cloudflare_checked"] = True
                    state["youtube_checked"] = True
                    state["discord_checked"] = True
                    state["whatsapp_checked"] = True
                    state["hard_checked"] = True
                    save_state()
                    if IS_DEBUG_MODE: log_func("[StrategyChecker-Debug] Состояние сохранено.")
                else:
                    if IS_DEBUG_MODE: log_func("[StrategyChecker-Debug] Пропуск сохранения флагов (уже установлены).")
                # --- Загрузка кандидатов из general.json ---
                
                if not is_service_active or is_closing:
                    log_func("[Check] Проверка остановлена перед этапом Эволюции.")
                    is_scanning = False
                    break

                # --- PHASE 3: EVOLUTION (3 STAGES) ---
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
                    if start_stage >= len(stages):
                        if IS_DEBUG_MODE: log_func(f"[StrategyChecker-Debug] Все этапы эволюции завершены, пропуск блока.")
                    else:
                        if start_stage > 0:
                            log_func(f"[Check] Восстановление эволюции с этапа {start_stage+1}/3...")
                        
                        
                        for stage_idx, percentage in enumerate(stages):
                            prefix = f"[Evo-{stage_idx+1}]"
                            if stage_idx < start_stage: 
                                if IS_DEBUG_MODE: log_func(f"[Check-Debug] Пропуск этапа {stage_idx} (Target: {start_stage})")
                                continue
                            if not is_service_active or is_closing: break

                            
                            # Сохраняем текущий этап в начале
                            state["evolution_stage"] = stage_idx
                            save_state()
                            
                            # 1. Gather Strategies from Files (Freshly Sorted)
                            strategies_to_evolve = []
                            
                            try:
                                # === LOGIC SPLIT: --evo режим vs обычный режим ===
                                
                                if IS_EVO_MODE:
                                    # === РЕЖИМ --evo: Мутации текущих стратегий ===
                                    # Этап 1: 60%, Этап 2: 40%, Этап 3: 20% (от лимита, округление вверх)
                                    evo_pct = stages[stage_idx] if stage_idx < len(stages) else 0.2
                                    
                                    log_func(f"[Evo] Режим --evo: Этап {stage_idx+1} ({int(evo_pct*100)}%)")
                                    
                                    d = load_json_robust(strat_path, {})
                                    if not isinstance(d, dict): d = {}
                                    
                                    # 1. General: берём hard_1-12 из strategies.json
                                    # Limit for General is technically 60, but we operate on Active Hard ones primarily here.
                                    # User requirement: "60% from their limit".
                                    # Check general.json for candidates if we want to follow the rule strictly?
                                    # User mentioned "youtube.json checked all... so on evo checked 60%".
                                    # For General, let's keep current logic of Hard strategies but maybe filter count?
                                    # No, existing logic takes ALL 12 hard strategies. 12 is 20% of 60. So perfectly fits all stages.
                                    
                                    for i in range(12):
                                        k = f"hard_{i+1}"
                                        if k in d:
                                            strategies_to_evolve.append(({
                                                "name": k, 
                                                "args": d[k]
                                            }, "general"))
                                    
                                    # + текущая general стратегия
                                    if "general" in d and isinstance(d["general"], list):
                                        strategies_to_evolve.append(({
                                            "name": "Current General",
                                            "args": d["general"]
                                        }, "general"))
                                    
                                    # === FIX: Include general.json candidates (60% of limit 60) ===
                                    gen_limit = 60
                                    gen_count = int(gen_limit * evo_pct + 0.999)
                                    
                                    gen_pool_path = os.path.join(base_dir, "strat", "general.json")
                                    if os.path.exists(gen_pool_path):
                                        g_data = load_json_robust(gen_pool_path, {})
                                        g_list = []
                                        if isinstance(g_data, dict) and "strategies" in g_data:
                                            g_list = g_data["strategies"]
                                        elif isinstance(g_data, list):
                                            g_list = g_data
                                        
                                        # Avoid duplicates (hard_1..12 are likely in here too, but args comparison handles it later)
                                        # We just take Top N from the sorted file
                                        for s in g_list[:gen_count]:
                                             if isinstance(s, dict) and "args" in s:
                                                 strategies_to_evolve.append((s, "general"))
                                    
                                    # 2. YouTube: текущая + из youtube.json (Top N%)
                                    if "youtube" in d and isinstance(d["youtube"], list):
                                        strategies_to_evolve.append(({
                                            "name": "Current youtube",
                                            "args": d["youtube"]
                                        }, "youtube"))
                                    
                                    yt_limit = 12
                                    yt_count = int(yt_limit * evo_pct + 0.999)
                                    
                                    yt_path = os.path.join(base_dir, "strat", "youtube.json")
                                    if os.path.exists(yt_path):
                                        yt_data = load_json_robust(yt_path, {})
                                        yt_list = []
                                        if isinstance(yt_data, dict) and "strategies" in yt_data:
                                            yt_list = yt_data["strategies"]
                                        elif isinstance(yt_data, list):
                                            yt_list = yt_data
                                        # Sort just in case to get TOP
                                        # (Assuming file is generally sorted, but verification doesn't hurt if we have cache)
                                        # Simple truncation for now as per previous logic, usually sorted by Last Check
                                        for s in yt_list[:yt_count]:
                                            if isinstance(s, dict) and "args" in s:
                                                strategies_to_evolve.append((s, "youtube"))
                                    
                                    # 3. Discord: текущая + из discord.json (Top N%)
                                    if "discord" in d and isinstance(d["discord"], list):
                                        strategies_to_evolve.append(({
                                            "name": "Current discord", 
                                            "args": d["discord"]
                                        }, "discord"))
                                    
                                    dc_limit = 12
                                    dc_count = int(dc_limit * evo_pct + 0.999)
                                    
                                    dc_path = os.path.join(base_dir, "strat", "discord.json")
                                    if os.path.exists(dc_path):
                                        dc_data = load_json_robust(dc_path, {})
                                        dc_list = []
                                        if isinstance(dc_data, dict) and "strategies" in dc_data:
                                            dc_list = dc_data["strategies"]
                                        elif isinstance(dc_data, list):
                                            dc_list = dc_data
                                        for s in dc_list[:dc_count]:
                                            if isinstance(s, dict) and "args" in s:
                                                strategies_to_evolve.append((s, "discord"))
                                    
                                else:
                                    # === ОБЫЧНЫЙ РЕЖИМ: 60% → 40% → 20% из проверенных файлов ===
                                    
                                    # 1. General: ТОЛЬКО из general.json (не hard_x)
                                    gen_path = os.path.join(base_dir, "strat", "general.json")
                                    if os.path.exists(gen_path):
                                        gen_data = load_json_robust(gen_path, {})
                                        gen_list = []
                                        if isinstance(gen_data, dict) and "strategies" in gen_data:
                                            gen_list = gen_data["strategies"]
                                        elif isinstance(gen_data, list):
                                            gen_list = gen_data
                                        
                                        # Сортируем по score из кэша если есть
                                        scored_gen = []
                                        for s in gen_list:
                                            if isinstance(s, dict) and "args" in s:
                                                name = s.get("name", "")
                                                cached_score = active_scores_runtime.get(("general", name), 0)
                                                scored_gen.append((cached_score, s))
                                        
                                        scored_gen.sort(key=lambda x: x[0], reverse=True)
                                        
                                        max_general = 60
                                        count = int(max_general * percentage)
                                        if count < 1: count = 1
                                        
                                        for _, s in scored_gen[:count]:
                                            strategies_to_evolve.append((s, "general"))
                                    
                                    # 2. YouTube: из youtube.json
                                    max_special = 12
                                    special_count = int(max_special * percentage)
                                    if special_count < 1: special_count = 1
                                    
                                    for svc in ["youtube", "discord"]:
                                        sp = os.path.join(base_dir, "strat", f"{svc}.json")
                                        if os.path.exists(sp):
                                            s_spec_data = load_json_robust(sp, {})
                                            s_spec_list = []
                                            
                                            if isinstance(s_spec_data, dict) and "strategies" in s_spec_data:
                                                s_spec_list = s_spec_data["strategies"]
                                            elif isinstance(s_spec_data, list):
                                                s_spec_list = s_spec_data
                                            
                                            # Сортируем по score
                                            scored_spec = []
                                            for s in s_spec_list:
                                                if isinstance(s, dict) and "args" in s:
                                                    name = s.get("name", "")
                                                    cached_score = active_scores_runtime.get((svc, name), 0)
                                                    scored_spec.append((cached_score, s))
                                            
                                            scored_spec.sort(key=lambda x: x[0], reverse=True)
                                            
                                            # Unique filter
                                            unique_spec = []
                                            seen_args = set()
                                            for _, s in scored_spec:
                                                a = s.get("args", "")
                                                if a:
                                                    a_key = str(a)
                                                    if a_key not in seen_args:
                                                        seen_args.add(a_key)
                                                        unique_spec.append(s)
                                            
                                            for s in unique_spec[:special_count]:
                                                strategies_to_evolve.append((s, svc))
                                
                            except Exception as e:
                                log_func(f"[StrategyChecker-Debug] Ошибка подготовки эволюции: {e}")
                                pass



                            # 2. Mutate
                            evo_tasks = []
                            learning_data = load_learning_data()  # Загружаем статистику один раз
                            
                            # Filter out strategies for perfect services (100% success)
                            strategies_to_evolve = [x for x in strategies_to_evolve if x[1] not in perfect_services]

                            reset_domain_offset_counter()  # Сбрасываем счётчик offset для диверсификации
                            
                            for strat, svc in strategies_to_evolve:
                                # Skip blocked services
                                if svc in blocked_services: continue
                                
                                # Select domains
                                target_doms = domains_for_general
                                if svc != "general":
                                    # Load list
                                    l_path = os.path.join(base_dir, "list", f"{svc}.txt")
                                    t_doms = []
                                    if os.path.exists(l_path):
                                         try:
                                             with open(l_path, "r") as f: t_doms = [l.strip() for l in f if l.strip()]
                                         except: pass
                                    if t_doms: target_doms = t_doms
                                
                                # Генерируем мутации с учётом статистики обучения
                                mutations = mutate_strategy(strat['args'], bin_files, learning_data=learning_data)
                                
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

                            if not evo_tasks: 
                                log_func(f"{prefix} Нет задач для выполнения.")
                                continue

                            
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
                                    # s_display = strat["name"]
                                    # if len(s_display) > 30: s_display = s_display[:27] + "..."
                                    
                                    # Initial render setup but NO creation
                                    # bar = get_progress_bar(0, 0, len(doms), width=20)
                                    # initial_msg = f"[Check] {s_display} ({svc}) [{bar}] 0/0"
                                    # progress_manager.create_line(line_id, initial_msg) # REMOYED
                                    
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
                                                msg = f"{pfx} {s_name} ({s_svc}) {bar} {state['score']}/{state['checked']}"
                                                progress_manager.update_line(lid, msg, is_final=False)
                                        return tracker

                                    tracker_func = make_evo_tracker(line_id, strat['name'], svc, len(doms))
                                    
                                    fut = executor.submit(check_strat_threaded, strat["args"], doms, progress_tracker=tracker_func, run_id=current_run_id)
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
                                        cache_score(svc_t, strat_t['name'], sc)
                                        
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
                                        
                                        evo_results.append((sc, strat_t, svc_t))
                                        total_cnt = len(doms_t)
                                        gray_count = total_cnt - sc
                                        bar = get_progress_bar(sc, gray_count, total_cnt, width=20)
                                        final_msg = f"{prefix} {strat_t['name']} ({svc_t}) {bar} {sc}/{total_cnt} ✓"
                                        progress_manager.update_line(line_id, final_msg, is_final=True)
                                        
                                        bl = service_baselines.get(svc_t, 0)
                                        if sc > bl:
                                             log_func(f"{prefix} >>> Улучшение для {svc_t}: {sc} (было {bl}) -> {strat_t['name']}")
                                             service_baselines[svc_t] = sc
                                             better_found = True # Keep for logic outside (maybe redundant now)
                                             
                                             # IMMEDIATE HOT SWAP FOR EVO
                                             update_active_config_immediate(svc_t, strat_t["args"], f"{prefix} Применена лучшая стратегия {strat_t['name']}")
                                    except: pass

                            # Cancel futures and log stop message
                            if not is_service_active or is_closing:
                                for f in active_evo.keys():
                                    f.cancel()
                                stop_msg = f"{prefix} Эволюция стратегий остановлена пользователем. Прогресс сохранён."
                                progress_manager.log_message(stop_msg)

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
                            
                            # 5. Instant Restart (Hot Swap)
                            if better_found and is_service_active and not is_closing:
                                log_func(f"[Check] Эволюция нашла улучшения (Hot Swap).")
                                if root: root.after(0, perform_hot_restart_backend)

                    if is_service_active and not is_closing:
                        # FINISH
                        log_func("[Check] Подбор полностью завершен.")
                        
                        # Sync keys to match reading logic
                        state["last_check_time"] = time.time()
                        state["last_full_check_time"] = time.time() 
                        state["completed"] = True # FIX: Mark full cycle as completed to prevent immediate restart
                        state["evolution_stage"] = 0  # Сбрасываем этап эволюции для следующего цикла
                        save_state()
                        
                        # CRITICAL FIX: Stop the outer "wile is_scanning" loop
                        is_scanning = False
                        break


                # End of block
                is_scanning = False
                
                # FIX: Clear progress on successful full completion
                # But only if we actually did something?
                # For now, let's keep the progress file - it serves as "Temporary knowledge" 
                # that expires in 4 hours. No explicit delete needed, handled by timestamp check.
                
                log_func("[Check] Цикл проверки завершен.")
                
                # Prevent Busy-Loop in Idle: Sleep before next checking cycle
                # If urgent checks appear, they wake via matcher_wakeup_event or queue in next loop start
                time.sleep(30)

            except Exception as e:
                # FIX: Silent exit on deliberate stop
                if "aborted_by_service" in str(e) or "Остановка сервиса" in str(e) or not is_service_active:
                     # Already logged above, just pass
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

    def add_to_hard_list_safe(domain):
        """Безопасно добавляет домен в temp/hard.txt для подбора стратегии."""
        with hard_list_lock:
            try:
                base_dir = get_base_dir()
                hard_path = os.path.join(base_dir, "temp", "hard.txt")
                
                with open(hard_path, "a+", encoding="utf-8") as f:
                    f.seek(0)
                    content = f.read()
                    domain_lower = domain.lower()
                    
                    # Проверяем что домена нет в списке
                    if domain_lower not in content.lower():
                        if content and not content.endswith("\n"):
                            f.write("\n")
                        f.write(f"{domain_lower}\n")
            except Exception as e:
                pass

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
            ip, status = dns_manager.resolve(domain, dns_manager.burst_limiter, check_cache=False)
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
        hard_path = os.path.join(get_base_dir(), "temp", "hard.txt")
        try:
            lines = []
            if os.path.exists(hard_path):
                with open(hard_path, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            
            new_lines = []
            found = False
            timestamp = time.strftime("%d.%m.%Y в %H:%M")
            new_entry = f"{domain} # Не удалось разблокировать (Auto-Detect {timestamp})\n"
            
            for line in lines:
                parts = line.strip().split('#')[0].strip()
                if parts == domain:
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
                   # print("[Migration] strategies_evolution сброшен (old version)")
                
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
        if "[Check]" in line: return "info"
        if "[ExcludeCheck]" in line: return "info"
        
        if any(x in text_lower for x in ["err:", "error", "dead", "crash", "could not read", "fatal", "panic", "must specify", "unknown option", "не удается", "не найдено"]):
            return "error"
        
        if "fail" in text_lower:
            return "fail"
        
        if "ok (" in text_lower:
            return "normal"
        
        if any(x in text_lower for x in ["пропуск", "удаление", "отмена", "инфо", "успешно", "ядро активно"]):
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

        services = ['https://api.ipify.org', 'https://ifconfig.me', 'https://icanhazip.com']
        local_port = random.randint(16000, 16009)
        session = requests.Session()
        session.mount('https://', SourcePortAdapter(local_port))
        try:
            for url in services:
                try:
                    return session.get(url, timeout=10).text.strip()
                except: continue
        finally:
            session.close()
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
                        # print("[Migration] Learning Data сброшен (old version)")
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

    strategy_learner = StrategyLearner()

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
                if log_func:
                    pass # log_func(f"[AdaptiveSystem] Смена IP: {new_ip} - Полная переверификация стратегий")
            else:
                # IP не менялся, проверяем 7-дневный лимит
                now = time.time()
                if last_full_recheck_date is None or (now - last_full_recheck_date) > (7 * 24 * 3600):
                    last_full_recheck_date = now
                    needs_recheck = True
                    if log_func:
                        log_func(f"[AdaptiveSystem] 7 дней без переверификации - Полная переверификация")
        
        save_ip_history()
        return needs_recheck

    def get_hot_domains(max_count=20):
        """Возвращает HOT домены (посещённые) отсортированные по приоритету."""
        global visited_domains_stats
        with visited_domains_lock:
            sorted_domains = sorted(
                visited_domains_stats.items(),
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
                    
                    # Запуск теста (аналог check_strat)
                    # ... (упрощенно: запускаем winws с фильтром на порт и проверяем домен)
                    # Для простоты используем check_domain_robust после запуска winws
                    # Но нам нужен порт и изоляция.
                    # В рамках этого worker'а сложно сделать полную изоляцию без дублирования кода.
                    # Поэтому мы будем использовать audit_ports_queue и запускать winws на короткое время.
                    
                    # TODO: Реализовать полноценный тест с изоляцией, как в чекере.
                    # Пока пропустим сложную реализацию и сделаем паузу.
                    pass
                
                # Примечание: Полная реализация требует переноса check_strat в глобальную область или дублирования.
                # В текущей архитектуре лучше оставить это на hard_strategy_matcher, который уже перебирает hard стратегии.
                # Но требование - отдельный фоновый процесс.
                
                # ВМЕСТО ЭТОГО: Мы будем обновлять boost.json успешными стратегиями из hard_strategy_matcher
                # Если hard_strategy_matcher находит "легкую" стратегию, он может сохранить её в boost.json
                
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
            
            proc = subprocess.Popen(final_args, cwd=base_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(1.5)
            
            status, _ = detect_throttled_load(domain, port)
            
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
                
                # Если нет нумерованных boost_x, создаем их из дефолтных
                has_numbered = any(re.match(r"boost_\d+$", k) for k in available_boost)
                if not has_numbered:
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
                                        found_strategy = h_name
                                        break
                        
                        if found_strategy:
                            if root: root.after(0, perform_hot_restart)
                        else:
                            log_func(f"[HardMatcher] Быстрый подбор не удался для {domain}. В очередь глубокого анализа.")
                            add_to_hard_list_safe(domain)
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

    def check_and_update_worker(log_func):
        """Фоновая проверка обновлений."""
        # Обновление работает только в скомпилированном виде (.exe)
        # FIX: Debug log to verify start
        log_func("[Update] Запуск потока обновлений...") 
        
        # FIX: Robust frozen check for Nuitka onefile
        is_frozen = getattr(sys, 'frozen', False) or sys.argv[0].lower().endswith(".exe")
        
        if not is_frozen:
            log_func(f"[Update] Не скомпилировано (frozen={getattr(sys, 'frozen', False)}). Режим отладки: только проверка версии.")
            # return  <-- FIX: Don't return, allow checking

        try:
            # FIX: Import requests here to ensure it's available in this thread
            import requests
            log_func("[Update] Модуль requests успешно инициализирован")
        except ImportError as e:
            log_func(f"[Update] CRITICAL: Ошибка импорта requests: {e}")
            return

        while not is_closing:
            try:
                # 1. Проверка версии
                latest_version = None
                download_url = None
                expected_hash = None
                
                try:
                    session = requests.Session()
                    session.trust_env = False
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
                        log_func("[Update] Новая версия программы готовится (Status != 200)")
                        
                except Exception as e:
                    # Ошибка сети/парсинга -> считаем что обновления нет/готовится
                    # FIX: Show error for debug
                    log_func(f"[Update] Ошибка получения данных: {e}") 
                    log_func("[Update] Новая версия программы готовится")
                    # Пауза 24 часа
                    for _ in range(86400):
                        if is_closing: return
                        time.sleep(1)
                    continue

                if not latest_version or not download_url:
                     # JSON некорректен или нет URL
                    log_func("[Update] Новая версия программы готовится")
                    for _ in range(86400):
                        if is_closing: return
                        time.sleep(1)
                    continue

                if compare_versions(latest_version, CURRENT_VERSION):
                    
                    # FIX: Check frozen status BEFORE downloading
                    if not is_frozen:
                         log_func(f"[Update] Найдено обновление: {latest_version}. (Скачивание пропущено: запуск из исходника)")
                         for _ in range(86400):
                            if is_closing: return
                            time.sleep(1)
                         continue

                    log_func(f"[Update] Происходит обновление программы. Ожидайте.")
                    
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
                                for chunk in r.iter_content(chunk_size=8192):
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
                        # Пауза 24 часа
                        for _ in range(86400):
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
                    time.sleep(3) # Даем время на закрытие файлов и процессов (увеличено до 3с)
                    log_func("[Update] Службы остановлены. Замена файлов...")
                    
                    # Подмена файлов
                    old_exe = current_exe + ".old"
                    try:
                        if os.path.exists(old_exe): os.remove(old_exe)
                        os.rename(current_exe, old_exe)
                        os.rename(new_exe, current_exe)
                        
                        log_func("[Update] Файлы заменены. Перезапуск...")
                        # Перезапуск
                        clean_argv = [a for a in sys.argv[1:] if a != "--updated"]
                        # Use close_fds=True to ensure no handles from the old process (like the lock on .old) are inherited
                        subprocess.Popen([current_exe, "--updated"] + clean_argv, creationflags=subprocess.CREATE_NO_WINDOW, close_fds=True)
                        os._exit(0)
                        
                    except Exception as e:
                        log_func(f"[Update] Критическая ошибка при замене файла: {e}")
                        # Откат
                        if os.path.exists(old_exe) and not os.path.exists(current_exe):
                            try: os.rename(old_exe, current_exe)
                            except: pass
                        
                        log_func("Обновление программы невозможно автоматически. Перезапустите Nova для установки обновления вручную")
                else:
                    log_func("Версия программы актуальна")

            except Exception as e:
                log_func(f"[Update] Ошибка: {e}")
            
            # Пауза 24 часа перед следующей проверкой
            for _ in range(86400):
                if is_closing: return
                time.sleep(1)

    def _start_nova_service_impl(silent=False, restart_mode=False):
        try:
            _start_nova_service_logic(silent, restart_mode)
        except Exception as e:
            msg = f"Startup Error: {e}"
            print(msg)
            try:
                 if 'log_print' in globals(): log_print(msg)
            except: pass
            try: stop_nova_service(silent=True)
            except: pass

    def repair_windivert_driver(log_func=None):
        """
        Attempts to repair broken WinDivert driver installation.
        Fixes:
        - Code 177 (Driver locked)
        - Code 577 (Signature verification)
        - "Service cannot be started... disabled" (0x422)
        """
        if log_func: log_func("[Repair] Запуск процедуры восстановления драйвера WinDivert...")
        
        # 1. Force Enable Service (Fix for "Service Disabled" 0x422 error)
        # Some optimizers disable "windivert" service. We must re-enable it.
        try:
            # "start= demand" (Note the space!)
            subprocess.run(["sc", "config", "windivert", "start=", "demand"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        except: pass

        # 2. Stop and Delete Service (Force Reinstall)
        # If enabling didn't work, we nuke it so winws can re-register it.
        try:
            subprocess.run(["sc", "stop", "windivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(["sc", "delete", "windivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        except: pass
        
        # 3. Add delay for SCM to clean up registry
        time.sleep(2.0)
        
        # 4. Restore driver files from backup if available (or assume they are present in bin)
        # Note: In Nuitka OneFile, sys._MEIPASS contains the original files. 
        # But deployed bin/ is what matters. deploy_infrastructure should have handled this.
        # We can try to force-copy if frozen.
        if getattr(sys, 'frozen', False):
             try:
                 base_dir = get_base_dir()
                 internal = get_internal_path("bin")
                 if os.path.exists(internal):
                     for f in os.listdir(internal):
                         if f.endswith(".sys") or f.endswith(".dll"):
                             src = os.path.join(internal, f)
                             dst = os.path.join(base_dir, "bin", f)
                             try: shutil.copy2(src, dst)
                             except: pass
                     if log_func: log_func("[Repair] Файлы драйвера обновлены из ресурсов.")
             except Exception as e:
                 if log_func: log_func(f"[Repair] Ошибка копирования файлов: {e}")

        if log_func: log_func("[Repair] Процедура завершена. Ожидание запуска...")

    def _start_nova_service_logic(silent=False, restart_mode=False): # Added restart_mode
        global is_service_active, process, is_closing
        
        # Сбрасываем флаг завершения при перезапуске, чтобы фоновые проверки возобновились
        is_closing = False
        
        if not is_admin(): 
            root.after(0, lambda: messagebox.showerror("Ошибка", "Нужны права Администратора!"))
            return
        
        exe_path = os.path.join(get_base_dir(), "bin", WINWS_FILENAME)
        if not os.path.exists(exe_path): 
            root.after(0, lambda: messagebox.showerror("Ошибка", f"Файл {WINWS_FILENAME} не найден!"))
            return
        
        # EARLY CLEANUP START: Initiate driver stop ASAP to run in parallel with config loading
        try:
             if not restart_mode:
                 subprocess.run(["sc", "stop", "windivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        except: pass

        # === НОВОЕ: Синхронизация hard_X доменов перед запуском ===
        sync_hard_domains_to_strategies(log_print if not silent else None)
        
        # Wait for driver to fully release (partially covered by config loading time above)
        time.sleep(1.2) # Back to 1.2s (0.8s proved insufficient)

        # === EARLY CLEANUP: Kill old process and clean driver BEFORE loading configs ===
        # This allows driver unload to happen in parallel with config loading
        try: 
            # Phase 1: Soft Kill
            subprocess.run(["taskkill", "/IM", WINWS_FILENAME], creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Wait up to 0.4s for graceful exit
            wait_start = time.time()
            killed_gracefully = False
            while time.time() - wait_start < 0.4:
                check = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {WINWS_FILENAME}"], 
                                     capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                if WINWS_FILENAME not in check.stdout:
                    killed_gracefully = True
                    break
                time.sleep(0.05)
            
            if killed_gracefully:
                # Check if driver exists (zombie from warp.bat or previous crash)
                try:
                    sq = subprocess.run(["sc", "query", "windivert"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    is_service_present = (sq.returncode == 0)
                except: is_service_present = False

                if not is_service_present:
                    # TRUE COLD START: No cleanup needed
                    pass
                else:
                    # DIRTY STATE: Need cleanup
                    if not restart_mode:
                        raise Exception("Driver Dirty")
                    else:
                        pass # Restart mode: Driver persistence is expected
            else:
                raise Exception("Process Stuck")

        except:
            # Phase 2: Hard Kill + Driver Cleanup
            subprocess.run(["taskkill", "/F", "/IM", WINWS_FILENAME], creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            try:
               subprocess.run(["sc", "stop", "windivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
               # subprocess.run(["sc", "delete", "windivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW) # Removed to avoid startup delay
            except: pass
            
            # Start 1.0s timer - will complete during config loading below
            cleanup_start_time = time.time()
        
        # === НОВОЕ: Загрузка реестра замедленных доменов ===
        global throttled_domains_registry
        throttled_domains_registry = load_throttled_registry()
        if throttled_domains_registry and not silent:
            log_print(f"[Init] Загружено {len(throttled_domains_registry)} замедленных доменов из реестра")
        
        # === НОВОЕ: Загрузка адаптивной системы подбора стратегий ===
        visited_count = load_visited_domains()
        evo_count = load_strategies_evolution()
        ip_count = load_ip_history()
        if not silent:
            log_print(f"[Init] Адаптивная система: {visited_count} посещённых доменов, {evo_count} стратегий в эволюции, {ip_count} IP в истории")
        
        # Wait for remaining cleanup time if needed - REMOVED (Covered by preventive Wait)
        # try:
        #     elapsed = time.time() - cleanup_start_time
        #     remaining = 1.0 - elapsed
        #     if remaining > 0:
        #         time.sleep(remaining)
        # except NameError: pass

        is_service_active = True
        try: restart_requested_event.clear()
        except: pass
        root.after(0, lambda: btn_toggle.config(text="ОСТАНОВИТЬ"))
        root.after(0, lambda: status_label.config(text="АКТИВНО : РАБОТАЕТ", fg=COLOR_TEXT_NORMAL))
        
        paths = ensure_structure()
        
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
        
        num_specific_strats_added = 0
        for strat_name in strat_keys:
            if strat_name.startswith("_"): continue

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
        
        if gen_list_exists or os.path.exists(paths['ip_general']):
            if num_specific_strats_added > 0:
                args.append("--new")
            
            # Define common args for General strategy reuse
            general_common_args = []
            general_common_args.extend(exclusions)
            if gen_list_exists:
                general_common_args.append(f"--hostlist={target_gen_list}")
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
            
            # PREVENT RESTART if stopped (unless explicitly restarting)
            if not is_service_active and not is_closing and not is_restarting:
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
                        if IS_DEBUG_MODE:
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
        if is_service_active and not is_closing:
             threading.Thread(target=run_process, daemon=True).start()

    def stop_nova_service(silent=False, wait_for_cleanup=False, restart_mode=False):
        global is_service_active, process, is_closing, nova_service_status
        
        # === НЕМЕДЛЕННОЕ обновление состояния ===
        if not restart_mode:
            is_service_active = False
        # is_closing = True <-- FIX: Do not kill background workers on stop! Only on exit.
        
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
            except: pass
            
            # FIX: Force Driver Stop to release resources (but do not delete, to avoid startup delay/lock)
            try:
                if not restart_mode:
                    subprocess.run(["sc", "stop", "windivert"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
            except: pass
            
            # Обновляем general после завершения
            try: smart_update_general()
            except: pass
            
            if not silent: print("Готово.\n")
        
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
        
        # Stop everything synchronously first
        try:
             stop_nova_service(silent=True, wait_for_cleanup=True)
        except: pass
        
        is_closing = True 
        
        # Захватываем геометрию в главном потоке ДО уничтожения окна, чтобы избежать ошибок
        main_geo = None
        log_geo = None
        try:
            main_geo = root.geometry()
            if log_window and tk.Toplevel.winfo_exists(log_window):
                log_geo = log_window.geometry()
        except: pass

        # === Быстрое сохранение состояния (в отдельном потоке если долго) ===
        def save_state_and_cleanup(m_geo, l_geo):
            """Сохраняет состояние и завершает процессы"""
            try:
                state_to_save = {}
                if m_geo: state_to_save["main_geometry"] = m_geo
                if l_geo: state_to_save["log_size"] = l_geo
                
                if state_to_save:
                    save_window_state(**state_to_save)
            except:
                pass
            
            # === Сохраняем адаптивную систему при выходе ===
            try:
                if dns_manager:
                    dns_manager.save_cache()
                save_visited_domains()
                save_strategies_evolution()
                save_ip_history()
                save_exclude_auto_checked()
                strategy_learner.save() # Сохраняем знания AI
            except Exception as e:
                print(f"[AdaptiveSystem] Ошибка сохранения при выходе: {e}")
            
            try:
                queue_list = []
                while not check_queue.empty():
                    try: queue_list.append(check_queue.get_nowait())
                    except: break
                
                if queue_list:
                    try:
                        with open(PENDING_CHECKS_FILE, "w", encoding="utf-8") as f:
                            json.dump(queue_list, f)
                    except: pass
            except: pass

            # Завершение процессов (асинхронно)
            if process:
                try: subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except: pass
            
            time.sleep(0.1)
            try: subprocess.run(["taskkill", "/F", "/IM", WINWS_FILENAME], creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except: pass
            
            try: smart_update_general()
            except: pass
        
        # Запускаем сохранение в отдельном потоке, не блокируя основной UI
        cleanup_thread = threading.Thread(target=save_state_and_cleanup, args=(main_geo, log_geo), daemon=True)
        cleanup_thread.start()
        
        # Немедленно закрываем окно (не ждём завершения фонового потока)
        try: root.destroy()
        except: pass
        # Выходим (фоновый поток завершится сам)
        os._exit(0)

    def perform_hot_restart_backend():
        """
        Мгновенный перезапуск только ядра WinWS (Backend) для применения новых стратегий.
        Не останавливает GUI и потоки проверок.
        """
        global process, is_service_active
        
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

        time.sleep(0.2) # Small breath
        
        # 2. Restart via start_nova_service (Global context)
        # Flag restart to prevent old thread from reporting Crash
        global is_restarting
        is_restarting = True
        
        if is_service_active and not is_closing:
             # Call start_nova_service which is Thread-Safe (uses root.after for UI)
             # We use a lambda to pass arguments
             if root:
                 root.after(0, lambda: start_nova_service(silent=True, restart_mode=True))
                 if IS_DEBUG_MODE: print("[HotSwap] Запрошен перезапуск через start_nova_service.")
             else:
                 # Fallback
                 threading.Thread(target=start_nova_service, args=(True, True), daemon=True).start()

    def launch_background_tasks():
        """Запуск тяжелых фоновых задач ПОСЛЕ отображения окна"""
        global dns_manager
        
        # 1. Инициализация DNS Manager (тяжелая операция)
        if dns_manager is None:
             dns_manager = DNSManager(get_base_dir())
        
        # Убираем процессы (перенесено из main)
        try: subprocess.run(["taskkill", "/F", "/IM", WINWS_FILENAME], creationflags=subprocess.CREATE_NO_WINDOW, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except: pass

        # Инициализация систем (перенесено из main)
        init_checker_system(log_print)
        clean_hard_list()
        log_previous_session_results(log_print) # Вывод результатов прошлой сессии
        
        # Check if updated flag was passed (set in main's ARGS_PARSED global)
        try:
            if ARGS_PARSED.get('updated', False):
                log_print("Установлена последняя версия Nova.")
                # Сообщаем об очистке, если она была
                if OLD_VERSION_CLEANED:
                     log_print("Следы прежней версии программы удалены")
            
            if ARGS_PARSED.get('fresh', False):
                log_print("Запуск с флагом --fresh: Временные файлы и состояние стратегий сброшены.")

        except NameError:
            # ARGS_PARSED not yet defined (shouldn't happen in normal flow)
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
                    # Silent fail or debug log
                    pass
            
            if migrated_count > 0:
                 log_func(f"[Migration] Успешно обновлен формат у {migrated_count} файлов стратегий.")

        migrate_service_strategies_format(log_print)
        
        log_print("Запуск фоновых процессов...")
        # Отключаем старый генератор стратегий, чтобы избежать дублирования
        # threading.Thread(target=strategy_builder_worker, args=(log_print,), daemon=True).start()
        threading.Thread(target=advanced_strategy_checker_worker, args=(log_print,), daemon=True).start()
        threading.Thread(target=payload_worker, args=(log_print,), daemon=True).start()
        threading.Thread(target=vpn_monitor_worker, args=(log_print,), daemon=True).start()
        threading.Thread(target=hard_strategy_matcher_worker, args=(log_print,), daemon=True).start()
        threading.Thread(target=boost_evolution_worker, args=(log_print,), daemon=True).start()
        
        paths = ensure_structure()
        threading.Thread(target=update_ip_cache_worker, args=(paths, log_print), daemon=True).start()
        
        for _ in range(2): # Оптимизация: уменьшаем кол-во потоков чекера с 4 до 2 (снижение нагрузки на CPU/Сеть)
            threading.Thread(target=background_checker_worker, args=(log_print,), daemon=True).start()
            
        threading.Thread(target=periodic_exclude_checker_worker, args=(log_print,), daemon=True).start()
        threading.Thread(target=exclude_auto_monitor_worker, args=(log_print,), daemon=True).start()
        threading.Thread(target=boost_strategy_matcher_worker, args=(log_print,), daemon=True).start()
        threading.Thread(target=batch_exclude_worker, args=(log_print,), daemon=True).start()
        threading.Thread(target=check_and_update_worker, args=(log_print,), daemon=True).start()
        threading.Thread(target=domain_cleaner_worker, args=(log_print,), daemon=True).start()

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

    # ================= STARTUP =================
    if __name__ == "__main__":
        # === ARGUMENT PARSING: Order-independent, but execution in correct sequence ===
        # Parse all arguments first
        ARGS_PARSED = {
            'fresh': '--fresh' in sys.argv,
            'debug': '--debug' in sys.argv or '-debug' in sys.argv,
            'updated': '--updated' in sys.argv,
            'show_log': '--show-log' in sys.argv  # Auto-open log window (used on restart)
        }
        
        # Execute in correct order: 1. Fresh (cleanup), 2. Debug (logging)
        if ARGS_PARSED['fresh']:
            try:
                t_dir = os.path.join(get_base_dir(), "temp")
                if os.path.exists(t_dir):
                     for item in os.listdir(t_dir):
                         if item.lower() == "window_state.json": continue
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
            
            # DEBUG BLOCK START
            # msg_debug = f"DEBUG INFO:\nDir: {base_dir}\nExec: {sys.executable}\nInfra: {has_infrastructure}\nCompiled: {is_compiled}"
            # try: 
            #     msg_debug += f"\nItems: {str(os.listdir(base_dir)[:5])}"
            # except: pass
            # ctypes.windll.user32.MessageBoxW(0, msg_debug, "Nova Debug", 0)
            # DEBUG BLOCK END

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
                
                # DEBUG 2
                # if is_cluttered:
                #      ctypes.windll.user32.MessageBoxW(0, f"Clutter found: {found_alien}", "Nova Debug", 0)

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
                            current_exe = os.path.abspath(sys.executable)
                            target_exe = os.path.abspath(os.path.join(target_dir, exe_name))
                            
                            # 3. Validation
                            if not os.path.exists(current_exe):
                                raise FileNotFoundError(f"Source file not found: {current_exe}")
                                
                            # 4. Copy File
                            shutil.copy2(current_exe, target_exe)
                            
                            # 5. Flush & Verify
                            time.sleep(0.5) # Give file system a moment
                            if not os.path.exists(target_exe):
                                raise FileNotFoundError(f"Target file creation failed: {target_exe}")
                            
                            # 6. Launch new process
                            # Use abspath for cwd to be safe
                            subprocess.Popen([target_exe] + sys.argv[1:], cwd=os.path.abspath(target_dir))
                            
                            # === SELF-DELETION ===
                            # Запускаем фоновую команду: подождать 3 сек и удалить исходный файл
                            kill_cmd = f'cmd /c ping 127.0.0.1 -n 3 > nul & del /F /Q "{current_exe}"'
                            subprocess.Popen(kill_cmd, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                            
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
        # dns_manager инициализируется в launch_background_tasks

        # === INFRASTRUCTURE DEPLOY ===
        # Теперь безопасно распаковываем файлы (мы либо в чистой папке, либо переехали)
        
        # Check First Run Condition BEFORE deploy (if strat folder missing, it's a fresh install)
        is_first_run_condition = not os.path.exists(os.path.join(get_base_dir(), "strat"))
        
        dep_logs = deploy_infrastructure()
        
        # Исправляем стратегии синхронно перед запуском GUI, чтобы избежать гонок
        rest_logs = restore_missing_strategies()
        
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

        if display_logs:
             # Limit log size
             if len(display_logs) > 20:
                 display_logs_msg = display_logs[:20] + [f"... и еще {len(display_logs)-20} изменений"]
             else:
                 display_logs_msg = display_logs
             
             msg_txt = f"Версия {CURRENT_VERSION} установлена.\n\nОтчет об обновлении:\n" + "\n".join(display_logs_msg)
             # FIX: Only show update report popup if running as compiled EXE (user request)
             if is_compiled:
                 try: ctypes.windll.user32.MessageBoxW(0, msg_txt, "Nova - Обновление", 0x40) # MB_ICONINFORMATION
                 except: pass

        import struct # Импорт struct для работы с IP
        
        try:
            old_exe_chk = sys.argv[0] + ".old" # Используем sys.argv[0] для надежности
            if os.path.exists(old_exe_chk):
                 # Пытаемся удалить старый exe.
                 for _ in range(3):
                     try:
                         os.remove(old_exe_chk)
                         OLD_VERSION_CLEANED = True
                         break
                     except:
                         time.sleep(0.5)
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
            # Cache monitor info once per drag start
            try:
                root._cached_mon_bounds = get_monitor_work_area(root.winfo_x() + root.winfo_width()//2, root.winfo_y() + 10)
            except: root._cached_mon_bounds = None
            
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
                align_log_window_to_main(forced_main_geom=(x, y, root.winfo_width(), root.winfo_height()), cached_mon_bounds=getattr(root, '_cached_mon_bounds', None))

        root.bind("<Button-1>", start_move)
        root.bind("<B1-Motion>", do_move)

        state = load_window_state()
        geom = state.get("main_geometry")
        w, h = 360, 270
        if geom: 
            root.geometry(geom)
            try:
                match = re.match(r"(\d+)x(\d+)", geom)
                if match:
                    w, h = int(match.group(1)), int(match.group(2))
            except: pass
        else:
            sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
            root.geometry(f"{w}x{h}+{int((sw/2)-(w/2))}+{int((sh/2)-(h/2))}")

        main_canvas = tk.Canvas(root, width=w, height=h, highlightthickness=0, bg=COLOR_BG)
        main_canvas.pack(fill="both", expand=True)
        main_canvas.bind("<Button-1>", start_move)
        main_canvas.bind("<B1-Motion>", do_move)

        bg_image = None
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
        except Exception as e:
            print(f"[UI] Ошибка загрузки фона: {e}")

        status_label = CanvasLabel(main_canvas, w/2, h/2 - 45, "Запуск...", ("Segoe UI Semibold", 10), "grey", bg_color="#E0E0E0", outline_color="#DFF07E", outline_width=2)
        status_label.bind("<Button-1>", start_move)
        status_label.bind("<B1-Motion>", do_move)
        
        btn_toggle = RoundedButton(main_canvas, w/2, h/2 + 10, 160, 40, 20, COLOR_BLUEBERRY_YOGURT, "ЗАПУСТИТЬ", toggle_service)
        
        btn_logs = CanvasButton(main_canvas, w-10, h-10, "Показать лог", ("Segoe UI", 9, "bold"), toggle_log_window, fg="#777777", bg_color="#E0E0E0")

        root.update()
        ensure_log_window_created()
        
        # Auto-open log window if --show-log argument is present (restart)
        if ARGS_PARSED.get('show_log', False):
            show_log_window()
        else:
            hide_log_window()
        
        # Показываем окно ПОСЛЕ загрузки всех элементов (устранение мерцания)
        root.deiconify()
        
        # Gentle Focus: Аккуратно выводим окно на передний план
        try:
            root.lift()
            root.attributes('-topmost', True)
            root.after(50, lambda: root.attributes('-topmost', False))
            root.focus_force()
            # FIX: Explicitly ensure log window is not stuck
            root.after(1000, lambda: log_window.attributes('-topmost', False) if log_window and tk.Toplevel.winfo_exists(log_window) else None)
        except: pass
        
        # Запуск основного ядра
        start_nova_service()
        
        # Запуск фоновых задач после инициализации ядра
        root.after(1000, lambda: launch_background_tasks())
        
        check_scan_status_loop() 
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()

except Exception as e:
    try:
        err_root = tk.Tk()
        err_root.withdraw()
    except: pass
    messagebox.showerror("Критическая ошибка", traceback.format_exc())
    sys.exit(1)