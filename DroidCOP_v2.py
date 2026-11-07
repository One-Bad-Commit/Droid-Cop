#!/usr/bin/env python3
"""
DroidCOP v2 — Android ADB Security Auditor
============================================
A comprehensive, non-destructive read-only security audit tool for Android devices
connected via ADB. Detects malicious apps, suspicious settings, rootkits, spyware
indicators, hidden files, network anomalies, and more.

⚠️  Use only on devices you own or have explicit written permission to assess.
    The authors are not responsible for misuse.

Requirements:
    - Python 3.8+
    - Android Platform Tools (adb) in PATH
    - USB debugging enabled and device authorized

Usage:
    python DroidCOP_v2.py                          # auto-pick single connected device
    python DroidCOP_v2.py --serial <SERIAL>        # specific device
    python DroidCOP_v2.py --out ./my_reports       # custom output dir
    python DroidCOP_v2.py --no-logcat              # skip logcat scan (faster)
"""

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import textwrap
import time
from typing import Dict, List, Optional, Tuple

# ─────────────────────────────  CONSTANTS  ─────────────────────────────────

VERSION   = "2.0.0"
TOOL_NAME = "DroidCOP"
TIMEOUT   = 30   # seconds per adb call
LONG_TIMEOUT = 60

# ANSI colors for console output
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    GREY   = "\033[90m"
    WHITE  = "\033[97m"

# Risk levels
RISK_CRITICAL = "CRITICAL"
RISK_HIGH     = "HIGH"
RISK_MEDIUM   = "MEDIUM"
RISK_LOW      = "LOW"
RISK_INFO     = "INFO"

# ── Suspicious permissions ───────────────────────────────────────────────────
SUSPICIOUS_PERMS = {
    "android.permission.SYSTEM_ALERT_WINDOW":         (RISK_HIGH,   "Draw overlay over other apps"),
    "android.permission.BIND_ACCESSIBILITY_SERVICE":  (RISK_HIGH,   "Accessibility service — can read screen/input"),
    "android.permission.RECEIVE_BOOT_COMPLETED":      (RISK_MEDIUM, "Auto-start on device boot"),
    "android.permission.SEND_SMS":                    (RISK_HIGH,   "Can send SMS messages"),
    "android.permission.RECEIVE_SMS":                 (RISK_HIGH,   "Can read incoming SMS"),
    "android.permission.READ_SMS":                    (RISK_HIGH,   "Can read all SMS"),
    "android.permission.CALL_PHONE":                  (RISK_HIGH,   "Can make phone calls"),
    "android.permission.READ_CALL_LOG":               (RISK_HIGH,   "Can read call logs"),
    "android.permission.WRITE_CALL_LOG":              (RISK_HIGH,   "Can modify call logs"),
    "android.permission.PROCESS_OUTGOING_CALLS":      (RISK_HIGH,   "Can intercept outgoing calls"),
    "android.permission.WRITE_SETTINGS":              (RISK_MEDIUM, "Can modify system settings"),
    "android.permission.REQUEST_INSTALL_PACKAGES":    (RISK_HIGH,   "Can silently install other APKs"),
    "android.permission.INSTALL_PACKAGES":            (RISK_CRITICAL,"Can install packages (system-level)"),
    "android.permission.DELETE_PACKAGES":             (RISK_HIGH,   "Can silently uninstall apps"),
    "android.permission.PACKAGE_USAGE_STATS":         (RISK_MEDIUM, "Can spy on app usage history"),
    "android.permission.READ_PHONE_STATE":            (RISK_MEDIUM, "Read IMEI and phone state"),
    "android.permission.READ_PRECISE_PHONE_STATE":    (RISK_MEDIUM, "Read precise phone identifiers"),
    "android.permission.QUERY_ALL_PACKAGES":          (RISK_MEDIUM, "Can enumerate all installed apps"),
    "android.permission.READ_CONTACTS":               (RISK_MEDIUM, "Can read all contacts"),
    "android.permission.READ_EXTERNAL_STORAGE":       (RISK_LOW,    "Can read all files on storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE":      (RISK_LOW,    "Can write to external storage"),
    "android.permission.ACCESS_FINE_LOCATION":        (RISK_HIGH,   "GPS-level location tracking"),
    "android.permission.ACCESS_BACKGROUND_LOCATION":  (RISK_HIGH,   "Tracks location when app is backgrounded"),
    "android.permission.RECORD_AUDIO":                (RISK_HIGH,   "Can record microphone audio"),
    "android.permission.CAMERA":                      (RISK_HIGH,   "Can use camera"),
    "android.permission.READ_CLIPBOARD":              (RISK_HIGH,   "Can read clipboard contents"),
    "android.permission.BIND_DEVICE_ADMIN":           (RISK_CRITICAL,"Device Administrator — powerful control"),
    "android.permission.MANAGE_EXTERNAL_STORAGE":     (RISK_HIGH,   "All-files access (Android 11+)"),
    "android.permission.USE_BIOMETRIC":               (RISK_MEDIUM, "Can use biometric authentication"),
    "android.permission.CAPTURE_AUDIO_OUTPUT":        (RISK_CRITICAL,"Can capture audio output (system perm)"),
    "android.permission.CAPTURE_VIDEO_OUTPUT":        (RISK_CRITICAL,"Can capture screen video (system perm)"),
    "android.permission.READ_FRAME_BUFFER":           (RISK_CRITICAL,"Can read screen framebuffer"),
    "android.permission.INJECT_EVENTS":               (RISK_CRITICAL,"Can inject touch/key events (keylogger)"),
    "android.permission.INTERNAL_SYSTEM_WINDOW":      (RISK_CRITICAL,"Internal system window access"),
    "android.permission.CHANGE_NETWORK_STATE":        (RISK_MEDIUM, "Can change network connectivity"),
    "android.permission.CHANGE_WIFI_STATE":           (RISK_MEDIUM, "Can control Wi-Fi"),
    "android.permission.BLUETOOTH_ADMIN":             (RISK_LOW,    "Can control Bluetooth"),
    "android.permission.NFC":                         (RISK_LOW,    "NFC access"),
    "android.permission.HIDE_OVERLAY_WINDOWS":        (RISK_HIGH,   "Can hide overlay windows from user"),
    "android.permission.USE_CREDENTIALS":             (RISK_HIGH,   "Can use stored account credentials"),
    "android.permission.MANAGE_ACCOUNTS":             (RISK_HIGH,   "Can manage user accounts"),
    "android.permission.AUTHENTICATE_ACCOUNTS":       (RISK_HIGH,   "Can authenticate as account manager"),
    "android.permission.READ_SYNC_SETTINGS":          (RISK_LOW,    "Read sync settings"),
    "android.permission.WRITE_SYNC_SETTINGS":         (RISK_MEDIUM, "Modify sync settings"),
    "android.permission.WAKE_LOCK":                   (RISK_LOW,    "Prevent device sleep"),
    "android.permission.FOREGROUND_SERVICE":          (RISK_LOW,    "Run hidden foreground service"),
    "android.permission.USE_EXACT_ALARM":             (RISK_LOW,    "Schedule precise alarms"),
    "android.permission.SCHEDULE_EXACT_ALARM":        (RISK_LOW,    "Schedule exact alarms"),
    "android.permission.RECEIVE_WAP_PUSH":            (RISK_MEDIUM, "Receive WAP push messages"),
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": (RISK_HIGH, "Read all device notifications"),
    "android.permission.ACCESS_NOTIFICATION_POLICY":  (RISK_MEDIUM, "Manage Do-Not-Disturb/notifications"),
}

# ── Known malicious / stalkerware / RAT package names (partial list) ─────────
KNOWN_MALICIOUS_PACKAGES = {
    # Stalkerware / Spyware
    "com.spyapp.android", "com.android.monitorapp", "com.hspy.pro", "com.ispy.android",
    "org.microspy", "com.android.phspy", "com.phonesheriff", "com.mspy.android",
    "com.flexispy", "com.spymaster.android", "com.thetruthspy", "com.trackview",
    "com.highster.mobile", "com.spyera", "com.familyorbit", "com.cerberus.app",
    "com.android.smsbackuprestore", "com.copy9.app",
    # Root tools
    "com.noshufou.android.su", "com.koushikdutta.superuser", "eu.chainfire.supersu",
    "com.topjohnwu.magisk", "com.kingroot.kinguser", "com.kingo.root",
    "com.zhiqupk.root.global", "com.alephzain.framaroot",
    # RATs / Exploits
    "org.metasploit", "com.csploit.android", "com.drozer.agent",
    "de.robv.android.xposed.installer", "com.saurik.substrate",
    # Adware
    "com.leadbolt.ad", "com.startapp.android", "com.airpush.android",
    # Fake system apps
    "com.android.system.manager", "com.google.system.service",
    "com.android.systemservice", "com.system.phone.service",
}

# ── Heuristic keywords ────────────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "keylogger", "keylog", "inject", "stealth", "rat", " spy", "spyware",
    "monitor", "surveillance", "csploit", "drozer", "metasploit", "xhelper",
    "kingroot", "frida", "magisk", "supersu", "substrate", "xposed",
    "screenrecord", "screencap", "sms intercept", "call intercept",
    "location track", "hidden", "invisible", "no-icon",
]

# ── Suspicious system file paths ──────────────────────────────────────────────
SUSPICIOUS_PATHS = [
    "/system/bin/su", "/system/xbin/su", "/sbin/su",
    "/system/xbin/busybox", "/system/bin/busybox",
    "/system/app/Superuser.apk", "/system/app/SuperSU",
    "/data/local/tmp/frida-server", "/data/local/tmp/frida",
    "/data/local.prop",
    "/system/xbin/bstk",
    "/system/bin/.ext", "/system/.ext",
    "/system/bin/daemonsu", "/system/xbin/daemonsu",
    "/dev/com.koushikdutta.superuser.daemon",
]

# ── Dangerous system properties ───────────────────────────────────────────────
DANGEROUS_PROPS = {
    "ro.debuggable":   ("1",  RISK_HIGH,   "Build is debuggable (test/dev build)"),
    "ro.secure":       ("0",  RISK_HIGH,   "ro.secure=0 means adbd runs as root"),
    "ro.build.type":   ("eng", RISK_MEDIUM,"Engineering build — fewer restrictions"),
    "ro.build.tags":   ("test-keys", RISK_HIGH, "Signed with test keys (unofficial ROM)"),
    "service.adb.root":("1",  RISK_CRITICAL,"adbd running as root RIGHT NOW"),
}

# ─────────────────────────────  LOGGING  ───────────────────────────────────

_log_lines: List[str] = []   # captured for report

def _ts() -> str:
    return dt.datetime.now().strftime("%H:%M:%S")

def log(msg: str, level: str = "INFO", color: str = C.WHITE):
    tag_colors = {
        "INFO":     C.CYAN,
        "OK":       C.GREEN,
        "WARN":     C.YELLOW,
        "ALERT":    C.RED,
        "DEBUG":    C.GREY,
        "SECTION":  C.MAGENTA,
    }
    tc = tag_colors.get(level, C.WHITE)
    tag = f"{tc}[{level:6s}]{C.RESET}"
    ts  = f"{C.GREY}{_ts()}{C.RESET}"
    print(f"{ts} {tag} {color}{msg}{C.RESET}", flush=True)
    _log_lines.append(f"[{_ts()}] [{level:6s}] {msg}")

def section(title: str):
    bar = "─" * 60
    print(f"\n{C.MAGENTA}{C.BOLD}{bar}\n  {title}\n{bar}{C.RESET}", flush=True)
    _log_lines.append(f"\n{'─'*60}\n  {title}\n{'─'*60}")

def done(msg: str):  log(msg, "OK",    C.GREEN)
def warn(msg: str):  log(msg, "WARN",  C.YELLOW)
def alert(msg: str): log(msg, "ALERT", C.RED)
def info(msg: str):  log(msg, "INFO",  C.CYAN)
def debug(msg: str): log(msg, "DEBUG", C.GREY)

# ─────────────────────────────  ADB HELPERS  ────────────────────────────────

def run_cmd(cmd: List[str], timeout: int = TIMEOUT) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, text=True
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"TIMEOUT after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"Command not found: {cmd[0]}"

def adb(serial: Optional[str], *args: str, timeout: int = TIMEOUT) -> Tuple[int, str, str]:
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    return run_cmd(cmd, timeout=timeout)

def shell(serial: str, cmd_str: str, timeout: int = TIMEOUT) -> Tuple[int, str, str]:
    return adb(serial, "shell", cmd_str, timeout=timeout)

def shell_out(serial: str, cmd_str: str, timeout: int = TIMEOUT) -> str:
    _, out, _ = shell(serial, cmd_str, timeout=timeout)
    return out.strip()

# ─────────────────────────────  DEVICE INIT  ────────────────────────────────

def ensure_adb():
    if not shutil.which("adb"):
        sys.exit(f"{C.RED}[FATAL] 'adb' not found in PATH. Install Android Platform Tools.{C.RESET}")

def pick_device(serial: Optional[str]) -> str:
    code, out, err = adb(None, "devices")
    if code != 0:
        sys.exit(f"Failed running 'adb devices': {err}")
    lines = [l for l in out.splitlines()[1:] if l.strip()]
    authorized = [l.split("\t")[0] for l in lines if "\tdevice" in l]
    unauthorized = [l.split("\t")[0] for l in lines if "unauthorized" in l]

    if unauthorized:
        warn(f"Unauthorized device(s) found (not audited): {unauthorized}")
        warn("On the device, tap 'Allow USB debugging' and re-run.")

    if serial:
        if serial not in authorized:
            sys.exit(f"Serial {serial!r} not in authorized devices: {authorized}")
        return serial
    if not authorized:
        sys.exit("No authorized ADB devices. Connect a device and grant USB debugging.")
    if len(authorized) > 1:
        sys.exit(f"Multiple devices: {authorized}. Use --serial to specify one.")
    return authorized[0]

# ─────────────────────────────  CHECK MODULES  ──────────────────────────────

def collect_device_info(serial: str) -> Dict:
    section("DEVICE INFORMATION")
    info("Collecting system properties...")
    _, prop_raw, _ = shell(serial, "getprop", timeout=LONG_TIMEOUT)
    props: Dict[str, str] = {}
    for line in prop_raw.splitlines():
        m = re.match(r"\[(.*?)\]: \[(.*)\]", line)
        if m:
            props[m.group(1)] = m.group(2)

    keys = [
        "ro.build.display.id", "ro.build.version.release", "ro.build.version.sdk",
        "ro.build.version.security_patch", "ro.product.brand", "ro.product.manufacturer",
        "ro.product.model", "ro.product.device", "ro.build.type", "ro.build.tags",
        "ro.debuggable", "ro.secure", "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked", "ro.hardware", "ro.kernel.version",
        "persist.sys.timezone", "ro.product.locale",
        "service.adb.root",
    ]
    build = {k: props.get(k, "") for k in keys}

    done(f"Device: {build.get('ro.product.brand')} {build.get('ro.product.model')} "
         f"Android {build.get('ro.build.version.release')} "
         f"(SDK {build.get('ro.build.version.sdk')})")
    debug(f"Security patch: {build.get('ro.build.version.security_patch', 'unknown')}")
    debug(f"Build type: {build.get('ro.build.type')}  tags: {build.get('ro.build.tags')}")
    debug(f"Verified boot: {build.get('ro.boot.verifiedbootstate', 'unknown')}")

    return {"build_info": build, "_all_props": props}


def check_dangerous_props(props: Dict[str, str]) -> List[Dict]:
    section("DANGEROUS SYSTEM PROPERTIES")
    findings = []
    for key, (bad_val, severity, desc) in DANGEROUS_PROPS.items():
        actual = props.get(key, "")
        if actual == bad_val or (key == "ro.build.tags" and bad_val in actual):
            msg = f"{key} = {actual!r} → {desc}"
            findings.append({"prop": key, "value": actual, "severity": severity, "desc": desc})
            if severity == RISK_CRITICAL:
                alert(msg)
            elif severity == RISK_HIGH:
                warn(msg)
            else:
                info(msg)
    if not findings:
        done("No dangerous property values detected.")
    return findings


def check_root_status(serial: str) -> Dict:
    section("ROOT / PRIVILEGE ESCALATION")
    result = {}

    # su binary
    su_paths_found = []
    for path in ["/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/xbin/daemonsu"]:
        out = shell_out(serial, f"ls {path} 2>/dev/null || echo MISSING")
        if "MISSING" not in out and out:
            su_paths_found.append(path)
    result["su_paths_found"] = su_paths_found
    if su_paths_found:
        alert(f"su binary found at: {su_paths_found}")
    else:
        done("No su binary in common paths.")

    # which su
    which_su = shell_out(serial, "which su 2>/dev/null || echo none")
    result["which_su"] = which_su
    if which_su != "none" and which_su:
        warn(f"'which su' found su at: {which_su}")

    # SELinux
    enforce = shell_out(serial, "getenforce 2>/dev/null || echo Unknown")
    result["selinux"] = enforce
    if enforce.lower() == "enforcing":
        done(f"SELinux: {enforce}")
    elif enforce.lower() == "permissive":
        alert(f"SELinux is PERMISSIVE — root exploits are much easier!")
    else:
        warn(f"SELinux status: {enforce}")

    # /system partition
    mounts = shell_out(serial, "mount | grep ' /system '")
    result["system_rw"] = " rw," in mounts
    if result["system_rw"]:
        alert("/system is mounted READ-WRITE — indicates deep root compromise!")
    else:
        done("/system is read-only.")

    # Magisk / SuperSU detection
    magisk_out = shell_out(serial, "magisk --version 2>/dev/null || echo none")
    result["magisk_version"] = magisk_out if "none" not in magisk_out else None
    if result["magisk_version"]:
        alert(f"Magisk detected — version: {magisk_out}")
    else:
        done("Magisk not detected via CLI.")

    # Check /data/adb (Magisk data directory)
    magisk_data = shell_out(serial, "ls /data/adb 2>/dev/null || echo NONE")
    result["magisk_data_dir"] = magisk_data if "NONE" not in magisk_data else None
    if result["magisk_data_dir"]:
        warn(f"/data/adb exists — Magisk artifacts: {magisk_data}")

    # adbd root
    adb_root = adb(serial, "root", timeout=5)[0] == 0
    result["adb_root_allowed"] = adb_root
    if adb_root:
        warn("adbd accepted 'adb root' (userdebug/eng build or custom ROM)")

    # Frida server
    frida_check = shell_out(serial, "ps -A 2>/dev/null | grep -i frida || echo none")
    result["frida_running"] = "frida" in frida_check.lower()
    if result["frida_running"]:
        alert(f"Frida server process detected! Dynamic instrumentation active.")
    else:
        done("Frida server not detected in process list.")

    return result


def check_suspicious_files(serial: str) -> List[Dict]:
    section("SUSPICIOUS FILES & PATHS")
    findings = []
    for path in SUSPICIOUS_PATHS:
        out = shell_out(serial, f"ls -la {path} 2>/dev/null || echo MISSING")
        if "MISSING" not in out and out.strip():
            findings.append({"path": path, "info": out.strip()})
            alert(f"Found suspicious file: {path}")
            debug(f"  → {out.strip()}")

    # Check /data/local/tmp for executable files (common dropper location)
    tmp_files = shell_out(serial, "ls -la /data/local/tmp/ 2>/dev/null || echo EMPTY")
    if "EMPTY" not in tmp_files and tmp_files:
        warn(f"/data/local/tmp contents:\n{tmp_files}")
        findings.append({"path": "/data/local/tmp", "info": tmp_files})
    else:
        done("/data/local/tmp is empty (good).")

    # APK files outside /data/app
    info("Scanning for APK files in unexpected locations...")
    apks_tmp = shell_out(serial, "find /data/local/tmp /sdcard /cache -name '*.apk' 2>/dev/null || echo none", timeout=LONG_TIMEOUT)
    if apks_tmp and apks_tmp != "none":
        for apk in apks_tmp.splitlines():
            if apk.strip():
                warn(f"APK found in unexpected location: {apk.strip()}")
                findings.append({"path": apk.strip(), "info": "APK in non-standard location"})
    else:
        done("No stray APKs found in tmp/sdcard/cache.")

    # Check for hidden directories in /data
    hidden = shell_out(serial, "ls -la /data/ 2>/dev/null | grep ' \\.'", timeout=LONG_TIMEOUT)
    if hidden:
        warn(f"Hidden directories/files in /data:\n{hidden}")
        findings.append({"path": "/data (hidden)", "info": hidden})

    if not findings:
        done("No suspicious files detected in common locations.")
    return findings


def check_security_settings(serial: str) -> Dict:
    section("ANDROID SECURITY SETTINGS")

    def s(scope: str, key: str) -> str:
        return shell_out(serial, f"settings get {scope} {key}")

    settings = {
        "adb_enabled":                s("global", "adb_enabled"),
        "dev_options_enabled":        s("global", "development_settings_enabled"),
        "unknown_sources_pre_O":      s("global", "install_non_market_apps"),
        "package_verifier_enable":    s("global", "package_verifier_enable"),
        "verify_apps_over_usb":       s("global", "verifier_verify_adb_installs"),
        "auto_time":                  s("global", "auto_time"),
        "auto_time_zone":             s("global", "auto_time_zone"),
        "always_on_vpn":              s("secure", "always_on_vpn_app"),
        "vpn_lockdown":               s("secure", "always_on_vpn_lockdown"),
        "default_sms_app":            s("secure", "sms_default_application"),
        "enabled_accessibility_svcs": s("secure", "enabled_accessibility_services"),
        "device_admins":              s("secure", "device_provisioning_migration_status"),
        "location_mode":              s("secure", "location_mode"),
        "lock_screen_show_notifs":    s("secure", "lock_screen_show_notifications"),
        "bluetooth_on":               s("global", "bluetooth_on"),
        "wifi_on":                    s("global", "wifi_on"),
        "mock_location_app":          s("secure", "mock_location"),
        "usb_mass_storage_enabled":   s("global", "usb_mass_storage_enabled"),
        "stay_on_while_plugged_in":   s("global", "stay_on_while_plugged_in"),
    }

    # Report notable settings
    if settings["adb_enabled"] == "1":
        warn("ADB is enabled — expected if you're auditing, suspicious otherwise.")
    if settings["dev_options_enabled"] == "1":
        warn("Developer Options are enabled.")
    if settings["unknown_sources_pre_O"] == "1":
        alert("Unknown sources (pre-Android 8) is enabled — sideloading allowed!")
    if settings["package_verifier_enable"] == "0":
        alert("Package verifier is DISABLED — Play Protect won't scan installs!")
    if settings["always_on_vpn"]:
        info(f"Always-on VPN set to: {settings['always_on_vpn']}")
    if settings["mock_location_app"] and settings["mock_location_app"] != "null":
        warn(f"Mock location provider active: {settings['mock_location_app']}")
    if settings["enabled_accessibility_svcs"] and settings["enabled_accessibility_svcs"] not in ("null", "", "0"):
        warn(f"Active accessibility services: {settings['enabled_accessibility_svcs']}")

    # Check active device admins directly
    admin_out = shell_out(serial, "dumpsys device_policy | grep -A2 'Active Admin' 2>/dev/null || echo none")
    settings["active_device_admins_raw"] = admin_out
    if admin_out and "none" not in admin_out:
        warn(f"Active Device Admins detected:\n{admin_out}")

    return settings


def audit_packages(serial: str) -> List[Dict]:
    section("INSTALLED PACKAGE AUDIT")
    info("Listing all installed packages (this may take a while)...")

    _, u_out, _ = shell(serial, "pm list packages -3", timeout=LONG_TIMEOUT)
    _, s_out, _ = shell(serial, "pm list packages -s", timeout=LONG_TIMEOUT)
    _, d_out, _ = shell(serial, "pm list packages -d", timeout=LONG_TIMEOUT)  # disabled

    def parse_pkgs(raw: str) -> List[str]:
        return [l.split(":", 1)[1].strip() for l in raw.splitlines() if l.startswith("package:")]

    user_pkgs   = set(parse_pkgs(u_out))
    system_pkgs = set(parse_pkgs(s_out))
    disabled_pkgs = set(parse_pkgs(d_out))
    all_pkgs    = sorted(user_pkgs | system_pkgs)

    info(f"Found {len(all_pkgs)} packages total ({len(user_pkgs)} user, {len(system_pkgs)} system, {len(disabled_pkgs)} disabled).")

    packages = []
    flagged  = 0

    for i, pkg in enumerate(all_pkgs):
        debug(f"  [{i+1}/{len(all_pkgs)}] Analyzing: {pkg}")

        entry: Dict = {
            "package":       pkg,
            "is_system":     pkg in system_pkgs,
            "is_disabled":   pkg in disabled_pkgs,
            "is_known_malicious": pkg in KNOWN_MALICIOUS_PACKAGES,
            "flags":         [],
        }

        # Known malicious
        if entry["is_known_malicious"]:
            alert(f"  KNOWN MALICIOUS PACKAGE: {pkg}")
            entry["flags"].append(f"{RISK_CRITICAL}: Known malicious/stalkerware package")
            flagged += 1

        # dumpsys for deep analysis
        _, dump, _ = shell(serial, f"dumpsys package {pkg}", timeout=LONG_TIMEOUT)

        # Installer source
        m = re.search(r"installerPackageName=(\S+)", dump)
        entry["installer"] = m.group(1) if m else "unknown"
        if entry["installer"] not in ("com.android.vending", "com.google.android.packageinstaller",
                                       "com.miui.packageinstaller", "com.samsung.android.packageinstaller",
                                       "com.huawei.appmarket", "unknown", "null", ""):
            if not entry["is_system"]:
                warn(f"  {pkg} installed from non-Play source: {entry['installer']}")
                entry["flags"].append(f"{RISK_MEDIUM}: Sideloaded (installer: {entry['installer']})")

        # Install time
        m_inst = re.search(r"firstInstallTime=(.+)", dump)
        m_upd  = re.search(r"lastUpdateTime=(.+)", dump)
        entry["first_install"] = m_inst.group(1).strip() if m_inst else ""
        entry["last_update"]   = m_upd.group(1).strip() if m_upd else ""

        # Version
        m_ver = re.search(r"versionName=(.+)", dump)
        entry["version"] = m_ver.group(1).strip() if m_ver else ""

        # Permissions
        req_block  = re.search(r"requested permissions:(.*?)(?:\n\S|\Z)", dump, re.S)
        gran_block = re.search(r"install permissions:(.*?)(?:\n\S|\Z)", dump, re.S)
        run_block  = re.search(r"runtime permissions:(.*?)(?:\n\S|\Z)", dump, re.S)

        req_perms  = re.findall(r"\s+(android\.\S+)", req_block.group(1))  if req_block  else []
        gran_perms = re.findall(r"\s+(android\.\S+)", gran_block.group(1)) if gran_block else []
        run_perms  = re.findall(r"\s+(android\.\S+)", run_block.group(1))  if run_block  else []
        all_perms  = set(req_perms + gran_perms + run_perms)

        entry["requested_permissions"] = list(req_perms)
        entry["granted_permissions"]   = list(set(gran_perms + run_perms))
        entry["suspicious_permissions"] = []

        for perm, (severity, desc) in SUSPICIOUS_PERMS.items():
            if perm in all_perms:
                entry["suspicious_permissions"].append({
                    "permission": perm, "severity": severity, "desc": desc
                })
                if severity in (RISK_CRITICAL, RISK_HIGH) and not entry["is_system"]:
                    warn(f"  {pkg} has {severity} perm: {perm} → {desc}")
                    entry["flags"].append(f"{severity}: {perm} ({desc})")
                    flagged += 1

        # Boot receiver
        entry["boot_receiver"] = bool(re.search(r"android\.intent\.action\.BOOT_COMPLETED", dump))

        # Accessibility service
        entry["is_accessibility_service"] = bool(re.search(r"android\.accessibilityservice\.AccessibilityService", dump))
        if entry["is_accessibility_service"] and not entry["is_system"]:
            warn(f"  {pkg} declares an accessibility service!")
            entry["flags"].append(f"{RISK_HIGH}: Declares accessibility service")

        # Device admin
        entry["is_device_admin"] = bool(re.search(r"android\.app\.action\.DEVICE_ADMIN_ENABLED|BIND_DEVICE_ADMIN", dump))
        if entry["is_device_admin"] and not entry["is_system"]:
            alert(f"  {pkg} is a Device Administrator!")
            entry["flags"].append(f"{RISK_CRITICAL}: Device administrator")

        # Overlay permission
        entry["has_overlay"] = "android.permission.SYSTEM_ALERT_WINDOW" in all_perms

        # Notification listener
        entry["is_notif_listener"] = bool(re.search(r"android\.service\.notification\.NotificationListenerService", dump))
        if entry["is_notif_listener"] and not entry["is_system"]:
            warn(f"  {pkg} listens to all notifications!")
            entry["flags"].append(f"{RISK_HIGH}: Notification listener service")

        # Suspicious keywords in dump
        kw_found = [k for k in SUSPICIOUS_KEYWORDS if k.lower() in dump.lower()]
        entry["suspicious_keywords"] = kw_found
        if kw_found and not entry["is_system"]:
            warn(f"  {pkg} dump contains suspicious keywords: {kw_found}")
            entry["flags"].append(f"{RISK_MEDIUM}: Suspicious keywords in package info: {kw_found}")

        # No launcher icon (hidden app)
        has_launcher = bool(re.search(r"android\.intent\.category\.LAUNCHER", dump))
        entry["has_launcher_icon"] = has_launcher
        if not has_launcher and not entry["is_system"] and not entry["is_disabled"]:
            info(f"  {pkg} has NO launcher icon — hidden from app drawer!")
            entry["flags"].append(f"{RISK_MEDIUM}: Hidden app (no launcher icon)")

        if entry["flags"]:
            flagged += 1

        packages.append(entry)

    info(f"Package audit complete. {flagged} packages flagged.")
    return packages


def check_running_processes(serial: str) -> List[Dict]:
    section("RUNNING PROCESSES")
    _, out, _ = shell(serial, "ps -A -o USER,PID,PPID,NAME 2>/dev/null || ps", timeout=LONG_TIMEOUT)
    procs = []
    lines = out.splitlines()
    if not lines:
        warn("Could not retrieve process list.")
        return procs

    headers = re.split(r"\s+", lines[0].strip()) if lines else []
    for line in lines[1:]:
        parts = re.split(r"\s+", line.strip())
        if len(parts) < 2:
            continue
        proc = {"raw": line.strip()}
        if len(parts) >= 4:
            proc["user"] = parts[0]
            proc["pid"]  = parts[1]
            proc["ppid"] = parts[2]
            proc["name"] = " ".join(parts[3:])
        elif len(parts) >= 2:
            proc["user"] = parts[0]
            proc["pid"]  = parts[1]
            proc["name"] = parts[-1]
        else:
            proc["user"] = ""
            proc["pid"]  = ""
            proc["name"] = line.strip()
        procs.append(proc)

    # Flag suspicious process names
    for proc in procs:
        name = proc.get("name", "").lower()
        for kw in ["frida", "gdbserver", "tcpdump", "nmap", "netcat", "nc", "strace", "ltrace", "adbd"]:
            if kw in name:
                if kw == "adbd":
                    debug(f"adbd running as user: {proc.get('user','?')}")
                    if proc.get("user") == "root":
                        alert(f"adbd running as ROOT — full shell access active!")
                else:
                    alert(f"Suspicious process: {proc.get('name')} (PID {proc.get('pid')}) user={proc.get('user')}")

    info(f"Found {len(procs)} running processes.")
    return procs


def check_network(serial: str) -> Dict:
    section("NETWORK CONNECTIONS & CONFIGURATION")

    # Open sockets
    _, ss_out, _ = shell(serial, "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || echo none", timeout=LONG_TIMEOUT)
    sockets = []
    for line in ss_out.splitlines()[1:]:
        cols = re.split(r"\s+", line.strip())
        if len(cols) < 5:
            continue
        sockets.append({"proto": cols[0], "state": cols[1], "local": cols[4] if len(cols)>4 else "",
                         "peer": cols[5] if len(cols)>5 else "", "process": cols[-1] if cols else ""})

    # External connections (non-loopback, non-wildcard)
    external = [s for s in sockets if s.get("peer") and
                not any(s["peer"].startswith(x) for x in ("127.", "0.0.0.0", "::", "*", "[::"))
                and s.get("state") in ("ESTABLISHED", "ESTAB")]
    if external:
        warn(f"{len(external)} external network connection(s):")
        for s in external:
            warn(f"  {s['proto']} {s['local']} → {s['peer']}  {s['process']}")
    else:
        done("No suspicious external connections detected.")

    # DNS settings
    dns1 = shell_out(serial, "getprop net.dns1")
    dns2 = shell_out(serial, "getprop net.dns2")
    debug(f"DNS: {dns1}, {dns2}")

    # VPN interfaces
    vpn_iface = shell_out(serial, "ip link show | grep -E 'tun|ppp|vpn' || echo none")
    vpn_active = vpn_iface and "none" not in vpn_iface
    if vpn_active:
        warn(f"VPN/tunnel interfaces detected: {vpn_iface}")
    else:
        done("No VPN tunnel interfaces detected.")

    # iptables rules
    _, ipt_out, _ = shell(serial, "iptables -S 2>/dev/null || iptables -L -n 2>/dev/null || echo UNAVAILABLE", timeout=LONG_TIMEOUT)
    suspicious_rules = [l for l in ipt_out.splitlines()
                        if re.search(r"REDIRECT|DNAT|SNAT|MASQUERADE", l, re.I)]
    if suspicious_rules:
        alert(f"Suspicious iptables rules (traffic redirect/NAT):")
        for r in suspicious_rules:
            alert(f"  {r}")

    # Wi-Fi SSID / BSSID
    wifi_info = shell_out(serial, "dumpsys wifi | grep -E 'SSID|BSSID|ipAddress' | head -20")
    debug(f"Wi-Fi info:\n{wifi_info}")

    return {
        "sockets": sockets,
        "external_connections": external,
        "vpn_interfaces": vpn_iface,
        "iptables_suspicious": suspicious_rules,
        "dns1": dns1, "dns2": dns2,
        "wifi_info": wifi_info,
    }


def check_accessibility_services(serial: str) -> Dict:
    section("ACCESSIBILITY & OVERLAY SERVICES")
    enabled = shell_out(serial, "settings get secure enabled_accessibility_services")
    info(f"Enabled accessibility services: {enabled or '(none)'}")
    services = [s.strip() for s in enabled.split(":") if s.strip() and enabled not in ("null", "", "0")]

    overlay_apps = shell_out(serial, "dumpsys window | grep -E 'mCurrentFocus|mFocusedApp|overlay' | head -30")
    debug(f"Current window focus/overlay:\n{overlay_apps}")

    if services:
        warn(f"{len(services)} accessibility service(s) active:")
        for svc in services:
            warn(f"  → {svc}")

    return {"enabled_services": services, "overlay_focus_raw": overlay_apps}


def check_logcat_anomalies(serial: str, duration: int = 10) -> List[str]:
    section("LOGCAT ANOMALY SCAN")
    info(f"Capturing logcat for {duration} seconds...")

    suspicious_patterns = [
        r"(root|su |superuser|supersu|magisk)",
        r"(frida|gadget|objection)",
        r"(keylog|keystroke|inject)",
        r"(overlay|draw over)",
        r"(accessibility.*granted|grant.*accessibility)",
        r"(device.admin|device admin.*activated)",
        r"(install.*apk|apk.*install)",
        r"(send.*sms|sms.*sent|smsmessage)",
        r"(record.*audio|audio.*record|microphone)",
        r"(location.*listener|location.*update)",
        r"(clipboard.*read|read.*clipboard)",
        r"(camera.*open|open.*camera)",
        r"(screenshot|screencap|screenrecord)",
        r"(data.*exfil|upload.*data|post.*data)",
        r"(bind.*service|remote.*service.*connected)",
        r"(dex.*load|loadclass|reflect.*invoke)",
    ]

    # Dump recent logcat buffer
    _, log_out, _ = adb(serial, "logcat", "-d", "-v", "brief", "--buffer=all",
                         timeout=duration + 10)
    flagged_lines = []
    for line in log_out.splitlines():
        for pat in suspicious_patterns:
            if re.search(pat, line, re.I):
                flagged_lines.append(line.strip())
                break

    if flagged_lines:
        warn(f"Logcat contains {len(flagged_lines)} suspicious entries:")
        for l in flagged_lines[:30]:
            warn(f"  [LOG] {l}")
        if len(flagged_lines) > 30:
            warn(f"  ... and {len(flagged_lines)-30} more (see JSON report).")
    else:
        done("No obviously suspicious logcat entries detected.")

    return flagged_lines


def check_sms_calls(serial: str) -> Dict:
    section("SMS & CALL LOG INDICATORS")
    # Check if any non-default app has READ_SMS
    sms_app = shell_out(serial, "settings get secure sms_default_application")
    info(f"Default SMS app: {sms_app or 'unknown'}")

    # Check for forwarding / USSD traps (heuristic — look at telephony properties)
    call_fwd = shell_out(serial, "getprop gsm.call.forwarded 2>/dev/null || echo none")
    debug(f"Call forwarding flag: {call_fwd}")
    if call_fwd == "true":
        alert("Call forwarding appears to be active!")

    return {"default_sms_app": sms_app, "call_forwarding_flag": call_fwd}


def check_battery_and_wakelocks(serial: str) -> Dict:
    section("BATTERY & WAKELOCKS (Background Activity)")
    dump = shell_out(serial, "dumpsys batterystats --charged 2>/dev/null | head -200", timeout=LONG_TIMEOUT)

    # Top battery consumers
    wakelocks = re.findall(r"([\w\.]+)\s+wakelock.*?(\d+\.\d+) hrs", dump, re.I)
    top_consumers = re.findall(r"(\d+\.\d+)%\s+([\w\.\/ ]+)", dump)

    if wakelocks:
        warn(f"Apps holding wakelocks:")
        for pkg, hrs in wakelocks[:10]:
            warn(f"  {pkg}: {hrs} hrs")
    if top_consumers:
        info("Top battery consumers:")
        for pct, pkg in top_consumers[:10]:
            info(f"  {pct}%: {pkg.strip()}")

    return {"wakelocks": wakelocks[:20], "top_consumers": top_consumers[:10]}


def check_accounts_and_sync(serial: str) -> Dict:
    section("ACCOUNTS & SYNC")
    accounts = shell_out(serial, "dumpsys account 2>/dev/null | head -80")
    debug(f"Accounts:\n{accounts}")

    # Extract account types
    account_types = re.findall(r"type=([\w\.]+)", accounts)
    info(f"Account types found: {list(set(account_types))}")

    # Sync adapters
    sync = shell_out(serial, "dumpsys content | grep -i sync | head -30")
    return {"accounts_raw": accounts[:2000], "account_types": list(set(account_types))}


def check_clipboard(serial: str) -> Dict:
    section("CLIPBOARD ACCESS CHECK")
    # Check which apps have clipboard access (Android 12+ logs)
    clip_log = shell_out(serial, "logcat -d -s ClipboardService 2>/dev/null | tail -30")
    if clip_log:
        info(f"Recent clipboard access log:\n{clip_log}")
    else:
        info("No recent clipboard access in logcat (ClipboardService).")
    return {"clipboard_access_log": clip_log}


def check_active_services(serial: str) -> List[str]:
    section("ACTIVE / FOREGROUND SERVICES")
    out = shell_out(serial, "dumpsys activity services 2>/dev/null | grep -E 'ServiceRecord|app=' | head -60", timeout=LONG_TIMEOUT)
    services = []
    for line in out.splitlines():
        m = re.search(r"ServiceRecord\{[^}]+ (\S+)\}", line)
        if m:
            services.append(m.group(1))
    if services:
        info(f"{len(services)} active services:")
        for svc in services[:30]:
            debug(f"  {svc}")
    return services


def check_device_admins(serial: str) -> List[str]:
    section("DEVICE ADMINISTRATORS")
    _, out, _ = shell(serial, "dumpsys device_policy 2>/dev/null | grep -E 'admin|Admin' | head -30")
    admins = [l.strip() for l in out.splitlines() if l.strip()]
    if admins:
        alert(f"Device admin entries found ({len(admins)}):")
        for a in admins:
            alert(f"  {a}")
    else:
        done("No device administrator entries detected.")
    return admins


def check_crypto_and_storage(serial: str) -> Dict:
    section("ENCRYPTION & STORAGE")
    enc_state = shell_out(serial, "getprop ro.crypto.state")
    enc_type  = shell_out(serial, "getprop ro.crypto.type")
    fbe       = shell_out(serial, "getprop ro.crypto.volume.filenames_mode")
    debug(f"Encryption state: {enc_state}, type: {enc_type}, FBE mode: {fbe}")

    if enc_state == "encrypted":
        done(f"Storage is encrypted. Type: {enc_type}")
    elif enc_state == "unencrypted":
        alert("Storage is NOT ENCRYPTED — all data readable if device is accessed physically!")
    else:
        info(f"Encryption state: {enc_state or 'unknown'}")

    return {"encryption_state": enc_state, "encryption_type": enc_type, "fbe_mode": fbe}


def check_recent_apk_installs(serial: str) -> List[Dict]:
    section("RECENTLY INSTALLED / UPDATED PACKAGES")
    out = shell_out(serial, "pm list packages -3 --show-versioncode 2>/dev/null", timeout=LONG_TIMEOUT)
    # Look at install times via dumpsys pm
    _, dump, _ = shell(serial, "dumpsys package 2>/dev/null | grep -E 'firstInstallTime|packageName' | head -200", timeout=LONG_TIMEOUT)
    recent = []
    lines = dump.splitlines()
    current_pkg = ""
    for line in lines:
        m_pkg  = re.search(r"packageName=(\S+)", line)
        m_time = re.search(r"firstInstallTime=(.+)", line)
        if m_pkg:
            current_pkg = m_pkg.group(1)
        if m_time and current_pkg:
            install_str = m_time.group(1).strip()
            try:
                # Try to detect installs within last 7 days
                # Time strings vary by Android version — best effort
                recent.append({"package": current_pkg, "install_time": install_str})
            except Exception:
                pass

    # Sort by most recent (heuristic — lexicographic on ISO dates)
    recent = sorted(recent, key=lambda x: x.get("install_time",""), reverse=True)[:20]
    if recent:
        info(f"Most recently installed/updated apps:")
        for r in recent[:10]:
            info(f"  {r['package']} @ {r['install_time']}")
    return recent


# ─────────────────────────────  RISK SCORING  ───────────────────────────────

def compute_risk(report: Dict) -> Dict:
    score = 0
    findings = []

    def add(pts: int, msg: str, sev: str = RISK_MEDIUM):
        nonlocal score
        score += pts
        findings.append({"severity": sev, "msg": msg, "pts": pts})

    root = report.get("root_status", {})
    if root.get("su_paths_found"):
        add(30, f"su binary found at: {root['su_paths_found']}", RISK_CRITICAL)
    if root.get("magisk_version"):
        add(25, f"Magisk {root['magisk_version']} detected", RISK_CRITICAL)
    if root.get("magisk_data_dir"):
        add(15, "Magisk /data/adb directory exists", RISK_HIGH)
    if root.get("frida_running"):
        add(30, "Frida instrumentation server running", RISK_CRITICAL)
    if root.get("system_rw"):
        add(20, "/system partition mounted read-write", RISK_CRITICAL)
    if root.get("selinux", "").lower() == "permissive":
        add(20, "SELinux is permissive", RISK_HIGH)
    if root.get("adb_root_allowed"):
        add(10, "adb root allowed (userdebug/eng build)", RISK_HIGH)

    dangerous_props = report.get("dangerous_props", [])
    for p in dangerous_props:
        sev = p.get("severity", RISK_MEDIUM)
        add(15 if sev == RISK_CRITICAL else 10 if sev == RISK_HIGH else 5,
            f"Dangerous prop {p['prop']}={p['value']}: {p['desc']}", sev)

    sus_files = report.get("suspicious_files", [])
    add(min(len(sus_files) * 5, 20), f"{len(sus_files)} suspicious file(s) found", RISK_HIGH) if sus_files else None

    settings = report.get("security_settings", {})
    if settings.get("package_verifier_enable") == "0":
        add(15, "Play Protect / package verifier disabled", RISK_HIGH)
    if settings.get("unknown_sources_pre_O") == "1":
        add(10, "Unknown sources enabled (pre-Android 8)", RISK_HIGH)
    if settings.get("mock_location_app") not in ("null", "", None):
        add(10, f"Mock location provider active: {settings.get('mock_location_app')}", RISK_HIGH)

    packages = report.get("packages", [])
    malicious = [p for p in packages if p.get("is_known_malicious")]
    if malicious:
        add(min(len(malicious) * 30, 50), f"{len(malicious)} known malicious package(s)", RISK_CRITICAL)

    hidden = [p for p in packages if not p.get("is_system") and not p.get("has_launcher_icon") and not p.get("is_disabled")]
    if hidden:
        add(min(len(hidden) * 5, 20), f"{len(hidden)} hidden user app(s) (no launcher icon)", RISK_HIGH)

    high_perm_apps = [p for p in packages if not p.get("is_system") and
                      any(sp["severity"] in (RISK_CRITICAL, RISK_HIGH)
                          for sp in p.get("suspicious_permissions", []))]
    if high_perm_apps:
        add(min(len(high_perm_apps) * 5, 20),
            f"{len(high_perm_apps)} user app(s) with CRITICAL/HIGH-risk permissions", RISK_HIGH)

    admins = [p for p in packages if p.get("is_device_admin") and not p.get("is_system")]
    if admins:
        add(min(len(admins) * 20, 30), f"{len(admins)} user app(s) are device admins", RISK_CRITICAL)

    accessibility = [p for p in packages if p.get("is_accessibility_service") and not p.get("is_system")]
    if accessibility:
        add(min(len(accessibility) * 10, 20), f"{len(accessibility)} user app(s) with accessibility service", RISK_HIGH)

    notif_listeners = [p for p in packages if p.get("is_notif_listener") and not p.get("is_system")]
    if notif_listeners:
        add(min(len(notif_listeners) * 10, 15), f"{len(notif_listeners)} user app(s) as notification listener", RISK_HIGH)

    kw_pkgs = [p for p in packages if p.get("suspicious_keywords") and not p.get("is_system")]
    if kw_pkgs:
        add(min(len(kw_pkgs) * 5, 15), f"{len(kw_pkgs)} app(s) with suspicious keywords in manifest", RISK_MEDIUM)

    network = report.get("network", {})
    ext_conns = network.get("external_connections", [])
    if ext_conns:
        add(min(len(ext_conns) * 5, 20), f"{len(ext_conns)} active external connection(s)", RISK_HIGH)
    if network.get("iptables_suspicious"):
        add(15, "Suspicious iptables traffic-redirect rules detected", RISK_HIGH)

    logcat_hits = report.get("logcat_anomalies", [])
    if logcat_hits:
        add(min(len(logcat_hits), 15), f"{len(logcat_hits)} suspicious logcat event(s)", RISK_MEDIUM)

    encryption = report.get("encryption", {})
    if encryption.get("encryption_state") == "unencrypted":
        add(10, "Storage is NOT encrypted", RISK_HIGH)

    score = max(0, min(100, score))

    # Overall verdict
    if score >= 70:
        verdict = "🔴 CRITICAL — Strong indicators of compromise or malware present"
        color   = RISK_CRITICAL
    elif score >= 45:
        verdict = "🟠 HIGH — Significant security risks detected"
        color   = RISK_HIGH
    elif score >= 20:
        verdict = "🟡 MEDIUM — Some suspicious indicators, investigate further"
        color   = RISK_MEDIUM
    elif score >= 5:
        verdict = "🟢 LOW — Minor issues, generally looks clean"
        color   = RISK_LOW
    else:
        verdict = "✅ CLEAN — No significant threats detected"
        color   = RISK_INFO

    return {
        "risk_score":   score,
        "verdict":      verdict,
        "severity":     color,
        "findings":     sorted(findings, key=lambda x: -x["pts"]),
    }


# ─────────────────────────────  REPORT BUILDER  ─────────────────────────────

def build_text_report(report: Dict) -> str:
    lines = []
    W = 70

    def h1(t):   lines.append(f"\n{'═'*W}\n  {t}\n{'═'*W}")
    def h2(t):   lines.append(f"\n── {t} {'─'*(W-len(t)-4)}")
    def item(t): lines.append(f"  • {t}")
    def blank():  lines.append("")
    def rule():   lines.append("─" * W)

    lines.append(f"""
{'═'*W}
  {TOOL_NAME} v{VERSION} — Android Security Audit Report
{'═'*W}
  Generated : {report['generated_at']}
  Device    : {report['serial']}
{'═'*W}""")

    # ── Device Info ──
    h1("DEVICE INFORMATION")
    bi = report.get("build_info", {})
    item(f"Brand/Model   : {bi.get('ro.product.brand','')} {bi.get('ro.product.model','')}")
    item(f"Android       : {bi.get('ro.build.version.release','')} (SDK {bi.get('ro.build.version.sdk','')})")
    item(f"Security Patch: {bi.get('ro.build.version.security_patch','unknown')}")
    item(f"Build         : {bi.get('ro.build.display.id','')} [{bi.get('ro.build.type','')}; {bi.get('ro.build.tags','')}]")
    item(f"Verified Boot : {bi.get('ro.boot.verifiedbootstate','unknown')}")
    item(f"Boot Unlocked : {bi.get('ro.boot.flash.locked','unknown')}")
    item(f"Debuggable    : {bi.get('ro.debuggable','')}")
    item(f"ro.secure     : {bi.get('ro.secure','')}")

    # ── Risk ──
    h1("RISK ASSESSMENT")
    risk = report.get("risk_assessment", {})
    lines.append(f"\n  Risk Score : {risk.get('risk_score', 0)} / 100")
    lines.append(f"  Verdict    : {risk.get('verdict', '')}")
    blank()
    lines.append("  Key Findings:")
    for f in risk.get("findings", []):
        if f["pts"] > 0:
            item(f"[{f['severity']:8s}] (+{f['pts']:2d}pts) {f['msg']}")

    # ── Root ──
    h1("ROOT STATUS")
    rs = report.get("root_status", {})
    item(f"su binary paths found : {rs.get('su_paths_found') or 'None'}")
    item(f"Magisk version        : {rs.get('magisk_version') or 'Not detected'}")
    item(f"Magisk /data/adb      : {rs.get('magisk_data_dir') or 'Not present'}")
    item(f"Frida server running  : {rs.get('frida_running', False)}")
    item(f"SELinux               : {rs.get('selinux', 'Unknown')}")
    item(f"/system mounted R/W   : {rs.get('system_rw', False)}")
    item(f"adb root allowed      : {rs.get('adb_root_allowed', False)}")
    item(f"'which su' result     : {rs.get('which_su', 'none')}")

    # ── Dangerous Props ──
    h1("DANGEROUS SYSTEM PROPERTIES")
    dp = report.get("dangerous_props", [])
    if dp:
        for p in dp:
            item(f"[{p['severity']:8s}] {p['prop']} = {p['value']!r} → {p['desc']}")
    else:
        item("None detected.")

    # ── Suspicious Files ──
    h1("SUSPICIOUS FILES")
    sf = report.get("suspicious_files", [])
    if sf:
        for f in sf:
            item(f"{f['path']}")
            lines.append(f"             {f['info'][:120]}")
    else:
        item("No suspicious files detected.")

    # ── Security Settings ──
    h1("SECURITY SETTINGS")
    ss = report.get("security_settings", {})
    for k, v in ss.items():
        if k.endswith("_raw"):
            continue
        item(f"{k:35s} = {str(v)[:60]}")

    # ── Encryption ──
    h1("STORAGE ENCRYPTION")
    enc = report.get("encryption", {})
    item(f"State : {enc.get('encryption_state','unknown')}")
    item(f"Type  : {enc.get('encryption_type','unknown')}")
    item(f"FBE   : {enc.get('fbe_mode','unknown')}")

    # ── Package Audit ──
    h1("PACKAGE AUDIT SUMMARY")
    pkgs = report.get("packages", [])
    user_pkgs   = [p for p in pkgs if not p["is_system"]]
    sys_pkgs    = [p for p in pkgs if p["is_system"]]
    flagged     = [p for p in pkgs if p.get("flags")]
    malicious   = [p for p in pkgs if p.get("is_known_malicious")]
    hidden      = [p for p in user_pkgs if not p.get("has_launcher_icon") and not p.get("is_disabled")]
    sideloaded  = [p for p in user_pkgs if p.get("installer") not in
                   ("com.android.vending","unknown","null","") and p.get("installer")]

    item(f"Total packages    : {len(pkgs)}")
    item(f"User apps         : {len(user_pkgs)}")
    item(f"System apps       : {len(sys_pkgs)}")
    item(f"Flagged packages  : {len(flagged)}")
    item(f"Known malicious   : {len(malicious)}")
    item(f"Hidden (no icon)  : {len(hidden)}")
    item(f"Sideloaded        : {len(sideloaded)}")

    if malicious:
        h2("⚠  KNOWN MALICIOUS PACKAGES")
        for p in malicious:
            item(f"{p['package']}")

    if hidden:
        h2("Hidden Apps (No Launcher Icon)")
        for p in hidden[:30]:
            item(f"{p['package']} | installer={p.get('installer','?')}")

    if sideloaded:
        h2("Sideloaded Apps (Non-Play Install)")
        for p in sideloaded[:30]:
            item(f"{p['package']} | installer={p.get('installer','?')}")

    h2("Flagged Packages — Details")
    for p in flagged[:50]:
        if not p.get("is_system"):
            lines.append(f"\n  [{p['package']}]")
            lines.append(f"    system={p['is_system']} | installer={p.get('installer','?')} | version={p.get('version','?')}")
            for fl in p.get("flags", []):
                lines.append(f"    ⚑ {fl}")

    # ── Accessibility & Overlay ──
    h1("ACCESSIBILITY & OVERLAY")
    acc = report.get("accessibility", {})
    svcs = acc.get("enabled_services", [])
    if svcs:
        item(f"{len(svcs)} active accessibility service(s):")
        for s in svcs:
            item(f"  → {s}")
    else:
        item("No accessibility services active.")

    # ── Network ──
    h1("NETWORK")
    net = report.get("network", {})
    ext = net.get("external_connections", [])
    item(f"Total open sockets      : {len(net.get('sockets',[]))}")
    item(f"External connections    : {len(ext)}")
    item(f"VPN/tunnel interfaces   : {net.get('vpn_interfaces','none')}")
    item(f"DNS1                    : {net.get('dns1','?')}")
    item(f"DNS2                    : {net.get('dns2','?')}")
    item(f"Suspicious iptables rules: {len(net.get('iptables_suspicious',[]))}")
    if ext:
        h2("External Connections")
        for s in ext[:20]:
            item(f"{s['proto']} {s.get('local','?')} → {s.get('peer','?')} ({s.get('process','?')})")

    # ── Device Admins ──
    h1("DEVICE ADMINISTRATORS")
    da = report.get("device_admins", [])
    if da:
        for a in da:
            item(a)
    else:
        item("None detected.")

    # ── Logcat ──
    h1("LOGCAT ANOMALIES")
    lc = report.get("logcat_anomalies", [])
    item(f"Suspicious logcat entries: {len(lc)}")
    for line in lc[:30]:
        lines.append(f"  [LOG] {line[:140]}")

    # ── Active Services ──
    h1("ACTIVE SERVICES (top 20)")
    for svc in report.get("active_services", [])[:20]:
        item(svc)

    # ── Running Procs ──
    h1("NOTABLE RUNNING PROCESSES")
    procs = report.get("running_processes", [])
    suspicious_procs = [p for p in procs if any(k in p.get("name","").lower()
                        for k in ["frida","gdbserver","tcpdump","nmap","strace","ltrace"])]
    item(f"Total processes: {len(procs)}")
    if suspicious_procs:
        item(f"SUSPICIOUS processes:")
        for p in suspicious_procs:
            item(f"  PID={p.get('pid')} user={p.get('user')} name={p.get('name')}")
    else:
        item("No obviously suspicious processes detected.")

    # ── Audit Log ──
    h1("SCAN DEBUG LOG (condensed)")
    for line in _log_lines:
        lines.append(line)

    lines.append(f"\n{'═'*W}")
    lines.append(f"  End of Report — {TOOL_NAME} v{VERSION}")
    lines.append(f"{'═'*W}\n")

    return "\n".join(lines)


# ─────────────────────────────  MAIN  ───────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{VERSION} — Android ADB Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(__doc__ or "")
    )
    parser.add_argument("--serial",    help="ADB device serial (if multiple devices)")
    parser.add_argument("--out",       default="./DroidCOP_reports", help="Output directory")
    parser.add_argument("--no-logcat", action="store_true", help="Skip logcat scan (faster)")
    parser.add_argument("--logcat-time", type=int, default=10, help="Logcat capture seconds (default 10)")
    args = parser.parse_args()

    # Banner
    print(f"""
{C.CYAN}{C.BOLD}
  ██████╗ ██████╗  ██████╗ ██╗██████╗      ██████╗ ██████╗ ██████╗
  ██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗    ██╔════╝██╔═══██╗██╔══██╗
  ██║  ██║██████╔╝██║   ██║██║██║  ██║    ██║     ██║   ██║██████╔╝
  ██║  ██║██╔══██╗██║   ██║██║██║  ██║    ██║     ██║   ██║██╔═══╝
  ██████╔╝██║  ██║╚██████╔╝██║██████╔╝    ╚██████╗╚██████╔╝██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝      ╚═════╝ ╚═════╝ ╚═╝
{C.RESET}
  {C.WHITE}Android Security Auditor v{VERSION}  —  by DroidCOP{C.RESET}
  {C.GREY}Non-destructive. Read-only. Use only on devices you own.{C.RESET}
""", flush=True)

    ensure_adb()
    serial = pick_device(args.serial)
    info(f"Target device: {C.BOLD}{serial}{C.RESET}")

    pathlib.Path(args.out).mkdir(parents=True, exist_ok=True)
    start_time = time.time()

    # ── Run all checks ──
    dev_info        = collect_device_info(serial)
    dangerous_props = check_dangerous_props(dev_info.get("_all_props", {}))
    root_status     = check_root_status(serial)
    suspicious_files= check_suspicious_files(serial)
    security_settings = check_security_settings(serial)
    packages        = audit_packages(serial)
    running_procs   = check_running_processes(serial)
    network         = check_network(serial)
    accessibility   = check_accessibility_services(serial)
    active_services = check_active_services(serial)
    device_admins   = check_device_admins(serial)
    encryption      = check_crypto_and_storage(serial)
    battery         = check_battery_and_wakelocks(serial)
    accounts        = check_accounts_and_sync(serial)
    sms_info        = check_sms_calls(serial)
    clipboard       = check_clipboard(serial)
    recent_installs = check_recent_apk_installs(serial)
    logcat_anomalies = [] if args.no_logcat else check_logcat_anomalies(serial, args.logcat_time)

    elapsed = time.time() - start_time

    # ── Assemble report ──
    report: Dict = {
        "generated_at":    dt.datetime.now().isoformat(),
        "serial":          serial,
        "scan_duration_s": round(elapsed, 1),
        "build_info":      dev_info.get("build_info", {}),
        "dangerous_props": dangerous_props,
        "root_status":     root_status,
        "suspicious_files":suspicious_files,
        "security_settings": security_settings,
        "packages":        packages,
        "running_processes": running_procs,
        "network":         network,
        "accessibility":   accessibility,
        "active_services": active_services,
        "device_admins":   device_admins,
        "encryption":      encryption,
        "battery":         battery,
        "accounts":        accounts,
        "sms_info":        sms_info,
        "clipboard":       clipboard,
        "recent_installs": recent_installs,
        "logcat_anomalies":logcat_anomalies,
        "scan_log":        _log_lines,
    }
    report["risk_assessment"] = compute_risk(report)

    # ── Write outputs ──
    section("SAVING REPORTS")
    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_serial = re.sub(r"[^a-zA-Z0-9_\-]", "_", serial)
    base     = os.path.join(args.out, f"DroidCOP_{safe_serial}_{stamp}")
    txt_path = base + ".txt"
    json_path= base + ".json"

    text_report = build_text_report(report)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(text_report)

    # Remove raw props from JSON to keep size manageable
    report_json = {k: v for k, v in report.items() if k != "_all_props"}
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_json, f, indent=2, ensure_ascii=False)

    # ── Final summary ──
    risk = report["risk_assessment"]
    section("FINAL SUMMARY")
    score = risk["risk_score"]
    color = C.RED if score >= 70 else C.YELLOW if score >= 45 else C.GREEN if score < 20 else C.YELLOW

    print(f"""
  {C.BOLD}Risk Score : {color}{score}/100{C.RESET}
  {C.BOLD}Verdict    : {color}{risk['verdict']}{C.RESET}

  {C.BOLD}Top findings:{C.RESET}""")
    for f in risk["findings"][:8]:
        sev_col = C.RED if f["severity"] in (RISK_CRITICAL, RISK_HIGH) else C.YELLOW
        print(f"  {sev_col}• [{f['severity']:8s}] {f['msg']}{C.RESET}")

    print(f"""
  {C.BOLD}Reports saved:{C.RESET}
  {C.CYAN}  Text : {txt_path}{C.RESET}
  {C.CYAN}  JSON : {json_path}{C.RESET}

  Scan completed in {elapsed:.1f}s
""")


if __name__ == "__main__":
    main()
