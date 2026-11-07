<div align="center">

<img src="assets/droidcop_banner.png" alt="DroidCOP" width="100%">

**`ANDROID FORENSICS & INCIDENT RESPONSE ENGINE`**

<br>

![Version](https://img.shields.io/badge/VERSION-2.0.0-00ff9d?style=for-the-badge&labelColor=0d1117)
![Python](https://img.shields.io/badge/PYTHON-3.8+-00c9ff?style=for-the-badge&logo=python&logoColor=white&labelColor=0d1117)
![ADB](https://img.shields.io/badge/ADB-NATIVE-ff3c5c?style=for-the-badge&logo=android&logoColor=white&labelColor=0d1117)
![Mode](https://img.shields.io/badge/MODE-READ--ONLY-00ff9d?style=for-the-badge&labelColor=0d1117)
![Modules](https://img.shields.io/badge/MODULES-15-ffb300?style=for-the-badge&labelColor=0d1117)

<br>

> *`// CONNECT. SCAN. EXTRACT. REPORT.`*
> 
> *`// NON-DESTRUCTIVE · FORENSIC-GRADE · ZERO WRITES TO TARGET`*

</div>

---

## ⬛ `[ MISSION BRIEFING ]`

**DroidCOP** is a comprehensive, non-destructive Android security audit tool built for **digital forensicators**, **incident responders**, and **mobile security engineers**.

Connect any Android device over ADB and deploy a **15-module scan engine** that rips out every Indicator of Compromise (IOC) needed to determine whether a device has been infiltrated, monitored, or weaponized — all without writing a single byte to the target.

Every scan produces:
- 🟩 A machine-readable **JSON report** for SIEM ingestion and evidence databases
- 🟦 A human-readable **text report** for analyst review and case documentation
- 🔴 An automated **0–100 Risk Score** with severity-ranked findings and a threat verdict

---

## ⬛ `[ SYSTEM REQUIREMENTS ]`

| Requirement | Details |
|---|---|
| 🐍 **Python** | `3.8` or later — zero external dependencies |
| 📡 **ADB** | Android Platform Tools in system `PATH` |
| 🔓 **USB Debugging** | Enabled on target device and host authorized |
| 🔌 **Connection** | USB or TCP/IP ADB connection |

```bash
# Verify ADB is reachable
adb devices

# Expected output for an authorized target:
# List of devices attached
# emulator-5554   device
```

> [!WARNING]
> If your device shows as `unauthorized`, tap **"Allow USB Debugging"** on the device screen, then re-run `adb devices`.

---

## ⬛ `[ DEPLOYMENT SEQUENCE ]`

```bash
# ── Clone the repository ──────────────────────────────────
git clone https://github.com/yourusername/DroidCOP.git
cd DroidCOP

# ── Auto-detect single connected device ───────────────────
python DroidCOP_v2.py

# ── Target a specific device serial ───────────────────────
python DroidCOP_v2.py --serial emulator-5554

# ── Custom output directory ───────────────────────────────
python DroidCOP_v2.py --out ./investigation_case_001

# ── Skip logcat (faster run) ──────────────────────────────
python DroidCOP_v2.py --no-logcat

# ── Extend logcat capture window (seconds) ────────────────
python DroidCOP_v2.py --logcat-time 30

# ── Full options ──────────────────────────────────────────
python DroidCOP_v2.py --help
```

---

## ⬛ `[ SCAN MODULES · 15 ACTIVE ]`

<details>
<summary><b>🔧 MODULE 01 — Device &amp; Build Intelligence</b></summary>

Collects brand, model, Android version, SDK level, security patch date, build type, verified boot state, hardware identifiers, timezone, and locale. Full `getprop` dump parsed and cross-referenced.

**Key properties checked:** `ro.build.display.id` · `ro.build.version.security_patch` · `ro.boot.verifiedbootstate` · `ro.boot.flash.locked` · `ro.debuggable` · `ro.secure`

</details>

<details>
<summary><b>⚠️ MODULE 02 — Dangerous System Properties</b></summary>

Cross-references live system properties against a threat-intel list of dangerous values known to indicate rooted, compromised, or development builds.

| Property | Dangerous Value | Severity |
|---|---|---|
| `service.adb.root` | `1` | 🔴 CRITICAL |
| `ro.debuggable` | `1` | 🔴 HIGH |
| `ro.secure` | `0` | 🔴 HIGH |
| `ro.build.tags` | `test-keys` | 🔴 HIGH |
| `ro.build.type` | `eng` | 🟡 MEDIUM |

</details>

<details>
<summary><b>🔓 MODULE 03 — Root &amp; Privilege Escalation</b></summary>

Hunts every known root indicator across the filesystem and runtime.

- `su` binary at `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/system/xbin/daemonsu`
- **Magisk** version detection via CLI + `/data/adb` directory
- **SELinux** enforcement mode — Permissive = critical finding
- `/system` partition mount state — R/W mount = deep compromise
- **Frida** instrumentation server in process list
- `adb root` acceptance (userdebug/eng build indicator)

</details>

<details>
<summary><b>📂 MODULE 04 — Suspicious Files &amp; Paths</b></summary>

Scans known threat actor drop locations and rootkit residue paths.

```
/system/bin/su              /system/xbin/su
/data/local/tmp/frida-server /data/local.prop
/system/app/Superuser.apk   /system/bin/daemonsu
/system/xbin/busybox        /system/bin/.ext
/dev/com.koushikdutta.superuser.daemon
```

Also scans for APKs in `/data/local/tmp`, `/sdcard`, `/cache` and hidden directories inside `/data`.

</details>

<details>
<summary><b>⚙️ MODULE 05 — Security Settings Audit</b></summary>

Pulls 20+ Android security settings and flags dangerous configurations.

| Setting | Flagged When |
|---|---|
| Unknown Sources (pre-Android 8) | Enabled |
| Package Verifier (Play Protect) | Disabled |
| Mock Location Provider | Active |
| Accessibility Services | Non-empty |
| Active Device Admins | Detected |
| ADB over Network | Enabled |
| Developer Options | Enabled |

</details>

<details>
<summary><b>📦 MODULE 06 — Full Package Audit (deepest module)</b></summary>

Every installed package is analyzed via `dumpsys package`. Cross-referenced against:

- **40+ known malicious/stalkerware package signatures**
- **50+ dangerous permission definitions** with per-permission severity
- Installer origin (Play Store vs sideloaded)
- Presence of accessibility service declaration
- Presence of device admin registration
- Notification listener service registration
- Hidden app detection (no LAUNCHER intent = invisible on home screen)
- Suspicious keyword scan over package manifest dump

</details>

<details>
<summary><b>⚡ MODULE 07 — Running Process Analysis</b></summary>

Full `ps -A` output analyzed for known attacker tools.

**Flagged processes:** `frida` · `gdbserver` · `tcpdump` · `nmap` · `netcat` · `nc` · `strace` · `ltrace` · `adbd` running as `root`

</details>

<details>
<summary><b>🌐 MODULE 08 — Network Connections &amp; Configuration</b></summary>

- Open sockets via `ss -tunap` / `netstat`
- Active **external connections** (non-loopback ESTABLISHED)
- VPN/tunnel interfaces (`tun`, `ppp` interfaces)
- DNS server configuration
- **iptables** REDIRECT / DNAT / SNAT / MASQUERADE rule detection
- Wi-Fi SSID/BSSID/IP

</details>

<details>
<summary><b>♿ MODULE 09 — Accessibility &amp; Overlay Services</b></summary>

Lists every active accessibility service and overlay window — the **primary vector** for Android keyloggers, screen-readers, and UI-hijacking malware (banking trojans, RATs).

</details>

<details>
<summary><b>📋 MODULE 10 — Logcat Anomaly Scan</b></summary>

16-pattern regex engine over live and buffered logcat output hunting for:

```
root grants · su access · Frida/Gadget · keyloggers · overlay draws
accessibility grants · device admin activation · silent APK installs
audio recording · location tracking · clipboard reads · camera access
screenshots · DEX class loading · dynamic reflection · data exfil
```

</details>

<details>
<summary><b>📱 MODULE 11 — SMS &amp; Call Log Indicators</b></summary>

Identifies the default SMS application and checks `gsm.call.forwarded` property — active call forwarding is a known spyware persistence mechanism.

</details>

<details>
<summary><b>🔋 MODULE 12 — Battery &amp; Wakelocks</b></summary>

Surfaces apps holding excessive wakelocks and top battery consumers — behavioral signatures of background stalkerware running continuous location tracking, audio recording, or data exfil loops.

</details>

<details>
<summary><b>🛡️ MODULE 13 — Device Administrator Enumeration</b></summary>

Enumerates all apps registered with Device Admin rights via `dumpsys device_policy`. Used by MDM software — and sophisticated malware — for persistence, remote wipe capability, and lock screen control.

</details>

<details>
<summary><b>🔐 MODULE 14 — Encryption &amp; Storage State</b></summary>

Checks `ro.crypto.state`, `ro.crypto.type`, and `ro.crypto.volume.filenames_mode`. Unencrypted storage is flagged **HIGH** — all data is physically readable without authentication.

</details>

<details>
<summary><b>📥 MODULE 15 — Recent APK Installation Timeline</b></summary>

Surfaces the most recently installed/updated user apps ordered by `firstInstallTime`. Critical for correlating compromise timestamps with known incident windows.

</details>

---

## ⬛ `[ IOC DETECTION COVERAGE ]`

| IOC Category | Severity | Indicators |
|---|:---:|---|
| Root / Privilege Escalation | 🔴 `CRITICAL` | su binary, Magisk, adbd as root, /system R/W |
| Dynamic Instrumentation | 🔴 `CRITICAL` | Frida server, gdbserver, strace |
| Known Malicious Packages | 🔴 `CRITICAL` | Stalkerware, RATs, spyware (40+ sigs) |
| Device Administrator Abuse | 🔴 `CRITICAL` | Non-system BIND_DEVICE_ADMIN |
| Keylogger-class Permissions | 🔴 `CRITICAL` | INJECT_EVENTS, READ_FRAME_BUFFER, CAPTURE_AUDIO_OUTPUT |
| SELinux Tampered | 🔴 `HIGH` | Permissive mode active |
| Microphone / Camera Abuse | 🔴 `HIGH` | RECORD_AUDIO, CAMERA on user apps |
| Background Location Tracking | 🔴 `HIGH` | ACCESS_BACKGROUND_LOCATION |
| Clipboard Interception | 🔴 `HIGH` | READ_CLIPBOARD permission |
| SMS / Call Interception | 🔴 `HIGH` | RECEIVE_SMS, READ_SMS, PROCESS_OUTGOING_CALLS |
| Accessibility Keylogger | 🔴 `HIGH` | Non-system AccessibilityService declared |
| Notification Scraping | 🔴 `HIGH` | NotificationListenerService on user apps |
| Hidden Applications | 🔴 `HIGH` | No LAUNCHER intent (invisible from home screen) |
| Traffic Redirection | 🔴 `HIGH` | iptables REDIRECT / DNAT rules |
| Play Protect Disabled | 🔴 `HIGH` | package_verifier_enable = 0 |
| Dangerous Build Properties | 🟡 `MEDIUM` | test-keys ROM, engineering build |
| Sideloaded Apps | 🟡 `MEDIUM` | Non-Play Store installer origin |
| Mock Location Active | 🟡 `MEDIUM` | GPS spoofing provider active |
| Developer Options On | 🟡 `MEDIUM` | development_settings_enabled = 1 |
| Excessive Wakelocks | 🟢 `LOW` | Background battery drain patterns |
| Unencrypted Storage | 🔴 `HIGH` | ro.crypto.state = unencrypted |

---

## ⬛ `[ RISK SCORING ENGINE ]`

DroidCOP computes a **0–100 composite risk score** from all weighted findings.

```
Score     Verdict
──────────────────────────────────────────────────────────
 0 – 4   ✅  CLEAN    — No significant threats detected
 5 – 19  🟢  LOW      — Minor issues, generally looks clean
20 – 44  🟡  MEDIUM   — Some suspicious indicators, investigate further
45 – 69  🟠  HIGH     — Significant security risks detected
70 – 100 🔴  CRITICAL — Strong indicators of compromise or malware present
```

**Sample terminal output:**

```
════════════════════════════════════════════════════════════════
  FINAL SUMMARY
════════════════════════════════════════════════════════════════

  Risk Score : 82/100
  Verdict    : 🔴 CRITICAL — Strong indicators of compromise or malware present

  Top findings:
  • [CRITICAL ] (+30pts) su binary found at: ['/system/xbin/su']
  • [CRITICAL ] (+30pts) Frida instrumentation server running
  • [CRITICAL ] (+30pts) 1 known malicious package(s)
  • [HIGH     ] (+20pts) SELinux is PERMISSIVE
  • [HIGH     ] (+15pts) Dangerous prop: service.adb.root=1
  • [HIGH     ] (+10pts) 2 user apps with CRITICAL/HIGH-risk permissions
  • [MEDIUM   ] ( +5pts) 3 suspicious logcat events

  Reports saved:
    Text : ./DroidCOP_reports/DroidCOP_emulator5554_20241215_143022.txt
    JSON : ./DroidCOP_reports/DroidCOP_emulator5554_20241215_143022.json

  Scan completed in 47.3s
```

---

## ⬛ `[ OUTPUT ARTIFACTS ]`

### 🟩 JSON Report — `DroidCOP_<serial>_<timestamp>.json`

Machine-readable structured output containing every raw finding, full permission tables, process lists, socket data, build properties, and the complete risk assessment. Ready for ingestion into SIEM platforms, evidence databases, or automated triage pipelines.

### 🟦 Text Report — `DroidCOP_<serial>_<timestamp>.txt`

Human-readable audit report with section headers, severity-tagged findings, full package audit tables, and the complete scan debug log. Designed for analyst review, case documentation, and incident reports.

---

## ⬛ `[ PERMISSION THREAT INTELLIGENCE ]`

DroidCOP tracks **50+ Android permissions** ranked by threat severity. Every installed package is cross-referenced at scan time.

```
CRITICAL ══════════════════════════════════════════════════════
  INJECT_EVENTS              → Can inject touch/key events (keylogger)
  READ_FRAME_BUFFER          → Can read screen framebuffer
  CAPTURE_AUDIO_OUTPUT       → Can capture system audio
  CAPTURE_VIDEO_OUTPUT       → Can capture screen video
  BIND_DEVICE_ADMIN          → Device Administrator — powerful control
  INSTALL_PACKAGES           → Can install packages (system-level)
  INTERNAL_SYSTEM_WINDOW     → Internal system window access

HIGH ══════════════════════════════════════════════════════════
  RECORD_AUDIO               → Can record microphone audio
  CAMERA                     → Can use camera
  ACCESS_BACKGROUND_LOCATION → Tracks location when backgrounded
  BIND_ACCESSIBILITY_SERVICE → Can read screen & input events
  READ_CLIPBOARD             → Can read clipboard contents
  RECEIVE_SMS / READ_SMS     → Can intercept SMS
  PROCESS_OUTGOING_CALLS     → Can intercept outgoing calls
  REQUEST_INSTALL_PACKAGES   → Can silently install APKs
  DELETE_PACKAGES            → Can silently uninstall apps
  SYSTEM_ALERT_WINDOW        → Draw overlay over other apps
  BIND_NOTIFICATION_LISTENER → Read all device notifications
  MANAGE_EXTERNAL_STORAGE    → Full filesystem access (Android 11+)
  HIDE_OVERLAY_WINDOWS       → Can hide overlays from user
  USE_CREDENTIALS            → Can use stored account credentials
```

---

## ⬛ `[ KNOWN MALWARE SIGNATURES ]`

DroidCOP maintains a package-name threat-intel list covering:

| Category | Examples |
|---|---|
| 🕵️ **Stalkerware / Spyware** | `com.hspy.pro` · `com.mspy.android` · `com.flexispy` · `com.spyera` · `com.highster.mobile` |
| 🤖 **RATs / Exploit Frameworks** | `org.metasploit` · `com.csploit.android` · `com.drozer.agent` |
| 🔧 **Root Tools** | `com.topjohnwu.magisk` · `eu.chainfire.supersu` · `com.kingroot.kinguser` |
| 🪝 **Hooking Frameworks** | `de.robv.android.xposed.installer` · `com.saurik.substrate` |
| 📢 **Adware** | `com.leadbolt.ad` · `com.startapp.android` |
| 👻 **Fake System Apps** | `com.android.system.manager` · `com.google.system.service` |

---

## ⬛ `[ LEGAL — AUTHORIZED USE ONLY ]`

> [!CAUTION]
> **DroidCOP is a forensic and incident response tool intended exclusively for use on devices you own or have received explicit written authorization to assess.**
>
> Unauthorized use against devices you do not own or lack written permission to audit may violate applicable laws including:
> - **Computer Fraud and Abuse Act (CFAA)** — United States
> - **Electronic Communications Privacy Act (ECPA)** — United States
> - **Computer Misuse Act** — United Kingdom
> - Equivalent legislation in your jurisdiction
>
> The authors and contributors accept **no liability** for misuse of this tool.
> DroidCOP performs **read-only, non-destructive operations only** — it does not modify, delete, or exfiltrate data from any target device.

**Intended users:** Security researchers · Mobile forensic analysts · Incident response professionals · Penetration testers operating under signed scope agreements · Device owners auditing their own hardware.

---

## ⬛ `[ CONTRIBUTING ]`

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Areas to contribute:
- 🧬 Expanding the malicious package signature database
- 🔑 Adding new dangerous permission definitions
- 📱 Android version-specific detection logic
- 📊 Report format improvements

---

<div align="center">

---

```
[ DroidCOP v2.0.0 ]  ·  Android ADB Security Auditor
NON-DESTRUCTIVE · READ-ONLY · FORENSIC-GRADE
```

![Made with Python](https://img.shields.io/badge/MADE%20WITH-PYTHON-00c9ff?style=for-the-badge&logo=python&logoColor=white&labelColor=0d1117)
![For IR](https://img.shields.io/badge/FOR-INCIDENT%20RESPONSE-ff3c5c?style=for-the-badge&labelColor=0d1117)
![Authorized Only](https://img.shields.io/badge/AUTHORIZED-USE%20ONLY-ffb300?style=for-the-badge&labelColor=0d1117)

</div>
