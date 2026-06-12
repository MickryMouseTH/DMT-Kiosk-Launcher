# DMT Kiosk Launcher — Code Review & Documentation

> เอกสารตรวจสอบโค้ดและคู่มืออ้างอิง · เวอร์ชันโปรแกรม **2.0**
> ตรวจสอบเมื่อ: 2026-06-11 → 2026-06-12 · ไฟล์: `Kiosk_Launcher.py`, `LogLibrary.py`

---

## 1. ภาพรวม (Overview)

โปรแกรมนี้คือ **Kiosk Launcher บน Windows** สำหรับรันโปรแกรม `.exe` (Win32) ในโหมดคีออสค์ โดยมีหน้าที่หลัก:

1. **เรียกใช้ Admin (UAC)** อัตโนมัติเมื่อเริ่มโปรแกรม
2. **เปิดโปรแกรมเป้าหมาย** (target EXE) และทำให้เป็น **fullscreen + topmost**
3. **เฝ้ามอนิเตอร์** กระบวนการ หากปิด/แครชจะสตาร์ตใหม่อัตโนมัติ
4. **บล็อกคีย์ลัด** ที่ใช้หนีออกจากคีออสค์ (Alt+F4, Ctrl+W, Win, Ctrl+Esc ฯลฯ)
5. **ปุ่มฉุกเฉิน** (`Ctrl+Alt+Q`) เปิดหน้าจอใส่รหัสผ่านเพื่อออกจากคีออสค์อย่างปลอดภัย
6. **บังคับ NumLock เปิด** และอนุญาตปุ่ม Numpad เสมอ
7. **บันทึก Log** ผ่าน Loguru (หมุนไฟล์ตามขนาด + เก็บย้อนหลัง)

### Dependencies
`pywin32`, `psutil`, `keyboard`, `loguru`, `tkinter` (built-in)
*(ตัด `cryptography` ออกแล้ว — ระบบรหัสผ่านใหม่ใช้ `hashlib` stdlib, ดูข้อ 8)*

---

## 2. โครงสร้างการทำงาน (Flow)

```
__main__
  └─ resolve_exit_password_hash()    → plaintext ใน config? → hash + เขียนกลับ (ข้อ 8)
  └─ ensure_admin_and_elevate()      → ถ้าไม่ใช่ admin → ShellExecuteW("runas") → exit instance เดิม
  └─ ensure_numlock_on()
  └─ thread: monitor_loop() (daemon)
        ├─ block_hotkeys_when_target_active()   → hard-block Win keys + keyboard hook (suppress=True)
        ├─ emergency_stop_listener()            → ลงทะเบียน hotkey Ctrl+Alt+Q (ครั้งเดียว)
        └─ while _running:
              ├─ ถ้า _monitor_paused → sleep แล้วข้าม
              ├─ ถ้า target ตาย/ยังไม่เปิด → start_target() → find_hwnd_by_pid() → make_window_fullscreen()
              ├─ ถ้า target ยังอยู่ → ตรวจ foreground → ดึง topmost/focus กลับมา
              └─ ตรวจ liveness → restart ถ้าจำเป็น
  └─ main thread: while _running: รอ _emergency_request (Event, timeout 1s)
        └─ ถูก set → handle_emergency()   ← Tk dialog รันบน MAIN thread เสมอ
```

### Flow ปุ่มฉุกเฉิน (event-driven, แก้ M4)
```
keyboard thread: กด Ctrl+Alt+Q → _emergency_request.set()   (แค่ส่งสัญญาณ)
main thread: handle_emergency()
  ├─ _dialog_open guard (กันเปิดซ้อน)
  ├─ _monitor_paused = True → ปลด topmost ของ target ชั่วคราว
  ├─ แสดง Tkinter fullscreen password dialog (mainloop, ปิดด้วย root.destroy())
  │     ├─ Submit/Enter → verify_password() กับ hash
  │     └─ Cancel/Esc  → ปิด dialog กลับสู่คีออสค์ (ไม่ต้องรู้รหัส)
  ├─ ตัดสินผลขณะยัง pause อยู่:
  │     ├─ รหัสถูก → _running = False (ก่อน unpause — กัน monitor restart แทรก)
  │     └─ รหัสผิด/ยกเลิก → คืน topmost ให้ target
  ├─ _monitor_paused = False
  └─ ถ้ารหัสถูก: restore style → terminate_target() → โปรแกรมจบ
```

---

## 3. คู่มือ Config (`Kiosk_Launcher_config.json`)

ไฟล์จะถูกสร้างอัตโนมัติด้วยค่า default ถ้ายังไม่มี

| Key | ค่า default | ความหมาย |
|-----|------------|----------|
| `EXE_Path` | `""` | **(บังคับ)** path เต็มของ EXE เป้าหมาย — ถ้าว่าง/ไม่พบไฟล์ โปรแกรมจะ `exit(1)` |
| `Restart_Delay` | `2` | หน่วงเวลา (วินาที) ก่อนสตาร์ตใหม่หลัง target ปิด |
| `EXIT_Password` | `""` | รหัสผ่านออกคีออสค์ — ใส่ plaintext ครั้งแรก แล้วระบบแปลงเป็น PBKDF2 hash อัตโนมัติ (ดูข้อ 8) |
| `Watch_Interval` | `1.0` | ความถี่ตรวจสอบ (วินาที) |
| `log_Level` | `"DEBUG"` | ระดับ log |
| `Log_Console` | `1` | `1` = แสดง log บน console |
| `log_Backup` | `90` | เก็บ log ย้อนหลัง (วัน) |
| `Log_Size` | `"100 MB"` | ขนาดไฟล์ก่อนหมุน |

---

## 4. คู่มือฟังก์ชัน (Function Reference)

### `Kiosk_Launcher.py`
| ฟังก์ชัน | หน้าที่ |
|----------|---------|
| `hash_password(plain)` | สร้าง salted PBKDF2 hash (`algo$iters$salt$hash`) |
| `verify_password(plain, stored)` | เทียบรหัสกับ hash แบบ constant-time |
| `resolve_exit_password_hash(cfg)` | ตรวจ config: plaintext → hash + เขียนกลับ, hash → ใช้เลย |
| `terminate_target(grace)` | ปิด target อย่างนุ่มนวล (WM_CLOSE) → terminate → kill tree |
| `ensure_numlock_on()` | บังคับ NumLock เปิด |
| `is_admin()` / `ensure_admin_and_elevate()` | ตรวจ/ขอสิทธิ์ Admin |
| `start_target()` | เปิด target EXE (Popen ถ้า admin) |
| `find_hwnd_by_pid(pid)` | หา top-level window ตัวแรกของ pid |
| `make_window_fullscreen(hwnd)` | borderless fullscreen + topmost |
| `restore_window_style(hwnd)` | คืน title bar/ขนาดหน้าต่าง |
| `block_hotkeys_when_target_active()` | hard-block ปุ่ม Win + keyboard hook (`suppress=True`) บล็อกคีย์ลัด |
| `show_fullscreen_password_dialog()` | Tk dialog รหัสผ่าน (main thread) — Submit/Cancel/Esc |
| `handle_emergency()` | จัดการ flow ฉุกเฉินทั้งหมดบน main thread |
| `emergency_stop_listener()` | ลงทะเบียน hotkey ฉุกเฉิน (set Event ให้ main thread) |
| `monitor_loop()` | ลูปเฝ้า/ดึง focus/restart |

### `LogLibrary.py`
| ฟังก์ชัน | หน้าที่ |
|----------|---------|
| `Load_Config(default, name)` | โหลด/สร้าง JSON config |
| `Save_Config(config, name)` | บันทึก config dict กลับลงไฟล์ JSON |
| `Loguru_Logging(config, name, version)` | ตั้งค่า logger (console + ไฟล์หมุน zip) |

---

## 5. 🐞 รายการ Bug และข้อควรระวัง

จัดเรียงตามความรุนแรง

### 🔴 ระดับสูง (High) — กระทบการทำงานหลัก / lockout

#### H1. Tkinter `mainloop()` อาจค้าง (hang) เพราะ destroy เฉพาะ Toplevel
`Kiosk_Launcher.py:489` `dialog.destroy()` แต่ `root` (บรรทัด 424) ถูก `withdraw()` ไว้และ **ไม่เคยถูก destroy/quit**
ใน Tkinter `root.mainloop()` (บรรทัด 507) จะคืนค่าเมื่อ **root** ถูกทำลายหรือเรียก `quit()` เท่านั้น — การทำลายแค่ Toplevel ลูกไม่ทำให้ mainloop จบ
→ เสี่ยงที่หลังใส่รหัสถูกต้องแล้ว `show_fullscreen_password_dialog()` ไม่ return → `on_emergency` ค้าง → ออกคีออสค์ไม่ได้
**แก้:** เปลี่ยนเป็น `root.destroy()` (หรือ `root.quit()`) แทน/เพิ่มหลัง `dialog.destroy()` และทำเช่นเดียวกันในกรณีอื่นที่ปิด dialog

#### H2. ลงทะเบียน hotkey ฉุกเฉินซ้ำซ้อน → dialog เด้งหลายชั้น
`emergency_stop_listener()` เรียก `keyboard.add_hotkey(EMERGENCY_HOTKEY, on_emergency)` ที่บรรทัด 560
แต่ภายใน `on_emergency` ก็เรียกซ้ำที่บรรทัด 532 ("Re-Add Hotkey") โดย **ไม่ได้ลบตัวเดิมก่อน**
Tkinter mainloop ไม่ได้ลบ hotkey ของ library `keyboard` → สมมติฐานในคอมเมนต์ผิด
→ หลังกดฉุกเฉินครั้งแรก จะมี handler 2 ตัว, ครั้งต่อไป 3 ตัว... กดทีเดียวเปิด dialog ซ้อนหลายอัน
**แก้:** ลบบรรทัด 532 ออก หรือใช้ `keyboard.remove_hotkey(...)` ก่อน add ใหม่

#### H3. ถอดรหัสรหัสผ่านล้มเหลว → ออกคีออสค์ไม่ได้ (lockout)
`KEY = b"9rs7UghTL.....X"` (บรรทัด 50) เป็น **placeholder ไม่ใช่ Fernet key ที่ถูกต้อง** (ต้องเป็น base64 32 ไบต์)
→ `decrypt_data` throw → `EXIT_PASSWORD = ""` (บรรทัด 76)
→ ในหน้า dialog ปุ่ม Submit ถูก disable เมื่อช่องว่าง (บรรทัด 478) จึงพิมพ์รหัสว่างไม่ได้ และรหัสที่พิมพ์ก็ไม่มีทางตรงกับ `""`
→ **ออกจากคีออสค์ผ่านรหัสผ่านไม่ได้เลย** ต้องใช้ KEY และ EXIT_Password ของจริงเสมอ
**แก้:** ใส่ KEY จริง + ตรวจสอบว่า decrypt สำเร็จก่อนรัน, ถ้า `EXIT_PASSWORD == ""` ควร log error ชัดเจนและพิจารณาไม่ให้สตาร์ต

### 🟠 ระดับกลาง (Medium)

#### M1. `PseudoProc.poll()` ตรรกะกลับด้าน (เส้นทาง non-admin)
`Kiosk_Launcher.py:232-237`
```python
return None if pr.is_running() and pr.status() == psutil.STATUS_ZOMBIE else 0
```
ความหมายของ `poll()`: คืน `None` = ยังรัน, คืนเลข = จบแล้ว
แต่โค้ดนี้คืน `None` (ยังรัน) เฉพาะตอนเป็น **zombie** เท่านั้น → process ปกติที่กำลังรันจะคืน `0` (เข้าใจว่าตายแล้ว)
→ monitor_loop จะ restart วนไม่หยุด
*หมายเหตุ:* คอมเมนต์ระบุว่าเส้นทางนี้ "theoretically unreachable" แต่ตรรกะยังผิดอยู่

#### M2. เส้นทาง non-admin ไม่ได้เซ็ต `_target_pid`
`start_target()` else-branch: `pid = _start_target_elevated_shell()` (บรรทัด 226) แต่ไม่เคยมี `_target_pid = pid`
→ `PseudoProc.poll()` อ้าง global `_target_pid` ที่ยังเป็น `None` → `psutil.Process(None)` error
(เกี่ยวข้องกับ M1, อยู่ในเส้นทางเดียวกัน)

#### M3. Race condition บนตัวแปร global ระหว่าง 2 thread
`_target_proc / _target_pid / _target_hwnd / _running / _monitor_paused` ถูกอ่าน-เขียนจากทั้ง **monitor thread** และ **keyboard hotkey thread** โดยไม่มี lock
→ เสี่ยง read หลัง set เป็น None เช่น `terminate_target` ทำงานพร้อม monitor_loop กำลังเช็ค hwnd
**แก้:** ใช้ `threading.Lock` ครอบส่วนที่แก้ไข state เหล่านี้

#### M4. Tkinter ถูกสร้างใน thread ที่ไม่ใช่ main thread
`on_emergency` (callback ของ library `keyboard`) รันใน thread ของ keyboard แล้วสร้าง `tk.Tk()` + `mainloop()`
Tkinter ออกแบบให้รันบน main thread — การสร้างใน thread อื่นทำงานได้บางครั้งแต่เปราะบาง อาจเกิด error/แครชแบบสุ่ม
**แก้:** ส่งสัญญาณไปให้ main thread เปิด dialog (เช่นผ่าน queue / event)

#### M5. รหัสผ่าน/คีย์ฝังไว้ใน source → การเข้ารหัสไม่ให้ความปลอดภัยจริง
`KEY` ฝังอยู่ในไฟล์ `.py` → ใครเห็น source ก็ถอดรหัส `EXIT_Password` ได้ทันที
การเข้ารหัสจึงเป็นเพียง obfuscation ไม่ใช่ security
**แก้:** เก็บ KEY แยก (env var / ไฟล์สิทธิ์จำกัด / DPAPI) และเทียบรหัสด้วย hash (เช่น `bcrypt`) แทน plaintext

### 🟡 ระดับต่ำ (Low) / ปรับปรุงคุณภาพ

- **L1.** `find_hwnd_by_pid` คืนหน้าต่าง visible อันแรก อาจได้ splash screen แทนหน้าต่างหลัก
- **L2.** `make_window_fullscreen` ใช้ `SM_CXSCREEN/CYSCREEN` = จอหลักเท่านั้น ไม่รองรับ multi-monitor
- **L3.** Ctrl+Esc ถูกบล็อกตลอด (ไม่เช็ค `active_ok`) ต่างจากคีย์อื่น — น่าจะตั้งใจ แต่ควรเขียนคอมเมนต์
- **L4.** `ensure_admin_and_elevate` ต่อ `sys.argv[1:]` ด้วย space โดยไม่ quote → argument ที่มีช่องว่าง/path จะเพี้ยน
- **L5.** เทียบรหัสผ่านด้วย `==` (ไม่ constant-time) — เปิดช่อง timing attack ตามทฤษฎี (ความเสี่ยงต่ำในบริบทคีออสค์)
- **L6.** `LogLibrary.py:40` `global script_dir` ที่ระดับ module เป็น no-op
- **L7.** docstring ใน `LogLibrary.py` แสดง signature `Load_Config(default, name, script_dir)` 3 args แต่ของจริงมี 2 — เอกสารไม่ตรง
- **L8.** `overrideredirect(True)` ทำให้ `WM_DELETE_WINDOW` / `disable_close` แทบไม่ทำงาน (ไม่มี title bar ให้ปิด)
- **L9.** ระหว่าง dialog เปิด (`_monitor_paused`) ปุ่ม Win ยังถูก `block_key` แบบ hard-block อยู่ (อยู่นอก hook) — น่าจะตั้งใจแต่ควรระบุ

---

## 6. สรุปสิ่งที่ควรแก้ก่อนใช้งานจริง (Priority)

1. ✅ **ใส่ `KEY` และ `EXIT_Password` ของจริง** ที่ถอดรหัสได้ (กัน lockout — H3)
2. ✅ **แก้ mainloop hang** → `root.destroy()` (H1)
3. ✅ **ลบการ add_hotkey ซ้ำ** ใน `on_emergency` (H2)
4. ⚠️ พิจารณา lock สำหรับ global state (M3) และย้าย Tkinter ไป main thread (M4)
5. ⚠️ ทบทวน/ลบเส้นทาง non-admin ที่ตรรกะผิด (M1, M2)

---

## 7. บันทึกการแก้ไข (Changelog — 2026-06-11)

แก้ไขบั๊กทั้งหมดในโค้ดแล้ว สรุปสิ่งที่เปลี่ยน:

| รหัส | สถานะ | สิ่งที่แก้ |
|------|-------|-----------|
| **H1** | ✅ แก้แล้ว | เพิ่ม `close_dialog()` ที่ cancel refocus job แล้วเรียก `root.destroy()` (แทน `dialog.destroy()`) เพื่อให้ `mainloop()` คืนค่าจริง — ไม่ค้างอีก |
| **H2** | ✅ แก้แล้ว | ลบการ `add_hotkey` ซ้ำ ลงทะเบียน hotkey ครั้งเดียว + เพิ่ม `_dialog_open` re-entrancy guard |
| **H3** | ✅ แก้แล้ว | เปลี่ยนเป็นระบบ hash (ดูข้อ 8) ตัดปัญหา decrypt fail/lockout จาก KEY ผิด · รหัสว่าง → log `critical` + dialog เตือน + `verify_password` ปฏิเสธ |
| **M5** | ✅ แก้แล้ว | ลบ Fernet + KEY ที่ฝังในซอร์ส → ใช้ PBKDF2 hash ทางเดียว ไม่ต้องเก็บ key (ดูข้อ 8) |
| **M1** | ✅ แก้แล้ว | `PseudoProc.poll()` คืน `None` ขณะรัน, คืน `0` เมื่อจบ (ตรรกะถูกต้อง) |
| **M2** | ✅ แก้แล้ว | เซ็ต `_target_pid = pid` ในเส้นทาง non-admin |
| **M3** | ✅ แก้แล้ว | เพิ่ม `_state_lock` (RLock) ครอบการแก้ไข `_target_proc/_pid/_hwnd` ใน `terminate_target`, `start_target`, monitor restart |
| **M4** | ✅ แก้แล้ว | ย้าย Tkinter ไปรันบน **main thread**: keyboard hotkey เพียง `set()` event, main loop เรียก `handle_emergency()` |
| **L4** | ✅ แก้แล้ว | ใช้ `subprocess.list2cmdline()` quote argument ตอน relaunch |
| **L6** | ✅ แก้แล้ว | ลบ `global script_dir` ที่เป็น no-op ใน `LogLibrary.py` |
| **L7** | ✅ แก้แล้ว | แก้ docstring `Load_Config/Loguru_Logging` ให้ตรง signature จริง |
| L1, L2, L3, L5, L8, L9 | ⏸️ คงไว้ | เป็นข้อจำกัดเชิงพฤติกรรม/ออกแบบ (multi-monitor, splash, timing) — ยังไม่แก้ ดูรายละเอียดข้อ 5 |

### สถาปัตยกรรมที่เปลี่ยน (สำคัญ)
- **Emergency exit ทำงานแบบ event-driven ข้าม thread:**
  `keyboard thread` (กด `Ctrl+Alt+Q`) → `_emergency_request.set()` → `main thread` รัน Tk dialog
  ทำให้ Tkinter ปลอดภัย (อยู่ main thread) และไม่มีปัญหา hotkey ซ้ำ
- ✅ ตรวจ syntax ผ่าน (`py_compile`) ทั้ง 2 ไฟล์ — *ยังไม่ได้ทดสอบรันจริงบน Windows เพราะต้องใช้ pywin32/keyboard*

---

## 8. ระบบรหัสผ่านใหม่ (ไม่ต้องใช้ KEY) — 2026-06-11

เปลี่ยนจาก **Fernet (เข้ารหัสย้อนกลับได้ + ต้องฝัง KEY)** → **PBKDF2-HMAC-SHA256 hash (ทางเดียว + ไม่ต้องมี key)**

### วิธีตั้งรหัสผ่าน (ง่ายมาก)
1. เปิดไฟล์ `Kiosk_Launcher_config.json`
2. ใส่รหัสผ่าน **แบบข้อความธรรมดา** ในช่อง `EXIT_Password` เช่น
   ```json
   "EXIT_Password": "MySecret123"
   ```
3. รันโปรแกรม 1 ครั้ง → โปรแกรมจะ **แปลงเป็น hash อัตโนมัติ** และเขียนทับ plaintext ในไฟล์ทันที
   ```json
   "EXIT_Password": "pbkdf2_sha256$200000$<salt>$<hash>"
   ```
   (plaintext จะไม่ถูกเก็บค้างในไฟล์อีก)

### ทำงานอย่างไร
| ฟังก์ชัน (ใน `Kiosk_Launcher.py`) | หน้าที่ |
|------|---------|
| `hash_password(plain)` | สร้าง salt สุ่ม + PBKDF2 (200,000 รอบ) → string รูปแบบ `algo$iters$salt$hash` |
| `verify_password(plain, stored)` | เทียบแบบ **constant-time** (`hmac.compare_digest`) — แก้ timing attack (L5) |
| `resolve_exit_password_hash(cfg)` | ตรวจว่าเป็น hash แล้วหรือยัง ถ้าเป็น plaintext → hash + `Save_Config()` เขียนกลับ |
| `Save_Config()` (`LogLibrary.py`) | บันทึก config dict กลับลงไฟล์ JSON |

### ข้อดี
- ✅ **ไม่มี KEY ฝังในซอร์สโค้ด** (แก้ M5) — ถึงมีซอร์สก็ถอดรหัสผ่านกลับไม่ได้
- ✅ salt สุ่มต่อรหัส — รหัสเดียวกันให้ hash ไม่ซ้ำ
- ✅ เทียบ constant-time (แก้ L5)
- ✅ ผู้ใช้แค่พิมพ์ plaintext ครั้งเดียว ไม่ต้องรันคำสั่งเข้ารหัสเอง

### ⚠️ สิ่งที่ผู้ใช้ต้องทำ (กัน lockout)
1. ใส่รหัสผ่าน plaintext ใน `EXIT_Password` แล้วรัน 1 ครั้งให้แปลงเป็น hash
2. ทดสอบ `Ctrl+Alt+Q` + ใส่รหัสให้ออกได้จริง **ก่อน** deploy

---

## 9. ผลตรวจสอบ Logic ครบถ้วน (Verification — 2026-06-12)

ไล่ตรวจ flow ทั้งโปรแกรม (startup → monitor → emergency → shutdown) เทียบกับเอกสาร พบและแก้เพิ่ม 4 จุด:

| รหัส | ระดับ | ปัญหา | การแก้ |
|------|-------|-------|--------|
| **V1** | 🔴 ร้ายแรง | `keyboard.hook(listener)` ไม่ใส่ `suppress=True` → ใน library `keyboard` ค่า return `False` มีผลบล็อกเฉพาะ blocking hook เท่านั้น → **Alt+F4 / Ctrl+W / Ctrl+Esc / Alt+Tab / Win+combo ไม่ถูกบล็อกจริงเลย** (เป็นมาตั้งแต่เวอร์ชันแรก — มีแค่ `block_key` ปุ่ม Win ที่ทำงาน) | ✅ เปลี่ยนเป็น `keyboard.hook(listener, suppress=True)` |
| **V2** | 🔴 สูง | Dialog รหัสผ่านปิดได้ทางเดียวคือใส่รหัสถูก — กด `Ctrl+Alt+Q` พลาด = หน้ารหัสผ่าน (fullscreen+topmost) ค้างทับคีออสค์ตลอด | ✅ เพิ่มปุ่ม **Cancel** + กด **Esc** ปิด dialog กลับสู่คีออสค์ได้ |
| **V3** | 🟠 กลาง | `handle_emergency` ปลด `_monitor_paused` ก่อนเซ็ต `_running=False` → monitor อาจตื่นมา **restart target แวบหนึ่ง** ระหว่าง shutdown | ✅ ตัดสินผลรหัส + เซ็ต `_running=False` **ก่อน** unpause (ใน try block) |
| **V4** | 🟡 ต่ำ | กด hotkey ระหว่าง dialog เปิด → Event ถูก set ค้าง → dialog เด้งซ้ำทันทีหลังปิด | ✅ `_emergency_request.clear()` หลัง `handle_emergency()` จบ |

### Cleanup เพิ่มเติม
- ลบ `from tkinter import simpledialog` (ไม่ได้ใช้)
- ลบ global `_altf4_handler` (ไม่ได้ใช้)
- อัปเดตเอกสารข้อ 1, 2, 4 ให้ตรงโค้ดปัจจุบัน (ตัด `cryptography`, flow ใหม่, ตารางฟังก์ชันใหม่)

### ส่วนที่ตรวจแล้ว "ถูกต้อง" (ไม่ต้องแก้)
- ✅ ระบบ plaintext → hash auto-migration: ทำงานก่อน elevation → relaunch ครั้งที่ 2 อ่านเป็น hash แล้ว ไม่ hash ซ้ำ
- ✅ การปิดโปรแกรม: `_running=False` → main loop จบ → monitor (daemon) ถูกเก็บ, `terminate_target` เรียกซ้ำได้ (idempotent, มี lock)
- ✅ `_dialog_open` guard + `if _running` ใน main loop กัน dialog ซ้อนครบทุกเส้นทาง
- ✅ Logging ครอบคลุมทุกเส้นทางสำคัญ: startup, elevation, start/restart target, fullscreen, ความพยายามใส่รหัสผิด (warning), emergency exit (warning), cleanup, done
- ⚠️ ยังเหลือข้อจำกัดเดิมที่ตั้งใจคงไว้: L1 (splash window), L2 (จอเดียว), L8/L9 (พฤติกรรม dialog) — ดูข้อ 5

> **สำคัญ:** V1 ทำให้ฟีเจอร์บล็อกคีย์ "เพิ่งทำงานจริงครั้งแรก" ในเวอร์ชันนี้ — ตอนทดสอบบน Windows ควรไล่ทดสอบทุกคีย์: Alt+F4, Ctrl+W, Ctrl+Esc, Alt+Tab, Win+D/E/X/R และ **ยืนยันว่า Ctrl+Alt+Q + รหัสผ่าน + ปุ่ม Cancel ยังใช้ได้** ก่อน deploy
