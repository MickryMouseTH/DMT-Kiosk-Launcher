# วิธี Build Kiosk_Launcher.exe (Windows 11 Pro x64)

> ⚠️ PyInstaller **cross-compile ไม่ได้** — ต้อง build บนเครื่อง Windows เท่านั้น
> (build บน Mac/Linux จะได้ binary ของ OS นั้น ไม่ใช่ .exe)

## สิ่งที่ต้องมีบนเครื่อง build

1. **Windows 10/11 x64**
2. **Python 3.10 – 3.12 (64-bit)** จาก [python.org](https://www.python.org/downloads/)
   - ตอนติดตั้งให้ติ๊ก ✅ *"Add python.exe to PATH"*

## ขั้นตอน Build (ทางลัด)

1. Clone หรือ copy โปรเจกต์ทั้งโฟลเดอร์ไปที่เครื่อง Windows
2. **ดับเบิลคลิก `build.bat`** — สคริปต์จะติดตั้ง dependencies และ build ให้อัตโนมัติ
3. ได้ไฟล์ผลลัพธ์ที่ **`dist\Kiosk_Launcher.exe`** (ไฟล์เดียว ~15–25 MB)

### หรือ build เองด้วยมือ
```bat
py -m pip install -r requirements.txt
py -m PyInstaller --clean --noconfirm Kiosk_Launcher.spec
```

## ค่าที่ตั้งไว้ใน spec file

| ตัวเลือก | ค่า | เหตุผล |
|----------|-----|--------|
| onefile | ✅ | ไฟล์เดียว deploy ง่าย |
| `console=False` | ✅ | ไม่มีหน้าต่างดำโผล่บนจอคีออสค์ → **log ลงไฟล์เท่านั้น** (`Log_Console` ใน config ไม่มีผลใน exe) |
| `uac_admin=True` | ✅ | ฝัง UAC manifest — Windows เด้งขอสิทธิ์ Admin เองตอนเปิด ไม่ต้องพึ่ง self-elevation ในโค้ด |
| `upx=False` | ✅ | ลดโอกาส Antivirus มองเป็นไวรัส |
| `hiddenimports=['win32timezone']` | ✅ | pywin32 โหลด module นี้แบบ dynamic — PyInstaller มักหาไม่เจอเอง |

## การ Deploy บนเครื่องคีออสค์

1. copy `Kiosk_Launcher.exe` ไปวางในโฟลเดอร์ที่ต้องการ เช่น `C:\Kiosk\`
2. รันครั้งแรก → ไฟล์ `Kiosk_Launcher_config.json` ถูกสร้างข้าง ๆ exe
3. แก้ config:
   - `EXE_Path` → path เต็มของโปรแกรมเป้าหมาย
   - `EXIT_Password` → พิมพ์รหัสผ่าน **plaintext** (รันครั้งถัดไปจะถูกแปลงเป็น hash อัตโนมัติ)
4. รันอีกครั้ง → ตรวจว่า password ใน config กลายเป็น `pbkdf2_sha256$...` แล้ว
5. โฟลเดอร์ `logs\` จะถูกสร้างข้าง exe อัตโนมัติ

### ทดสอบก่อนใช้จริง (สำคัญ — กัน lockout)
- [ ] App เป้าหมายขึ้น fullscreen และถูกดึง focus กลับเมื่อสลับหนี
- [ ] Alt+F4, Ctrl+W, Alt+Tab, Alt+Esc, Ctrl+Esc, Ctrl+Shift+Esc, Win ถูกบล็อก
- [ ] พิมพ์งานปกติ + Numpad ใช้ได้
- [ ] `Ctrl+Alt+Q` → ใส่รหัส → ออกได้จริง / ปุ่ม Cancel กลับคีออสค์ได้

## ตั้งให้รันอัตโนมัติตอนเปิดเครื่อง (แนะนำ Task Scheduler)

```
Task Scheduler → Create Task
  General : ✅ Run with highest privileges (ข้าม UAC prompt)
  Trigger : At log on
  Action  : Start a program → C:\Kiosk\Kiosk_Launcher.exe
```

## ปัญหาที่อาจเจอ

| อาการ | สาเหตุ / วิธีแก้ |
|-------|------------------|
| SmartScreen เตือน "Windows protected your PC" | exe ไม่ได้ sign — กด *More info → Run anyway* หรือใช้ code-signing cert |
| Antivirus ลบ/กัก exe | เพิ่ม exclusion ให้โฟลเดอร์ `C:\Kiosk\` (อาการปกติของ PyInstaller onefile) |
| เปิดแล้วเงียบหาย ไม่มีอะไรขึ้น | ดู `logs\Kiosk_Launcher_2.1.log` ข้าง exe — ส่วนใหญ่คือ `EXE_Path` ผิด |
| `ModuleNotFoundError: win32timezone` | build โดยไม่ใช้ spec file — ให้ build ผ่าน `Kiosk_Launcher.spec` เสมอ |
