# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Kiosk Launcher (Windows 11 Pro x64)
# Build on a Windows machine:  py -m PyInstaller --clean --noconfirm Kiosk_Launcher.spec

a = Analysis(
    ['Kiosk_Launcher.py'],
    pathex=[],
    binaries=[],
    datas=[],
    # win32timezone is loaded dynamically by pywin32 and is often missed
    hiddenimports=['win32timezone'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Kiosk_Launcher',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,                # UPX often triggers antivirus false-positives
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,            # kiosk: no console window (logs go to file only)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,           # embed UAC manifest -> Windows prompts for admin at launch
    icon=None,                # set to 'kiosk.ico' if you add an icon file
)
