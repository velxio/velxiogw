# PyInstaller spec — one self-contained executable, no console window games:
# it IS a console app, the pairing code is printed there.
from PyInstaller.building.api import COLLECT, EXE, PYZ
from PyInstaller.building.build_main import Analysis

a = Analysis(
    ['entry.py'],
    pathex=[],
    hiddenimports=[],
    excludes=['tkinter', 'unittest', 'pydoc_data'],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas,
    name='velxiogw',
    console=True,
    upx=False,
)
