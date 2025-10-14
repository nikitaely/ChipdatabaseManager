## # -*- mode: python -*-

block_cipher = None

a = Analysis(['main.py'],
             pathex=['/home/nik/projects/ChipdatabaseManager'],
             binaries=[],
             datas=[],
             hiddenimports=['psycopg2', 'tkinter', 'tkinter.ttk', 'tkinter.messagebox', 'tkinter.filedialog'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='ChipDatabaseManager',
          debug=False,
          strip=False,
          upx=False,
          runtime_tmpdir=None,
          console=False)


