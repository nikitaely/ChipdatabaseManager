#!/bin/bash

echo "Сборка Chip Database Manager..."

# Создаем директорию для сборки
mkdir -p build

# Копируем все исходные файлы
cp main.py build/
cp auth.py build/
cp database.py build/
cp file_manager.py build/
cp login_window.py build/
cp main_window.py build/

# Переходим в директорию сборки
cd build

# Создаем spec файл
cat > chip_app.spec << 'EOF'
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


EOF

# Запускаем сборку
pyinstaller --onefile --windowed chip_app.spec

echo "Сборка завершена!"
echo "Исполняемый файл: build/dist/ChipDatabaseManager"