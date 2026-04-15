@echo off
echo Installing PyInstaller...
pip install pyinstaller

echo.
echo Building ipscaner.exe...
pyinstaller --onefile --name ipscaner --clean ip_scanner.py

echo.
if exist dist\ipscaner.exe (
    copy dist\ipscaner.exe ipscaner.exe
    echo Done! ipscaner.exe is ready.
) else (
    echo Build failed.
)
pause
