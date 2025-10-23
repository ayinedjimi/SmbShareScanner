@echo off
REM SmbShareScanner - Script de compilation
REM Ayi NEDJIMI Consultants - https://www.ayinedjimi-consultants.fr

echo Compilation de SmbShareScanner...
cl /EHsc /nologo /W4 /MD /O2 /DUNICODE /D_UNICODE SmbShareScanner.cpp /link netapi32.lib advapi32.lib comctl32.lib user32.lib gdi32.lib shell32.lib comdlg32.lib

if errorlevel 1 (
    echo Erreur de compilation!
    pause
    exit /b 1
)

echo Compilation reussie: SmbShareScanner.exe
pause
