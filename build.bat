@echo off
set PATH=%PATH%;%USERPROFILE%\.cargo\bin
cd /d C:\Claude\tools\bip\analyzebugger
call npx tauri build
