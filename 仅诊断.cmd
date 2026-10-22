@echo off
setlocal
cd /d "%~dp0"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Fix-CodexNetwork.ps1" -Mode Diagnose %*
set "tool_exit=%errorlevel%"
echo.
pause
exit /b %tool_exit%
