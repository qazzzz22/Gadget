@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0Fix-CodexNetwork.ps1" goto missing
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Fix-CodexNetwork.ps1" -Mode Repair %*
set "tool_exit=%errorlevel%"
echo.
pause
exit /b %tool_exit%
:missing
echo Please extract the entire ZIP before running this tool.
pause
exit /b 1
