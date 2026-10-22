@echo off
setlocal
set "PYTHONUTF8=1"
set "PYTHONDONTWRITEBYTECODE=1"
rem Never let Python launcher/manager install a missing runtime automatically.
set "PYTHON_MANAGER_AUTOMATIC_INSTALL=false"
set "PYLAUNCHER_ALLOW_INSTALL="
set "repair_python="
set "repair_use_py="
if not exist "%~dp0codex_proxy_repair.py" goto missing
where py.exe >nul 2>nul
if errorlevel 1 goto find_python
py -3 -c "import sys;sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if errorlevel 1 goto find_python
set "repair_use_py=1"
goto run
:find_python
for /f "delims=" %%P in ('where python.exe 2^>nul') do call :select_python "%%P"
if defined repair_python goto run
if defined CODEX_PRIMARY_RUNTIME_PYTHON call :select_python "%CODEX_PRIMARY_RUNTIME_PYTHON%"
if defined repair_python goto run
call :select_python "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if defined repair_python goto run
for %%V in (315 314 313 312 311) do call :select_python "%LOCALAPPDATA%\Programs\Python\Python%%V\python.exe"
if defined repair_python goto run
echo Python 3.11 or newer was not found.
echo Install Python from https://www.python.org/downloads/windows/ and run again.
echo No proxy or Codex settings were changed.
set "repair_exit=2"
goto finish
:select_python
if defined repair_python exit /b 0
if not exist "%~1" exit /b 0
if /i "%~dp1"=="%LOCALAPPDATA%\Microsoft\WindowsApps\" exit /b 0
"%~1" -c "import sys;sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if not errorlevel 1 set "repair_python=%~1"
exit /b 0
:run
if defined repair_use_py goto run_launcher
"%repair_python%" "%~dp0codex_proxy_repair.py" %*
set "repair_exit=%errorlevel%"
goto finish
:run_launcher
py -3 "%~dp0codex_proxy_repair.py" %*
set "repair_exit=%errorlevel%"
goto finish
:missing
echo Please extract the entire Python ZIP before running this tool.
set "repair_exit=2"
:finish
echo.
if not defined CODEX_PROXY_REPAIR_NOPAUSE pause
exit /b %repair_exit%
