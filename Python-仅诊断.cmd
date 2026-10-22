@echo off
call "%~dp0run-python.cmd" --mode diagnose %*
exit /b %errorlevel%
