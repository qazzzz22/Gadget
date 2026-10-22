@echo off
call "%~dp0run-python.cmd" --mode repair %*
exit /b %errorlevel%
