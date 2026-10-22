@echo off
call "%~dp0run-python.cmd" --mode restore %*
exit /b %errorlevel%
