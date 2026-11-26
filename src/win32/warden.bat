@ECHO OFF
REM Run from bin\ so warden.exe is found whatever folder the shortcut starts in.
CD /D "%~dp0"
warden.exe %*
PAUSE
