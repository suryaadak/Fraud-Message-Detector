@echo off
title Phishing Detection Platform Launcher
echo ========================================================
echo   Starting Phishing Detection Platform...
echo ========================================================
echo.

cd /d "%~dp0"

echo [1] Checking for Microsoft Edge or Google Chrome...
if exist "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" (
    start "" "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" "%~dp0index.html"
    goto done
)

if exist "C:\Program Files\Google\Chrome\Application\chrome.exe" (
    start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" "%~dp0index.html"
    goto done
)

echo [2] Opening via default web browser...
start "" "%~dp0index.html"

:done
echo.
echo Platform successfully launched!
echo Enjoy testing and analyzing URLs!
echo.
pause
