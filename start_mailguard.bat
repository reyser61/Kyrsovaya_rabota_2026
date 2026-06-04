@echo off
rem === MailGuard one-click launcher ===
rem Messages are in English on purpose: a .bat with Cyrillic text is parsed
rem unreliably by cmd.exe. Program output (analysis) is still shown in Russian.
chcp 65001 >nul
cd /d "%~dp0"
title MailGuard

rem Pick interpreter: prefer the Windows launcher "py", fall back to "python"
where py >nul 2>nul && (set "PY=py") || (set "PY=python")

echo ============================================================
echo    MailGuard - one-click launcher
echo ============================================================
echo.

echo [1/5] Installing dependencies (Flask, PyYAML)...
%PY% -m pip install -r requirements.txt
if errorlevel 1 (echo. & echo ERROR: dependency install failed. & pause & exit /b 1)

echo.
echo [2/5] Running unit tests...
%PY% -m unittest discover -s tests
if errorlevel 1 (echo. & echo ERROR: tests failed. & pause & exit /b 1)

echo.
echo [3/5] Generating sample data (logs + emails)...
%PY% tools\generate_sample_logs.py
if errorlevel 1 (echo. & echo ERROR: log generation failed. & pause & exit /b 1)
%PY% tools\generate_sample_emails.py
if errorlevel 1 (echo. & echo ERROR: email generation failed. & pause & exit /b 1)

echo.
echo [4/5] Analyzing logs and emails (saving to DB)...
%PY% run.py analyze --postfix data\sample_logs\postfix.log --dovecot data\sample_logs\dovecot.log --emails data\sample_emails --save
if errorlevel 1 (echo. & echo ERROR: analysis failed. & pause & exit /b 1)

echo.
echo [5/5] Starting web dashboard: http://127.0.0.1:5000
echo The browser will open automatically in a few seconds.
echo To stop the server: close this window or press Ctrl+C.
echo.

rem Open the browser after a short delay (once the server is up)
start "" /min powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 4; Start-Process 'http://127.0.0.1:5000'"

%PY% run.py web

echo.
echo Server stopped.
pause
