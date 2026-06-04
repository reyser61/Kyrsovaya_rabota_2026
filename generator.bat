@echo off
rem === MailGuard scenario generator (interactive menu) - ASCII-named twin ===
chcp 65001 >nul
cd /d "%~dp0"
where py >nul 2>nul && (set "PY=py") || (set "PY=python")
%PY% tools\make_case_menu.py
pause
