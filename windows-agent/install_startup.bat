@echo off
:: Run as Administrator
set AGENT_DIR=%~dp0
set STARTUP_KEY=HKCU\Software\Microsoft\Windows\CurrentVersion\Run
echo Installing Guardian Agent to startup...
reg add "%STARTUP_KEY%" /v "GuardianAgent" /t REG_SZ /d "pythonw \"%AGENT_DIR%guardian_agent.py\"" /f
echo Done. Guardian Agent will run silently on next login.
echo To remove: reg delete "%STARTUP_KEY%" /v "GuardianAgent" /f
pause