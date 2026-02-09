@echo off
REM Run this AFTER fixing the bad filename on GitHub (see PULL_PUSH_INSTRUCTIONS.txt)
cd /d "%~dp0"
echo Pulling from origin main...
git pull --rebase origin main
if errorlevel 1 (
  echo Pull failed. Fix the bad file on GitHub first - see PULL_PUSH_INSTRUCTIONS.txt
  pause
  exit /b 1
)
echo Pushing to origin main...
git push origin main
if errorlevel 1 (
  echo Push failed.
  pause
  exit /b 1
)
echo Done.
pause
