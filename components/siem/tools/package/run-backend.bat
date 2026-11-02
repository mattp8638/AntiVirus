@echo off
REM Run backend services using the packaged virtualenv.
SETLOCAL
if exist .venv\Scripts\python.exe (
  .venv\Scripts\python.exe backend\run_services.py %*
) else (
  echo Virtual environment not found. Run bootstrap.ps1 first:
  echo   powershell -ExecutionPolicy Bypass -File .\bootstrap.ps1
)
ENDLOCAL
