@echo off
REM Backend (FastAPI) ve frontend (Vite) sunucularini ayri pencerelerde baslatir.
cd /d "%~dp0"
start "SIEM Backend" cmd /k "cd backend && .venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000"
start "SIEM Frontend" cmd /k "cd frontend && npm run dev"
timeout /t 4 >nul
start http://127.0.0.1:5173
