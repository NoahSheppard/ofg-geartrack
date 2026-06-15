@echo off
REM Kills any process listening on the ports used by the dev/prod stacks
REM (SAML IdP :3000, backend :3001, Vite dev server :5173).

setlocal enabledelayedexpansion

for %%p in (3000 3001 5173) do (
    set "found="
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr /r /c:":%%p[ 	].*LISTENING"') do (
        if not "!found_%%a!"=="1" (
            set "found_%%a=1"
            set "found=1"
            echo Killing process on port %%p ^(PID %%a^)
            taskkill /F /PID %%a >nul 2>&1
        )
    )
    if not defined found (
        echo Port %%p is free.
    )
)

endlocal
