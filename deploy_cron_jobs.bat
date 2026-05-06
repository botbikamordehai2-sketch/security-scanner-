@echo off
REM ──────────────────────────────────────────────────────
REM  Cloud Scheduler Deployment — Daily Intelligence Jobs
REM  Runs tech_pulse (market research) + data_hunter (commodities)
REM  Schedule: Every weekday at 08:00 Jerusalem time (05:00 UTC)
REM ──────────────────────────────────────────────────────

echo ============================================
echo  Deploying Cloud Scheduler Jobs
echo  Agentic Platform — Daily Intelligence
echo ============================================
echo.

REM ── Check gcloud ──
where gcloud >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] gcloud CLI not found. Install: https://cloud.google.com/sdk/docs/install
    exit /b 1
)

REM ── Get PROJECT_ID ──
for /f "tokens=*" %%i in ('gcloud config get-value project 2^>nul') do set PROJECT_ID=%%i
if "%PROJECT_ID%"=="" (
    echo [ERROR] No GCP project set. Run: gcloud config set project YOUR_PROJECT_ID
    exit /b 1
)
echo Project: %PROJECT_ID%
echo.

REM ── Service accounts ──
set SA_EMAIL=cloud-scheduler@%PROJECT_ID%.iam.gserviceaccount.com

REM ────────────────────────────────────────────────
REM  1. Tech Pulse Agent — Daily Market Research
REM ────────────────────────────────────────────────
echo [1/4] Creating Cloud Scheduler job: tech-pulse-daily...
gcloud scheduler jobs create http tech-pulse-daily ^
    --schedule="0 5 * * 1-5" ^
    --time-zone="Asia/Jerusalem" ^
    --uri="https://tech-pulse-xxxxx-uc.a.run.app/run" ^
    --http-method="GET" ^
    --oidc-service-account-email="%SA_EMAIL%" ^
    --oidc-token-audience="https://tech-pulse-xxxxx-uc.a.run.app/run" ^
    --attempt-deadline="600s" ^
    --description="Daily tech research: GitHub, ArXiv, Medium innovations — summarized by DeepSeek" ^
    2>nul

if %ERRORLEVEL% EQU 0 (
    echo   ✅ tech-pulse-daily created
) else (
    echo   ⚠️  tech-pulse-daily already exists or needs updating
    echo   Updating existing job...
    gcloud scheduler jobs update http tech-pulse-daily ^
        --schedule="0 5 * * 1-5" ^
        --time-zone="Asia/Jerusalem" ^
        --uri="https://tech-pulse-xxxxx-uc.a.run.app/run" ^
        --http-method="GET" ^
        --oidc-service-account-email="%SA_EMAIL%" ^
        --oidc-token-audience="https://tech-pulse-xxxxx-uc.a.run.app/run" ^
        --attempt-deadline="600s" ^
        2>nul
)
echo.

REM ────────────────────────────────────────────────
REM  2. Data Hunter Agent — Daily Commodity Prices
REM ────────────────────────────────────────────────
echo [2/4] Creating Cloud Scheduler job: data-hunter-daily...
gcloud scheduler jobs create http data-hunter-daily ^
    --schedule="30 5 * * 1-5" ^
    --time-zone="Asia/Jerusalem" ^
    --uri="https://data-hunter-xxxxx-uc.a.run.app/run" ^
    --http-method="GET" ^
    --oidc-service-account-email="%SA_EMAIL%" ^
    --oidc-token-audience="https://data-hunter-xxxxx-uc.a.run.app/run" ^
    --attempt-deadline="600s" ^
    --description="Daily commodity prices: Gold, Silver, Oil, DXY — summarized by DeepSeek" ^
    2>nul

if %ERRORLEVEL% EQU 0 (
    echo   ✅ data-hunter-daily created
) else (
    echo   ⚠️  data-hunter-daily already exists or needs updating
    echo   Updating existing job...
    gcloud scheduler jobs update http data-hunter-daily ^
        --schedule="30 5 * * 1-5" ^
        --time-zone="Asia/Jerusalem" ^
        --uri="https://data-hunter-xxxxx-uc.a.run.app/run" ^
        --http-method="GET" ^
        --oidc-service-account-email="%SA_EMAIL%" ^
        --oidc-token-audience="https://data-hunter-xxxxx-uc.a.run.app/run" ^
        --attempt-deadline="600s" ^
        2>nul
)
echo.

REM ────────────────────────────────────────────────
REM  3. Data Hunter — Midday Price Update
REM ────────────────────────────────────────────────
echo [3/4] Creating Cloud Scheduler job: data-hunter-midday...
gcloud scheduler jobs create http data-hunter-midday ^
    --schedule="0 11 * * 1-5" ^
    --time-zone="Asia/Jerusalem" ^
    --uri="https://data-hunter-xxxxx-uc.a.run.app/run" ^
    --http-method="GET" ^
    --oidc-service-account-email="%SA_EMAIL%" ^
    --oidc-token-audience="https://data-hunter-xxxxx-uc.a.run.app/run" ^
    --attempt-deadline="600s" ^
    --description="Midday commodity price update — NY session overlap" ^
    2>nul

if %ERRORLEVEL% EQU 0 (
    echo   ✅ data-hunter-midday created
) else (
    echo   ⚠️  data-hunter-midday exists or needs updating
    gcloud scheduler jobs update http data-hunter-midday ^
        --schedule="0 11 * * 1-5" ^
        --time-zone="Asia/Jerusalem" ^
        --uri="https://data-hunter-xxxxx-uc.a.run.app/run" ^
        --http-method="GET" ^
        --oidc-service-account-email="%SA_EMAIL%" ^
        --oidc-token-audience="https://data-hunter-xxxxx-uc.a.run.app/run" ^
        --attempt-deadline="600s" ^
        2>nul
)
echo.

REM ────────────────────────────────────────────────
REM  4. List all jobs
REM ────────────────────────────────────────────────
echo [4/4] Current Cloud Scheduler jobs:
echo ----------------------------------------
gcloud scheduler jobs list --format="table(name, schedule, timeZone, state)"
echo.

echo ============================================
echo  Deployment complete!
echo.
echo  ⚠️  IMPORTANT: Update the URLs above!
echo     Replace xxxxx with actual Cloud Run service names.
echo.
echo  URLs to update:
echo     tech-pulse:   https://TECH_PULSE_SERVICE-xxxxx-uc.a.run.app/run
echo     data-hunter:  https://DATA_HUNTER_SERVICE-xxxxx-uc.a.run.app/run
echo.
echo  To trigger manually now:
echo     gcloud scheduler jobs run tech-pulse-daily
echo     gcloud scheduler jobs run data-hunter-daily
echo ============================================