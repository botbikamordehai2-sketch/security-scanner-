@echo off
REM ═══════════════════════════════════════════════════════
REM  🐝 SWARM DEPLOY — Full Agentic Platform Deployment
REM  Run AFTER billing is linked:
REM    gcloud beta billing projects link PROJECT_ID --billing-account=013B42-2E247D-2E9CDF
REM ═══════════════════════════════════════════════════════
setlocal enabledelayedexpansion

echo.
echo ╔════════════════════════════════════════════════════════╗
echo ║  🐝 Agentic Security Scanner — Full Swarm Deploy     ║
echo ║  Orchestrator + Security + Tech Pulse + Data Hunter  ║
echo ╚════════════════════════════════════════════════════════╝
echo.

REM ── Step 0: Verify prerequisites ──────────────────────
echo [0/8] Checking prerequisites...

where gcloud >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo   ❌ gcloud CLI not found. Install: https://cloud.google.com/sdk/docs/install
    exit /b 1
)

REM Get project
for /f "tokens=*" %%i in ('gcloud config get-value project 2^>nul') do set PROJECT_ID=%%i
if "%PROJECT_ID%"=="" (
    echo   ❌ No GCP project set. Run: gcloud config set project YOUR_PROJECT_ID
    exit /b 1
)
echo   ✅ gcloud found — Project: %PROJECT_ID%

REM Verify billing
echo   Checking billing status...
for /f "tokens=*" %%b in ('gcloud beta billing projects describe %PROJECT_ID% --format="value(billingEnabled)" 2^>nul') do set BILLING=%%b
if /i NOT "%BILLING%"=="True" (
    echo   ❌ Billing NOT enabled on project %PROJECT_ID%!
    echo   Run first:
    echo     gcloud beta billing projects link %PROJECT_ID% --billing-account=BILLING_ACCOUNT_ID
    echo   Then re-run this script.
    exit /b 1
)
echo   ✅ Billing is enabled
echo.

REM ── Step 1: Enable APIs ──────────────────────────────
echo [1/8] Enabling GCP APIs...
set APIS=run.googleapis.com pubsub.googleapis.com firestore.googleapis.com cloudscheduler.googleapis.com cloudbuild.googleapis.com eventarc.googleapis.com logging.googleapis.com

for %%a in (%APIS%) do (
    echo   Enabling %%a...
    gcloud services enable %%a --project=%PROJECT_ID% 2>nul
)
echo   ✅ All APIs enabled
echo.

REM ── Step 2: Create Pub/Sub Topics ─────────────────────
echo [2/8] Creating Pub/Sub topics...
gcloud pubsub topics create scan.requests --project=%PROJECT_ID% 2>nul
gcloud pubsub topics create scan.results --project=%PROJECT_ID% 2>nul
gcloud pubsub topics create scan.requests.dlq --project=%PROJECT_ID% 2>nul
echo   ✅ Pub/Sub topics ready
echo.

REM ── Step 3: Create Firestore Database ─────────────────
echo [3/8] Creating Firestore database...
gcloud firestore databases create --location=nam5 --project=%PROJECT_ID% 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo   ℹ️  Firestore may already exist — continuing
)
echo   ✅ Firestore ready
echo.

REM ── Step 4: Deploy Orchestrator (FastAPI :8000) ───────
echo [4/8] Deploying Orchestrator...
gcloud run deploy orchestrator ^
    --source=.\orchestrator\ ^
    --platform=managed ^
    --region=us-central1 ^
    --allow-unauthenticated ^
    --memory=512Mi ^
    --cpu=1 ^
    --timeout=300 ^
    --set-env-vars="PROJECT_ID=%PROJECT_ID%,DEEPSEEK_API_KEY=%DEEPSEEK_API_KEY%,TELEGRAM_BOT_TOKEN=%TELEGRAM_BOT_TOKEN%,TELEGRAM_CHAT_ID=%TELEGRAM_CHAT_ID%" ^
    --project=%PROJECT_ID%

if %ERRORLEVEL% NEQ 0 (
    echo   ⚠️  Orchestrator deploy had issues — check logs
) else (
    echo   ✅ Orchestrator deployed
)

REM Get Orchestrator URL
for /f "tokens=*" %%u in ('gcloud run services describe orchestrator --region=us-central1 --format="value(status.url)" --project=%PROJECT_ID% 2^>nul') do set ORCH_URL=%%u
echo   Orchestrator URL: %ORCH_URL%
echo.

REM ── Step 5: Deploy Security Agent ─────────────────────
echo [5/8] Deploying Security Agent...
gcloud run deploy security-agent ^
    --source=.\agents\security_agent\ ^
    --platform=managed ^
    --region=us-central1 ^
    --no-allow-unauthenticated ^
    --memory=256Mi ^
    --cpu=1 ^
    --timeout=120 ^
    --set-env-vars="PROJECT_ID=%PROJECT_ID%" ^
    --project=%PROJECT_ID%

if %ERRORLEVEL% NEQ 0 (
    echo   ⚠️  Security Agent deploy had issues — check logs
) else (
    echo   ✅ Security Agent deployed
)

REM Get Security Agent URL
for /f "tokens=*" %%u in ('gcloud run services describe security-agent --region=us-central1 --format="value(status.url)" --project=%PROJECT_ID% 2^>nul') do set SEC_URL=%%u
echo   Security Agent URL: !SEC_URL!
echo.

REM ── Step 6: Deploy Tech Pulse Agent ───────────────────
echo [6/8] Deploying Tech Pulse Agent...
gcloud run deploy tech-pulse ^
    --source=.\agents\tech_pulse\ ^
    --platform=managed ^
    --region=us-central1 ^
    --no-allow-unauthenticated ^
    --memory=256Mi ^
    --cpu=1 ^
    --timeout=600 ^
    --set-env-vars="PROJECT_ID=%PROJECT_ID%,DEEPSEEK_API_KEY=%DEEPSEEK_API_KEY%,GOOGLE_API_KEY=%GOOGLE_API_KEY%,SEARCH_ENGINE_CX=%SEARCH_ENGINE_CX%" ^
    --project=%PROJECT_ID%

if %ERRORLEVEL% NEQ 0 (
    echo   ⚠️  Tech Pulse deploy had issues — check logs
) else (
    echo   ✅ Tech Pulse Agent deployed
)

for /f "tokens=*" %%u in ('gcloud run services describe tech-pulse --region=us-central1 --format="value(status.url)" --project=%PROJECT_ID% 2^>nul') do set TP_URL=%%u
echo   Tech Pulse URL: !TP_URL!
echo.

REM ── Step 7: Deploy Data Hunter Agent ──────────────────
echo [7/8] Deploying Data Hunter Agent...
gcloud run deploy data-hunter ^
    --source=.\agents\data_hunter\ ^
    --platform=managed ^
    --region=us-central1 ^
    --no-allow-unauthenticated ^
    --memory=256Mi ^
    --cpu=1 ^
    --timeout=600 ^
    --set-env-vars="PROJECT_ID=%PROJECT_ID%,DEEPSEEK_API_KEY=%DEEPSEEK_API_KEY%,OIL_API_KEY=%OIL_API_KEY%,MARINETRAFFIC_API_KEY=%MARINETRAFFIC_API_KEY%" ^
    --project=%PROJECT_ID%

if %ERRORLEVEL% NEQ 0 (
    echo   ⚠️  Data Hunter deploy had issues — check logs
) else (
    echo   ✅ Data Hunter Agent deployed
)

for /f "tokens=*" %%u in ('gcloud run services describe data-hunter --region=us-central1 --format="value(status.url)" --project=%PROJECT_ID% 2^>nul') do set DH_URL=%%u
echo   Data Hunter URL: !DH_URL!
echo.

REM ── Step 8: Create Pub/Sub Push Subscriptions ─────────
echo [8/9] Creating Pub/Sub push subscriptions...

REM Service account for push auth
set SA_EMAIL=cloud-run-pubsub-invoker@%PROJECT_ID%.iam.gserviceaccount.com

REM Create service account if needed
gcloud iam service-accounts create cloud-run-pubsub-invoker ^
    --display-name="Cloud Run Pub/Sub Invoker" ^
    --project=%PROJECT_ID% 2>nul

REM Grant Pub/Sub subscriber role
gcloud projects add-iam-policy-binding %PROJECT_ID% ^
    --member="serviceAccount:%SA_EMAIL%" ^
    --role="roles/pubsub.subscriber" 2>nul

REM Grant Cloud Run invoker role for push
gcloud run services add-iam-policy-binding security-agent ^
    --region=us-central1 ^
    --member="serviceAccount:%SA_EMAIL%" ^
    --role="roles/run.invoker" ^
    --project=%PROJECT_ID% 2>nul

gcloud run services add-iam-policy-binding tech-pulse ^
    --region=us-central1 ^
    --member="serviceAccount:%SA_EMAIL%" ^
    --role="roles/run.invoker" ^
    --project=%PROJECT_ID% 2>nul

REM Security Agent subscription
gcloud pubsub subscriptions create scan.requests.security-agent ^
    --topic=scan.requests ^
    --push-endpoint=%SEC_URL% ^
    --push-auth-service-account=%SA_EMAIL% ^
    --ack-deadline=120 ^
    --project=%PROJECT_ID% 2>nul
echo   ✅ security-agent subscription

REM Tech Pulse subscription
gcloud pubsub subscriptions create scan.requests.tech-pulse ^
    --topic=scan.requests ^
    --push-endpoint=%TP_URL% ^
    --push-auth-service-account=%SA_EMAIL% ^
    --ack-deadline=600 ^
    --project=%PROJECT_ID% 2>nul
echo   ✅ tech-pulse subscription

echo.

REM ── Step 9: Configure Cloud Scheduler ─────────────────
echo [9/9] Configuring Cloud Scheduler jobs...

REM Tech Pulse — Daily at 08:00 Jerusalem (05:00 UTC)
gcloud scheduler jobs create http tech-pulse-daily ^
    --schedule="0 5 * * 1-5" ^
    --time-zone="Asia/Jerusalem" ^
    --uri="%TP_URL%/run" ^
    --http-method="GET" ^
    --oidc-service-account-email="%SA_EMAIL%" ^
    --oidc-token-audience="%TP_URL%/run" ^
    --attempt-deadline="600s" ^
    --project=%PROJECT_ID% 2>nul
if %ERRORLEVEL% EQU 0 (echo   ✅ tech-pulse-daily) else (echo   ⚠️  tech-pulse-daily may already exist)

REM Data Hunter — Daily at 08:30 Jerusalem (05:30 UTC)
gcloud scheduler jobs create http data-hunter-daily ^
    --schedule="30 5 * * 1-5" ^
    --time-zone="Asia/Jerusalem" ^
    --uri="%DH_URL%/run" ^
    --http-method="GET" ^
    --oidc-service-account-email="%SA_EMAIL%" ^
    --oidc-token-audience="%DH_URL%/run" ^
    --attempt-deadline="600s" ^
    --project=%PROJECT_ID% 2>nul
if %ERRORLEVEL% EQU 0 (echo   ✅ data-hunter-daily) else (echo   ⚠️  data-hunter-daily may already exist)

REM Data Hunter — Midday at 14:00 Jerusalem (11:00 UTC)
gcloud scheduler jobs create http data-hunter-midday ^
    --schedule="0 11 * * 1-5" ^
    --time-zone="Asia/Jerusalem" ^
    --uri="%DH_URL%/run" ^
    --http-method="GET" ^
    --oidc-service-account-email="%SA_EMAIL%" ^
    --oidc-token-audience="%DH_URL%/run" ^
    --attempt-deadline="600s" ^
    --project=%PROJECT_ID% 2>nul
if %ERRORLEVEL% EQU 0 (echo   ✅ data-hunter-midday) else (echo   ⚠️  data-hunter-midday may already exist)

echo.

REM ═══════════════════════════════════════════════════════
REM  🎉 HEALTH CHECK
REM ═══════════════════════════════════════════════════════
echo.
echo ╔════════════════════════════════════════════════════════╗
echo ║  🏥 Health Check — All Services                      ║
echo ╚════════════════════════════════════════════════════════╝
echo.

REM Check Orchestrator
echo 🔄 Orchestrator:
curl -s "%ORCH_URL%/api/health" 2>nul
echo.

REM Check Security Agent
echo 🔄 Security Agent:
curl -s "%SEC_URL%/health" 2>nul
echo.

REM Check Tech Pulse
echo 🔄 Tech Pulse:
curl -s "%TP_URL%/health" 2>nul
echo.

REM Check Data Hunter
echo 🔄 Data Hunter:
curl -s "%DH_URL%/health" 2>nul
echo.

REM List Cloud Scheduler jobs
echo.
echo 📅 Cloud Scheduler Jobs:
gcloud scheduler jobs list --format="table(name, schedule, timeZone, state)" --project=%PROJECT_ID% 2>nul

echo.
echo ╔════════════════════════════════════════════════════════╗
echo ║  ✅ SWARM DEPLOY COMPLETE                            ║
echo ╚════════════════════════════════════════════════════════╝
echo.
echo   🌐 Dashboard:     %ORCH_URL%
echo   📡 API Docs:      %ORCH_URL%/docs
echo   🤖 Agents:        %ORCH_URL%/api/agents
echo   🛡️  Security:      %SEC_URL%/health
echo   🔬 Tech Pulse:    %TP_URL%/health
echo   🥇 Data Hunter:   %DH_URL%/health
echo.
echo   To trigger manually now:
echo     gcloud scheduler jobs run tech-pulse-daily
echo     gcloud scheduler jobs run data-hunter-daily
echo.
echo   To test DeepSeek:
echo     curl -X POST %ORCH_URL%/api/agent/deepseek -H "Content-Type: application/json" -d "{\"prompt\":\"שלום, מה מצב השווקים היום?\",\"system\":\"You are a trading analyst. Respond in Hebrew.\"}"
echo.

endlocal