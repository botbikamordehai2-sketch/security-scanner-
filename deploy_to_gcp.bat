@echo off
setlocal enabledelayedexpansion
echo ==============================================
echo  Agentic Security Scanner — Deploy to GCP
echo ==============================================
echo.

REM =====================================================
REM  🔧 EDIT THESE TWO VALUES BEFORE RUNNING
REM =====================================================
set PROJECT_ID=project-6a3ebdcd-15ff-47e1-8c1
set REGION=us-central1
set SERVICE_NAME=agentic-security-scanner
set IMAGE=gcr.io/%PROJECT_ID%/%SERVICE_NAME%

REM =====================================================
REM  🔑 API Keys (optional — leave blank if not available)
REM     Gets injected as env vars to Cloud Run
REM =====================================================
set DEEPSEEK_KEY=
set GOOGLE_API_KEY=
set SEARCH_ENGINE_CX=53abe856f64dd45b5

REM =====================================================
REM  Safety check
REM =====================================================
if "%PROJECT_ID%"=="YOUR_PROJECT_ID_HERE" (
    echo [ERROR] Open deploy_to_gcp.bat and set PROJECT_ID to your real GCP project ID.
    echo.
    echo   Example: set PROJECT_ID=agentic-core-12345
    echo.
    pause
    exit /b 1
)

echo Project:  %PROJECT_ID%
echo Service:  %SERVICE_NAME%
echo Region:   %REGION%
echo Image:    %IMAGE%
echo.

REM =====================================================
REM  Set active project
REM =====================================================
call gcloud config set project %PROJECT_ID%
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to set project. Is gcloud installed and logged in?
    pause
    exit /b 1
)

REM =====================================================
REM  Enable required APIs
REM =====================================================
call gcloud services enable run.googleapis.com cloudbuild.googleapis.com --project=%PROJECT_ID%
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to enable APIs. Check billing / permissions.
    pause
    exit /b 1
)

REM =====================================================
REM  [1/3] Build & push container to Container Registry
REM =====================================================
echo.
echo [1/3] Building container with Cloud Build...
gcloud builds submit --tag %IMAGE% --project=%PROJECT_ID%
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Cloud Build failed. Check the logs above.
    pause
    exit /b 1
)

REM =====================================================
REM  [2/3] Deploy to Cloud Run
REM =====================================================
echo.
echo [2/3] Deploying to Cloud Run...

REM Build env-vars flag only if DEEPSEEK_KEY is set
set ENV_FLAGS=--memory 256Mi --cpu 1 --min-instances 0 --max-instances 3 --timeout 120
if not "%DEEPSEEK_KEY%"=="" (
    set ENV_FLAGS=%ENV_FLAGS% --set-env-vars DEEPSEEK_API_KEY=%DEEPSEEK_KEY%
    echo        DeepSeek key found — Sales Agent will be active.
) else (
    echo        No DeepSeek key — Sales Agent disabled.
)

gcloud run deploy %SERVICE_NAME% ^
    --image %IMAGE% ^
    --platform managed ^
    --region %REGION% ^
    --allow-unauthenticated ^
    %ENV_FLAGS% ^
    --project=%PROJECT_ID%
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Cloud Run deployment failed.
    pause
    exit /b 1
)

REM =====================================================
REM  [3/3] Print the public URL
REM =====================================================
echo.
echo [3/3] ✓ Deployment complete!
echo.
echo ──────────────────────────────────────────────
echo   🔗 YOUR PUBLIC DASHBOARD URL:
gcloud run services describe %SERVICE_NAME% --platform managed --region %REGION% --project=%PROJECT_ID% --format="value(status.url)"
echo ──────────────────────────────────────────────
echo.
echo Open this URL in any browser.
echo Scan endpoint:   {URL}/api/scan/security
echo Health check:    {URL}/api/health
echo API docs:        {URL}/docs
echo.
echo To set a custom domain, run:
echo   gcloud run domain-mappings create --service=%SERVICE_NAME% --domain=scan.yourdomain.com --region=%REGION%
echo.
pause