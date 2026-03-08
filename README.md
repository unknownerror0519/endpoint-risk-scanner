# Endpoint Risk Scanning Web App

This repo contains:
- `product/`: existing offline pipeline (inventory → match → enrich → score → aggregate → report)
- `backend/`: FastAPI API that runs scans **one endpoint at a time** and writes results back to Firestore
- `frontend/`: React (Vite) + Tailwind dashboard UI

## Backend (FastAPI)

### Requirements
- Python
- Firestore access via **ADC** (recommended) or `GOOGLE_APPLICATION_CREDENTIALS`

### Configure
Create `backend/.env` (example in `backend/.env.example`). Minimum:
- `FIRESTORE_COLLECTION=endpoint data` (agent-reported endpoint docs; backend treats this as read-only)
- `FIRESTORE_SCAN_COLLECTION=endpoint_scans` (system-generated scan status/results; MUST be different)
- `CORS_ALLOW_ORIGINS=http://localhost:5173`

Auth options:
- Local dev: set `GOOGLE_APPLICATION_CREDENTIALS=product/secrets/serviceAccountKey.json`
- GCP/Cloud Run: use the runtime service account + IAM permissions (no key file)

### Run locally
From repo root:
- `C:/Users/YASINDU/AppData/Local/Programs/Python/Python314/python.exe -m uvicorn backend.main:app --reload --port 8000`

API endpoints:
- `GET /endpoints`
- `GET /endpoints/{endpoint_id}/results`
- `POST /endpoints/{endpoint_id}/scan` (starts background scan; status is tracked in Firestore)
- `GET /health`

## Frontend (React + Vite + Tailwind)

### Configure
- Copy `frontend/.env.example` to `frontend/.env`
- Set `VITE_API_BASE_URL=http://localhost:8000`

### Run locally
- `cd frontend`
- `npm install`
- `npm run dev`

## Deployment (GCS + Cloud Run)

### Frontend → Google Cloud Storage (static hosting)
1. Build:
   - `cd frontend`
   - `npm run build`
2. Upload `frontend/dist` to a GCS bucket:
   - `gsutil -m rsync -r -d dist gs://YOUR_BUCKET`
3. SPA routing (recommended for React Router on GCS website hosting):
   - `gsutil web set -m index.html -e index.html gs://YOUR_BUCKET`
4. Make bucket publicly readable (or put behind Cloud CDN / signed URLs as desired).

### Backend → Cloud Run
The backend should run on Cloud Run (GCS is storage, not an app runtime).

1. Build container image (uses `backend/Dockerfile`):
   - `gcloud builds submit --tag gcr.io/YOUR_PROJECT/endpoint-risk-api -f backend/Dockerfile .`
2. Deploy image to Cloud Run:
   - `gcloud run deploy endpoint-risk-api \
       --image gcr.io/YOUR_PROJECT/endpoint-risk-api \
       --region YOUR_REGION \
       --allow-unauthenticated \
   --set-env-vars FIRESTORE_COLLECTION="endpoint data",FIRESTORE_SCAN_COLLECTION="endpoint_scans",CORS_ALLOW_ORIGINS="https://YOUR_GCS_SITE_OR_DOMAIN"`
2. Ensure the Cloud Run service account has Firestore permissions to read endpoints and write scan results.

Notes:
- Scan artifacts are written to the container filesystem by `product/run_endpoint_scan.py` and are **ephemeral** on Cloud Run.
- The UI relies on the results saved back into Firestore (`scan_status`, `latest_endpoint_summary`, `application_summaries`, etc.).
