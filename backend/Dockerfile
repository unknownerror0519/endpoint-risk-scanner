FROM python:3.12-slim

WORKDIR /app

# Install backend deps
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy source (includes product pipeline + ML model artifacts)
COPY backend ./backend
COPY product ./product
COPY ml_model/models ./ml_model/models
COPY epss_scores.csv ./epss_scores.csv
COPY known_exploited_vulnerabilities.json ./known_exploited_vulnerabilities.json

ENV PYTHONUNBUFFERED=1
ENV PORT=8080

EXPOSE 8080

# Cloud Run-friendly
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
