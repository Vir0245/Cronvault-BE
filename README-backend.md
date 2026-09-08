# CronVault — Backend
Pipeline: `.github/workflows/deploy-backend.yml` (backend-only). Pushes `app.py`, `Dockerfile`, `docker-compose.yml` to backend (`BE_PRIVATE_IP`), then restarts container (`docker compose up -d --build`). Secrets: `BE_PRIVATE_IP`, `SSH_KEY_PEM`. Part of 3-tier AWS deploy (FastAPI + Postgres, private subnets).
