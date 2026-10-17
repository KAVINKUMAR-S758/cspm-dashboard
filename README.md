# Cloud Posture dashboard

A small FastAPI backend plus a single-page UI on top of the Prowler App API.
A user enters read-only AWS keys. The backend registers the account in Prowler,
starts a scan, and shows the findings.

## Requirements
- Docker with Compose, and Python 3.10+
- About 10 GB of RAM available to Docker (on WSL, set `memory=11GB` in `.wslconfig`)
- An AWS IAM user with `SecurityAudit`, `ViewOnlyAccess` and Prowler's additional read-only policy

## 1. Run Prowler App (the scanner and API)
    mkdir -p ~/prowler-app && cd ~/prowler-app
    curl -LO https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/docker-compose.yml
    curl -LO https://raw.githubusercontent.com/prowler-cloud/prowler/refs/heads/master/.env
    cp <path-to-this-repo>/prowler/docker-compose.override.yml .
    docker compose up -d

Open http://localhost:3000 and sign up. If port 5432 is taken, stop any local
PostgreSQL first (`sudo systemctl stop postgresql`). Do not commit Prowler's `.env`.

## 2. Run the dashboard
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env        # then put the Prowler email and password in .env
    uvicorn app:app --env-file .env --host 127.0.0.1 --port 9000

Open http://127.0.0.1:9000 and click "Add AWS account". The first scan takes
roughly 30 to 60 minutes. Keep the machine awake and do not restart Docker meanwhile.

## Demo mode (sample data, no Prowler or AWS needed)
    uvicorn demo_app:app --host 127.0.0.1 --port 9001

## Security notes
- The dashboard has no login. Run it on localhost only.
- Keys are forwarded to Prowler and are not stored by this app.
- Never commit `.env` or any AWS keys. Use read-only IAM users and rotate keys.
