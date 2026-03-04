# HyperFit - Full-Stack E-Commerce Clothing Platform

Flask backend + React storefront/admin, served together on one URL in local mode.

## Quick Start (single Flask server on `http://127.0.0.1:5000/`)

1. Prepare env file
```bash
cd /Users/mohammadadeenhussain/Desktop/HyperFit
cp .env.example .env
```

2. Build frontend once
```bash
cd frontend
npm install
npm run build
```

3. Run backend
```bash
cd ../backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app run
```

If `flask` command is not found, use:
```bash
python3 -m flask --app app run
```

Open: `http://127.0.0.1:5000/`

## Important local behavior

- Database tables are auto-created at startup (`db.create_all()`), so `flask db init/migrate/upgrade` is not required for local run.
- Admin user is auto-created from `.env` values:
  - `ADMIN_EMAIL`
  - `ADMIN_PASSWORD`
- Default DB fallback is SQLite (`backend/hyperfit.db`) if `DATABASE_URL` is not set.
- For PostgreSQL, set `DATABASE_URL` in `.env`.

## Project Structure

```text
backend/
  app.py
  config.py
  models.py
  schema.sql
  routes/
  services/
  utils/
  scripts/
frontend/
  src/
    components/
    pages/
    services/
    context/
```

## API and Schema

- API reference: `backend/API_ENDPOINTS.md`
- SQLAlchemy models: `backend/models.py`
- PostgreSQL schema reference: `backend/schema.sql`

## Deployment

- Gunicorn entrypoint: `backend/wsgi.py`
- Docker files: `backend/Dockerfile`, `frontend/Dockerfile`
- Compose: `docker-compose.yml`
- Deployment notes: `DEPLOYMENT.md`
