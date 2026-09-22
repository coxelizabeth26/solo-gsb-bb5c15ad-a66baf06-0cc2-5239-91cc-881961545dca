#!/bin/sh
# Initialise the SQLite database (schema is created idempotently), then start
# the API on port 8000.
set -e

: "${DR_DB_PATH:=/data/sss.db}"
export DR_DB_PATH
echo "[entrypoint] Initialising database at ${DR_DB_PATH} ..."
python3 -c "import os; from app.database import Database; Database(os.environ['DR_DB_PATH']).close(); print('[entrypoint] Database ready.')"

exec uvicorn app.main:app --host 0.0.0.0 --port 8000
