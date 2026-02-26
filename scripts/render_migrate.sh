#!/usr/bin/env bash
set -euo pipefail

max_attempts="${MIGRATE_MAX_ATTEMPTS:-8}"
sleep_seconds="${MIGRATE_RETRY_SLEEP_SECONDS:-15}"

attempt=1
while [ "$attempt" -le "$max_attempts" ]; do
  echo "[render-migrate] attempt ${attempt}/${max_attempts}" >&2

  output="$(python manage.py migrate --noinput 2>&1)" && {
    echo "$output"
    echo "[render-migrate] migrations completed" >&2
    exit 0
  }

  echo "$output" >&2

  if echo "$output" | grep -qi "Max client connections reached"; then
    if [ "$attempt" -lt "$max_attempts" ]; then
      echo "[render-migrate] Supabase pool exhausted, retrying in ${sleep_seconds}s..." >&2
      sleep "$sleep_seconds"
      attempt=$((attempt + 1))
      continue
    fi

    echo "[render-migrate] exhausted retries waiting for free database connections" >&2
    exit 1
  fi

  echo "[render-migrate] migration failed due to a non-retryable error" >&2
  exit 1
done
