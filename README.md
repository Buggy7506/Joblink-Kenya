# Joblink-Kenya

[![Better Stack Badge](https://uptime.betterstack.com/status-badges/v3/monitor/2d64d.svg)](https://uptime.betterstack.com/?utm_source=status_badge)

A job-listing web application built with **Django**.  
This project powers the Joblink Kenya portal — helping users find and post job opportunities.

---

## 🧠 Overview

Joblink-Kenya is a web platform designed to:
- Display job listings
- Allow employers to post jobs
- Provide search and filtering
- Stay online with uptime monitoring

---

## 🚀 Features

✔ Django backend  
✔ Job posting and browsing  
✔ Database support (SQLite/PostgreSQL)  
✔ `/ping/` keep-alive endpoint  
✔ Render-compatible deployment  
✔ Favicon already set up  
```html
<!-- Favicon -->
<link rel="icon" type="image/png"
      href="https://res.cloudinary.com/dc6z1giw2/image/upload/v1765303178/joblink-logo_xjj0qp.png">
```

---

## 🔎 Scalable Job Aggregator (Built-In)

JobLink now ships with a Django-native aggregation pipeline that automatically ingests jobs from **configured sources** on a schedule and keeps listings fresh.

> Note: no aggregator can legally/technically pull from “all job sites” by default. You add supported sources explicitly.

### What was added
- `AggregatedJobRecord` model to map external-source metadata to local `Job` rows.
- Pluggable source adapters (`core/aggregator/sources.py`) with default adapters:
  - `remotive`
  - `arbeitnow`
- Ingestion service (`core/aggregator/service.py`) that:
  - normalizes and deduplicates jobs using fingerprints,
  - creates/updates jobs under a system employer account,
  - stores source payload metadata,
  - deactivates stale jobs not seen for a configurable duration.

### Run manually

```bash
python manage.py run_job_aggregation --limit 500 --stale-hours 48
```

### Configure which sources are enabled

You can configure sources from environment variables (recommended):

```bash
JOB_AGGREGATOR_ENABLED_SOURCES=remotive,arbeitnow
JOB_AGGREGATOR_STALE_HOURS=48
JOB_AGGREGATOR_HTTP_TIMEOUT=25
```

Or directly in Django settings:

```python
JOB_AGGREGATOR_ENABLED_SOURCES = ("remotive", "arbeitnow")
JOB_AGGREGATOR_STALE_HOURS = 48
JOB_AGGREGATOR_HTTP_TIMEOUT = 25
```

To verify your active configuration:

```bash
python manage.py list_job_aggregator_sources
```

### Scheduler example (cron)

```bash
*/30 * * * * cd /path/to/Joblink-Kenya && /path/to/venv/bin/python manage.py run_job_aggregation --limit 500 --stale-hours 48
```

### Aggregated apply behavior
When a user clicks apply for an aggregated job, JobLink redirects to the original external `apply_url` instead of creating a local in-platform application record.
