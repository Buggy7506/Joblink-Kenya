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

---

## 🔎 Scalable Job Aggregator (Built-In)

This project now includes a Django-native aggregation pipeline that can ingest jobs from external sources at scale while staying compatible with existing JobLink Kenya flows.

### What was added
- `AggregatedJobRecord` model to map external-source metadata to local `Job` rows.
- Pluggable source adapters (`core/aggregator/sources.py`) with a default `Remotive` API adapter.
- Ingestion service (`core/aggregator/service.py`) that:
  - normalizes and deduplicates jobs using fingerprints,
  - creates/updates jobs under a system employer account,
  - keeps source payload metadata for future NLP/search indexing.
- Management command:

```bash
python manage.py run_job_aggregation --limit 500
```

### Scheduler example (cron)

```bash
*/30 * * * * cd /path/to/Joblink-Kenya && /path/to/venv/bin/python manage.py run_job_aggregation --limit 500
```

### Aggregated apply behavior
When a user clicks apply for an aggregated job, JobLink redirects to the original external `apply_url` instead of creating a local in-platform application record.
## 🏗️ Job Aggregation Blueprint

For a production-ready MovieBox-style aggregation architecture adapted to JobLink Kenya, see:

- [`docs/job-aggregation-architecture.md`](docs/job-aggregation-architecture.md)

