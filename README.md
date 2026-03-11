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

Supported source keys:
`remotive, arbeitnow, adzuna, jooble, remoteok, weworkremotely, greenhouse, lever, ashby, smartrecruiters, workable, bamboohr, personio, recruitee, jobicy, remotewx, ycombinator, wellfound, remotive_api, usajobs, remotive_global`

You can configure sources from environment variables (recommended):

```bash
JOB_AGGREGATOR_ENABLED_SOURCES=remotive,arbeitnow,adzuna,jooble,remoteok,weworkremotely,greenhouse,lever,ashby,smartrecruiters,workable,bamboohr,personio,recruitee,jobicy,remotewx,ycombinator,wellfound,remotive_api,usajobs,remotive_global
JOB_AGGREGATOR_STALE_HOURS=48
JOB_AGGREGATOR_HTTP_TIMEOUT=25
```

Or directly in Django settings:

```python
JOB_AGGREGATOR_ENABLED_SOURCES = ("remotive", "arbeitnow")
JOB_AGGREGATOR_STALE_HOURS = 48
JOB_AGGREGATOR_HTTP_TIMEOUT = 25
```

Optional endpoints for configurable JSON sources (set only the providers you use):

```bash
JOB_AGGREGATOR_ADZUNA_ENDPOINT=
JOB_AGGREGATOR_JOOBLE_ENDPOINT=
JOB_AGGREGATOR_GREENHOUSE_ENDPOINT=
JOB_AGGREGATOR_LEVER_ENDPOINT=
JOB_AGGREGATOR_ASHBY_ENDPOINT=
JOB_AGGREGATOR_SMARTRECRUITERS_ENDPOINT=
JOB_AGGREGATOR_WORKABLE_ENDPOINT=
JOB_AGGREGATOR_BAMBOOHR_ENDPOINT=
JOB_AGGREGATOR_PERSONIO_ENDPOINT=
JOB_AGGREGATOR_RECRUITEE_ENDPOINT=
JOB_AGGREGATOR_REMOTEWX_ENDPOINT=
JOB_AGGREGATOR_YCOMBINATOR_ENDPOINT=
JOB_AGGREGATOR_WELLFOUND_ENDPOINT=
JOB_AGGREGATOR_USAJOBS_ENDPOINT=
```

To verify your active configuration:

```bash
python manage.py list_job_aggregator_sources
```

### Scheduler example (cron)

```bash
*/30 * * * * cd /path/to/Joblink-Kenya && /path/to/venv/bin/python manage.py run_job_aggregation --limit 500 --stale-hours 48
```

### Scheduler example (cron-job.org / Render-friendly)

If your deployment platform does not provide shell cron access (for example Render free services), use an HTTP scheduler such as [cron-job.org](https://cron-job.org).

1. Set a strong environment variable on your server:

```bash
CRON_SECRET_KEY=replace-with-long-random-secret
```

2. Create a scheduled job that calls:

```text
https://<your-domain>/cron/run-job-aggregation/?key=<CRON_SECRET_KEY>
```

3. Suggested starting schedule for JobLink:
   - Every 2 hours
   - Command defaults: `limit=500` and `stale_hours=48`

The endpoint is protected by a secret key and an in-process cache lock to avoid overlapping runs.

### Troubleshooting Render `503 hibernate-wake-error`

If cron-job.org shows `503 Service Unavailable` with `x-render-routing: hibernate-wake-error`, the request likely hit your Render service while it was sleeping and failed during wake-up. This is an infrastructure wake issue (before Django executes your view).

Recommended fixes:
- Add a separate keepalive monitor/job to `https://<your-domain>/ping/` every 5 minutes.
- Schedule the aggregation URL a minute after the keepalive ping (for example, `:01` every 2 hours).
- In cron-job.org, enable retries so transient wake failures are retried.
- If you need strict reliability, use Render paid always-on instance or Render Cron Jobs/Background Worker.

### Aggregated apply behavior
When a user clicks apply for an aggregated job, JobLink redirects to the original external `apply_url` instead of creating a local in-platform application record.
