# Job Aggregation Architecture Blueprint (JobLink Kenya)

This document converts the MovieBox-style aggregation idea into a production-ready architecture for JobLink Kenya.

## 1) Ingestion Channels

Use a multi-channel ingestion layer so listings stay fresh even when one source slows down.

### 1.1 APIs (Primary)
Preferred for reliability and structured payloads.

Potential providers:
- Adzuna
- Jooble
- Partner/company APIs
- Any official ATS APIs exposed by employers

Expected normalized input fields from API payloads:
- title
- company
- location
- salary (optional)
- description
- apply_url
- posted_date

### 1.2 RSS Feeds (Secondary)
Use for employer career pages and boards that publish job RSS.

Recommended flow:
1. Pull feed URL
2. Parse entries
3. Enrich missing metadata (location, salary, tags)
4. Push into normalization pipeline

### 1.3 Scraping (Fallback)
Use only when API/RSS is unavailable.

Implementation recommendations:
- Static pages: `requests + BeautifulSoup`
- Structured crawl targets: Scrapy spiders
- Dynamic pages: Playwright/Selenium (selectively)

Operational guardrails:
- Respect `robots.txt`
- Apply per-domain rate limiting and retry backoff
- Use source health metrics (success/failure ratio)

## 2) Canonical Job Schema

All sources map into one canonical schema before persistence.

Suggested table/model fields:
- id
- external_id (nullable)
- source
- source_type (`api|rss|scrape`)
- title
- company
- location
- country
- employment_type
- salary_min
- salary_max
- salary_currency
- description
- skills (derived)
- apply_url
- posted_date
- ingested_at
- expires_at
- fingerprint (dedupe key)

### 2.1 Mapping Layer

Each connector should provide a mapper that transforms source fields into canonical fields.

Examples:
- `position -> title`
- `employer -> company`
- `city -> location`
- `wage -> salary_*`

## 3) Deduplication and Freshness

### 3.1 Dedupe strategy
Create a deterministic `fingerprint` using normalized values such as:
- title
- company
- location
- apply_url (if stable)

Keep a unique index on `(source, fingerprint)` or global `fingerprint` depending on desired behavior.

### 3.2 Expiry policy
- Default expiry: 30 days after `posted_date` if unknown from source
- Mark inactive rather than hard delete when possible
- Periodic cleanup job for stale records

## 4) Pipeline Orchestration

Move from cron-only to queue-based orchestration for reliability.

Recommended stack for this Django project:
- Celery workers
- Redis broker
- Django management commands as task entrypoints

Task groups:
1. `fetch_sources` (APIs/RSS/scrapers)
2. `normalize_jobs`
3. `dedupe_and_upsert`
4. `index_search`
5. `expire_stale_jobs`

Suggested cadence:
- High-volume APIs: every 15–30 minutes
- RSS feeds: every 30–60 minutes
- Scrapers: every 2–6 hours (rate-limited)
- Expiry cleanup: daily

## 5) Storage and Search

### 5.1 Primary database
Use PostgreSQL as the source of truth.

### 5.2 Search engine
Use Meilisearch (or Elasticsearch) for fast user-facing search.

Index fields:
- title
- company
- location
- skills
- description
- employment_type

Filtering examples:
- location = Nairobi
- remote = true
- salary_min >= X

## 6) Proposed System Architecture

```text
[APIs]   [RSS]   [Scrapers]
   \       |         /
    \      |        /
     [Ingestion Connectors]
              |
      [Normalization Layer]
              |
      [Dedupe + Validation]
              |
         [PostgreSQL]
              |
       [Search Indexer]
              |
         [Meilisearch]
              |
      [Django API + Web UI]
```

## 7) Observability and Reliability

Track the pipeline like a production data platform.

Minimum telemetry:
- jobs fetched per source
- normalization failures
- dedupe hit rate
- indexing lag
- stale source alerts

Recommended controls:
- source-level circuit breaker when repeated failures occur
- idempotent upserts
- dead-letter queue for malformed records

## 8) AI Enhancements (Optional, High Impact)

1. Skill extraction from descriptions (e.g., Python, Django, AWS)
2. Salary estimation when missing (confidence-scored)
3. Job categorization (engineering, sales, support, etc.)

Guidelines:
- Keep AI outputs as derived fields
- Store confidence scores
- Never overwrite trusted source values without traceability

## 9) Legal and Compliance

- Respect each source's terms of service and robots directives
- Avoid authenticated/private pages unless explicitly authorized
- Store only relevant job data (no unnecessary personal data)
- Keep source attribution and original apply links

## 10) Implementation Plan (Practical Rollout)

Phase 1 (2–3 weeks):
- Canonical schema + migrations
- 3–5 API/RSS connectors
- Basic dedupe + upsert pipeline

Phase 2 (2–4 weeks):
- Meilisearch indexing + advanced filters
- Source monitoring dashboard
- Expiry and quality scoring

Phase 3 (ongoing):
- Scale to 50+ sources
- Add selective scraping for key sources
- Add AI tagging and salary estimation

## 11) Initial Targets for JobLink Kenya

Start with a balanced mix:
- Kenyan employer career pages (RSS/API first)
- Regional boards that expose official feeds/APIs
- Curated scraping only for high-value sources with no official feed

## 12) Aggregated Applied Jobs + Employer Chat (How to Implement)

Goal: let an applicant apply to aggregated jobs from JobLink, keep the application in **Applied Jobs**, and enable chat with the real employer (or recruiter) inside JobLink.

### 12.1 Current behavior (what exists today)
- Aggregated jobs are owned by a system employer account (`aggregator-bot`).
- When an applicant applies to an aggregated job, we create a local `Application` record and redirect to external `apply_url`.
- Chat already works when an `Application` exists, but messages route to whoever owns the job record.

This means chat for aggregated jobs currently points to the bot owner unless we map the job to a real employer account.

### 12.2 Required data model additions
Add fields that link aggregated jobs to a real, chat-capable employer identity:

1. `AggregatedJobRecord.partner_employer` (FK to `CustomUser`, nullable)
2. `AggregatedJobRecord.partner_company_name` (cached label for display)
3. `AggregatedJobRecord.chat_enabled` (bool)
4. `AggregatedJobRecord.partner_contact_email` (optional for fallback workflow)

Optional: a separate `AggregatedJobPartnerMapping` table if one source needs complex routing rules.

### 12.3 Partner onboarding workflow
1. Employer creates/verifies employer account on JobLink.
2. Admin links their external source/company identifier to that employer account.
3. Aggregator ingestion sets `partner_employer` on matching records.
4. Only records with `chat_enabled=true` show “Chat Employer” CTA in Applied Jobs.

### 12.4 Application + chat flow for aggregated jobs
1. Applicant clicks Apply.
2. Create/get `Application` (same as now), keep it in Applied Jobs.
3. If aggregated record has `partner_employer` and chat is enabled:
   - show “Open Chat” immediately after save;
   - allow internal chat even if external application finishes off-site.
4. Redirect applicant to external `apply_url` (existing behavior).

### 12.5 Messaging policy and trust
- Mark these threads as “External listing chat” in UI.
- Keep auditable event logs (message created/edited/deleted).
- Add moderation/report endpoint for abuse.
- If partner employer is missing, show fallback: “Contact via source site only.”

### 12.6 Rollout plan
Phase A (fastest):
- Enable chat only for explicitly mapped partners.

Phase B:
- Add admin tooling to bulk-map source companies to verified employers.

Phase C:
- Add SLA metrics (first-response time, unread aging) for partner quality ranking.

Success metrics for first milestone:
- 2,000+ active jobs
- <5% duplicate rate
- <1 hour median freshness on API/RSS sources
- <300 ms median search response time
