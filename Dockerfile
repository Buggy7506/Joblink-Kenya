# =========================
# Base image
# =========================
FROM python:3.11-slim

# =========================
# Environment variables
# =========================
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# =========================
# Set working directory
# =========================
WORKDIR /app

# =========================
# Install system deps
# =========================
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# =========================
# Install Python deps
# =========================
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# =========================
# Copy project
# =========================
COPY . .

# =========================
# Collect static files (safe)
# =========================
RUN python manage.py collectstatic --noinput || true

# =========================
# Start Gunicorn (Back4App injects PORT)
# =========================
CMD ["sh", "-c", "gunicorn joblink.wsgi:application --bind 0.0.0.0:$PORT"]
