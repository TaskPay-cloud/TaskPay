FROM python:3.12-slim

# PYTHONUNBUFFERED makes print() output show up in the deploy logs immediately,
# even if the app crashes on startup (otherwise the logs can be empty).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=3000 \
    DB_PATH=/data/taskpay.db

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Fail the BUILD (with a clear message) if the HTML templates weren't added.
RUN [ -f templates/index.html ] || [ -f index.html ] || \
    (echo "ERROR: index.html not found - put your HTML files in templates/" && exit 1)

# Database lives here. Mount a persistent volume at /data or it resets on redeploy.
RUN mkdir -p /data
VOLUME /data

EXPOSE 3000

# One worker on purpose: SQLite allows a single writer, and startup runs
# schema creation/migration. Threads give concurrency without lock fights.
CMD ["gunicorn", "-b", "0.0.0.0:3000", "-w", "1", "--threads", "4", "--timeout", "60", \
     "--access-logfile", "-", "--error-logfile", "-", "--capture-output", "app:app"]
