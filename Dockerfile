FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data

EXPOSE 5001

ENV PYTHONUNBUFFERED=1
ENV DB_PATH=/data/keys.db

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5001/api/v1/health || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "4", "app:app"]
