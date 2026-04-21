FROM python:3.11-slim

LABEL maintainer="VulnScanX Team"
LABEL description="Advanced Vulnerability Scanning Framework"

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap curl dnsutils whois git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p reports/output logs

EXPOSE 5000

ENV PYTHONUNBUFFERED=1
ENV FLASK_ENV=production

CMD ["python", "web/app.py"]
