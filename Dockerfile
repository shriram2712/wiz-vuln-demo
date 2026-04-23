# Intentionally vulnerable Dockerfile for Wiz CLI demo
# DO NOT USE IN PRODUCTION.

# VULN: Old Python + Bullseye base (many CVEs in base layer)
FROM python:3.9-bullseye

LABEL maintainer="demo@example.com"

# MISCONFIG: Hardcoded secrets in ENV
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENV DB_PASSWORD="SuperSecret123!"

WORKDIR /app

# VULN: Install vulnerable Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# VULN: Install vulnerable Node deps
COPY package.json .
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && npm install \
    && rm -rf /var/lib/apt/lists/*

COPY app.py .

# MISCONFIG: World-writable app directory
RUN chmod -R 777 /app

# MISCONFIG: Exposing privileged ports
EXPOSE 22 80

# MISCONFIG: No USER (runs as root), no HEALTHCHECK
CMD ["python", "app.py"]
