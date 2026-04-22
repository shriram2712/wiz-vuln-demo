# Intentionally vulnerable Dockerfile for Wiz CLI demo
# DO NOT USE IN PRODUCTION

# VULN: Old Python + Debian Bullseye (many CVEs)
FROM python:3.9-bullseye

LABEL maintainer="demo@example.com"

# VULN: Outdated OS packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    git \
    openssl \
    libxml2 \
    && rm -rf /var/lib/apt/lists/*

# MISCONFIG: Hardcoded secrets in ENV
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENV DB_PASSWORD="SuperSecret123!"

WORKDIR /app

# VULN: Vulnerable Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# MISCONFIG: World-writable files
RUN chmod -R 777 /app

# MISCONFIG: Exposing privileged ports
EXPOSE 22 80

# MISCONFIG: No USER directive (runs as root)
# MISCONFIG: No HEALTHCHECK
CMD ["python", "app.py"]
