# Intentionally Vulnerable Dockerfile for Wiz CLI Scanning Demo
# DO NOT USE IN PRODUCTION - FOR SECURITY TESTING ONLY
#
# This Dockerfile contains multiple categories of issues that Wiz CLI
# should detect: vulnerable base image, outdated OS packages, vulnerable
# language dependencies, secrets, and Dockerfile misconfigurations.

# ---- VULN #1: Old, EOL base image with known CVEs ----
# Debian 10 (Buster) reached EOL June 2024 — tons of unpatched CVEs
FROM python:3.7-buster

# ---- MISCONFIG #1: Running as root (no USER directive until end) ----
# ---- MISCONFIG #2: Using latest-style mutable tags implicitly ----

LABEL maintainer="security-demo@example.com"
LABEL description="Vulnerable app for Wiz CLI scanning demonstrations"

# ---- VULN #2: Install known-vulnerable OS packages ----
# These versions ship with unpatched CVEs in buster
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl=7.64.0-4+deb10u* \
    wget \
    git \
    openssl \
    libxml2 \
    libcurl4 \
    sudo \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# ---- MISCONFIG #3: Hardcoded secrets in ENV (Wiz detects these) ----
ENV AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
ENV DB_PASSWORD="SuperSecret123!"
ENV API_TOKEN="ghp_ExampleGitHubTokenDoNotUseInProd1234567"

# ---- MISCONFIG #4: ADD with remote URL (prefer COPY) ----
ADD https://raw.githubusercontent.com/octocat/Hello-World/master/README /tmp/readme

WORKDIR /app

# ---- VULN #3: Vulnerable Python dependencies ----
# Each of these has well-known CVEs
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---- VULN #4: Vulnerable Node packages (for SCA scanning) ----
COPY package.json .
RUN apt-get update && apt-get install -y nodejs npm && npm install

COPY . .

# ---- MISCONFIG #5: Overly permissive file perms ----
RUN chmod -R 777 /app

# ---- MISCONFIG #6: Exposing privileged port as root ----
EXPOSE 22 80 443 3306

# ---- MISCONFIG #7: No HEALTHCHECK, no non-root USER, no read-only FS hint ----
# (Left deliberately — Wiz flags missing USER)

CMD ["python", "app.py"]
