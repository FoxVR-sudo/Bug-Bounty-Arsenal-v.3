# Download pre-built Go tool binaries via GitHub API (handles versioned filenames)
FROM alpine:3.20 AS go-tools

RUN apk add --no-cache curl tar ca-certificates unzip jq

RUN mkdir -p /out

# subfinder
RUN URL=$(curl -fsSL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest \
        | jq -r '.assets[] | select(.name | test("linux_amd64\\.zip$")) | .browser_download_url' | head -1) \
    && curl -fsSL "$URL" -o /tmp/subfinder.zip \
    && unzip -j /tmp/subfinder.zip "subfinder" -d /out/ \
    && chmod +x /out/subfinder \
    || echo "subfinder download failed, skipping"

# httpx
RUN URL=$(curl -fsSL https://api.github.com/repos/projectdiscovery/httpx/releases/latest \
        | jq -r '.assets[] | select(.name | test("linux_amd64\\.zip$")) | .browser_download_url' | head -1) \
    && curl -fsSL "$URL" -o /tmp/httpx.zip \
    && unzip -j /tmp/httpx.zip "httpx" -d /out/ \
    && chmod +x /out/httpx \
    || echo "httpx download failed, skipping"

# katana
RUN URL=$(curl -fsSL https://api.github.com/repos/projectdiscovery/katana/releases/latest \
        | jq -r '.assets[] | select(.name | test("linux_amd64\\.zip$")) | .browser_download_url' | head -1) \
    && curl -fsSL "$URL" -o /tmp/katana.zip \
    && unzip -j /tmp/katana.zip "katana" -d /out/ \
    && chmod +x /out/katana \
    || echo "katana download failed, skipping"

# dalfox (assets named: dalfox-linux-amd64.tar.gz)
RUN URL=$(curl -fsSL https://api.github.com/repos/hahwul/dalfox/releases/latest \
        | jq -r '.assets[] | select(.name | test("linux-amd64\\.tar\\.gz$")) | .browser_download_url' | head -1) \
    && curl -fsSL "$URL" -o /tmp/dalfox.tar.gz \
    && tar -xzf /tmp/dalfox.tar.gz -C /out/ \
    && mv /out/dalfox-linux-amd64 /out/dalfox 2>/dev/null || mv /out/dalfox* /out/dalfox 2>/dev/null || true \
    && chmod +x /out/dalfox \
    || echo "dalfox download failed, skipping"

# ffuf
RUN URL=$(curl -fsSL https://api.github.com/repos/ffuf/ffuf/releases/latest \
        | jq -r '.assets[] | select(.name | test("linux_amd64\\.tar\\.gz$")) | .browser_download_url' | head -1) \
    && curl -fsSL "$URL" -o /tmp/ffuf.tar.gz \
    && tar -xzf /tmp/ffuf.tar.gz -C /out/ ffuf \
    && chmod +x /out/ffuf \
    || echo "ffuf download failed, skipping"

# amass (assets named: amass_linux_amd64.tar.gz — binary is inside a subdirectory)
RUN URL=$(curl -fsSL https://api.github.com/repos/owasp-amass/amass/releases/latest \
        | jq -r '.assets[] | select(.name | test("linux_amd64\\.tar\\.gz$")) | .browser_download_url' | head -1) \
    && curl -fsSL "$URL" -o /tmp/amass.tar.gz \
    && mkdir -p /tmp/amass_extract \
    && tar -xzf /tmp/amass.tar.gz -C /tmp/amass_extract/ \
    && find /tmp/amass_extract -name "amass" -type f -exec cp {} /out/amass \; \
    && chmod +x /out/amass \
    || echo "amass download failed, skipping"


# Python application with Django + Celery
FROM python:3.12-slim

# Install system dependencies (including nmap for port scanning)
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    chromium \
    chromium-driver \
    postgresql-client \
    netcat-traditional \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first (for layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Go tool binaries from build stage AFTER pip install
# (pip installs a Python httpx shim that would overwrite the Go binary)
RUN mkdir -p /usr/local/bin
COPY --from=go-tools /out/ /usr/local/bin/
RUN chmod +x /usr/local/bin/subfinder /usr/local/bin/httpx /usr/local/bin/katana \
      /usr/local/bin/dalfox /usr/local/bin/ffuf /usr/local/bin/amass 2>/dev/null || true

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p recon_output scan_progress screenshots bug_evidence/screenshots reports recon_results raw_responses media staticfiles

# Download Nuclei templates and CVE database at build time
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /app/nuclei-templates 2>/dev/null || true
RUN git clone --depth 1 https://github.com/CVEProject/cvelistV5.git /app/cvelistV5 2>/dev/null || true

# Collect static files
RUN python manage.py collectstatic --noinput || true

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=config.settings
ENV ENVIRONMENT=production

# External tool locations (so Celery/Django don't depend on PATH)
ENV SUBFINDER_BIN=/usr/local/bin/subfinder
ENV AMASS_BIN=/usr/local/bin/amass
ENV HTTPX_BIN=/usr/local/bin/httpx
ENV KATANA_BIN=/usr/local/bin/katana
ENV DALFOX_BIN=/usr/local/bin/dalfox
ENV FFUF_BIN=/usr/local/bin/ffuf
ENV NMAP_BIN=/usr/bin/nmap
ENV CVE_DB_PATH=/app/cvelistV5/cves
ENV NUCLEI_TEMPLATES=/app/nuclei-templates

# Expose port
EXPOSE 8000

# Run migrations and start ASGI server (Daphne for WebSocket support)
CMD ["sh", "-c", "python manage.py migrate && daphne -b 0.0.0.0 -p ${PORT:-8000} config.asgi:application"]
