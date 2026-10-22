# VulnTriage: dashboard + nightly scheduler + Trivy (and optionally Grype).
# Runs as an unprivileged user; reaches Docker only through a read-only socket proxy.
FROM python:3.12-slim-bookworm

ARG TRIVY_VERSION=0.75.0
ARG GRYPE_VERSION=0.120.0
ARG INSTALL_GRYPE=false

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl nmap tini \
 && rm -rf /var/lib/apt/lists/*

# Scanner binaries, verified against the release checksum files.
RUN set -eux; cd /tmp; \
    curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
    curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep " trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -C /usr/local/bin trivy; \
    if [ "$INSTALL_GRYPE" = "true" ]; then \
      curl -fsSLO "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz"; \
      curl -fsSLO "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_checksums.txt"; \
      grep " grype_${GRYPE_VERSION}_linux_amd64.tar.gz\$" "grype_${GRYPE_VERSION}_checksums.txt" | sha256sum -c -; \
      tar -xzf "grype_${GRYPE_VERSION}_linux_amd64.tar.gz" -C /usr/local/bin grype; \
    fi; \
    rm -f /tmp/*.tar.gz /tmp/*.txt

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY vulntriage ./vulntriage
COPY fixtures ./fixtures
RUN pip install --no-cache-dir ".[llm,postgres]"

RUN useradd --system --uid 10001 --home /data vulntriage \
 && mkdir -p /data /reports \
 && chown -R vulntriage /data /reports
USER vulntriage

ENV DATA_DIR=/data \
    DATABASE_URL=sqlite:////data/vulntriage.db \
    REPORTS_DIR=/reports \
    TRIVY_CACHE_DIR=/data/trivy-cache \
    TMPDIR=/data/tmp \
    DOCKER_HOST=tcp://docker-proxy:2375 \
    PYTHONUNBUFFERED=1

VOLUME ["/data", "/reports"]
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4)"

ENTRYPOINT ["/usr/bin/tini", "--"]
# 0.0.0.0 *inside* the container; docker-compose.yml publishes it on 127.0.0.1 by default.
CMD ["sh", "-c", "mkdir -p \"$TMPDIR\" && exec vulntriage serve --host 0.0.0.0 --port 8080"]
