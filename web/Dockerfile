# Sureguard hosted UI — paste-a-GitHub-URL scanner.
#
# Image layout:
#   /app  — Sureguard source (editable install)
#   semgrep, gitleaks, git — preinstalled scanners
#
# Why this image is multi-stage: gitleaks is a Go binary we pull from the
# upstream release archive, not pip. Keeping the fetch in a builder stage means
# the final image doesn't ship curl + tar layers.

FROM python:3.12-slim AS gitleaks-fetcher
ARG GITLEAKS_VERSION=8.21.2
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# git for cloning, ca-certificates for HTTPS to PyPI/npm/OSV/KEV/EPSS.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=gitleaks-fetcher /usr/local/bin/gitleaks /usr/local/bin/gitleaks

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY server ./server
COPY web ./web
RUN pip install --no-cache-dir ".[web]" semgrep

# Non-root user (we clone untrusted repos at runtime; never as root).
RUN useradd --create-home --shell /bin/bash sureguard \
    && mkdir -p /tmp/sureguard-jobs \
    && chown -R sureguard:sureguard /app /tmp/sureguard-jobs
USER sureguard

EXPOSE 8000
ENV PORT=8000
CMD ["sh", "-c", "uvicorn web.main:app --host 0.0.0.0 --port ${PORT}"]
