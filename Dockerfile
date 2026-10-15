FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    MCPM_TRANSPORT=http \
    MCPM_HTTP_HOST=0.0.0.0 \
    MCPM_HTTP_PORT=8765 \
    MCPM_DATA_DIR=/data

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install . \
    && useradd --uid 1000 --no-create-home --shell /usr/sbin/nologin mcpm \
    && mkdir -p /data && chown mcpm /data

USER mcpm
VOLUME /data
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('MCPM_HTTP_PORT','8765'), timeout=4)" || exit 1

ENTRYPOINT ["mcpmonitor"]
