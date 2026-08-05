FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOCUS_HOST=0.0.0.0 \
    LOCUS_PORT=8000 \
    LOCUS_STATIC_DIR=/app/web

WORKDIR /app
RUN useradd --create-home --uid 10001 locus

COPY pyproject.toml README.md ./
COPY sentinel ./sentinel
COPY scripts ./scripts
COPY web ./web
RUN pip install --no-cache-dir .

USER locus
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2)"

CMD ["python", "-m", "sentinel.server"]
