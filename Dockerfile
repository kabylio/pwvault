FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY pwvault ./pwvault
COPY pwvault_server ./pwvault_server

# Run as an unprivileged user; the database lives on a mounted volume.
RUN useradd --system --uid 10001 --no-create-home app \
    && mkdir /data && chown app /data
USER app
ENV PWVAULT_DATABASE_URL=sqlite:////data/pwvault.db
VOLUME /data
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"

# --proxy-headers: trust X-Forwarded-For from the reverse proxy so the audit log
# records real client IPs. Only safe because port 8000 is NOT published (see compose).
CMD ["uvicorn", "pwvault_server.app:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
