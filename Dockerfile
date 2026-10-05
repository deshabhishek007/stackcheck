FROM python:3.12-alpine
WORKDIR /app
COPY stackcheck ./stackcheck
RUN adduser -D -H stackcheck
USER stackcheck
# Listen on all interfaces inside the container. The port comes from STACKCHECK_PORT, then the PORT that
# hosting platforms set, then 8080.
ENV STACKCHECK_HOST=0.0.0.0 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s \
  CMD wget -qO- "http://127.0.0.1:${STACKCHECK_PORT:-${PORT:-8080}}/healthz" || exit 1
CMD ["python", "-m", "stackcheck"]
