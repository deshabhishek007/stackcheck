FROM python:3.12-alpine
WORKDIR /app
COPY stackcheck.py fingerprints.json ./
COPY static ./static
RUN adduser -D -H stackcheck
USER stackcheck
ENV STACKCHECK_HOST=0.0.0.0 STACKCHECK_PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
CMD ["python", "stackcheck.py"]
