# ─────────────────────────────────────────────────────────────
# Livestrym SRS Media Server — Dockerfile
# Base: ossrs/srs:6 (stable — do NOT use :latest)
# Exposes: 1935 (RTMPS public), 1985 (HTTP API internal), 8080 (HLS internal)
# ─────────────────────────────────────────────────────────────
FROM ossrs/srs:6

# Copy production config
COPY conf/srs.conf /usr/local/srs/conf/srs.conf

# Copy TLS certificates for RTMPS
COPY conf/server.crt /usr/local/srs/conf/server.crt
COPY conf/server.key /usr/local/srs/conf/server.key

# Secure the private key permissions (required by SRS/OpenSSL)
RUN chmod 600 /usr/local/srs/conf/server.key

# Ports:
# 1935 — RTMPS ingest (public, TCP) — encoders connect here
# 1985 — HTTP Management API (internal Railway network only)
# 8080 — HLS delivery (internal Railway network only)
EXPOSE 1935 1985 8080

CMD ["/usr/local/srs/objs/srs", "-c", "/usr/local/srs/conf/srs.conf"]