# syntax=docker/dockerfile:1

# Digests resolved 2026-10-24 from the python:3.12-slim-bookworm multi-arch index.
FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_NO_CACHE=1

WORKDIR /build

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src

RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1

RUN groupadd --system --gid 10001 occ \
    && useradd --system --uid 10001 --gid occ \
        --home-dir /nonexistent --shell /usr/sbin/nologin occ

COPY --from=builder /opt/venv /opt/venv

# Directory for OCC_LOG_FILE, owned by the runtime user. A named volume mounted
# on the parent starts out root-owned (Docker copies the image's content into the
# volume but not the mount point's own ownership), so the log lives one level
# down in `logs/`: that directory is copied into the volume with its 10001
# ownership, which makes it writable without a privileged init step.
RUN install -d -o 10001 -g 10001 -m 0750 /var/log/opencanary-correlator/logs

USER 10001:10001

# 8080 is only the default OCC_HEALTH_PORT; it stays container-internal.
EXPOSE 1514/tcp 5514/tcp 5514/udp 8080/tcp

# Reads OCC_HEALTH_PORT from the environment (0/empty = endpoint disabled), so a
# changed or disabled health listener never leaves the container permanently
# unhealthy. Use the environment variable, not --health-port, inside Docker.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-m", "opencanary_correlator.healthcheck"]

ENTRYPOINT ["opencanary-correlator"]
