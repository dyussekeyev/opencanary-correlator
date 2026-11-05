# syntax=docker/dockerfile:1

# Digests resolved 2026-11-04 from the python:3.12-slim-bookworm multi-arch
# index. The refresh carries openssl/libssl3 3.0.22-1~deb12u2, the fix for
# CVE-2026-84782 that the previous pin (deb12u1) failed the container scan on.
FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_NO_CACHE=1

WORKDIR /build

COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src

# The `geo` extra (maxminddb) is small and lets an operator enrich alerts by
# mounting a DB-IP/GeoLite2 file, without which it is never imported.
RUN uv sync --frozen --no-dev --no-editable --extra geo

FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337 AS runtime

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1

# The pinned base still ships apt/libapt-pkg6.0 2.6.1, which the container scan
# flags as CVE-2026-109518 (fixed in 2.6.2). The slim base does not reliably
# enable bookworm-security, so add it and upgrade the pair explicitly instead
# of suppressing the finding.
RUN printf 'deb http://deb.debian.org/debian-security bookworm-security main\n' \
        > /etc/apt/sources.list.d/bookworm-security.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends apt=2.6.2 libapt-pkg6.0=2.6.2 \
    && rm -rf /var/lib/apt/lists/*

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

# 15142 is only the default OCC_HEALTH_PORT; it stays container-internal.
EXPOSE 15140/tcp 15141/tcp 15141/udp 15142/tcp

# Reads OCC_HEALTH_PORT from the environment (0/empty = endpoint disabled), so a
# changed or disabled health listener never leaves the container permanently
# unhealthy. Use the environment variable, not --health-port, inside Docker.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-m", "opencanary_correlator.healthcheck"]

ENTRYPOINT ["opencanary-correlator"]
