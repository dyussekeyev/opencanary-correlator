# syntax=docker/dockerfile:1

# Test environment for tools/linux_check.sh: the same interpreter as the CI
# test job and the locked development dependencies. The repository is mounted
# at run time, so it is never copied into the image and a source change does
# not invalidate the cached layer (only pyproject.toml or uv.lock does).
FROM python:3.11-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.13.0 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_NO_CACHE=1 \
    PATH="/opt/venv/bin:${PATH}"

WORKDIR /build

COPY pyproject.toml uv.lock ./

RUN uv sync --frozen --extra dev --no-install-project
