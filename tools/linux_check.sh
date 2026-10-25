#!/usr/bin/env bash
#
# Run the test suite on Linux, because that is what CI and production run.
#
# A green `pytest` on Windows does not prove much: the POSIX selector transport,
# signal delivery and socket semantics differ from the Windows ones, and a
# regression that only breaks Linux (for example the asyncio datagram transport
# type check) survives every local run. This script mounts the working tree
# read-only into a container built from the locked development dependencies and
# runs pytest there, with a disposable Redis for the opt-in real-server tests.
#
# Usage:
#   tools/linux_check.sh                     # whole suite, with Redis
#   tools/linux_check.sh tests/integration   # a subset, extra args go to pytest
#   tools/linux_check.sh --no-redis          # skip the real-Redis tests
#   tools/linux_check.sh --rebuild           # rebuild the test image
#
# Exit status is pytest's, so it can gate a push or a script.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${LINUX_CHECK_IMAGE:-opencanary-correlator-linux-check:local}"
REDIS_IMAGE="${LINUX_CHECK_REDIS_IMAGE:-redis:7-alpine}"
REDIS_CONTAINER="occ-linux-check-redis"

rebuild=0
use_redis=1
pytest_args=()

usage() {
    sed -n '3,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --rebuild)
            rebuild=1
            shift
            ;;
        --no-redis)
            use_redis=0
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            pytest_args+=("$@")
            break
            ;;
        *)
            pytest_args+=("$1")
            shift
            ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "linux check: docker is required" >&2
    exit 2
fi
if ! docker info >/dev/null 2>&1; then
    echo "linux check: the Docker daemon is not reachable; start Docker Desktop or the engine" >&2
    exit 2
fi

# Git Bash for Windows hands Docker a POSIX path, which the daemon cannot mount
# or build from, so every host path is converted first.
mount_source="$REPO_ROOT"
if command -v cygpath >/dev/null 2>&1; then
    mount_source="$(cygpath -w "$REPO_ROOT")"
fi

if [[ "$rebuild" -eq 1 ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "linux check: building $IMAGE (cached by pyproject.toml and uv.lock)"
    MSYS_NO_PATHCONV=1 docker build \
        --file "${mount_source}/tools/linux_check.Dockerfile" \
        --tag "$IMAGE" \
        "$mount_source"
fi

redis_started=0
cleanup() {
    if [[ "$redis_started" -eq 1 ]]; then
        docker rm --force "$REDIS_CONTAINER" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# The project itself is not installed in the image (sources are mounted), so
# subprocess-based tests and `python -m opencanary_correlator` need PYTHONPATH.
container_env=(-e COVERAGE_FILE=/tmp/.coverage -e PYTHONPATH=/src/src -e PYTHONDONTWRITEBYTECODE=1 \
    -e RUFF_CACHE_DIR=/tmp/.ruff_cache -e MYPY_CACHE_DIR=/tmp/.mypy_cache)
if [[ "$use_redis" -eq 1 ]]; then
    docker rm --force "$REDIS_CONTAINER" >/dev/null 2>&1 || true
    docker run --detach --rm --name "$REDIS_CONTAINER" \
        --publish 127.0.0.1::6379 "$REDIS_IMAGE" >/dev/null
    redis_started=1
    redis_port="$(docker port "$REDIS_CONTAINER" 6379/tcp | head -n 1 | sed 's/.*://')"
    for _ in $(seq 1 50); do
        if docker exec "$REDIS_CONTAINER" redis-cli ping >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
    if [[ -z "$redis_port" ]]; then
        echo "linux check: could not determine the Redis port" >&2
        exit 2
    fi
    container_env+=(-e "OCC_TEST_REDIS_URL=redis://host.docker.internal:${redis_port}/15")
fi

pytest_cmd=(python -m pytest -p no:cacheprovider)
if [[ ${#pytest_args[@]} -gt 0 ]]; then
    # A subset cannot reach the project-wide coverage gate, so measure nothing
    # unless the caller asked for coverage explicitly.
    wants_cov=0
    for arg in "${pytest_args[@]}"; do
        [[ "$arg" == --cov* ]] && wants_cov=1
    done
    if [[ "$wants_cov" -eq 0 ]]; then
        pytest_cmd+=(--no-cov)
    fi
    pytest_cmd+=("${pytest_args[@]}")
fi

# mypy and ruff answer per platform: under Linux `sys.platform` narrows to
# `"linux"`, so a `if sys.platform != "win32"` runtime guard is reported as
# unreachable there and not on the host, and a Windows-side run cannot see it.
# The gates therefore run where the CI lint job runs them.
static_cmd=()
if [[ ${#pytest_args[@]} -eq 0 ]]; then
    static_cmd=(sh -c 'python -m ruff check . && python -m ruff format --check . \
        && python -m mypy src tools && exec "$@"' sh)
fi

echo "linux check: ruff, mypy and pytest on python 3.11 in a container (redis=${use_redis})"
status=0
MSYS_NO_PATHCONV=1 docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    --volume "${mount_source}:/src:ro" \
    --workdir /src \
    "${container_env[@]}" \
    "$IMAGE" \
    "${static_cmd[@]}" "${pytest_cmd[@]}" || status=$?

if [[ "$status" -eq 0 ]]; then
    echo "linux check: passed"
else
    echo "linux check: FAILED (exit $status)" >&2
fi
exit "$status"
