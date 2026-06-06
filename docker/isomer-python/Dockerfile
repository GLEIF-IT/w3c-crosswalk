# syntax=docker/dockerfile:1.7

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ISOMER_HOST=0.0.0.0 \
    ISOMER_PORT=8788 \
    ISOMER_OPERATION_ROOT=/data/operations \
    ISOMER_OPERATION_NAME=verifier

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        libsodium-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app/w3c-crosswalk

WORKDIR /app/w3c-crosswalk
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir \
        -e /app/w3c-crosswalk \
        "signifypy @ git+https://github.com/kentbull/signifypy.git@b11001d54f9d0d9b8b7a49c0e09307e6252db291" \
        "requests>=2,<3" \
    && python -m pip install --no-cache-dir --no-deps \
        -e /app/w3c-crosswalk/packages/signifypy-w3c \
        -e /app/w3c-crosswalk/packages/signifypy-did-webs \
        -e /app/w3c-crosswalk/packages/headless-w3c-e2e \
    && mkdir -p /data/operations

EXPOSE 8788

CMD ["sh", "-c", "test -n \"$ISOMER_RESOLVER_URL\" || { echo 'ISOMER_RESOLVER_URL is required' >&2; exit 64; }; exec isomer verifier serve --host \"$ISOMER_HOST\" --port \"$ISOMER_PORT\" --resolver \"$ISOMER_RESOLVER_URL\" --operation-root \"$ISOMER_OPERATION_ROOT\" --operation-name \"$ISOMER_OPERATION_NAME\""]
