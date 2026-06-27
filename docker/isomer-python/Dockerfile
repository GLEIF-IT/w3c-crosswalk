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
        /app/w3c-crosswalk \
        "signifypy>=0.4.2,<0.5.0" \
        "signifypy-w3c==0.1.0" \
        "signifypy-did-webs==0.1.0" \
        "headless-w3c-e2e==0.1.0" \
    && mkdir -p /data/operations

EXPOSE 8788

CMD ["sh", "-c", "test -n \"$ISOMER_RESOLVER_URL\" || { echo 'ISOMER_RESOLVER_URL is required' >&2; exit 64; }; exec isomer verifier serve --host \"$ISOMER_HOST\" --port \"$ISOMER_PORT\" --resolver \"$ISOMER_RESOLVER_URL\" --operation-root \"$ISOMER_OPERATION_ROOT\" --operation-name \"$ISOMER_OPERATION_NAME\""]
