# syntax=docker/dockerfile:1.7

FROM golang:1.26.2-bookworm AS build

WORKDIR /app
COPY --from=vc_go . /app/vc-go
COPY apps/isomer-go/go.mod apps/isomer-go/go.sum /app/w3c-crosswalk/apps/isomer-go/
COPY apps/isomer-go /app/w3c-crosswalk/apps/isomer-go

WORKDIR /app/w3c-crosswalk/apps/isomer-go
RUN go mod download \
    && CGO_ENABLED=0 GOOS=linux go build -o /usr/local/bin/isomer-go ./cmd/isomer-go

FROM debian:bookworm-slim

ENV ISOMER_HOST=0.0.0.0 \
    ISOMER_PORT=8788 \
    ISOMER_RESOURCE_ROOT=/app/w3c-crosswalk

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local/bin/isomer-go /usr/local/bin/isomer-go
COPY src/vc_isomer/resources /app/w3c-crosswalk/src/vc_isomer/resources

EXPOSE 8788

CMD ["sh", "-c", "test -n \"$ISOMER_RESOLVER_URL\" || { echo 'ISOMER_RESOLVER_URL is required' >&2; exit 64; }; exec /usr/local/bin/isomer-go --host \"$ISOMER_HOST\" --port \"$ISOMER_PORT\" --resolver-url \"$ISOMER_RESOLVER_URL\" --resource-root \"$ISOMER_RESOURCE_ROOT\""]
