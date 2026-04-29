# syntax=docker/dockerfile:1.7

FROM node:22-bookworm-slim

ENV ISOMER_HOST=0.0.0.0 \
    ISOMER_PORT=8788 \
    ISOMER_RESOURCE_ROOT=/app/w3c-crosswalk

WORKDIR /app
COPY --from=did_jwt_vc . /app/did-jwt-vc
COPY . /app/w3c-crosswalk

RUN corepack enable \
    && yarn --cwd /app/did-jwt-vc install --frozen-lockfile \
    && yarn --cwd /app/did-jwt-vc build \
    && npm --prefix /app/w3c-crosswalk/packages/webs-did-resolver ci \
    && npm --prefix /app/w3c-crosswalk/packages/webs-did-resolver run build \
    && npm --prefix /app/w3c-crosswalk/apps/isomer-node ci

ENV NODE_ENV=production

WORKDIR /app/w3c-crosswalk/apps/isomer-node
EXPOSE 8788

CMD ["sh", "-c", "test -n \"$ISOMER_RESOLVER_URL\" || { echo 'ISOMER_RESOLVER_URL is required' >&2; exit 64; }; exec npm run serve -- --host \"$ISOMER_HOST\" --port \"$ISOMER_PORT\" --resolver-url \"$ISOMER_RESOLVER_URL\" --resource-root \"$ISOMER_RESOURCE_ROOT\""]
