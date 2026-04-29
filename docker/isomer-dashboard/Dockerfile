# syntax=docker/dockerfile:1.7

FROM node:22-bookworm-slim

ENV ISOMER_DASHBOARD_HOST=0.0.0.0 \
    ISOMER_DASHBOARD_PORT=8791

WORKDIR /app/w3c-crosswalk
COPY apps/isomer-dashboard/package.json apps/isomer-dashboard/package-lock.json* /app/w3c-crosswalk/apps/isomer-dashboard/

COPY apps/isomer-dashboard /app/w3c-crosswalk/apps/isomer-dashboard

RUN rm -rf apps/isomer-dashboard/node_modules \
    && npm --prefix apps/isomer-dashboard install

ENV NODE_ENV=production

WORKDIR /app/w3c-crosswalk/apps/isomer-dashboard
EXPOSE 8791

CMD ["npm", "run", "serve"]
