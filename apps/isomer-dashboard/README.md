# isomer-dashboard

Webhook target and activity dashboard for successful Isomer presentation
verification events.

Run locally:

```bash
npm --prefix apps/isomer-dashboard install
ISOMER_DASHBOARD_HOST=127.0.0.1 \
ISOMER_DASHBOARD_PORT=8791 \
npm --prefix apps/isomer-dashboard run serve
```

Endpoints:

- `GET /healthz`
- `POST /webhooks/presentations`
- `GET /api/presentations`
- `GET /api/presentations/:id`
- `GET /events`
- `GET /`
