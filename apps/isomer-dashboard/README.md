# isomer-dashboard

Webhook target and activity dashboard for successful Isomer presentation
verification events.

Run locally:

```bash
cd apps/isomer-dashboard
make sync
make check
make test
make serve
```

Override serve defaults with `ISOMER_DASHBOARD_HOST` or
`ISOMER_DASHBOARD_PORT`.

Build the local container image:

```bash
cd apps/isomer-dashboard
make image
```

Endpoints:

- `GET /healthz`
- `POST /webhooks/presentations`
- `GET /api/presentations`
- `GET /api/presentations/:id`
- `GET /events`
- `GET /`
