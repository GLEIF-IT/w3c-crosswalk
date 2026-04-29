/**
 * Hono service for receiving and displaying Isomer verifier presentation events.
 */
import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { PresentationStore, stringField, stringList } from "./store.js";

export interface DashboardConfig {
  host: string;
  port: number;
}

export function createApp(store = new PresentationStore()): Hono {
  const app = new Hono();

  app.get("/healthz", (context) => context.json({ ok: true, service: "isomer-dashboard" }));

  app.post("/webhooks/presentations", async (context) => {
    let body: unknown;
    try {
      body = await context.req.json();
    } catch {
      return context.json({ ok: false, error: "presentation webhook body must be valid JSON" }, 400);
    }

    try {
      const result = store.record(body);
      return context.json({ ok: true, duplicate: result.duplicate, eventId: result.event.eventId }, result.duplicate ? 200 : 202);
    } catch (error) {
      return context.json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 400);
    }
  });

  app.get("/api/presentations", (context) => {
    const language = context.req.query("language");
    const verifier = context.req.query("verifier");
    const credentialType = context.req.query("credentialType");
    return context.json(store.list({ language, verifier, credentialType }));
  });

  app.get("/api/presentations/:id", (context) => {
    const event = store.get(context.req.param("id"));
    if (!event) {
      return context.json({ ok: false, error: "presentation event not found" }, 404);
    }
    return context.json(event);
  });

  app.get("/events", (context) => {
    let unsubscribe: () => void = () => {};
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        unsubscribe = store.subscribe(controller);
        context.req.raw.signal.addEventListener("abort", () => {
          unsubscribe();
          try {
            controller.close();
          } catch {
            // The connection may already be closed by the browser.
          }
        });
      },
      cancel() {
        unsubscribe();
      }
    });
    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
      }
    });
  });

  app.get("/", (context) => context.html(dashboardHtml()));

  return app;
}

export function serveDashboard(config: DashboardConfig): void {
  serve({
    fetch: createApp().fetch,
    hostname: config.host,
    port: config.port
  });
  console.log(`isomer-dashboard listening on http://${config.host}:${config.port}`);
}

function dashboardHtml(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Isomer Verifier Dashboard</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #17201b;
      --muted: #66736b;
      --line: #d8ded8;
      --paper: #f7f8f4;
      --panel: #ffffff;
      --green: #0f7b63;
      --coral: #c6533b;
      --gold: #9b6a12;
      --blue: #386fa4;
      --violet: #7251a5;
      --shadow: 0 18px 48px rgba(24, 31, 26, 0.12);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background:
        linear-gradient(180deg, rgba(255,255,255,0.74), rgba(247,248,244,0.96)),
        radial-gradient(circle at 82% 10%, rgba(198,83,59,0.12), transparent 32rem),
        radial-gradient(circle at 8% 18%, rgba(15,123,99,0.12), transparent 26rem),
        var(--paper);
      color: var(--ink);
      letter-spacing: 0;
    }
    header {
      padding: 28px clamp(18px, 4vw, 54px) 18px;
      border-bottom: 1px solid rgba(23,32,27,0.08);
      background: rgba(255,255,255,0.72);
      backdrop-filter: blur(18px);
      position: sticky;
      top: 0;
      z-index: 5;
    }
    .topbar {
      display: flex;
      gap: 20px;
      align-items: flex-end;
      justify-content: space-between;
      max-width: 1240px;
      margin: 0 auto;
    }
    h1 {
      margin: 0;
      font-size: clamp(28px, 3.2vw, 46px);
      line-height: 1.05;
      font-weight: 760;
    }
    .metric-row {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    .metric {
      min-width: 104px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255,255,255,0.84);
    }
    .metric strong {
      display: block;
      font-size: 20px;
      line-height: 1;
    }
    .metric span {
      display: block;
      margin-top: 4px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 680;
      text-transform: uppercase;
    }
    main {
      max-width: 1240px;
      margin: 0 auto;
      padding: 20px clamp(18px, 4vw, 54px) 54px;
    }
    .filters {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      margin: 12px 0 20px;
    }
    .filter {
      min-width: 170px;
      height: 38px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      color: var(--ink);
      padding: 0 10px;
      font: inherit;
    }
    .stream {
      display: grid;
      gap: 14px;
    }
    .event {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 16px;
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: rgba(255,255,255,0.92);
      box-shadow: var(--shadow);
    }
    .event-main {
      min-width: 0;
    }
    .event-title {
      display: flex;
      gap: 10px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }
    .event-title h2 {
      margin: 0;
      font-size: 18px;
      line-height: 1.2;
    }
    .event-time {
      color: var(--muted);
      font-size: 13px;
      white-space: nowrap;
    }
    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 7px;
      margin: 8px 0;
    }
    .chip {
      display: inline-flex;
      align-items: center;
      max-width: 100%;
      min-height: 26px;
      padding: 5px 8px;
      border-radius: 999px;
      background: #eef4ef;
      color: #234238;
      font-size: 12px;
      font-weight: 700;
      white-space: nowrap;
    }
    .chip.language { background: #e7f4f0; color: var(--green); }
    .chip.library { background: #f5ece6; color: var(--coral); }
    .chip.type { background: #f5f0df; color: var(--gold); }
    .chip.verifier { background: #e9eef7; color: var(--blue); }
    .chip.ok { background: #e7f4f0; color: var(--green); }
    .payload-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      margin-top: 12px;
    }
    details {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fbfcf9;
      overflow: hidden;
    }
    summary {
      cursor: pointer;
      padding: 10px 12px;
      font-weight: 720;
      color: #243229;
    }
    pre {
      margin: 0;
      padding: 12px;
      overflow: auto;
      max-height: 340px;
      border-top: 1px solid var(--line);
      background: #111714;
      color: #e8f0e8;
      font-size: 12px;
      line-height: 1.5;
    }
    .side {
      min-width: 170px;
      text-align: right;
      color: var(--muted);
      font-size: 13px;
    }
    .empty {
      padding: 42px 20px;
      border: 1px dashed #bec8bf;
      border-radius: 8px;
      background: rgba(255,255,255,0.64);
      text-align: center;
      color: var(--muted);
      font-weight: 680;
    }
    @media (max-width: 760px) {
      .topbar, .event {
        display: block;
      }
      .metric-row, .side {
        justify-content: flex-start;
        text-align: left;
        margin-top: 14px;
      }
      .payload-grid {
        grid-template-columns: 1fr;
      }
      .filter {
        width: 100%;
      }
    }
  </style>
</head>
<body>
  <header>
    <div class="topbar">
      <div>
        <h1>Isomer Verifier Dashboard</h1>
      </div>
      <div class="metric-row">
        <div class="metric"><strong id="total">0</strong><span>Presentations</span></div>
        <div class="metric"><strong id="languages">0</strong><span>Languages</span></div>
        <div class="metric"><strong id="verifiers">0</strong><span>Verifiers</span></div>
      </div>
    </div>
  </header>
  <main>
    <section class="filters" aria-label="Activity filters">
      <select id="language-filter" class="filter"><option value="">All languages</option></select>
      <select id="verifier-filter" class="filter"><option value="">All verifiers</option></select>
      <select id="type-filter" class="filter"><option value="">All credential types</option></select>
    </section>
    <section id="stream" class="stream" aria-live="polite"></section>
  </main>
  <script>
    const state = { events: [], language: '', verifier: '', credentialType: '' };
    const stream = document.getElementById('stream');
    const languageFilter = document.getElementById('language-filter');
    const verifierFilter = document.getElementById('verifier-filter');
    const typeFilter = document.getElementById('type-filter');

    async function refresh() {
      const response = await fetch('/api/presentations');
      state.events = await response.json();
      render();
    }

    function render() {
      const events = filteredEvents();
      document.getElementById('total').textContent = String(state.events.length);
      document.getElementById('languages').textContent = String(new Set(state.events.map((event) => event.verifier.language).filter(Boolean)).size);
      document.getElementById('verifiers').textContent = String(new Set(state.events.map((event) => event.verifier.id).filter(Boolean)).size);
      syncSelect(languageFilter, state.language, ['All languages', ...unique(state.events.map((event) => event.verifier.language))]);
      syncSelect(verifierFilter, state.verifier, ['All verifiers', ...unique(state.events.map((event) => event.verifier.id))]);
      syncSelect(typeFilter, state.credentialType, ['All credential types', ...unique(state.events.flatMap((event) => event.presentation.credentialTypes || []))]);

      if (events.length === 0) {
        stream.innerHTML = '<div class="empty">Waiting for verified presentations</div>';
        return;
      }
      stream.innerHTML = events.map(renderEvent).join('');
    }

    function renderEvent(event) {
      const verifier = event.verifier || {};
      const presentation = event.presentation || {};
      const verification = event.verification || {};
      const libraries = Array.isArray(verifier.libraries) ? verifier.libraries : [];
      const types = Array.isArray(presentation.credentialTypes) ? presentation.credentialTypes : [];
      const credentials = Array.isArray(presentation.credentials) ? presentation.credentials : [];
      return '<article class="event">' +
        '<div class="event-main">' +
          '<div class="event-title"><h2>' + escapeHtml(presentation.holder || 'Verified presentation') + '</h2><span class="chip ok">verified</span></div>' +
          '<div class="chips">' +
            chip(verifier.language, 'language') +
            chip(verifier.id, 'verifier') +
            types.map((item) => chip(item, 'type')).join('') +
            libraries.map((item) => chip(item.name || item, 'library')).join('') +
          '</div>' +
          '<div class="payload-grid">' +
            detailsBlock('Presentation payload', presentation.payload) +
            detailsBlock('Verification checks', verification.checks) +
            credentials.map((credential, index) => detailsBlock('Credential ' + (index + 1) + ' payload', credential.payload)).join('') +
          '</div>' +
        '</div>' +
        '<aside class="side">' +
          '<strong>' + escapeHtml(verifier.label || verifier.id || 'Verifier') + '</strong><br />' +
          '<span class="event-time">' + formatTime(event.verifiedAt) + '</span><br />' +
          '<span>' + escapeHtml(event.eventId) + '</span>' +
        '</aside>' +
      '</article>';
    }

    function chip(value, name) {
      if (!value) return '';
      return '<span class="chip ' + name + '">' + escapeHtml(String(value)) + '</span>';
    }

    function detailsBlock(title, body) {
      return '<details><summary>' + escapeHtml(title) + '</summary><pre>' + escapeHtml(JSON.stringify(body || {}, null, 2)) + '</pre></details>';
    }

    function filteredEvents() {
      return state.events.filter((event) => {
        const types = event.presentation.credentialTypes || [];
        return (!state.language || event.verifier.language === state.language) &&
          (!state.verifier || event.verifier.id === state.verifier) &&
          (!state.credentialType || types.includes(state.credentialType));
      });
    }

    function syncSelect(select, value, options) {
      const current = select.value;
      select.innerHTML = options.map((option, index) => {
        const optionValue = index === 0 ? '' : option;
        return '<option value="' + escapeHtml(optionValue) + '"' + (optionValue === value ? ' selected' : '') + '>' + escapeHtml(option) + '</option>';
      }).join('');
      select.value = value || current;
    }

    function unique(items) {
      return [...new Set(items.filter(Boolean))].sort();
    }

    function formatTime(value) {
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? '' : date.toLocaleString();
    }

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
    }

    languageFilter.addEventListener('change', () => { state.language = languageFilter.value; render(); });
    verifierFilter.addEventListener('change', () => { state.verifier = verifierFilter.value; render(); });
    typeFilter.addEventListener('change', () => { state.credentialType = typeFilter.value; render(); });
    const source = new EventSource('/events');
    source.addEventListener('presentation', (message) => {
      const event = JSON.parse(message.data);
      state.events = [event, ...state.events.filter((item) => item.eventId !== event.eventId)]
        .sort((left, right) => Date.parse(right.verifiedAt) - Date.parse(left.verifiedAt));
      render();
    });
    refresh();
  </script>
</body>
</html>`;
}
