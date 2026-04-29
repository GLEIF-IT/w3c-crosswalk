/**
 * In-memory presentation activity storage for the dashboard service.
 */

const EVENT_TYPE = "isomer.presentation.verified.v1";

export interface PresentationEvent {
  type: string;
  eventId: string;
  verifiedAt: string;
  receivedAt: string;
  verifier: Record<string, unknown>;
  presentation: Record<string, unknown>;
  verification: Record<string, unknown>;
}

export interface RecordResult {
  event: PresentationEvent;
  duplicate: boolean;
}

type Subscriber = ReadableStreamDefaultController<Uint8Array>;

/**
 * Bounded newest-first presentation store with SSE broadcast support.
 */
export class PresentationStore {
  private readonly maxEvents: number;
  private events: PresentationEvent[] = [];
  private subscribers = new Set<Subscriber>();
  private encoder = new TextEncoder();

  constructor(maxEvents = 200) {
    this.maxEvents = maxEvents;
  }

  record(input: unknown): RecordResult {
    const event = normalizeEvent(input);
    const existing = this.events.find((item) => item.eventId === event.eventId);
    if (existing) {
      return { event: existing, duplicate: true };
    }

    this.events.unshift(event);
    this.events.sort((left, right) => timestamp(right.verifiedAt) - timestamp(left.verifiedAt));
    this.events = this.events.slice(0, this.maxEvents);
    this.broadcast(event);
    return { event, duplicate: false };
  }

  list(filters: { language?: string; verifier?: string; credentialType?: string } = {}): PresentationEvent[] {
    return this.events.filter((event) => {
      const language = stringField(event.verifier, "language");
      const verifier = stringField(event.verifier, "id");
      const credentialTypes = stringList(event.presentation.credentialTypes);
      return (
        (!filters.language || language === filters.language) &&
        (!filters.verifier || verifier === filters.verifier) &&
        (!filters.credentialType || credentialTypes.includes(filters.credentialType))
      );
    });
  }

  get(eventId: string): PresentationEvent | undefined {
    return this.events.find((event) => event.eventId === eventId);
  }

  subscribe(controller: Subscriber): () => void {
    this.subscribers.add(controller);
    controller.enqueue(this.encoder.encode("event: ready\ndata: {\"ok\":true}\n\n"));
    return () => this.subscribers.delete(controller);
  }

  private broadcast(event: PresentationEvent): void {
    const frame = this.encoder.encode(`event: presentation\ndata: ${JSON.stringify(event)}\n\n`);
    for (const subscriber of this.subscribers) {
      try {
        subscriber.enqueue(frame);
      } catch {
        this.subscribers.delete(subscriber);
      }
    }
  }
}

export function normalizeEvent(input: unknown): PresentationEvent {
  if (!isRecord(input)) {
    throw new Error("presentation webhook body must be a JSON object");
  }
  if (input.type !== EVENT_TYPE) {
    throw new Error(`unsupported webhook event type: ${String(input.type)}`);
  }
  if (typeof input.eventId !== "string" || input.eventId.length === 0) {
    throw new Error("presentation webhook requires eventId");
  }
  if (typeof input.verifiedAt !== "string" || input.verifiedAt.length === 0) {
    throw new Error("presentation webhook requires verifiedAt");
  }
  if (!isRecord(input.verifier)) {
    throw new Error("presentation webhook requires verifier metadata");
  }
  if (!isRecord(input.presentation)) {
    throw new Error("presentation webhook requires presentation metadata");
  }
  if (!isRecord(input.verification)) {
    throw new Error("presentation webhook requires verification metadata");
  }

  return {
    type: input.type,
    eventId: input.eventId,
    verifiedAt: input.verifiedAt,
    receivedAt: new Date().toISOString(),
    verifier: cloneRecord(input.verifier),
    presentation: cloneRecord(input.presentation),
    verification: cloneRecord(input.verification)
  };
}

export function stringField(value: Record<string, unknown> | undefined, key: string): string | undefined {
  const field = value?.[key];
  return typeof field === "string" ? field : undefined;
}

export function stringList(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === "string");
  }
  return [];
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function cloneRecord(value: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(value)) as Record<string, unknown>;
}

function timestamp(value: string): number {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}
