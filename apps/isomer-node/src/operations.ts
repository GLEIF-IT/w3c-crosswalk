import { randomUUID } from "node:crypto";
import type { VerificationResult } from "./types.js";

export interface OperationError {
  code: number;
  message: string;
  details?: unknown;
}

export interface OperationMetadata {
  state: "pending" | "running" | "completed" | "failed";
  submittedAt: string;
  updatedAt: string;
}

export interface PendingOperationDocument {
  name: string;
  done: false;
  metadata: OperationMetadata;
}

export interface CompletedOperationDocument {
  name: string;
  done: true;
  metadata: OperationMetadata;
  response: VerificationResult;
}

export interface FailedOperationDocument {
  name: string;
  done: true;
  metadata: OperationMetadata;
  error: OperationError;
}

export type OperationDocument =
  | PendingOperationDocument
  | CompletedOperationDocument
  | FailedOperationDocument;

type OperationRecord = OperationDocument;

/**
 * Small in-memory long-running operation store for local sidecar verification.
 */
export class InMemoryOperationMonitor {
  private readonly records = new Map<string, OperationRecord>();

  submit(
    type: "verify-vc",
    task: (name: string) => Promise<VerificationResult>
  ): PendingOperationDocument {
    const now = new Date().toISOString();
    const name = `${type}.${randomUUID()}`;
    const document: PendingOperationDocument = {
      name,
      done: false,
      metadata: {
        state: "pending",
        submittedAt: now,
        updatedAt: now
      }
    };
    this.records.set(name, document);
    setTimeout(() => {
      void this.run(name, task);
    }, 0);
    return document;
  }

  list(type?: string): OperationDocument[] {
    const records = [...this.records.values()];
    if (type === undefined || type.length === 0) {
      return records;
    }
    return records.filter((record) => record.name.startsWith(`${type}.`));
  }

  get(name: string): OperationDocument | undefined {
    return this.records.get(name);
  }

  private async run(
    name: string,
    task: (name: string) => Promise<VerificationResult>
  ): Promise<void> {
    const current = this.records.get(name);
    if (current === undefined) {
      return;
    }
    this.records.set(name, {
      ...current,
      metadata: {
        ...current.metadata,
        state: "running",
        updatedAt: new Date().toISOString()
      }
    });

    try {
      const response = await task(name);
      const running = this.records.get(name);
      if (running === undefined) {
        return;
      }
      this.records.set(name, {
        name,
        done: true,
        metadata: {
          ...running.metadata,
          state: "completed",
          updatedAt: new Date().toISOString()
        },
        response
      });
    } catch (error) {
      const running = this.records.get(name);
      if (running === undefined) {
        return;
      }
      this.records.set(name, {
        name,
        done: true,
        metadata: {
          ...running.metadata,
          state: "failed",
          updatedAt: new Date().toISOString()
        },
        error: operationError(error)
      });
    }
  }
}

const operationError = (error: unknown): OperationError => {
  if (error instanceof Error) {
    return {
      code: 500,
      message: error.message,
      details: error.stack
    };
  }
  return {
    code: 500,
    message: String(error)
  };
};
