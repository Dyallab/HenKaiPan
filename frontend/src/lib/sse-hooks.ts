import { getSSEClient, SSEEventType, SSEEvent, FindingSummaryData, FindingValidationData } from "@lib/sse";

export function useSSE(options?: {
  projectId?: string;
  debug?: boolean;
}) {
  const client = getSSEClient({
    projectId: options?.projectId,
    debug: options?.debug ?? false,
  });

  if (!client.isConnected()) {
    client.connect();
  }

  return {
    on: <T = any>(type: SSEEventType, handler: (event: SSEEvent<T>) => void) => {
      client.on(type, handler);
    },

    off: <T = any>(type: SSEEventType, handler?: (event: SSEEvent<T>) => void) => {
      if (handler) {
        client.off(type, handler);
      } else {
        client.offAll(type);
      }
    },

    getStats: () => client.getStats(),

    isConnected: () => client.isConnected(),

    connect: () => client.connect(),

    disconnect: () => client.disconnect(),

    getClient: () => client,
  };
}

/**
 * Higher-order helper for handling finding summary events
 */
export function onFindingSummary(
  handler: (findingId: string, summary: string) => void,
  sse: ReturnType<typeof useSSE>,
) {
  sse.on<FindingSummaryData>("finding_summary_completed", (event) => {
    handler(event.data.finding_id, event.data.summary);
  });
}

/**
 * Higher-order helper for handling finding validation events
 */
export function onFindingValidation(
  handler: (
    findingId: string,
    confidence: number,
    reasoning: string,
    fpLikelihood: "low" | "medium" | "high",
  ) => void,
  sse: ReturnType<typeof useSSE>,
) {
  sse.on<FindingValidationData>("finding_validation_completed", (event) => {
    const { finding_id, confidence, reasoning, fp_likelihood } = event.data;
    handler(finding_id, confidence, reasoning, fp_likelihood);
  });
}

/**
 * Helper to create a Promise that resolves when a specific event is received
 * Useful for waiting for async operations
 * 
 * Usage:
 * ```ts
 * const summary = await waitForSSEEvent("finding_summary_completed", findingId);
 * ```
 */
export function waitForSSEEvent<T = any>(
  eventType: SSEEventType,
  timeoutMs: number = 60000,
  filterFn?: (event: SSEEvent<T>) => boolean,
): Promise<SSEEvent<T>> {
  return new Promise((resolve, reject) => {
    const client = getSSEClient();
    const timeout = setTimeout(() => {
      client.off(eventType, handler);
      reject(new Error(`Timeout waiting for ${eventType}`));
    }, timeoutMs);

    const handler = (event: SSEEvent<T>) => {
      if (filterFn && !filterFn(event)) {
        return;
      }
      clearTimeout(timeout);
      client.off(eventType, handler);
      resolve(event);
    };

    client.on(eventType, handler);

    // Auto-connect if not already connected
    if (!client.isConnected()) {
      client.connect();
    }
  });
}
