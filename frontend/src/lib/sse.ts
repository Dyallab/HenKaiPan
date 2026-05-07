import { API_BASE } from "./api";

export type SSEEventType =
  | "finding_summary_completed"
  | "finding_validation_completed"
  | "scan_completed"
  | "scan_failed"
  | "webhook_delivered"
  | "webhook_failed"
  | "risk_acceptance_approved"
  | "risk_acceptance_rejected"
  | "policy_violation"
  | "scheduled_task_completed"
  | "notification_created";

/** All known SSE event types — used to register EventSource listeners */
export const ALL_SSE_EVENT_TYPES: SSEEventType[] = [
  "finding_summary_completed",
  "finding_validation_completed",
  "scan_completed",
  "scan_failed",
  "webhook_delivered",
  "webhook_failed",
  "risk_acceptance_approved",
  "risk_acceptance_rejected",
  "policy_violation",
  "scheduled_task_completed",
  "notification_created",
];

export interface SSEEvent<T = any> {
  type: SSEEventType;
  data: T;
  metadata?: {
    user_id?: string;
    project_id?: string;
    finding_id?: string;
    scan_id?: string;
    tags?: Record<string, string>;
  };
  created_at: string;
}

// Event-specific data types
export interface FindingSummaryData {
  finding_id: string;
  summary: string;
}

export interface FindingValidationData {
  finding_id: string;
  confidence: number;
  reasoning: string;
  fp_likelihood: "low" | "medium" | "high";
}

export interface ScanData {
  scan_id: string;
  project_id: string;
  scanner: string;
  finding_count: number;
  error?: string;
}

export interface WebhookData {
  webhook_id: string;
  delivery_id: string;
  event_type: string;
  success: boolean;
  status_code?: number;
  error?: string;
}

export interface RiskAcceptanceData {
  risk_acceptance_id: string;
  finding_id: string;
  user_id: string;
  status: "approved" | "rejected";
  review_notes?: string;
}

export type SSEEventHandler<T = any> = (event: SSEEvent<T>) => void;

export interface SSEClientOptions {
  /** Project ID for scoped events */
  projectId?: string;
  /** Enable debug logging */
  debug?: boolean;
  /** Maximum reconnection attempts (default: Infinity) */
  maxReconnectAttempts?: number;
  /** Initial reconnection delay in ms (default: 1000) */
  reconnectDelay?: number;
  /** Maximum reconnection delay in ms (default: 30000) */
  maxReconnectDelay?: number;
  /** Delay multiplier for exponential backoff (default: 2) */
  reconnectDelayMultiplier?: number;
}

export interface SSEClientStats {
  connected: boolean;
  reconnecting: boolean;
  reconnectAttempts: number;
  lastEventAt?: Date;
  eventsReceived: number;
}

/**
 * SSE Client with automatic reconnection and event filtering
 */
export class SSEClient {
  private es: EventSource | null = null;
  private options: SSEClientOptions;
  private handlers: Map<SSEEventType, Set<SSEEventHandler>> = new Map();
  private stats: SSEClientStats = {
    connected: false,
    reconnecting: false,
    reconnectAttempts: 0,
    eventsReceived: 0,
  };
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private logEnabled: boolean;

  constructor(options: SSEClientOptions = {}) {
    this.options = {
      debug: false,
      maxReconnectAttempts: Infinity,
      reconnectDelay: 1000,
      maxReconnectDelay: 30000,
      reconnectDelayMultiplier: 2,
      ...options,
    };
    this.logEnabled = this.options.debug ?? false;
  }

  /**
   * Connect to SSE endpoint
   */
  connect(): void {
    if (this.es) {
      this.log("Connection already exists, skipping");
      return;
    }

    this.setupConnection();
  }

  private setupConnection(): void {
    const params = new URLSearchParams();

    if (this.options.projectId) {
      params.set("project_id", this.options.projectId);
    }

    const queryString = params.toString();
    const url = `${API_BASE}/api/events${queryString ? `?${queryString}` : ""}`;

    this.log("Connecting to SSE endpoint:", url);
    this.stats.reconnecting = true;

    this.es = new EventSource(url, { withCredentials: true });

    this.es.onopen = () => {
      this.log("SSE connection established");
      this.stats.connected = true;
      this.stats.reconnecting = false;
      this.stats.reconnectAttempts = 0;
      this.emit("connected" as SSEEventType, {
        type: "connected" as SSEEventType,
        data: { status: "connected" },
        created_at: new Date().toISOString(),
      });
    };

    this.es.onerror = (error) => {
      this.log("SSE connection error:", error);
      this.stats.connected = false;
      this.es?.close();
      this.es = null;

      this.scheduleReconnect();
    };

    ALL_SSE_EVENT_TYPES.forEach((type) => {
      this.es!.addEventListener(type, this.handleEvent(type));
    });

    this.es.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data) as SSEEvent;
        this.handleGenericEvent(parsed);
      } catch (err) {
        this.log("Failed to parse message:", event.data);
      }
    };
  }

  private handleEvent(type: SSEEventType) {
    return (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        const sseEvent: SSEEvent = {
          type,
          data: data.data || data,
          metadata: data.metadata,
          created_at: data.created_at || new Date().toISOString(),
        };
        this.emit(type, sseEvent);
      } catch (err) {
        this.log("Failed to parse event:", event.data, err);
      }
    };
  }

  private handleGenericEvent(event: SSEEvent): void {
    // Fallback for events that don't have a specific handler
    this.emit(event.type, event);
  }

  private scheduleReconnect(): void {
    if (
      this.stats.reconnectAttempts >= (this.options.maxReconnectAttempts ?? Infinity)
    ) {
      this.log("Max reconnection attempts reached");
      this.emit("connected" as SSEEventType, {
        type: "connected" as SSEEventType,
        data: { status: "disconnected", error: "max_reconnect_attempts" },
        created_at: new Date().toISOString(),
      });
      return;
    }

    const delay = Math.min(
      (this.options.reconnectDelay ?? 1000) *
        Math.pow(
          this.options.reconnectDelayMultiplier ?? 2,
          this.stats.reconnectAttempts,
        ),
      this.options.maxReconnectDelay ?? 30000,
    );

    this.stats.reconnectAttempts++;
    this.stats.reconnecting = true;

    this.log(`Scheduling reconnection in ${delay}ms (attempt ${this.stats.reconnectAttempts})`);

    this.reconnectTimer = setTimeout(() => {
      this.setupConnection();
    }, delay);
  }

  /**
   * Subscribe to an event type
   */
  on<T = any>(type: SSEEventType, handler: SSEEventHandler<T>): void {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, new Set());
    }
    this.handlers.get(type)!.add(handler as SSEEventHandler);
    this.log(`Subscribed to event type: ${type}`);
  }

  /**
   * Unsubscribe from an event type
   */
  off<T = any>(type: SSEEventType, handler: SSEEventHandler<T>): void {
    const handlers = this.handlers.get(type);
    if (handlers) {
      handlers.delete(handler as SSEEventHandler);
      this.log(`Unsubscribed from event type: ${type}`);
    }
  }

  /**
   * Clear all handlers for an event type
   */
  offAll(type: SSEEventType): void {
    this.handlers.delete(type);
  }

  private emit(type: SSEEventType, event: SSEEvent): void {
    this.stats.eventsReceived++;
    this.stats.lastEventAt = new Date();

    const handlers = this.handlers.get(type);
    if (handlers) {
      handlers.forEach((handler) => {
        try {
          handler(event);
        } catch (err) {
          console.error(`Error in SSE handler for ${type}:`, err);
        }
      });
    }

    // Also emit to generic handler if registered
    const genericHandlers = this.handlers.get("*" as SSEEventType);
    if (genericHandlers) {
      genericHandlers.forEach((handler) => {
        try {
          handler(event);
        } catch (err) {
          console.error(`Error in generic SSE handler:`, err);
        }
      });
    }
  }

  /**
   * Get current connection stats
   */
  getStats(): SSEClientStats {
    return { ...this.stats };
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.stats.connected;
  }

  /**
   * Disconnect from SSE endpoint
   */
  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.es) {
      this.es.close();
      this.es = null;
    }

    this.stats.connected = false;
    this.stats.reconnecting = false;
    this.log("SSE connection closed");
  }

  private log(...args: any[]): void {
    if (this.logEnabled) {
      console.log("[SSEClient]", ...args);
    }
  }
}

// Singleton instance for application-wide use
let globalSSEClient: SSEClient | null = null;

/**
 * Get or create the global SSE client instance
 */
export function getSSEClient(options?: SSEClientOptions): SSEClient {
  if (!globalSSEClient) {
    globalSSEClient = new SSEClient(options);
  }
  return globalSSEClient;
}

/**
 * Reset the global SSE client (useful for testing)
 */
export function resetSSEClient(): void {
  if (globalSSEClient) {
    globalSSEClient.disconnect();
    globalSSEClient = null;
  }
}
