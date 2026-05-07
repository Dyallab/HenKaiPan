import { getSSEClient, type SSEClientStats } from "@lib/sse";

export function createSSEIndicator(
  containerId: string,
  options?: { debug?: boolean },
) {
  const client = getSSEClient({ debug: options?.debug });
  const container = document.getElementById(containerId);

  if (!container) {
    console.warn(`SSE Indicator: Container #${containerId} not found`);
    return { update: () => {}, destroy: () => {} };
  }

  container.innerHTML = `
    <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium transition-all">
      <span class="material-symbols-outlined text-sm">wifi</span>
      <span class="status-text">Connecting...</span>
    </div>
  `;

  const indicator = container.firstElementChild as HTMLElement;
  const statusText = container.querySelector(".status-text") as HTMLElement;

  function update(stats: SSEClientStats) {
    if (stats.connected) {
      indicator.className =
        "inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium transition-all bg-emerald-500/10 border border-emerald-500/20 text-emerald-300";
      indicator.innerHTML = `
        <span class="material-symbols-outlined text-sm">wifi</span>
        <span class="status-text">Live</span>
      `;
    } else if (stats.reconnecting) {
      indicator.className =
        "inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium transition-all bg-amber-500/10 border border-amber-500/20 text-amber-300 animate-pulse";
      indicator.innerHTML = `
        <span class="material-symbols-outlined text-sm">wifi_off</span>
        <span class="status-text">Reconnecting (${stats.reconnectAttempts})...</span>
      `;
    } else {
      indicator.className =
        "inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium transition-all bg-red-500/10 border border-red-500/20 text-red-300";
      indicator.innerHTML = `
        <span class="material-symbols-outlined text-sm">wifi_off</span>
        <span class="status-text">Disconnected</span>
      `;
    }
  }

  update(client.getStats());

  let lastState: boolean | null = null;
  client.on("*" as any, () => {
    const stats = client.getStats();
    if (stats.connected !== lastState) {
      update(stats);
      lastState = stats.connected;
    }
  });

  return {
    update: (stats?: SSEClientStats) => {
      update(stats ?? client.getStats());
    },
    destroy: () => {
      container.innerHTML = "";
    },
  };
}

export function initSSEStatusIndicator(
  containerId: string = "sse-status",
  options?: { debug?: boolean },
) {
  const indicator = createSSEIndicator(containerId, options);

  const client = getSSEClient({ debug: options?.debug });
  if (!client.isConnected()) {
    client.connect();
  }

  const interval = setInterval(() => {
    indicator.update();
  }, 2000);

  return { indicator, interval };
}
