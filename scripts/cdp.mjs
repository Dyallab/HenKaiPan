#!/usr/bin/env node
// Dependency-free CDP client (Node 22+ has global WebSocket + fetch).
// Drives a Chromium started with --remote-debugging-port=PORT.
// Usage:
//   cdp screenshot --url <url> --out <file.png> [--cookie name=value ...]
//                    [--click <selector> ...] [--eval "<js>"] [--wait <ms>]
//                    [--viewport <W,H>] [--cdp-port 9222]
//   cdp eval --url <url> --eval "<js expression>" [--cookie name=value ...]
import process from "node:process";
import fs from "node:fs";

const PORT = process.env.CDP_PORT || "9222";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class CDP {
  constructor(wsUrl) {
    this.wsUrl = wsUrl;
    this.id = 0;
    this.pending = new Map();
    this.sessionId = null;
    this.loaded = false;
    this._open = new Promise((res, rej) => {
      this._res = res;
      this._rej = rej;
    });
    this.ws = null;
  }
  connect() {
    this.ws = new WebSocket(this.wsUrl);
    this.ws.onopen = () => this._res();
    this.ws.onmessage = (e) => this._onMsg(e.data);
    this.ws.onerror = (e) => console.error("[ws error]", e.message || e);
    this.ws.onclose = () => {};
    return this._open;
  }
  _onMsg(data) {
    let m;
    try {
      m = JSON.parse(data);
    } catch {
      return;
    }
    if (m.method === "Page.loadEventFired") this.loaded = true;
    if (m.id && this.pending.has(m.id)) {
      const { resolve, reject } = this.pending.get(m.id);
      this.pending.delete(m.id);
      if (m.error) reject(new Error(JSON.stringify(m.error)));
      else resolve(m.result);
    }
  }
  _send(method, params, sessionId = null) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      const payload = { id, method, params };
      if (sessionId) payload.sessionId = sessionId;
      this.ws.send(JSON.stringify(payload));
    });
  }
  browserCmd(method, params = {}) {
    return this._send(method, params);
  }
  cmd(method, params = {}) {
    return this._send(method, params, this.sessionId);
  }
  async waitForLoad(timeoutMs = 15000) {
    const start = Date.now();
    while (!this.loaded && Date.now() - start < timeoutMs) await sleep(100);
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args[0] === "screenshot" || args[0] === "eval") {
    // subcommand style
  }
  // Parse flags
  const get = (name, def) => {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : def;
  };
  const has = (name) => args.includes(name);
  const collect = (name) => {
    const out = [];
    for (let i = 0; i < args.length; i++) {
      if (args[i] === name) out.push(args[i + 1]);
    }
    return out;
  };

  const url = get("--url");
  const out = get("--out");
  const waitMs = parseInt(get("--wait", "2500"), 10);
  const clickWait = parseInt(get("--click-wait", "1200"), 10);
  const evalExpr = get("--eval");
  const cookies = collect("--cookie").map((c) => {
    const eq = c.indexOf("=");
    return { name: c.slice(0, eq), value: c.slice(eq + 1) };
  });
  const clicks = collect("--click");
  const vp = get("--viewport");
  const port = get("--cdp-port", PORT);

  if (!url) {
    console.error("Missing --url");
    process.exit(1);
  }

  const version = await fetch(`http://localhost:${port}/json/version`).then((r) =>
    r.json(),
  );
  const cdp = new CDP(version.webSocketDebuggerUrl);
  await cdp.connect();

  const host = new URL(url).hostname;
  const { targetId } = await cdp.browserCmd("Target.createTarget", {
    url: "about:blank",
  });
  const { sessionId } = await cdp.browserCmd("Target.attachToTarget", {
    targetId,
    flatten: true,
  });
  cdp.sessionId = sessionId;

  await cdp.cmd("Page.enable");
  await cdp.cmd("Network.enable");
  if (vp) {
    const [w, h] = vp.split(",").map((n) => parseInt(n, 10));
    await cdp.cmd("Emulation.setDeviceMetricsOverride", {
      width: w,
      height: h,
      deviceScaleFactor: 1,
      mobile: false,
    });
  }
  for (const c of cookies) {
    await cdp.cmd("Network.setCookie", {
      name: c.name,
      value: c.value,
      domain: host,
      path: "/",
      secure: false,
      sameSite: "Lax",
    });
  }

  cdp.loaded = false;
  await cdp.cmd("Page.navigate", { url });
  await cdp.waitForLoad();
  await sleep(waitMs);

  for (const sel of clicks) {
    await cdp.cmd("Runtime.evaluate", {
      expression: `(document.querySelector(${JSON.stringify(sel)})||{}).click && document.querySelector(${JSON.stringify(sel)}).click(); "clicked ${sel}"`,
    });
    await sleep(clickWait);
  }

  if (evalExpr) {
    const r = await cdp.cmd("Runtime.evaluate", {
      expression: evalExpr,
      returnByValue: true,
    });
    const v = r && r.result ? r.result.value : r;
    console.log(typeof v === "string" ? v : JSON.stringify(v, null, 2));
  }

  if (out) {
    const s = await cdp.cmd("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(out, Buffer.from(s.data, "base64"));
    console.error(`screenshot -> ${out}`);
  }

  await cdp.browserCmd("Target.closeTarget", { targetId });
  process.exit(0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
