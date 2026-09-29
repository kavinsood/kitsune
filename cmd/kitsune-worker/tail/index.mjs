// Tail consumer for kitsune-wasm: stores a compact summary of every trace
// event (CPU/wall time, outcome, and the Go side's JSON log lines) in KV.
// GET /events returns the most recent summaries.

function parseLogs(logs) {
  const out = {};
  for (const log of logs || []) {
    for (const part of log.message || []) {
      if (typeof part !== "string") continue;
      const i = part.indexOf("{");
      if (i < 0) continue;
      try {
        const obj = JSON.parse(part.slice(i));
        if (obj.event) out[obj.event] = obj;
      } catch {}
    }
  }
  return out;
}

export default {
  async tail(events, env, ctx) {
    const puts = [];
    for (const ev of events) {
      const parsed = parseLogs(ev.logs);
      const req = ev.event?.request;
      const summary = {
        ts: ev.eventTimestamp,
        path: req ? new URL(req.url).pathname : null,
        status: ev.event?.response?.status ?? null,
        outcome: ev.outcome,
        cpu_ms: ev.cpuTime,
        wall_ms: ev.wallTime,
        colo: req?.cf?.colo,
        cold: !!parsed.boot,
        boot_ms: parsed.boot?.boot_ms,
        init_ms: parsed.init?.init_ms,
        wasm_mem_mb: parsed.boot?.wasm_mem_mb,
        analyze: parsed.analyze,
        exceptions: (ev.exceptions || []).map((e) => `${e.name}: ${e.message}`.slice(0, 300)),
        errors: (ev.logs || []).filter((l) => l.level === "error").map((l) => String(l.message).slice(0, 300)),
      };
      console.log(JSON.stringify(summary));
      // Reverse-chronological keys so list() returns newest first.
      const key = `${String(1e13 - (ev.eventTimestamp || Date.now())).padStart(14, "0")}-${crypto.randomUUID().slice(0, 8)}`;
      puts.push(env.EVENTS.put(key, JSON.stringify(summary), { expirationTtl: 7 * 86400 }));
    }
    ctx.waitUntil(Promise.all(puts));
  },

  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname !== "/events") return new Response("not found", { status: 404 });
    const limit = Math.min(Number(url.searchParams.get("limit") || 100), 500);
    const { keys } = await env.EVENTS.list({ limit });
    const values = await Promise.all(keys.map((k) => env.EVENTS.get(k.name, "json")));
    return Response.json(values.filter(Boolean));
  },
};
