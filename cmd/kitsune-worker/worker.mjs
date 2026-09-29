// Boots the Go program once per isolate and reuses it for every request. The
// stock workers-go shim creates a fresh Wasm instance per request, which would re-run profiler.New() (JSON parse + ~20k regex
// compiles) and allocate a new linear memory each time.
import { connect } from "cloudflare:sockets";
import "./wasm_exec.js";
import mod from "./app.wasm";

globalThis.tryCatch = (fn) => {
  try {
    return { result: fn() };
  } catch (e) {
    return { error: e };
  }
};

// workers-go reads bindings from this object via js.Global().Get("context").
// connect backs its sockets package (see egress.go).
const context = { binding: {}, connect };

// Boot lazily on the first request: workerd disallows crypto.getRandomValues
// and timers at global scope, and the Go runtime needs both during init.
let instance;
let go;
function boot() {
  const bootStart = performance.now();
  go = new Go();
  let ready = false;
  instance = new WebAssembly.Instance(mod, {
    ...go.importObject,
    workers: { ready: () => { ready = true; } },
  });
  // main() runs synchronously until it blocks in select{}, so the engine is
  // initialized (and ready() called) before this returns.
  go.run(instance, context).catch((e) => console.error("go exited", e));
  if (!ready) throw new Error("Go program did not signal readiness");
  console.log(JSON.stringify({
    event: "boot",
    boot_ms: Math.round(performance.now() - bootStart),
    wasm_mem_mb: Math.round(instance.exports.mem.buffer.byteLength / 1048576),
  }));
}

export default {
  async fetch(req, env, ctx) {
    // If a previous request was killed mid-execution (e.g. exceededCpu), the Go
    // program is dead; start a fresh one rather than failing every request.
    const cold = instance === undefined || go.exited;
    if (cold) boot();
    context.env = env;
    context.ctx = ctx;
    let res;
    try {
      res = await context.binding.handleRequest(req);
    } catch (e) {
      // The Go side recovers handler panics itself, so an error here means the
      // runtime is in a bad state. Reboot on the next request.
      console.error("handleRequest failed; discarding instance", String(e));
      instance = undefined;
      return new Response("internal error", { status: 500 });
    }
    const headers = new Headers(res.headers);
    headers.set("x-cold-start", String(cold));
    headers.set("x-wasm-mem-mb", String(Math.round(instance.exports.mem.buffer.byteLength / 1048576)));
    return new Response(res.body, { status: res.status, headers });
  },
};
