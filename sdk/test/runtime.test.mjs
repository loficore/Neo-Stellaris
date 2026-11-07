// B1 — @neo/runtime shim: the TypeScript surface must call exactly the
// frozen native contract, and `api.def` must not drift from it.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

import { installMockHost, mockState } from "../dist/mock-host.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const sdkRoot = path.resolve(here, "..");

installMockHost();
const runtime = await import("../dist/runtime.js");

test("api.def is the frozen v1 contract", () => {
  const def = JSON.parse(readFileSync(path.join(sdkRoot, "api.def"), "utf8"));
  assert.deepEqual(def, {
    version: 1,
    functions: [
      { name: "__neo_register_system", params: ["function"], returns: "void" },
      { name: "__neo_system_degree", params: ["u32"], returns: "u32" },
      { name: "__neo_system_set_var", params: ["u32", "string", "f64"], returns: "void" },
      { name: "__neo_graph_betweenness", params: ["u32"], returns: "u32" },
      { name: "__neo_graph_is_chokepoint", params: ["u32"], returns: "bool" },
      { name: "__neo_log", params: ["string"], returns: "void" },
      { name: "__neo_api_version", params: [], returns: "u32" },
    ],
  });
  assert.equal(new Set(def.functions.map((f) => f.name)).size, 7);
});

test("API_VERSION mirrors api.def", () => {
  const def = JSON.parse(readFileSync(path.join(sdkRoot, "api.def"), "utf8"));
  assert.equal(runtime.API_VERSION, def.version);
});

test("onSystem hands the native id through and lazily reads degree", () => {
  const before = mockState().registers;
  let seen = null;
  runtime.onSystem((s) => {
    seen = { id: s.id, degree: s.degree };
  });
  const state = mockState();
  assert.equal(state.registers, before + 1);
  assert.equal(typeof state.handler, "function");

  state.handler(7);
  assert.deepEqual(seen, { id: 7, degree: state.degree });
  assert.deepEqual(
    state.calls.filter((c) => c.fn === "__neo_system_degree"),
    [{ fn: "__neo_system_degree", id: 7 }],
  );
});

test("graph, setVariable and log reach the native functions", () => {
  let call = null;
  runtime.onSystem((s) => {
    call = {
      betweenness: runtime.graph.betweenness(s),
      isChokepoint: runtime.graph.isChokepoint(s),
    };
    s.setVariable("neo_score", 42);
    runtime.log("hello");
  });
  const state = mockState();
  state.calls.length = 0;
  state.handler(7);

  assert.deepEqual(call, { betweenness: state.betweenness, isChokepoint: true });
  assert.deepEqual(state.calls, [
    { fn: "__neo_graph_betweenness", id: 7 },
    { fn: "__neo_graph_is_chokepoint", id: 7 },
    { fn: "__neo_system_set_var", id: 7, name: "neo_score", value: 42 },
    { fn: "__neo_log", message: "hello" },
  ]);
});

test("apiVersion delegates to __neo_api_version", () => {
  const state = mockState();
  const before = state.apiVersionCalls;
  assert.equal(runtime.apiVersion(), 1);
  assert.equal(mockState().apiVersionCalls, before + 1);
});
