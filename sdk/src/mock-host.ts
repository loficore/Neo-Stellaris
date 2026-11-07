// mock-host.ts — the v1 native contract, implemented in plain JavaScript.
//
// One source of truth for three consumers:
//   * `sdk/test/*.test.mjs` installs it on the Node `globalThis` (B1);
//   * `neo check` evaluates it inside a real QuickJS context before the bundle
//     (B3), so the smoke test exercises the same wrapper code the game will;
//   * the docs quote the recorded call shape.
//
// The script is deliberately ES5-flavoured and self-contained: it runs both in
// Node and in QuickJS with no module machinery.

export const MOCK_DEGREE = 3;
export const MOCK_BETWEENNESS = 250;
export const MOCK_CHOKEPOINT = true;
export const MOCK_API_VERSION = 1;

export interface MockCall {
  fn: string;
  id?: number;
  name?: string;
  value?: number;
  message?: string;
}

export interface MockState {
  handler: ((id: number) => void) | null;
  registers: number;
  apiVersionCalls: number;
  calls: MockCall[];
  degree: number;
  betweenness: number;
  chokepoint: boolean;
  apiVersion: number;
}

export interface MockHostOptions {
  /** Native names to leave undefined — used to prove `neo check` catches a missing API. */
  omit?: readonly string[];
}

const STATE_SOURCE = `
globalThis.__neo_mock = {
  handler: null,
  registers: 0,
  apiVersionCalls: 0,
  calls: [],
  degree: ${MOCK_DEGREE},
  betweenness: ${MOCK_BETWEENNESS},
  chokepoint: ${MOCK_CHOKEPOINT ? "true" : "false"},
  apiVersion: ${MOCK_API_VERSION}
};
`;

const FUNCTION_SOURCE: Record<string, string> = {
  __neo_register_system: `
globalThis.__neo_register_system = function (fn) {
  if (typeof fn !== "function") {
    throw new TypeError("__neo_register_system expects a function");
  }
  globalThis.__neo_mock.registers += 1;
  globalThis.__neo_mock.handler = fn;
};
`,
  __neo_system_degree: `
globalThis.__neo_system_degree = function (id) {
  globalThis.__neo_mock.calls.push({ fn: "__neo_system_degree", id: id >>> 0 });
  return globalThis.__neo_mock.degree;
};
`,
  __neo_system_set_var: `
globalThis.__neo_system_set_var = function (id, name, value) {
  globalThis.__neo_mock.calls.push({
    fn: "__neo_system_set_var",
    id: id >>> 0,
    name: String(name),
    value: Number(value)
  });
};
`,
  __neo_graph_betweenness: `
globalThis.__neo_graph_betweenness = function (id) {
  globalThis.__neo_mock.calls.push({ fn: "__neo_graph_betweenness", id: id >>> 0 });
  return globalThis.__neo_mock.betweenness;
};
`,
  __neo_graph_is_chokepoint: `
globalThis.__neo_graph_is_chokepoint = function (id) {
  globalThis.__neo_mock.calls.push({ fn: "__neo_graph_is_chokepoint", id: id >>> 0 });
  return globalThis.__neo_mock.chokepoint;
};
`,
  __neo_log: `
globalThis.__neo_log = function (message) {
  globalThis.__neo_mock.calls.push({ fn: "__neo_log", message: String(message) });
};
`,
  __neo_api_version: `
globalThis.__neo_api_version = function () {
  globalThis.__neo_mock.apiVersionCalls += 1;
  globalThis.__neo_mock.calls.push({ fn: "__neo_api_version" });
  return globalThis.__neo_mock.apiVersion;
};
`,
};

export const MOCK_HOST_FUNCTIONS = Object.keys(FUNCTION_SOURCE);

/** The script that installs the mock host (and its recorder) on `globalThis`. */
export function mockHostSource(options: MockHostOptions = {}): string {
  const omit = new Set(options.omit ?? []);
  const parts = [STATE_SOURCE];
  for (const name of MOCK_HOST_FUNCTIONS) {
    if (!omit.has(name)) parts.push(FUNCTION_SOURCE[name]);
  }
  return parts.join("\n");
}

/** Install the mock host on the current Node realm. */
export function installMockHost(options: MockHostOptions = {}): void {
  new Function(mockHostSource(options))();
}

/** The recorder installed by {@link installMockHost}. */
export function mockState(): MockState {
  return (globalThis as unknown as { __neo_mock: MockState }).__neo_mock;
}
