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
export const MOCK_NEIGHBORS: readonly number[] = [1, 2];
export const MOCK_BETWEENNESS = 250;
export const MOCK_CHOKEPOINT = true;
export const MOCK_API_VERSION = 1;
/** What `__neo_country_opinion` returns before a test overrides it. */
export const MOCK_OPINION = 7;

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
  /** `onCountry`'s handler (`__neo_register_country`). */
  countryHandler: ((id: number) => void) | null;
  countryRegisters: number;
  apiVersionCalls: number;
  calls: MockCall[];
  degree: number;
  neighbors: number[];
  /** Flags set through `__neo_system_set_flag`; `has_flag` reads this map. */
  flags: Record<string, boolean>;
  betweenness: number;
  chokepoint: boolean;
  apiVersion: number;
  /**
   * What the opinion natives return. `undefined` reproduces a refused read —
   * the native returns `undefined` and the SDK must map it to `null`.
   */
  opinion: number | undefined;
}

export interface MockHostOptions {
  /** Native names to leave undefined — used to prove `neo check` catches a missing API. */
  omit?: readonly string[];
}

const STATE_SOURCE = `
globalThis.__neo_mock = {
  handler: null,
  registers: 0,
  countryHandler: null,
  countryRegisters: 0,
  apiVersionCalls: 0,
  calls: [],
  degree: ${MOCK_DEGREE},
  neighbors: ${JSON.stringify(MOCK_NEIGHBORS)},
  flags: {},
  betweenness: ${MOCK_BETWEENNESS},
  chokepoint: ${MOCK_CHOKEPOINT ? "true" : "false"},
  apiVersion: ${MOCK_API_VERSION},
  opinion: ${MOCK_OPINION}
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
  __neo_system_neighbors: `
globalThis.__neo_system_neighbors = function (id) {
  globalThis.__neo_mock.calls.push({ fn: "__neo_system_neighbors", id: id >>> 0 });
  return globalThis.__neo_mock.neighbors.slice();
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
  __neo_system_set_flag: `
globalThis.__neo_system_set_flag = function (id, name) {
  globalThis.__neo_mock.calls.push({
    fn: "__neo_system_set_flag",
    id: id >>> 0,
    name: String(name)
  });
  globalThis.__neo_mock.flags[String(name)] = true;
};
`,
  __neo_system_has_flag: `
globalThis.__neo_system_has_flag = function (id, name) {
  globalThis.__neo_mock.calls.push({
    fn: "__neo_system_has_flag",
    id: id >>> 0,
    name: String(name)
  });
  return globalThis.__neo_mock.flags[String(name)] === true;
};
`,
  __neo_register_country: `
globalThis.__neo_register_country = function (fn) {
  if (typeof fn !== "function") {
    throw new TypeError("__neo_register_country expects a function");
  }
  globalThis.__neo_mock.countryRegisters += 1;
  globalThis.__neo_mock.countryHandler = fn;
};
`,
  __neo_country_opinion: `
globalThis.__neo_country_opinion = function (self, target) {
  globalThis.__neo_mock.calls.push({
    fn: "__neo_country_opinion",
    id: self >>> 0,
    name: String(target >>> 0)
  });
  return globalThis.__neo_mock.opinion;
};
`,
  __neo_country_their_opinion: `
globalThis.__neo_country_their_opinion = function (self, target) {
  globalThis.__neo_mock.calls.push({
    fn: "__neo_country_their_opinion",
    id: self >>> 0,
    name: String(target >>> 0)
  });
  return globalThis.__neo_mock.opinion;
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
