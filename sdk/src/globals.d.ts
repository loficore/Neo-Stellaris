// globals.d.ts — the native functions of the v1 contract (`sdk/api.def`).
//
// These are installed by the host (the injected DLL) before the bundle is
// evaluated; the SDK never defines them itself.  The names are frozen: the
// Track-B/contract fence compares this list with `api.def` and with the Zig
// host's registered names.  v1.1 is additive — the v1 seven keep their names
// and `API_VERSION` stays 1; the three `__neo_system_*` entries after them are
// the new tail (neighbors, set_flag, has_flag).
declare function __neo_register_system(fn: (id: number) => void): void;
declare function __neo_system_degree(id: number): number;
declare function __neo_system_set_var(id: number, name: string, value: number): void;
declare function __neo_graph_betweenness(id: number): number;
declare function __neo_graph_is_chokepoint(id: number): boolean;
declare function __neo_log(message: string): void;
declare function __neo_api_version(): number;
declare function __neo_system_neighbors(id: number): number[];
declare function __neo_system_set_flag(id: number, name: string): void;
declare function __neo_system_has_flag(id: number, name: string): boolean;
