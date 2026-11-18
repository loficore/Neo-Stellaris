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
// v1.1 country surface (2026-11-08): registration + the two read-only opinion
// cells. A refused read returns `undefined` — the SDK maps it to `null`.
declare function __neo_register_country(fn: (id: number) => void): void;
declare function __neo_country_opinion(self: number, target: number): number | undefined;
declare function __neo_country_their_opinion(self: number, target: number): number | undefined;
// v1.2 (2026-11-15) global time. Both are read-only and need no permission bit;
// the host answers `null` when the engine cannot be read (main menu, no campaign
// loaded, before the epoch). `null` is deliberately distinct from `0`: `0` is a
// valid absolute day index (the epoch day itself).
declare function __neo_game_date(): string | null;
declare function __neo_game_tick(): number | null;
// v1.3 (2026-11-15) country resource stock. Read-only, needs `resource.read`.
// `undefined` = refused (no permission), `null` = fail-closed (unreadable engine,
// unknown country/index, …) — the SDK maps both to `null`, never to `0`.
declare function __neo_country_resource(country: number, index: number): number | null | undefined;
