/// <reference path="./globals.d.ts" />
// runtime.ts — the `@neo/runtime` surface.  Every entry point is a thin shim
// over the frozen native contract in `sdk/api.def`; no state is cached here.
//
// `System` intentionally carries only `id` (plus `degree` and `neighbors`,
// which are read on each access).  The host may only use the engine scope for
// the duration of one call, so the SDK must not retain anything but the numeric
// id.
//
// v1.1 is additive: `neighbors`, `setStarFlag` and `hasStarFlag` are the only new
// members.  `API_VERSION` stays 1, so a Phase 1 bundle keeps running unchanged.
// `setStarFlag` writes through the official `set_star_flag` body (never engine
// memory) and its name must be a string literal — `neo check` enforces that at
// build time and rejects names that collide with an official keyword.

export const API_VERSION = 1;

export interface System {
  readonly id: number;
  readonly degree: number;
  /** Hyperlane neighbour system ids, as a fresh array on each access. */
  readonly neighbors: readonly number[];
  setVariable(name: string, value: number): void;
  /** Sets the official star flag `name` on this system (needs `flag.write`). */
  setStarFlag(name: string): void;
  /** Reads the official star flag `name` (needs `flag.read`). */
  hasStarFlag(name: string): boolean;
}

/**
 * A country handed to `onCountry`. Like `System`, it retains nothing but the
 * numeric id: the engine's country scope is only valid for the duration of the
 * dispatch.
 *
 * There is **no writer** on this interface and there will not be one in v1.1:
 * the opinion matrix is a read of a lazily-filled engine cache, and filling it
 * (`0x743bb0`) is a write.
 */
export interface Country {
  /**
   * Engine country id for this call: the **low 24 bits** of the dispatched
   * scope's `+0x10` (the high 8 bits are an engine type tag). Masked by the
   * host with `SCOPE_ID_MASK`, so it is also the id the opinion readers expect.
   */
  readonly id: number;
  /**
   * Engine `opinion` keyword for this country.
   *
   * `null` = fail-closed. Five ways to get there, all logged by the host as
   * `NEO_JS_OPINION_REJECT … reason=<tag>`: the cell is not computed yet
   * (`not_computed`, the engine sentinel `0x7fffffff`), either id is outside the
   * matrix (`out_of_range`), the matrix is not built (`table_null`, e.g. no
   * campaign loaded), the session lacks `opinion.read` (`no_permission`), or the
   * id is not the one being dispatched (`scope_mismatch`).
   *
   * **Direction is B-level.** `opinionOf` and `theirOpinionOf` read the two
   * transposed cells (that part is A); which one is "our opinion of them" is not
   * established, so the name is the engine's keyword, not a promise.
   */
  opinionOf(targetId: number): number | null;
  /** Engine `their_opinion` keyword: the transpose of {@link opinionOf}. */
  theirOpinionOf(targetId: number): number | null;
}

export function onSystem(fn: (s: System) => void): void {
  __neo_register_system((id: number) => {
    fn({
      id,
      get degree(): number {
        return __neo_system_degree(id);
      },
      get neighbors(): readonly number[] {
        return __neo_system_neighbors(id);
      },
      setVariable(name: string, value: number): void {
        __neo_system_set_var(id, name, value);
      },
      setStarFlag(name: string): void {
        __neo_system_set_flag(id, name);
      },
      hasStarFlag(name: string): boolean {
        return __neo_system_has_flag(id, name);
      },
    });
  });
}

export const graph = {
  betweenness(s: System): number {
    return __neo_graph_betweenness(s.id);
  },
  isChokepoint(s: System): boolean {
    return __neo_graph_is_chokepoint(s.id);
  },
};

/**
 * Registers the per-country handler. Needs `"country"` in the manifest's
 * `scope` — registering it from a system-only bundle logs
 * `NEO_JS_REGISTER_REJECT … scope=country` and is otherwise inert.
 */
export function onCountry(fn: (c: Country) => void): void {
  __neo_register_country((id: number) => {
    fn({
      id,
      opinionOf: (targetId: number) => intOrNull(__neo_country_opinion(id, targetId)),
      theirOpinionOf: (targetId: number) => intOrNull(__neo_country_their_opinion(id, targetId)),
    });
  });
}

/** A refused read comes back as `undefined`; the SDK's contract is `null`. */
function intOrNull(v: unknown): number | null {
  return typeof v === "number" ? v : null;
}

export function log(message: string): void {
  __neo_log(message);
}

export function apiVersion(): number {
  return __neo_api_version();
}
