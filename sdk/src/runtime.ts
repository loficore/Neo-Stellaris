/// <reference path="./globals.d.ts" />
// runtime.ts — the `@neo/runtime` surface.  Every entry point is a thin shim
// over the frozen native contract in `sdk/api.def`; no state is cached here.
//
// `System` intentionally carries only `id` (plus `degree`, which is read on
// each access).  The host may only use the engine scope for the duration of
// one call, so the SDK must not retain anything but the numeric id.

export const API_VERSION = 1;

export interface System {
  readonly id: number;
  readonly degree: number;
  setVariable(name: string, value: number): void;
}

export function onSystem(fn: (s: System) => void): void {
  __neo_register_system((id: number) => {
    fn({
      id,
      get degree(): number {
        return __neo_system_degree(id);
      },
      setVariable(name: string, value: number): void {
        __neo_system_set_var(id, name, value);
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

export function log(message: string): void {
  __neo_log(message);
}

export function apiVersion(): number {
  return __neo_api_version();
}
