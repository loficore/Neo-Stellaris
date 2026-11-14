"use strict";
// R10 good bundle — the v1 contract probe.  Hand-written on purpose (no SDK build):
// the loading contract is `C:/temp/neo_mods/<id>/neo/main.js` and the natives are
// the frozen names in `sdk/api.def`.
//
// Two lines per dispatch, nothing else:
//   R10_NBR  — `n === deg` is the reading: both natives read two fields of the same
//              edge container, so any disagreement is a layout/walk defect, not a
//              graph fact.  `first` is checked against the container id range.
//   R10_FLAG — `before=false` then `after=true`; a name that was already true before
//              the write would prove nothing (`r10flag` must not occur in the save).
const LOG = globalThis.__neo_log;

globalThis.__neo_register_system((id) => {
  const deg = __neo_system_degree(id);
  const nbr = __neo_system_neighbors(id);
  const first = nbr.length ? nbr[0] : 4294967295;
  LOG(`R10_NBR id=${id} deg=${deg} n=${nbr.length} first=${first}`);

  const before = __neo_system_has_flag(id, "r10flag");
  __neo_system_set_flag(id, "r10flag");
  const after = __neo_system_has_flag(id, "r10flag");
  LOG(`R10_FLAG id=${id} before=${before} after=${after}`);
});
