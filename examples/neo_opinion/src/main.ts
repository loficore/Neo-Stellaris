import { log, onCountry } from "@neo/runtime";

// 只读示例：报表式读取。单国存档里 target 可以就是自己（对角线），
// 所以这一条在 C1/C2 那种存档上也有可判读的日志；方向定型和跨国对照要另一发。
//
// `null` 不是 0：它表示这一格 fail-closed（未计算 / 越界 / 表没建 / 会话没有
// `opinion.read` / id 与当次派发的 scope 不一致），宿主会同时落一行
// `NEO_JS_OPINION_REJECT … reason=<tag>`。方向只有 B 级——`opinionOf` 与
// `theirOpinionOf` 读互为转置的两格（A），但「哪一向 = 己对目标」未定。
onCountry((c) => {
  const self = c.opinionOf(c.id);
  log(`NEO_OPINION_SELF id=${c.id} value=${self === null ? "null" : self}`);
});
