/**
 * Canvas 颜色常量集中管理
 * Canvas 不支持 CSS var()，所有 Canvas 组件的颜色定义统一放在此处。
 */

// ── 共用颜色：TraceTable 和 Minimap 都用到的颜色值 ──
export const SHARED_COLORS = {
  bgPrimary: "#1e1f22",
  borderColor: "#3e4150",
  textSecondary: "#636d83",
  textAddress: "#61afef",
  textChanges: "#e5c07b",
  asmMnemonic: "#c678dd",
  asmRegister: "#56b6c2",
  asmMemory: "#e5c07b",
  asmImmediate: "#d19a66",
};

// ── TraceTable 特有颜色 ──
export const TRACE_TABLE_COLORS = {
  bgSecondary: "#27282c",
  bgRowEven: "#1e1f22",
  bgRowOdd: "#222327",
  bgSelected: "#2c3e5c",
  textPrimary: "#abb2bf",
  asmShift: "#98c379",
  arrowAnchor: "#e05050",
  arrowDef: "#4caf50",
  arrowUse: "#5c9fd6",
  bgHover: "rgba(255,255,255,0.04)",
  arrowAnchorBg: "rgba(255,255,255,0.08)",
  arrowDefBg: "rgba(76,175,80,0.12)",
  arrowUseBg: "rgba(92,159,214,0.12)",
  bgMultiSelect: "rgba(80,200,120,0.18)",
  strikethroughLine: "#888888",
  commentGutter: "rgba(230,160,50,0.8)",
  commentInline: "#8b95a7",
  callInfoNormal: "#56d4dd",   // cyan: normal external function call
  callInfoJni: "#c792ea",      // purple: JNI call
};

// ── Minimap 特有颜色 ──
export const MINIMAP_COLORS = {
  selected: "rgba(44, 62, 92, 0.6)",
  viewportBg: "rgba(255,255,255,0.08)",
  viewportHover: "rgba(255,255,255,0.15)",
  viewportDrag: "rgba(255,255,255,0.20)",
};
