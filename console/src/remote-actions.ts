export type RemoteFeedback = { message: string; tone: "notice" | "warning" | "error" };

// Only finish the request that is actually pending. A late response from a
// timed-out click must not clear the next click's pending state.
export function cadResult(message: Record<string, unknown>, pending: string | null): RemoteFeedback | null {
  if (!pending || message.ch !== "sys") return null;
  if (message.t === "action.result" && message.action === "cad" && message.req === pending) {
    if (typeof message.ok !== "boolean" || typeof message.message !== "string" || !message.message) {
      return { tone: "error", message: "The Windows agent returned an invalid Ctrl+Alt+Del result. Update the agent and reconnect." };
    }
    return {
      tone: message.ok === true ? "notice" : "error",
      message: message.message,
    };
  }
  // Older agents have no correlated result and their direct SendSAS fallback
  // cannot verify success. Keep those responses visible without certifying it.
  if ((message.t === "notice" || message.t === "error") && typeof message.message === "string"
      && message.message.startsWith("Ctrl+Alt+Del")) {
    return message.t === "error"
      ? { tone: "error", message: message.message }
      : { tone: "warning", message: "The agent returned a legacy Ctrl+Alt+Del response. If the sign-in screen did not change, update the Windows agent and reconnect." };
  }
  return null;
}

// ------------------------------------------------------------------ screen sizing
// How the remote screen is shown. Every mode keeps the remote screen's shape: it is scaled by one factor for width and
// height, never stretched or squashed. "fit" fills the viewer window, "actual" shows real pixels (scroll if larger),
// and a fixed size shows it inside a box of exactly that many pixels, whatever the remote screen's resolution.
export type ScreenSizeMode = "fit" | "actual" | "1920x1080" | "1600x900" | "1366x768" | "1280x720";
export const SCREEN_SIZE_MODES: { value: ScreenSizeMode; label: string }[] = [
  { value: "fit", label: "Fit window" },
  { value: "actual", label: "Actual size (1:1)" },
  { value: "1920x1080", label: "1920 × 1080" },
  { value: "1600x900", label: "1600 × 900" },
  { value: "1366x768", label: "1366 × 768" },
  { value: "1280x720", label: "1280 × 720" },
];

export function isScreenSizeMode(value: unknown): value is ScreenSizeMode {
  return SCREEN_SIZE_MODES.some((m) => m.value === value);
}

/** The on-screen size of the remote picture: same proportions as the remote screen, whole pixels. */
export function screenDisplaySize(mode: ScreenSizeMode, remote: { w: number; h: number }, area: { w: number; h: number }) {
  const rw = Math.max(1, remote.w), rh = Math.max(1, remote.h);
  if (mode === "actual") return { w: rw, h: rh, scale: 1 };
  const [bw, bh] = mode === "fit" ? [area.w, area.h] : mode.split("x").map(Number);
  const scale = Math.max(0.01, Math.min(Math.max(1, bw) / rw, Math.max(1, bh) / rh));
  return { w: Math.max(1, Math.round(rw * scale)), h: Math.max(1, Math.round(rh * scale)), scale };
}
