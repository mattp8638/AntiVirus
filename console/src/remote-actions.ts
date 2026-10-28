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
