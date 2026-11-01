import { FormEvent, useEffect, useRef, useState } from "react";
import { Modal } from "./ui";

// In-page replacements for window.confirm / prompt / alert: they work in installed apps and on phones (where the browser
// dialogs are blocked or look broken), match the console, and keep focus and the Escape key where people expect them.
// Each returns a promise, so `if (!(await confirmDialog("Delete it?"))) return;` reads like the browser call it replaces.

interface ConfirmOptions { title?: string; confirmLabel?: string; danger?: boolean }
interface PromptOptions { title?: string; placeholder?: string; required?: boolean; multiline?: boolean; inputMode?: "text" | "numeric" }

type Request =
  | { kind: "confirm"; message: string; options: ConfirmOptions; resolve: (value: boolean) => void }
  | { kind: "prompt"; message: string; defaultValue: string; options: PromptOptions; resolve: (value: string | null) => void }
  | { kind: "notice"; message: string; title?: string; resolve: () => void };

let show: ((request: Request) => void) | null = null;
const waiting: Request[] = [];

function open(request: Request) {
  if (show) show(request);
  else waiting.push(request);
}

// Actions that destroy or cut something off get a red button unless the caller says otherwise.
const DESTRUCTIVE = /^(delete|remove|revoke|end|retire|rotate|reset|stop|merge|restore|issue a new|disconnect|wipe)\b/i;

export function confirmDialog(message: string, options: ConfirmOptions = {}): Promise<boolean> {
  return new Promise((resolve) => open({ kind: "confirm", message, options, resolve }));
}

/** Resolves to the text entered, or null when cancelled (like window.prompt). */
export function promptDialog(message: string, defaultValue = "", options: PromptOptions = {}): Promise<string | null> {
  return new Promise((resolve) => open({ kind: "prompt", message, defaultValue, options, resolve }));
}

export function noticeDialog(message: string, title?: string): Promise<void> {
  return new Promise((resolve) => open({ kind: "notice", message, title, resolve }));
}

/** Mounted once, next to the app. Shows one dialog at a time, in the order they were asked for. */
export function DialogHost() {
  const [queue, setQueue] = useState<Request[]>([]);
  const [text, setText] = useState("");
  const input = useRef<HTMLInputElement & HTMLTextAreaElement>(null);
  const confirmButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    show = (request) => setQueue((current) => [...current, request]);
    if (waiting.length) setQueue((current) => [...current, ...waiting.splice(0)]);
    return () => { show = null; };
  }, []);
  const current = queue[0];
  useEffect(() => {
    if (!current) return;
    setText(current.kind === "prompt" ? current.defaultValue : "");
    window.setTimeout(() => (current.kind === "prompt" ? input.current?.select() : confirmButton.current?.focus()), 0);
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") { e.preventDefault(); finish(false); } };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [current]);
  if (!current) return null;

  function finish(accepted: boolean) {
    if (!current) return;
    if (current.kind === "confirm") current.resolve(accepted);
    else if (current.kind === "prompt") current.resolve(accepted ? text : null);
    else current.resolve();
    setQueue((rest) => rest.slice(1));
  }
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (current.kind === "prompt" && current.options.required && !text.trim()) return;
    finish(true);
  };
  const danger = current.kind === "confirm" && (current.options.danger ?? DESTRUCTIVE.test(current.message));
  const title = current.kind === "notice" ? current.title ?? "Fenrir" : current.options.title ?? (current.kind === "confirm" ? "Please confirm" : "Fenrir");
  return (
    <Modal title={title} onClose={() => finish(false)}>
      <form onSubmit={submit}>
        {current.kind === "prompt" ? (
          <label className="field">{current.message}
            {current.options.multiline
              ? <textarea ref={input} rows={4} value={text} placeholder={current.options.placeholder} onChange={(e) => setText(e.target.value)} />
              : <input ref={input} value={text} placeholder={current.options.placeholder} inputMode={current.options.inputMode}
                       onChange={(e) => setText(e.target.value)} />}
          </label>
        ) : <p style={{ whiteSpace: "pre-wrap", marginTop: 0 }}>{current.message}</p>}
        <div className="foot">
          {current.kind !== "notice" && <button type="button" onClick={() => finish(false)}>Cancel</button>}
          <button ref={confirmButton} type="submit" className={danger ? "danger" : "primary"}
                  disabled={current.kind === "prompt" && !!current.options.required && !text.trim()}>
            {current.kind === "confirm" ? current.options.confirmLabel ?? "Continue" : "OK"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
