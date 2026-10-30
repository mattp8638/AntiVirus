// Script review (Settings > Platform > Security): a library script or remediation package runs only in a version
// someone who did not write or edit it has approved. The server sends the review state with each item.
import { api } from "../api";
import { useApp } from "../app-context";
import { confirmDialog } from "./dialogs";
import { Pill, useAction } from "./ui";

export interface Review {
  required: boolean;
  status: "shipped" | "reviewed" | "pending";
  hash: string;
  editors: string[];
  reviewedBy?: string | null;
  reviewedAt?: string | null;
  diff?: string;
}

export function needsReview(review?: Review): boolean {
  return !!review?.required && review.status === "pending";
}

export function ReviewPill({ review }: { review?: Review }) {
  if (!review?.required) return null;
  if (review.status === "pending") return <Pill value="needs review" tone="warn" />;
  return review.status === "reviewed" ? <Pill value="reviewed" tone="good" /> : null;
}

/** Shown on a script or package: what changed since the last review, and the approve button for a second person. */
export function ReviewPanel({ review, path, dirty, shared, onReviewed }: { review?: Review; path: string; dirty?: boolean; shared?: boolean; onReviewed: () => void }) {
  const { me, can } = useApp();
  const { run, busy } = useAction();
  if (!review?.required) return null;
  if (review.status !== "pending") {
    return review.reviewedBy ? <p className="small muted">Reviewed by {review.reviewedBy}{review.reviewedAt ? ` on ${new Date(review.reviewedAt).toLocaleDateString()}` : ""}.</p> : null;
  }
  const mine = !!me && review.editors.includes(me.user.email);
  const approve = async () => {
    if (!(await confirmDialog("Approve this version to run on devices? You are confirming you have read all of it."))) return;
    if (await run(() => api(`${path}/review`, { body: { hash: review.hash } }), "Approved: it can run now")) onReviewed();
  };
  return (
    <div className="card" style={{ borderColor: "var(--warn, #f59e0b)", marginBottom: 12 }}>
      <b>Waiting for review.</b> This version cannot run on devices until someone other than {review.editors.join(" or ") || "its author"} approves it.
      {review.diff ? <>
        <p className="small muted" style={{ marginBottom: 4 }}>Changes since the last reviewed version:</p>
        <pre className="small mono" style={{ whiteSpace: "pre-wrap", maxHeight: 260, overflow: "auto" }}>
          {review.diff.split("\n").map((line, i) => (
            <span key={i} style={{ display: "block", color: line.startsWith("+") && !line.startsWith("+++") ? "#86efac" : line.startsWith("-") && !line.startsWith("---") ? "#fca5a5" : undefined }}>{line}</span>
          ))}
        </pre>
      </> : <p className="small muted">Nothing was reviewed before: read the whole script below.</p>}
      {can("approve") && can("scripts") && (!shared || can("platform")) && !mine && <button className="primary" disabled={busy || dirty} onClick={approve}
        title={dirty ? "Save or discard your edits first" : undefined}>Approve this version</button>}
      {mine && <p className="small muted">You changed this version, so someone else has to review it.</p>}
    </div>
  );
}
