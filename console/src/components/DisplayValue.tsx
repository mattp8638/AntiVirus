import { isValidElement, type ReactNode } from "react";

/** API JSON is untrusted at runtime, even when a caller declared it as `any`.
 * Keep real React content intact; never pass an arbitrary object to React or
 * dump its fields (which may contain secrets) into a text-only control.
 */
export function displayValue(value: unknown): ReactNode {
  if (value == null || typeof value === "boolean") return null;
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (isValidElement(value)) return value;
  if (Array.isArray(value)) return value.map(displayValue);
  return "Unavailable";
}
