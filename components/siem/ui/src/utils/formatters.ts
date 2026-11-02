import type { StatusLevel } from "../data/overview";

// Convert strings to title case for UI labels.
export const toTitleCase = (value: string) =>
  value
    .replace(/[_-]+/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");

// Safe date formatting for audit-friendly timestamps.
export const formatUtcTimestamp = (value: string) => {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  return `${parsed.toLocaleString("en-GB", { timeZone: "UTC" })} UTC`;
};

// Lightweight relative time for operational recency.
export const formatRelativeTime = (value: string) => {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }
  const diffSeconds = Math.round((Date.now() - parsed.getTime()) / 1000);
  const diffMinutes = Math.round(diffSeconds / 60);
  if (Math.abs(diffMinutes) < 60) {
    return `${diffMinutes} minutes ago`;
  }
  const diffHours = Math.round(diffMinutes / 60);
  if (Math.abs(diffHours) < 24) {
    return `${diffHours} hours ago`;
  }
  const diffDays = Math.round(diffHours / 24);
  return `${diffDays} days ago`;
};

export const mapRiskScoreToCriticality = (score: number) => {
  if (score >= 85) {
    return "Critical";
  }
  if (score >= 70) {
    return "High";
  }
  if (score >= 50) {
    return "Medium";
  }
  return "Low";
};

export const mapPresenceToStatus = (status?: string): StatusLevel => {
  if (!status) {
    return "Degraded";
  }
  const normalised = status.toLowerCase();
  if (normalised === "online" || normalised === "healthy") {
    return "Healthy";
  }
  if (normalised === "offline" || normalised === "unreachable") {
    return "At Risk";
  }
  return "Degraded";
};
