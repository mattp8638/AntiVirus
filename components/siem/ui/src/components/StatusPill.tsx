type StatusPillProps = {
  status: "Healthy" | "Degraded" | "At Risk";
};

const StatusPill = ({ status }: StatusPillProps) => (
  <span className={`status-pill status-pill--${status.replace(" ", "-").toLowerCase()}`}>
    {status}
  </span>
);

export default StatusPill;
