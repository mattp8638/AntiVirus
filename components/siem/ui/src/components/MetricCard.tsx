type MetricCardProps = {
  title: string;
  value: string | number;
  subtitle: string;
  accent?: "neutral" | "success" | "warning" | "risk";
};

const MetricCard = ({ title, value, subtitle, accent = "neutral" }: MetricCardProps) => (
  <article className={`card metric-card metric-card--${accent}`}>
    <span className="eyebrow">{title}</span>
    <h3>{value}</h3>
    <p>{subtitle}</p>
  </article>
);

export default MetricCard;
