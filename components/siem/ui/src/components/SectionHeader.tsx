import { Link } from "react-router-dom";

type SectionHeaderProps = {
  title: string;
  description: string;
  actionLabel?: string;
  actionPath?: string;
};

const SectionHeader = ({ title, description, actionLabel, actionPath }: SectionHeaderProps) => (
  <div className="section-header">
    <div>
      <h2>{title}</h2>
      <p>{description}</p>
    </div>
    {actionLabel && actionPath ? (
      <Link className="ghost-button" to={actionPath}>
        {actionLabel}
      </Link>
    ) : null}
  </div>
);

export default SectionHeader;
